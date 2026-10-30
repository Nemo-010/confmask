//! The runner: pick the strongest available mode, deliver secrets, and
//! run the command.
//!
//! Three modes, chosen from what the host allows:
//!
//! | mode | needs | gives |
//! |---|---|---|
//! | redact | `ptrace` | cmdline/environ/comm of the whole tree are redacted |
//! | isolate | unprivileged user namespaces | the payload gets a private mount/pid/net view |
//! | plain | nothing | secrets still arrive as descriptors, never as argv/env |
//!
//! Secret delivery is the same in all three, because it never needed a
//! privilege: a sealed memfd inherited at a known descriptor.  That is
//! the part that works in a locked-down container, and it is the part
//! that matters most for the motivating case (a CI runner whose token is
//! otherwise readable by everything on the machine).

use crate::caps::Caps;
use crate::isolate::{self, Isolate};
use crate::redact::mask::Mask;
use crate::redact::tracer::ExitState;
use crate::secret::{self, Delivery, Secret, Source};
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// How the command is going to be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Redact,
    Isolate,
    Plain,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Redact => "redact",
            Mode::Isolate => "isolate",
            Mode::Plain => "plain",
        }
    }
}

/// What actually happened.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub mode: Mode,
    pub exit: ExitState,
    pub secrets_delivered: usize,
    pub notes: Vec<String>,
}

/// Builder for one supervised run.
pub struct Runner {
    label: Option<String>,
    follow_tree: bool,
    redact_environ: bool,
    exit_kill: bool,
    quiet: bool,
    verbose: bool,
    force_mode: Option<Mode>,
    isolate: Option<Isolate>,
    secrets: Vec<(String, Source)>,
    socket: Option<PathBuf>,
}

impl Default for Runner {
    fn default() -> Self {
        Runner::new()
    }
}

impl Runner {
    pub fn new() -> Runner {
        Runner {
            label: None,
            follow_tree: true,
            redact_environ: true,
            exit_kill: true,
            quiet: false,
            verbose: false,
            force_mode: None,
            isolate: None,
            secrets: Vec::new(),
            socket: None,
        }
    }

    pub fn label(mut self, l: impl Into<String>) -> Runner {
        self.label = Some(l.into());
        self
    }

    pub fn follow_tree(mut self, on: bool) -> Runner {
        self.follow_tree = on;
        self
    }

    pub fn keep_environ_visible(mut self) -> Runner {
        self.redact_environ = false;
        self
    }

    pub fn let_tree_survive_self_death(mut self) -> Runner {
        self.exit_kill = false;
        self
    }

    pub fn quiet(mut self) -> Runner {
        self.quiet = true;
        self.verbose = false;
        self
    }

    pub fn verbose(mut self) -> Runner {
        self.verbose = true;
        self.quiet = false;
        self
    }

    /// Skip `/proc` redaction even where ptrace is available.
    pub fn no_redaction(mut self) -> Runner {
        self.force_mode = Some(Mode::Plain);
        self
    }

    /// Run inside fresh namespaces (needs unprivileged user namespaces).
    pub fn isolate(mut self, iso: Isolate) -> Runner {
        self.isolate = Some(iso);
        self
    }

    pub fn secret(mut self, name: impl Into<String>, source: Source) -> Runner {
        self.secrets.push((name.into(), source));
        self
    }

    pub fn secret_spec(mut self, spec: &str) -> io::Result<Runner> {
        let (name, src) = Source::parse(spec)?;
        self.secrets.push((name, src));
        Ok(self)
    }

    pub fn daemon_socket(mut self, p: PathBuf) -> Runner {
        self.socket = Some(p);
        self
    }

    /// Decide the mode from the host's capabilities and the request.
    ///
    /// A request the host cannot honour degrades instead of failing: a
    /// `--isolate` on a host without unprivileged user namespaces still
    /// runs the command, with the redaction (or plain) mode it can have,
    /// and `run` reports the substitution.
    pub fn mode(&self) -> Mode {
        if let Some(m) = self.force_mode {
            return m;
        }
        let caps = Caps::cached();
        if self.isolate.is_some() && caps.userns {
            return Mode::Isolate;
        }
        if caps.ptrace {
            Mode::Redact
        } else {
            Mode::Plain
        }
    }

    /// True when isolation was asked for and the host refused it.
    pub fn isolate_unavailable(&self) -> bool {
        self.isolate.is_some() && !Caps::cached().userns
    }

    /// Run the command and wait for it.
    pub fn run<P, A>(&self, program: P, args: &[A]) -> io::Result<Outcome>
    where
        P: AsRef<std::ffi::OsStr>,
        A: AsRef<std::ffi::OsStr>,
    {
        let args: Vec<OsString> = args.iter().map(|a| a.as_ref().to_os_string()).collect();
        let mut notes = Vec::new();
        let mode = self.mode();
        if self.isolate_unavailable() {
            notes.push(
                "--isolate was requested but this host has no unprivileged user namespaces; \
                 running without it"
                    .to_string(),
            );
        }

        // 1. Load secrets into protected memory.
        let mut secrets: Vec<Secret> = Vec::with_capacity(self.secrets.len());
        for (name, src) in &self.secrets {
            secrets.push(secret::load(name, src, self.socket.as_ref())?);
        }
        let delivery = Delivery::new(&secrets)?;
        if !secrets.is_empty() {
            // Once we hold plaintext, stop other processes of this account
            // from reading our memory.
            notes.extend(crate::mem::harden_self());
        }

        // 2. Environment: inherited, plus the fd map.
        let mut extra_env: Vec<(OsString, OsString)> = delivery.env().to_vec();

        // 3. Dispatch.
        let exit = match mode {
            Mode::Redact => {
                let mut mask = Mask::new()
                    .follow_tree(self.follow_tree)
                    .inherit_fds(delivery.raw_fds())
                    .extra_env(std::mem::take(&mut extra_env));
                // No label means the engine's default: each program's own
                // basename, with arguments stripped.
                if let Some(l) = &self.label {
                    mask = mask.label(l.clone());
                }
                let mask = if self.redact_environ {
                    mask
                } else {
                    mask.keep_environ_visible()
                };
                let mask = if self.exit_kill {
                    mask
                } else {
                    mask.let_tree_survive_self_death()
                };
                let mask = if self.quiet {
                    mask.quiet()
                } else if self.verbose {
                    mask.verbose()
                } else {
                    mask
                };
                // Fork first (the child must see the real environment),
                // then give the supervisor the same treatment it gives
                // the tree: its own cmdline is `confmask run --secret
                // TOKEN=file:...`, which names the secret.
                let child = mask.spawn(program.as_ref(), &args)?;
                let comm = child.label_comm().to_vec();
                let redact_env = child.redacts_environ();
                crate::redact::selfmask::mask_self(&comm, redact_env);
                child.wait()?
            }
            Mode::Isolate => {
                let iso = self.isolate.unwrap_or_else(Isolate::all);
                let prog = resolve_program(program.as_ref())?;
                let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 1);
                argv_c.push(prog.clone());
                for a in &args {
                    argv_c.push(
                        CString::new(a.as_bytes()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in argument")
                        })?,
                    );
                }
                let mut argv_ptr: Vec<*const libc::c_char> =
                    argv_c.iter().map(|c| c.as_ptr()).collect();
                argv_ptr.push(std::ptr::null());

                let mut envp_c: Vec<CString> = Vec::new();
                for (k, v) in std::env::vars_os() {
                    let mut j = k.as_bytes().to_vec();
                    j.push(b'=');
                    j.extend_from_slice(v.as_bytes());
                    j.push(0);
                    envp_c.push(unsafe { CString::from_vec_unchecked(j) });
                }
                for (k, v) in &extra_env {
                    let mut j = k.as_bytes().to_vec();
                    j.push(b'=');
                    j.extend_from_slice(v.as_bytes());
                    j.push(0);
                    envp_c.push(unsafe { CString::from_vec_unchecked(j) });
                }
                let mut envp_ptr: Vec<*const libc::c_char> =
                    envp_c.iter().map(|c| c.as_ptr()).collect();
                envp_ptr.push(std::ptr::null());

                isolate::run(&iso, &prog, &argv_ptr, &envp_ptr, &delivery.raw_fds())?
            }
            Mode::Plain => {
                let prog = resolve_program(program.as_ref())?;
                let fds = delivery.raw_fds();
                let mut cmd = std::process::Command::new(
                    std::ffi::OsStr::from_bytes(prog.as_bytes()),
                );
                for a in &args {
                    cmd.arg(a);
                }
                for (k, v) in &extra_env {
                    cmd.env(k, v);
                }
                let delivery_ref = &delivery;
                // SAFETY: the closure only calls dup2/fcntl between fork
                // and exec.
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || {
                        for (i, _) in fds.iter().enumerate() {
                            let target = 3 + i as libc::c_int;
                            let src = fds[i];
                            if src != target {
                                libc::dup2(src, target);
                            }
                            libc::fcntl(target, libc::F_SETFD, 0);
                        }
                        let _ = delivery_ref;
                        Ok(())
                    });
                }
                let status = cmd.status()?;
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    ExitState {
                        code: 128 + sig,
                        signal: Some(sig),
                    }
                } else {
                    ExitState {
                        code: status.code().unwrap_or(255),
                        signal: None,
                    }
                }
            }
        };

        Ok(Outcome {
            mode,
            exit,
            secrets_delivered: delivery.raw_fds().len(),
            notes,
        })
    }
}

/// PATH-resolve the program, like `execvp`.
fn resolve_program(program: &std::ffi::OsStr) -> io::Result<CString> {
    let bytes = program.as_bytes();
    if bytes.contains(&b'/') {
        return CString::new(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name"));
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(program);
        if let Ok(md) = std::fs::metadata(&cand) {
            use std::os::unix::fs::MetadataExt;
            if md.is_file() && md.mode() & 0o111 != 0 {
                return CString::new(cand.as_os_str().as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name")
                });
            }
        }
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name"))
}
