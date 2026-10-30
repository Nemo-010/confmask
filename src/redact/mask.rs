//! Public session API: run or spawn a process tree under a metadata
//! mask.
//!
//! # Session contract
//!
//! A masking session is driven by a tracer that owns the calling
//! process's `waitpid(-1)` domain for its entire lifetime (exactly like
//! a classic ptrace supervisor).  Sessions are therefore serialized
//! internally: starting a second session while one is active blocks
//! until the first tree has exited.  Do not `waitpid(-1)` yourself
//! while a session is active.

use crate::redact::tracer::{Config, ExitState, Tracer};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};

static SESSION: Mutex<()> = Mutex::new(());

fn session_lock() -> MutexGuard<'static, ()> {
    SESSION.lock().unwrap_or_else(|p| p.into_inner())
}

/// Builder for a masking session.
///
/// Defaults: label = program basename, follow the whole tree, redact
/// `/proc/<pid>/environ` too, kill the tree if the tracer dies.
///
/// ```no_run
/// use argvmask::Mask;
///
/// let st = Mask::new()
///     .label("ci-runner")
///     .run("/usr/bin/deploy", &["--token", "SECRET"])?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Mask {
    label: Option<String>,
    follow_tree: bool,
    redact_environ: bool,
    exit_kill: bool,
    verbose: bool,
    quiet: bool,
    env: EnvMode,
    /// Extra environment entries (added after the inherited ones).
    extra_env: Vec<(OsString, OsString)>,
    /// Descriptors to install at fd 3.. in the child, in order.
    fds: Vec<libc::c_int>,
}

#[derive(Clone, Debug)]
enum EnvMode {
    Inherit,
    Clear,
    Explicit(Vec<(OsString, OsString)>),
}

use std::ffi::OsString;

impl Default for Mask {
    fn default() -> Self {
        Mask::new()
    }
}

impl Mask {
    pub fn new() -> Mask {
        Mask {
            label: None,
            follow_tree: true,
            redact_environ: true,
            exit_kill: true,
            verbose: false,
            quiet: false,
            env: EnvMode::Inherit,
            extra_env: Vec::new(),
            fds: Vec::new(),
        }
    }

    /// Install `fds` at descriptor numbers 3, 4, … in the child, with
    /// `FD_CLOEXEC` cleared so the program inherits them.
    pub fn inherit_fds(mut self, fds: Vec<libc::c_int>) -> Mask {
        self.fds = fds;
        self
    }

    /// Add environment entries on top of the inherited environment.
    pub fn extra_env(mut self, kv: Vec<(OsString, OsString)>) -> Mask {
        self.extra_env = kv;
        self
    }

    /// Set the presentation label: the command line every process in the
    /// tree shows in `/proc/<pid>/cmdline` (and its first 15 bytes as
    /// `comm`, the name `top`/`htop` display).  Remaining argv entries
    /// present as empty strings.
    pub fn label(mut self, label: impl Into<String>) -> Mask {
        self.label = Some(label.into());
        self
    }

    /// Redact all descendants (default).  With `false`, only the direct
    /// child is redacted; descendants are detached from the session and
    /// run unredacted, exactly like the C tool's `-F`.
    pub fn follow_tree(mut self, on: bool) -> Mask {
        self.follow_tree = on;
        self
    }

    /// Leave `/proc/<pid>/environ` visible (default: redacted).
    pub fn keep_environ_visible(mut self) -> Mask {
        self.redact_environ = false;
        self
    }

    /// Let the tree survive if the supervising process dies
    /// (default: the tree is killed, so no half-masked orphans remain).
    pub fn let_tree_survive_self_death(mut self) -> Mask {
        self.exit_kill = false;
        self
    }

    /// Log every event to stderr.
    pub fn verbose(mut self) -> Mask {
        self.verbose = true;
        self.quiet = false;
        self
    }

    /// Suppress all diagnostics.
    pub fn quiet(mut self) -> Mask {
        self.quiet = true;
        self.verbose = false;
        self
    }

    /// Run the program with an explicit environment instead of the
    /// inherited one (replaces it wholesale).
    pub fn envs<K: AsRef<OsStr>, V: AsRef<OsStr>>(
        mut self,
        vars: impl IntoIterator<Item = (K, V)>,
    ) -> Mask {
        self.env = EnvMode::Explicit(
            vars.into_iter()
                .map(|(k, v)| (k.as_ref().to_os_string(), v.as_ref().to_os_string()))
                .collect(),
        );
        self
    }

    /// Run the program with an empty environment.
    pub fn env_clear(mut self) -> Mask {
        self.env = EnvMode::Clear;
        self
    }

    fn to_config(&self, program: &OsStr) -> Config {
        let label = self
            .label
            .clone()
            .unwrap_or_else(|| basename(program).to_string());
        let mut comm: Vec<u8> = label.bytes().take(15).collect();
        if comm.is_empty() {
            comm.push(b' '); // kernel ignores empty; present as blank
        }
        Config {
            label: label.into_bytes(),
            label_comm: comm,
            redact_environ: self.redact_environ,
            follow_tree: self.follow_tree,
            exit_kill: self.exit_kill,
            verbose: self.verbose,
            quiet: self.quiet,
        }
    }

    /// Run a program under the mask and wait for its tree to exit.
    pub fn run<P: AsRef<OsStr>, A: AsRef<OsStr>>(
        &self,
        program: P,
        args: &[A],
    ) -> io::Result<ExitState> {
        let _g = session_lock();
        let cfg = self.to_config(program.as_ref());
        let pid = start_child(
            &cfg,
            program.as_ref(),
            args,
            &self.env,
            &self.extra_env,
            &self.fds,
        )?;
        Tracer::new(cfg).supervise(pid)
    }

    /// Start a program under the mask; the tracer runs on a background
    /// thread and the tree is kill-from-outside as usual.  Use
    /// [`MaskedChild::wait`] to collect the exit state.
    ///
    /// The child is forked *on the tracer thread*: the kernel binds a
    /// `PTRACE_TRACEME` child to the forking thread, so every ptrace
    /// operation of the session must run there.
    pub fn spawn<P: AsRef<OsStr>, A: AsRef<OsStr>>(
        &self,
        program: P,
        args: &[A],
    ) -> io::Result<MaskedChild> {
        let cfg = self.to_config(program.as_ref());
        let program = program.as_ref().to_os_string();
        let args: Vec<OsString> = args.iter().map(|a| a.as_ref().to_os_string()).collect();
        let env = self.env.clone();
        let extra_env = self.extra_env.clone();
        let fds = self.fds.clone();
        let (pid_tx, pid_rx) = mpsc::channel();
        let (st_tx, st_rx) = mpsc::channel();
        let cfg_thread = cfg.clone();
        std::thread::Builder::new()
            .name("argvmask-tracer".into())
            .spawn(move || {
                let _g = session_lock();
                let forked = start_child(
                    &cfg_thread,
                    &program,
                    &args,
                    &env,
                    &extra_env,
                    &fds,
                );
                let pid = match forked {
                    Ok(pid) => pid,
                    Err(e) => {
                        let _ = pid_tx.send(Err(e));
                        return;
                    }
                };
                let _ = pid_tx.send(Ok(pid));
                let r = Tracer::new(cfg_thread).supervise(pid);
                let _ = st_tx.send(r);
            })
            .map_err(io::Error::other)?;

        let pid = pid_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tracer thread gone"))??;
        Ok(MaskedChild {
            pid: pid as u32,
            label_comm: cfg.label_comm.clone(),
            redact_environ: cfg.redact_environ,
            st_rx,
        })
    }
}

/// Handle to a supervised process tree.
pub struct MaskedChild {
    pid: u32,
    label_comm: Vec<u8>,
    redact_environ: bool,
    st_rx: mpsc::Receiver<io::Result<ExitState>>,
}

impl MaskedChild {
    /// Process id of the direct child.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// The session's `comm` label (<= 15 bytes), for callers that want
    /// to apply the same treatment to themselves (see [`mask_self`]).
    pub fn label_comm(&self) -> &[u8] {
        &self.label_comm
    }

    /// Whether the session redacts `/proc/<pid>/environ`.
    pub fn redacts_environ(&self) -> bool {
        self.redact_environ
    }

    /// Send a signal to the direct child.
    pub fn signal(&self, sig: libc::c_int) -> io::Result<()> {
        // SAFETY: plain kill(2) with a checked pid.
        let rc = unsafe { libc::kill(self.pid as libc::pid_t, sig) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait for the whole tree to finish and report the direct child's
    /// terminal state.
    pub fn wait(self) -> io::Result<ExitState> {
        self.st_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tracer thread gone"))?
    }
}

/// Fork the supervised child.  The child performs `PTRACE_TRACEME`,
/// raises `SIGSTOP` (handshake with the tracer) and then execs with its
/// real argv/envp.  Only async-signal-safe calls happen post-fork.
fn start_child(
    cfg: &Config,
    program: &OsStr,
    args: &[impl AsRef<OsStr>],
    env: &EnvMode,
    extra_env: &[(OsString, OsString)],
    fds: &[libc::c_int],
) -> io::Result<libc::pid_t> {
    // ---- everything below is prepared before forking ----
    let prog_c = resolve_program(program, env)?;

    let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv_c.push(prog_c.clone());
    for a in args {
        argv_c.push(os_to_cstring(a.as_ref())?);
    }
    let envp_c: Vec<CString> = match env {
        EnvMode::Inherit => {
            let mut v = Vec::new();
            for (k, val) in std::env::vars_os() {
                // validates NUL-freedom of both halves
                let k = os_to_cstring(&k)?;
                let val = os_to_cstring(&val)?;
                let mut joined = k.into_bytes(); // without NUL
                joined.push(b'=');
                joined.extend_from_slice(val.as_bytes());
                joined.push(0);
                // SAFETY: `joined` ends with exactly one NUL and has no
                // interior NULs (components were checked above).
                v.push(unsafe { CString::from_vec_unchecked(joined) });
            }
            v
        }
        EnvMode::Clear => Vec::new(),
        EnvMode::Explicit(vars) => {
            let mut v = Vec::with_capacity(vars.len());
            for (k, val) in vars {
                let mut joined = os_to_cstring(k)?.into_bytes(); // without NUL
                joined.push(b'=');
                joined.extend_from_slice(os_to_cstring(val)?.as_bytes());
                joined.push(0);
                // SAFETY: as above
                v.push(unsafe { CString::from_vec_unchecked(joined) });
            }
            v
        }
    };

    // Caller-supplied entries win over the inherited environment, so a
    // stale CONFMASK_SECRET_* in the parent cannot shadow the real fd.
    let mut envp_c = envp_c;
    if !extra_env.is_empty() {
        let keys: Vec<Vec<u8>> = extra_env
            .iter()
            .map(|(k, _)| k.as_bytes().to_vec())
            .collect();
        envp_c.retain(|e| {
            let bytes = e.as_bytes();
            !keys.iter().any(|k| {
                bytes.len() > k.len() && bytes.starts_with(k) && bytes[k.len()] == b'='
            })
        });
        for (k, v) in extra_env {
            let mut joined = os_to_cstring(k)?.into_bytes();
            joined.push(b'=');
            joined.extend_from_slice(os_to_cstring(v)?.as_bytes());
            joined.push(0);
            // SAFETY: one trailing NUL, no interior NULs.
            envp_c.push(unsafe { CString::from_vec_unchecked(joined) });
        }
    }

    let comm_z: CString = {
        let mut b = cfg.label_comm.clone();
        b.push(0);
        // SAFETY: b ends with NUL; interior NULs impossible (label cannot
        // contain NUL: it came from a Rust string).
        unsafe { CString::from_vec_unchecked(b) }
    };

    let err_prefix: CString =
        CString::new(format!("argvmask: cannot exec '{}': ", prog_c.to_string_lossy())).unwrap();

    // C arrays of pointers, NUL-terminated
    let argv_ptr: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptr: Vec<*const libc::c_char> = envp_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // ---- fork ----
    // SAFETY: the child only calls async-signal-safe functions until
    // execve/_exit; all buffers were built before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        child_exec(&prog_c, &argv_ptr, &envp_ptr, &comm_z, &err_prefix, fds);
    }
    Ok(pid)
}

/// Child side of `start_child`.  Never returns.
fn child_exec(
    prog: &CStr,
    argv_ptr: &[*const libc::c_char],
    envp_ptr: &[*const libc::c_char],
    comm_z: &CStr,
    err_prefix: &CStr,
    fds: &[libc::c_int],
) -> ! {
    unsafe {
        // Hand the inherited descriptors to the program at 3, 4, …; the
        // sealed memfds are the only way a secret reaches it without
        // touching argv or the environment.
        for (i, fd) in fds.iter().enumerate() {
            let target = 3 + i as libc::c_int;
            if *fd != target {
                libc::dup2(*fd, target);
            }
            libc::fcntl(target, libc::F_SETFD, 0);
        }
        libc::prctl(libc::PR_SET_NAME, comm_z.as_ptr(), 0, 0, 0);
        if libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ) == -1
        {
            child_fail(err_prefix, 126);
        }
        libc::raise(libc::SIGSTOP);
        libc::execve(prog.as_ptr(), argv_ptr.as_ptr(), envp_ptr.as_ptr());
        let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let code = if e == libc::ENOENT { 127 } else { 126 };
        child_fail(err_prefix, code);
    }
}

/// Write `prefix + <errno number>\n` to stderr with a single `write`
/// and `_exit`.  Async-signal-safe.
fn child_fail(prefix: &CStr, code: i32) -> ! {
    unsafe {
        let mut buf = [0u8; 512];
        let p = prefix.to_bytes();
        let n = p.len().min(buf.len() - 16);
        buf[..n].copy_from_slice(&p[..n]);
        let mut m = n;
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // minimal itoa
        let mut digits = [0u8; 12];
        let mut d = 0;
        if errno == 0 {
            digits[d] = b'0';
            d += 1;
        } else {
            let mut v = errno;
            while v > 0 {
                digits[d] = b'0' + (v % 10) as u8;
                v /= 10;
                d += 1;
            }
        }
        for i in 0..d {
            buf[m] = digits[d - 1 - i];
            m += 1;
        }
        buf[m] = b'\n';
        m += 1;
        libc::write(2, buf.as_ptr() as *const libc::c_void, m);
        libc::_exit(code);
    }
}

fn resolve_program(program: &OsStr, env: &EnvMode) -> io::Result<CString> {
    let c = os_to_cstring(program)?;
    if program.as_bytes().contains(&b'/') {
        return Ok(c);
    }
    // PATH search (like execvp): PATH comes from the child's env if one
    // was configured, else from ours.
    let path = match env {
        EnvMode::Explicit(vars) => vars
            .iter()
            .find(|(k, _)| k.as_bytes() == b"PATH")
            .map(|(_, v)| v.to_os_string()),
        _ => std::env::var_os("PATH"),
    };
    let path = path.unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(program);
        if let Ok(md) = std::fs::metadata(&cand) {
            use std::os::unix::fs::MetadataExt;
            if md.is_file() && md.mode() & 0o111 != 0 {
                return os_to_cstring(cand.as_os_str());
            }
        }
    }
    Ok(c) // let execve report ENOENT, like execvp would
}

fn os_to_cstring(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in argument"))
}

fn basename(s: &OsStr) -> &str {
    let bytes = s.as_bytes();
    let start = bytes.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    std::str::from_utf8(&bytes[start..]).unwrap_or("argvmask-child")
}
