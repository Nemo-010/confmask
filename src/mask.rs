//! Public session API: run or spawn a process tree under a metadata
//! mask.
//!
//! # Session contract
//!
//! A masking session is driven by a tracer that owns the calling
//! process's `waitpid(-1)` domain for its entire lifetime (exactly like
//! a classic ptrace supervisor).  Sessions are therefore serialized
//! internally: starting a second session while one is active blocks
//! until the first session has ended.  Do not `waitpid(-1)` yourself
//! while a session is active.
//!
//! # Session end
//!
//! The session ends when the master process (the direct child) exits.
//! [`Mask::session_end`] chooses what happens to descendants that are
//! still alive at that moment:
//!
//! * `SessionEnd::Detach` (default): the tracer detaches from them.
//!   Their images are already redacted.  `wait` returns at once.
//! * `SessionEnd::WaitTree`: the tracer keeps supervising.  `wait`
//!   returns after the last descendant has exited.
//! * `SessionEnd::KillTree`: the tracer sends SIGKILL to every remaining
//!   descendant.
//!
//! # Label limits
//!
//! The label is truncated in three places.  The `comm` name is cut to 15
//! bytes (set it with [`Mask::comm`]).  The scratch space of the exec
//! entry path holds 254 label bytes.  The post-exec path (scripts) cuts
//! the label to the span of the argument area the kernel copied.  The
//! builder warns on stderr once, unless quiet, when a label is longer
//! than 254 bytes.
//!
//! # Differences from an unmasked run
//!
//! * The tracer consumes the SIGCHLD notifications `CLD_STOPPED`,
//!   `CLD_TRAPPED`, `CLD_CONTINUED` and `CLD_DUMPED`.  A masked program
//!   that waits for its own children does not see them as an unmasked
//!   program would.
//! * The session-end policy decides what happens to descendants after
//!   the master exits (see above).  An unmasked run leaves them to
//!   `init`.
//! * With `PR_SET_DUMPABLE` disabled ([`Mask::no_dumpable`]) core dumps
//!   and same-uid debugger attach stop working in the tree.
//! * With [`Mask::watch_rename`] the tree carries a seccomp filter and
//!   `no_new_privs`.

use crate::tracer::{Config, ExitState, SessionEnd, Tracer, TreeRegistry};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

static SESSION: Mutex<()> = Mutex::new(());

/// The argument vector of this process, copied out of
/// `/proc/self/cmdline` into owned memory.
///
/// A caller that reads its options from this copy can redact the
/// kernel-served argv block immediately at startup, before parsing, which
/// is the earliest point a supervisor can act on its own metadata.
pub fn snapshot_argv() -> Vec<OsString> {
    let raw = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| OsStr::from_bytes(s).to_os_string())
        .collect()
}

/// Zero the argv string block of this process (the memory `/proc/self/
/// cmdline` is served from).  The label is written later, when the
/// session starts; this only removes the bytes.
///
/// # Safety of the effect
/// Nothing may read the original argv after this call.  Rust's `std`
/// copies the argument vector at startup, so `std::env::args_os()` keeps
/// working, but it then returns empty strings.  Use
/// [`snapshot_argv`] before this call.
pub fn zero_argv_block() -> io::Result<()> {
    // SAFETY: the caller promises not to read the process's original argv.
    unsafe { crate::selfmask::zero_own_argv() }
}
static LONG_LABEL_WARNED: AtomicBool = AtomicBool::new(false);

/// Bytes of the label that the exec entry path can carry.
const ENTRY_SCRATCH_LABEL: usize = 254;

/// Value of `_CS_PATH` for `confstr(3)` (glibc and musl).
const CS_PATH: libc::c_int = 0;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const AT_EMPTY_PATH: libc::c_int = 0x1000;

extern "C" {
    fn confstr(name: libc::c_int, buf: *mut libc::c_char, len: libc::size_t) -> libc::size_t;
}

fn session_lock() -> MutexGuard<'static, ()> {
    SESSION.lock().unwrap_or_else(|p| p.into_inner())
}

/// Builder for a masking session.
///
/// Defaults: label = program basename, follow the whole tree, redact
/// `/proc/<pid>/environ` too, kill the tree if the tracer dies.
///
/// ```no_run
/// use confmask::Mask;
///
/// let st = Mask::new()
///     .label("ci-runner")
///     .run("/usr/bin/deploy", &["--token", "SECRET"])?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// `Debug` output never contains environment names or values.
#[derive(Clone)]
pub struct Mask {
    label: Option<String>,
    argv0: Option<OsString>,
    comm: Option<String>,
    follow_tree: bool,
    redact_environ: bool,
    exit_kill: bool,
    verbose: bool,
    quiet: bool,
    env: EnvMode,
    env_overrides: Vec<(OsString, OsString)>,
    keep_env_names: Vec<Vec<u8>>,
    session_end: SessionEnd,
    no_dumpable: bool,
    watch_rename: bool,
    no_new_privs: bool,
    unshare: bool,
    rexec: bool,
    scope_name: Option<String>,
    run_as: Option<(u32, u32)>,
    secret_fds: Vec<libc::c_int>,
}

#[derive(Clone)]
enum EnvMode {
    Inherit,
    Clear,
    Explicit(Vec<(OsString, OsString)>),
}

impl std::fmt::Debug for Mask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env_text = match &self.env {
            EnvMode::Inherit => "inherit".to_string(),
            EnvMode::Clear => "clear".to_string(),
            EnvMode::Explicit(v) => format!("explicit({} variables, <redacted>)", v.len()),
        };
        f.debug_struct("Mask")
            .field("label", &self.label)
            .field("argv0", &self.argv0)
            .field("comm", &self.comm)
            .field("follow_tree", &self.follow_tree)
            .field("redact_environ", &self.redact_environ)
            .field("exit_kill", &self.exit_kill)
            .field("verbose", &self.verbose)
            .field("quiet", &self.quiet)
            .field("env", &format_args!("{}", env_text))
            .field(
                "env_overrides",
                &format_args!("{} variables, <redacted>", self.env_overrides.len()),
            )
            .field(
                "keep_env_names",
                &format_args!("{} names", self.keep_env_names.len()),
            )
            .field("session_end", &self.session_end)
            .field("no_dumpable", &self.no_dumpable)
            .field("watch_rename", &self.watch_rename)
            .field("no_new_privs", &self.no_new_privs)
            .field("unshare", &self.unshare)
            .field("rexec", &self.rexec)
            .field("scope_name", &self.scope_name)
            .field("run_as", &self.run_as)
            .field("secret_fds", &format_args!("{} descriptors", self.secret_fds.len()))
            .finish()
    }
}

impl Default for Mask {
    fn default() -> Self {
        Mask::new()
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

/// Check a label for bytes that corrupt `ps` output: NUL, LF and CR.
/// An empty label is valid.
pub fn validate_label(label: &str) -> io::Result<()> {
    if label.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return Err(invalid("label must not contain NUL, LF or CR bytes"));
    }
    Ok(())
}

fn validate_env_key(key: &OsStr) -> io::Result<()> {
    let b = key.as_bytes();
    if b.is_empty() {
        return Err(invalid("environment variable name must not be empty"));
    }
    if b.contains(&b'=') {
        return Err(invalid("environment variable name must not contain '='"));
    }
    if b.contains(&0) {
        return Err(invalid("environment variable name must not contain NUL"));
    }
    Ok(())
}

/// The `systemd-run` command prefix that places a command in a transient
/// scope named `name`, or `None` when systemd-run is not usable.
pub fn scope_wrap_command(name: &str) -> Option<Vec<OsString>> {
    crate::scope::wrap_command(name)
}

impl Mask {
    pub fn new() -> Mask {
        Mask {
            label: None,
            argv0: None,
            comm: None,
            follow_tree: true,
            redact_environ: true,
            exit_kill: true,
            verbose: false,
            quiet: false,
            env: EnvMode::Inherit,
            env_overrides: Vec::new(),
            keep_env_names: Vec::new(),
            session_end: SessionEnd::Detach,
            no_dumpable: false,
            watch_rename: false,
            no_new_privs: false,
            unshare: false,
            rexec: false,
            scope_name: None,
            run_as: None,
            secret_fds: Vec::new(),
        }
    }

    /// Set the presentation label: the command line every process in the
    /// tree shows in `/proc/<pid>/cmdline`.  Remaining argv entries
    /// present as empty strings.  The `comm` name is the label cut to 15
    /// bytes unless [`Mask::comm`] sets it.
    ///
    /// `run` and `spawn` return an `InvalidInput` error when the label
    /// contains NUL, LF or CR.  The empty label is valid.
    pub fn label(mut self, label: impl Into<String>) -> Mask {
        self.label = Some(label.into());
        self
    }

    /// Set `argv[0]` of the program.  Default: the program string exactly
    /// as the caller passed it to `run` or `spawn` (not the resolved
    /// path).
    pub fn argv0(mut self, argv0: impl Into<OsString>) -> Mask {
        self.argv0 = Some(argv0.into());
        self
    }

    /// Set the `comm` name (`top` and `htop` show it).  At most 15 bytes,
    /// checked by `run` and `spawn`.  Default: the label cut to 15 bytes.
    pub fn comm(mut self, comm: impl Into<String>) -> Mask {
        self.comm = Some(comm.into());
        self
    }

    /// Redact all descendants (default).  With `false`, only the direct
    /// child is redacted; descendants are still traced (they have to be,
    /// to be followed at all) but run unredacted.
    pub fn follow_tree(mut self, on: bool) -> Mask {
        self.follow_tree = on;
        self
    }

    /// Leave `/proc/<pid>/environ` visible (default: redacted).
    pub fn keep_environ_visible(mut self) -> Mask {
        self.redact_environ = false;
        self
    }

    /// Keep the named environment variables visible in
    /// `/proc/<pid>/environ`.  Every other variable stays redacted.
    /// Repeated calls add names.
    pub fn keep_env_vars<I, S>(mut self, names: I) -> Mask
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for n in names {
            let n: String = n.into();
            self.keep_env_names.push(n.into_bytes());
        }
        self
    }

    /// Let the tree survive if the supervising process dies
    /// (default: the tree is killed, so no half-masked orphans remain).
    ///
    /// With this option, dropping a [`MaskedChild`] without `wait()`
    /// kills only the direct child.  Descendants keep running, detached
    /// from the tracer, and their later execs are unredacted.
    pub fn let_tree_survive_self_death(mut self) -> Mask {
        self.exit_kill = false;
        self
    }

    /// Choose what happens to descendants when the master exits.
    /// Default: `SessionEnd::Detach`.
    pub fn session_end(mut self, policy: SessionEnd) -> Mask {
        self.session_end = policy;
        self
    }

    /// Inject `prctl(PR_SET_DUMPABLE, 0)` into every process of the tree.
    /// Core dumps and same-uid debugger attach stop working.
    pub fn no_dumpable(mut self) -> Mask {
        self.no_dumpable = true;
        self
    }

    /// Keep the label as `comm` when a program renames itself with
    /// `prctl(PR_SET_NAME)`.  Installs a seccomp filter in the child, so
    /// it implies [`Mask::no_new_privs`].  When the filter cannot be
    /// installed the child prints one line and runs without it.
    pub fn watch_rename(mut self) -> Mask {
        self.watch_rename = true;
        self.no_new_privs = true;
        self
    }

    /// Set `PR_SET_NO_NEW_PRIVS` in the child before exec.  Set-uid,
    /// set-gid and file-capability binaries then gain nothing, for the
    /// whole tree.
    pub fn no_new_privs(mut self) -> Mask {
        self.no_new_privs = true;
        self
    }

    /// Run the tree in new user, pid and mount namespaces with a private
    /// `/proc`, when the kernel allows it.  When it does not, one line
    /// starting with `confmask: --unshare unavailable:` is printed and
    /// the run uses a plain fork.
    pub fn unshare(mut self) -> Mask {
        self.unshare = true;
        self
    }

    /// Copy the program into a sealed memfd and exec from it, so
    /// `/proc/<pid>/exe` names the memfd and not the file.  When the copy
    /// fails, one line is printed and the run uses the normal exec.
    pub fn rexec(mut self) -> Mask {
        self.rexec = true;
        self
    }

    /// Name a systemd transient scope for the tree.  `run` and `spawn`
    /// do not move the calling process into a scope: callers that want
    /// one re-exec themselves through [`scope_wrap_command`] (the
    /// `confmask` binary does).
    pub fn scope_name(mut self, name: impl Into<String>) -> Mask {
        self.scope_name = Some(name.into());
        self
    }

    /// The scope name set with [`Mask::scope_name`].
    pub fn scope_name_value(&self) -> Option<&str> {
        self.scope_name.as_deref()
    }

    /// Drop the child to `uid` and `gid` after the fork and before exec
    /// (`setgroups([])`, `setgid`, `setuid`).  The caller must be root.
    /// The tracer keeps its own credentials.
    pub fn run_as(mut self, uid: u32, gid: u32) -> Mask {
        self.run_as = Some((uid, gid));
        self
    }

    /// Install `fds` at descriptor numbers 3, 4, ... in the child, with
    /// `FD_CLOEXEC` cleared, so the program and everything it spawns
    /// inherits them.  This is how a secret reaches a program without
    /// touching its `argv` or its environment.
    ///
    /// The descriptors are duplicated in the child, between fork and
    /// exec, so they are safe to hand over from any number the caller
    /// happened to get.
    pub fn inherit_fds(mut self, fds: Vec<libc::c_int>) -> Mask {
        self.secret_fds = fds;
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
    /// inherited one (replaces it wholesale).  `run` and `spawn` return
    /// an `InvalidInput` error for a name that is empty or contains `=`
    /// or NUL.
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

    /// Set one variable on top of the environment the program would
    /// otherwise get.  A later call with the same name wins.  The name is
    /// checked like in [`Mask::envs`].
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Mask {
        self.env_overrides
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Run the program with an empty environment.  A program name
    /// without a slash is searched in the `confstr(_CS_PATH)` default
    /// path, like `execvp` with no `PATH`.
    pub fn env_clear(mut self) -> Mask {
        self.env = EnvMode::Clear;
        self
    }

    /// Check every lazily validated option.
    fn validate(&self) -> io::Result<()> {
        if let Some(l) = &self.label {
            validate_label(l)?;
        }
        if let Some(c) = &self.comm {
            if c.len() > crate::COMM_MAX {
                return Err(invalid("comm must be at most 15 bytes"));
            }
            if c.bytes().any(|b| b == 0) {
                return Err(invalid("comm must not contain NUL"));
            }
        }
        if let Some(a) = &self.argv0 {
            if a.as_bytes().contains(&0) {
                return Err(invalid("argv0 must not contain NUL"));
            }
        }
        if let EnvMode::Explicit(vars) = &self.env {
            for (k, _) in vars {
                validate_env_key(k)?;
            }
        }
        for (k, _) in &self.env_overrides {
            validate_env_key(k)?;
        }
        if let Some(s) = &self.scope_name {
            if s.bytes().any(|b| b == 0) {
                return Err(invalid("scope name must not contain NUL"));
            }
        }
        Ok(())
    }

    fn to_config(&self, program: &OsStr) -> io::Result<Config> {
        self.validate()?;
        let label = self.label.clone().unwrap_or_else(|| basename(program));
        if label.len() > ENTRY_SCRATCH_LABEL
            && !self.quiet
            && !LONG_LABEL_WARNED.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "confmask: warning: label is {} bytes; only the first {} bytes are presented",
                label.len(),
                ENTRY_SCRATCH_LABEL
            );
        }
        let mut comm: Vec<u8> = match &self.comm {
            Some(c) => c.clone().into_bytes(),
            None => label.bytes().take(crate::COMM_MAX).collect(),
        };
        if comm.is_empty() {
            comm.push(b' '); // kernel ignores empty; present as blank
        }
        Ok(Config {
            label: label.into_bytes(),
            label_comm: comm,
            redact_environ: self.redact_environ,
            follow_tree: self.follow_tree,
            exit_kill: self.exit_kill,
            verbose: self.verbose,
            quiet: self.quiet,
            no_dumpable: self.no_dumpable,
            watch_prctl: self.watch_rename,
            session_end: self.session_end,
            keep_env: self.keep_env_names.clone(),
            // Test hooks, read before the supervisor redacts its own
            // environment: a redacted environ is empty by design.
            fault_poke_at: std::env::var("CONFMASK_FAULT_POKE")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
            fault_no_vdso: std::env::var_os("CONFMASK_FAULT_NOVDSO").is_some(),
            tree: TreeRegistry::default(),
        })
    }

    /// The environment the program receives, as name and value pairs.
    fn env_pairs(&self) -> io::Result<Vec<(OsString, OsString)>> {
        let mut pairs: Vec<(OsString, OsString)> = match &self.env {
            EnvMode::Inherit => std::env::vars_os().collect(),
            EnvMode::Clear => Vec::new(),
            EnvMode::Explicit(v) => v.clone(),
        };
        for (k, v) in &self.env_overrides {
            match pairs.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v.clone(),
                None => pairs.push((k.clone(), v.clone())),
            }
        }
        Ok(pairs)
    }

    /// Build everything the child needs: argv, the environment snapshot,
    /// the resolved program path and the optional kernel features.
    /// Nothing is forked.  The result can be sent to another thread.
    pub fn prepare<P: AsRef<OsStr>, A: AsRef<OsStr>>(
        &self,
        program: P,
        args: &[A],
    ) -> io::Result<Prepared> {
        let program = program.as_ref();
        let cfg = self.to_config(program)?;
        let pairs = self.env_pairs()?;
        let prog_c = resolve_program(program, &pairs)?;

        let argv0: OsString = match &self.argv0 {
            Some(a) => a.clone(),
            None => program.to_os_string(),
        };
        let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 1);
        argv_c.push(os_to_cstring(&argv0)?);
        for a in args {
            argv_c.push(os_to_cstring(a.as_ref())?);
        }

        let mut envp_c: Vec<CString> = Vec::with_capacity(pairs.len());
        for (k, v) in &pairs {
            let mut joined = os_to_cstring(k)?.into_bytes();
            joined.push(b'=');
            joined.extend_from_slice(os_to_cstring(v)?.as_bytes());
            envp_c.push(os_to_cstring(OsStr::from_bytes(&joined))?);
        }

        let comm_z = os_to_cstring(OsStr::from_bytes(&cfg.label_comm))?;
        let err_prefix = c_text(&format!(
            "confmask: cannot exec '{}': ",
            prog_c.to_string_lossy()
        ));

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

        let no_new_privs = self.no_new_privs || self.watch_rename;
        let filter: Vec<libc::sock_filter> = if self.watch_rename {
            crate::seccomp::prctl_watch_filter()
        } else {
            Vec::new()
        };

        let mut unshare = self.unshare;
        if unshare && !crate::userns::available() {
            if !self.quiet {
                eprintln!("confmask: --unshare unavailable: user namespaces are not permitted here");
            }
            unshare = false;
        }

        let mut rexec_fd: libc::c_int = -1;
        // Loop guard: a program that already is a memfd image (for example
        // /proc/self/fd/N of a masked process) is executed as it is.
        let already_memfd = std::fs::read_link(OsStr::from_bytes(prog_c.to_bytes()))
            .map(|p| crate::rexec::is_memfd_path(&p.to_string_lossy()))
            .unwrap_or(false);
        if self.rexec && already_memfd {
            if !self.quiet {
                eprintln!("confmask: --rexec skipped: the program already is a memfd image");
            }
        } else if self.rexec {
            let label_text = String::from_utf8_lossy(&cfg.label).into_owned();
            match crate::rexec::prepare(&prog_c, &label_text) {
                Ok(image) => {
                    // The descriptor stays open across the fork; the
                    // parent closes its copy after the fork.
                    rexec_fd = image.fd;
                }
                Err(e) => {
                    if !self.quiet {
                        eprintln!("confmask: --rexec unavailable: {}", e);
                    }
                }
            }
        }

        Ok(Prepared {
            cfg,
            prog_c,
            argv_c,
            envp_c,
            argv_ptr,
            envp_ptr,
            comm_z,
            err_prefix,
            msg_nnp: c_text("confmask: --no-new-privs unavailable: prctl failed, errno "),
            msg_seccomp: c_text(
                "confmask: --watch-rename unavailable: seccomp filter not installed, errno ",
            ),
            msg_proc: c_text("confmask: --unshare unavailable: cannot mount private proc, errno "),
            no_new_privs,
            filter,
            rexec_fd,
            unshare,
            run_as: self.run_as,
            secret_fds: self.secret_fds.clone(),
        })
    }

    /// Run a program under the mask and wait for the session to end (see
    /// the module docs for what that means for descendants).
    pub fn run<P: AsRef<OsStr>, A: AsRef<OsStr>>(
        &self,
        program: P,
        args: &[A],
    ) -> io::Result<ExitState> {
        let _g = session_lock();
        let mut prepared = self.prepare(program, args)?;
        let cfg = prepared.cfg.clone();
        let (pid, go_fd) = fork_prepared(&mut prepared)?;
        Tracer::new(cfg).supervise(pid, go_fd)
    }

    /// Start a program under the mask; the tracer runs on a background
    /// thread.  Use [`MaskedChild::wait`] to collect the exit state.
    ///
    /// The child is forked *on the tracer thread*: every ptrace
    /// operation of the session must run there.
    pub fn spawn<P: AsRef<OsStr>, A: AsRef<OsStr>>(
        &self,
        program: P,
        args: &[A],
    ) -> io::Result<MaskedChild> {
        let prepared = self.prepare(program, args)?;
        self.spawn_prepared(prepared)
    }

    /// Fork a [`Prepared`] program on the tracer thread and supervise it.
    pub fn spawn_prepared(&self, prepared: Prepared) -> io::Result<MaskedChild> {
        let cfg = prepared.cfg.clone();
        let tree = cfg.tree.clone();
        let (pid_tx, pid_rx) = mpsc::channel();
        let (st_tx, st_rx) = mpsc::channel();
        let cfg_thread = cfg.clone();
        std::thread::Builder::new()
            .name("confmask-tracer".into())
            .spawn(move || {
                let _g = session_lock();
                let mut prepared = prepared;
                let (pid, go_fd) = match fork_prepared(&mut prepared) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = pid_tx.send(Err(e));
                        return;
                    }
                };
                drop(prepared);
                let _ = pid_tx.send(Ok(pid));
                let r = Tracer::new(cfg_thread).supervise(pid, go_fd);
                let _ = st_tx.send(r);
            })
            .map_err(io::Error::other)?;

        let pid = pid_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tracer thread gone"))??;
        Ok(MaskedChild {
            pid: pid as u32,
            label: cfg.label.clone(),
            label_comm: cfg.label_comm.clone(),
            redact_environ: cfg.redact_environ,
            waited: false,
            st_rx,
            tree,
            result: None,
        })
    }
}

/// Everything the child needs, built before the fork: the resolved
/// program, argv and envp as C strings with their pointer arrays, and
/// the optional kernel features.  It holds no borrowed data and can move
/// to the tracer thread.
pub struct Prepared {
    cfg: Config,
    prog_c: CString,
    // The pointer arrays point into these vectors.  Keep them alive.
    #[allow(dead_code)]
    argv_c: Vec<CString>,
    #[allow(dead_code)]
    envp_c: Vec<CString>,
    argv_ptr: Vec<*const libc::c_char>,
    envp_ptr: Vec<*const libc::c_char>,
    comm_z: CString,
    err_prefix: CString,
    msg_nnp: CString,
    msg_seccomp: CString,
    msg_proc: CString,
    no_new_privs: bool,
    filter: Vec<libc::sock_filter>,
    rexec_fd: libc::c_int,
    unshare: bool,
    run_as: Option<(u32, u32)>,
    /// Descriptors to install at 3, 4, ... in the child.
    secret_fds: Vec<libc::c_int>,
}

// SAFETY: the raw pointers in `argv_ptr` and `envp_ptr` point into heap
// buffers of the `CString`s owned by the same value.  Moving the value
// does not move those buffers, and nothing else aliases them.
unsafe impl Send for Prepared {}

impl Drop for Prepared {
    fn drop(&mut self) {
        if self.rexec_fd >= 0 {
            // SAFETY: the descriptor is owned by this value.
            unsafe {
                libc::close(self.rexec_fd);
            }
            self.rexec_fd = -1;
        }
    }
}

impl Prepared {
    /// The command-line label of the session.
    pub fn label(&self) -> &[u8] {
        &self.cfg.label
    }

    /// The `comm` name of the session (at most 15 bytes).
    pub fn label_comm(&self) -> &[u8] {
        &self.cfg.label_comm
    }

    /// Whether the session redacts `/proc/<pid>/environ`.
    pub fn redacts_environ(&self) -> bool {
        self.cfg.redact_environ
    }

    /// Apply the session label to the calling process (argv block,
    /// environment strings, `comm`).  Call it after `prepare` and before
    /// `spawn_prepared`: `prepare` already copied argv and the
    /// environment.
    pub fn mask_self(&self) -> io::Result<()> {
        crate::selfmask::mask_self_label(
            &self.cfg.label,
            &self.cfg.label_comm,
            self.cfg.redact_environ,
        )
    }
}

/// Handle to a supervised process tree.
///
/// Dropping the handle without calling [`MaskedChild::wait`] kills the
/// direct child: the tracer thread holds the process-wide session lock
/// for as long as the session lives, so an abandoned session would block
/// every later one.  Call `wait()` to collect the real exit status.
pub struct MaskedChild {
    pid: u32,
    label: Vec<u8>,
    label_comm: Vec<u8>,
    redact_environ: bool,
    waited: bool,
    st_rx: mpsc::Receiver<io::Result<ExitState>>,
    tree: TreeRegistry,
    result: Option<Result<ExitState, (io::ErrorKind, String)>>,
}

impl Drop for MaskedChild {
    fn drop(&mut self) {
        if !self.waited {
            // SAFETY: plain kill(2); an already-reaped pid just returns ESRCH.
            unsafe {
                libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

impl MaskedChild {
    /// Process id of the direct child.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// The session's command-line label.
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    /// The session's `comm` label (<= 15 bytes), for callers that want
    /// to apply the same treatment to themselves (see [`mask_self`]).
    ///
    /// [`mask_self`]: crate::mask_self
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

    /// Send SIGKILL to every live process of the tree and to the direct
    /// child.
    pub fn kill_tree(&self) {
        let pids: Vec<libc::pid_t> = match self.tree.lock() {
            Ok(set) => set.iter().copied().collect(),
            Err(poisoned) => poisoned.into_inner().iter().copied().collect(),
        };
        for pid in pids {
            // SAFETY: plain kill(2); a gone pid returns ESRCH.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        // SAFETY: as above.  The direct child is always killed, even
        // when the registry has not listed it yet.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
    }

    /// The cached result, when the session has already ended.
    fn cached(&self) -> Option<io::Result<ExitState>> {
        match &self.result {
            Some(Ok(st)) => Some(Ok(*st)),
            Some(Err((kind, msg))) => Some(Err(io::Error::new(*kind, msg.clone()))),
            None => None,
        }
    }

    /// Remember the final result so later calls return it again.
    fn store(&mut self, r: io::Result<ExitState>) -> io::Result<ExitState> {
        self.waited = true;
        match &r {
            Ok(st) => self.result = Some(Ok(*st)),
            Err(e) => self.result = Some(Err((e.kind(), e.to_string()))),
        }
        r
    }

    fn gone_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "tracer thread gone")
    }

    /// Check whether the session has ended, without blocking.  Returns
    /// `Ok(None)` while it runs.  After the session has ended, every call
    /// returns the same result again.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitState>> {
        if let Some(r) = self.cached() {
            return r.map(Some);
        }
        match self.st_rx.try_recv() {
            Ok(r) => self.store(r).map(Some),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.store(Err(Self::gone_error())).map(Some)
            }
        }
    }

    /// Wait up to `timeout` for the session to end.  Returns `Ok(None)`
    /// on timeout.  After the session has ended, every call returns the
    /// same result again.
    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitState>> {
        if let Some(r) = self.cached() {
            return r.map(Some);
        }
        match self.st_rx.recv_timeout(timeout) {
            Ok(r) => self.store(r).map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.store(Err(Self::gone_error())).map(Some)
            }
        }
    }

    /// Wait for the session to end and report the direct child's terminal
    /// state.  The session ends when the direct child exits; the
    /// `SessionEnd` policy decides whether `wait` also waits for the
    /// descendants (`WaitTree`) or not (`Detach`, `KillTree`).
    pub fn wait(mut self) -> io::Result<ExitState> {
        if let Some(r) = self.cached() {
            return r;
        }
        let r = match self.st_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Self::gone_error()),
        };
        self.store(r)
    }
}

/// Fork the supervised child on the calling thread.  Returns the pid and
/// the write end of the go pipe: the child blocks on the read end until
/// the tracer has seized it and writes one byte.  Only async-signal-safe
/// calls happen in the child.
fn fork_prepared(p: &mut Prepared) -> io::Result<(libc::pid_t, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is a valid two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let go_r = fds[0];
    let go_w = fds[1];

    let mut in_userns = false;
    let pid: libc::pid_t = if p.unshare {
        match crate::userns::fork_in_userns() {
            Ok(pid) => {
                in_userns = true;
                pid
            }
            Err(e) => {
                if !p.cfg.quiet {
                    eprintln!("confmask: --unshare unavailable: {}", e);
                }
                // SAFETY: plain fork; the child side is child_exec.
                unsafe { libc::fork() }
            }
        }
    } else {
        // SAFETY: the child only calls async-signal-safe functions until
        // execve/_exit; all buffers were built before the fork.
        unsafe { libc::fork() }
    };
    if pid < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: both descriptors were created above.
        unsafe {
            libc::close(go_r);
            libc::close(go_w);
        }
        return Err(e);
    }
    if pid == 0 {
        child_exec(p, in_userns && pid == 0, go_r, go_w);
    }
    // SAFETY: closing our copy of the read end and of the exec image.
    unsafe {
        libc::close(go_r);
        if p.rexec_fd >= 0 {
            libc::close(p.rexec_fd);
            p.rexec_fd = -1;
        }
    }
    Ok((pid, go_w))
}

/// Child side of `fork_prepared`.  Never returns.
fn child_exec(p: &Prepared, in_userns: bool, go_r: RawFd, go_w: RawFd) -> ! {
    let quiet = p.cfg.quiet;
    // SAFETY: async-signal-safe libc calls on buffers built before the fork.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, p.comm_z.as_ptr(), 0, 0, 0);
        libc::close(go_w);

        if in_userns {
            if let Err(e) = crate::userns::child_setup_proc() {
                if !quiet {
                    child_note(&p.msg_proc, e.raw_os_error().unwrap_or(0));
                }
            }
        }

        if let Some((uid, gid)) = p.run_as {
            if libc::setgroups(0, std::ptr::null()) == -1
                || libc::setgid(gid as libc::gid_t) == -1
                || libc::setuid(uid as libc::uid_t) == -1
            {
                child_fail(&p.err_prefix, 126);
            }
        }

        if p.no_new_privs && libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 && !quiet {
            child_note(&p.msg_nnp, last_errno());
        }

        if !p.filter.is_empty() {
            if let Err(e) = crate::seccomp::install(&p.filter) {
                if !quiet {
                    child_note(&p.msg_seccomp, e.raw_os_error().unwrap_or(0));
                }
            }
        }

        // Wait until the tracer has seized this process.
        let mut byte = 0u8;
        loop {
            let n = libc::read(go_r, &mut byte as *mut u8 as *mut libc::c_void, 1);
            if n == 1 {
                break;
            }
            if n == -1 && last_errno() == libc::EINTR {
                continue;
            }
            libc::_exit(126);
        }
        libc::raise(libc::SIGSTOP);

        install_secret_fds(&p.secret_fds);

        if p.rexec_fd >= 0 {
            let empty: [u8; 1] = [0];
            libc::syscall(
                libc::SYS_execveat,
                p.rexec_fd as libc::c_long,
                empty.as_ptr(),
                p.argv_ptr.as_ptr(),
                p.envp_ptr.as_ptr(),
                AT_EMPTY_PATH as libc::c_long,
            );
            // Fall through to the normal exec when execveat fails.
        }
        libc::execve(p.prog_c.as_ptr(), p.argv_ptr.as_ptr(), p.envp_ptr.as_ptr());
        let e = last_errno();
        let code = if e == libc::ENOENT { 127 } else { 126 };
        child_fail(&p.err_prefix, code);
    }
}

/// Install the inherited secret descriptors at 3, 4, ... and clear
/// `FD_CLOEXEC` so the program keeps them.  Async-signal-safe: only
/// `fcntl`, `dup2` and `close`.
fn install_secret_fds(fds: &[libc::c_int]) {
    if fds.is_empty() {
        return;
    }
    // SAFETY: descriptor arithmetic only; every call is checked.
    unsafe {
        // Move the sources out of the target range first: a source that
        // happens to sit at 3 while it must land at 4 would otherwise be
        // clobbered by an earlier dup2.
        for (i, fd) in fds.iter().enumerate() {
            let target = 3 + i as libc::c_int;
            if *fd != target {
                let hi = libc::fcntl(*fd, libc::F_DUPFD, 200);
                if hi >= 0 {
                    libc::dup2(hi, target);
                    libc::close(hi);
                }
            }
            libc::fcntl(target, libc::F_SETFD, 0);
        }
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Write `prefix + <errno number>\n` to stderr with a single `write`.
/// Async-signal-safe.
fn child_note(prefix: &CStr, errno: i32) {
    let mut buf = [0u8; 512];
    let p = prefix.to_bytes();
    let n = p.len().min(buf.len() - 16);
    buf[..n].copy_from_slice(&p[..n]);
    let mut m = n;
    let mut digits = [0u8; 12];
    let mut d = 0;
    if errno <= 0 {
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
    // SAFETY: buf holds m initialized bytes.
    unsafe {
        libc::write(2, buf.as_ptr() as *const libc::c_void, m);
    }
}

/// Write the errno line and `_exit`.  Async-signal-safe.
fn child_fail(prefix: &CStr, code: i32) -> ! {
    child_note(prefix, last_errno());
    // SAFETY: _exit never returns.
    unsafe { libc::_exit(code) }
}

/// The `confstr(_CS_PATH)` default path, like `execvp` with no `PATH`.
fn default_path() -> OsString {
    let fallback = || OsString::from("/usr/bin:/bin");
    // SAFETY: confstr(3) with a null buffer returns the needed size; the
    // second call fills a buffer of exactly that size.
    unsafe {
        let n = confstr(CS_PATH, std::ptr::null_mut(), 0);
        if n == 0 {
            return fallback();
        }
        let mut buf = vec![0u8; n];
        let m = confstr(CS_PATH, buf.as_mut_ptr() as *mut libc::c_char, n);
        if m == 0 {
            return fallback();
        }
        buf.truncate(n - 1); // drop the NUL
        OsString::from_vec(buf)
    }
}

fn resolve_program(program: &OsStr, pairs: &[(OsString, OsString)]) -> io::Result<CString> {
    let c = os_to_cstring(program)?;
    if program.as_bytes().contains(&b'/') {
        return Ok(c);
    }
    // PATH search like execvp: PATH comes from the child's environment;
    // without one, the confstr default applies.
    let path = pairs
        .iter()
        .find(|(k, _)| k.as_bytes() == b"PATH")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(default_path);
    for dir in std::env::split_paths(&path) {
        let dir = if dir.as_os_str().is_empty() {
            std::path::PathBuf::from(".")
        } else {
            dir
        };
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

/// A C string from fixed program text (no NUL by construction).
fn c_text(s: &str) -> CString {
    let cleaned: Vec<u8> = s.bytes().filter(|&b| b != 0).collect();
    CString::new(cleaned).unwrap_or_default()
}

fn basename(s: &OsStr) -> String {
    let bytes = s.as_bytes();
    let start = bytes.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    // The program path may be non-UTF-8; the label is display text, so a
    // lossy decode is the right thing here (argv bytes are never touched).
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}
