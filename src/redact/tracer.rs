//! The tracer: one thread/process supervising a whole process tree.
//!
//! Every process of the tree is auto-attached (`PTRACE_O_TRACE{FORK,
//! VFORK,CLONE,EXEC,EXIT}`) and syscall-supervised until its first exec
//! settles, which is where `execve`/`execveat` is stopped at syscall
//! *entry* and the real command line is swapped out before the kernel
//! copies it — see `execimg` for the image surgery.  After that the
//! process runs free and only exec events stop it again.

use crate::redact::arch::{self, Regs, SyscallInfo};
use crate::redact::inject::{self, InjectError};
use std::collections::HashMap;
use std::io;

/// Knobs of a masking session.
#[derive(Clone)]
pub struct Config {
    /// Label presented as the process command line (argv[0] of the
    /// /proc image); remaining argv entries present as empty strings.
    pub label: Vec<u8>,
    /// Label truncated to the kernel `comm` limit (15 bytes + NUL).
    pub label_comm: Vec<u8>,
    /// Also redact `/proc/<pid>/environ` (default on).
    pub redact_environ: bool,
    /// Follow every descendant (default on).
    pub follow_tree: bool,
    /// Kill the whole tree if the tracer dies (default on).
    pub exit_kill: bool,
    /// Event logging to stderr.
    pub verbose: bool,
    /// Suppress all diagnostics.
    pub quiet: bool,
}

/// Terminal state of the supervised master process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitState {
    /// Process exit code, or 128+signal if it died from a signal.
    pub code: i32,
    /// Signal number if the master was killed by a signal.
    pub signal: Option<i32>,
}

/// Where a tracee is in the exec lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Syscall supervision until the first exec completes (its entry
    /// stop is where the zero-exposure swap happens).
    Slow,
    /// Running free; only exec events will stop it (reread redaction).
    Run,
    /// exec entry arrays swapped, awaiting exec completion or error.
    Swapped,
    /// Script/unknown exec: redact after completion instead.
    Script,
    /// Redaction done; waiting for the final syscall-exit stop.
    Drain,
}

/// Per-tracee bookkeeping.
pub struct Tracee {
    pub state: State,
    /// `--no-follow` fallback: a descendant that could not be detached.
    /// It is never redacted; its exec/fork events are answered and it is
    /// resumed without syscall supervision.
    pub no_redact: bool,
    pub env_swapped: bool,
    pub av_addr: u64,
    pub ev_addr: u64,
    pub av_save: Option<Vec<u64>>,
    pub ev_save: Option<Vec<u64>>,
    pub argv: Option<Vec<Vec<u8>>>,
    pub envp: Option<Vec<Vec<u8>>>,
}

impl Tracee {
    fn new(state: State) -> Tracee {
        Tracee {
            state,
            no_redact: false,
            env_swapped: false,
            av_addr: 0,
            ev_addr: 0,
            av_save: None,
            ev_save: None,
            argv: None,
            envp: None,
        }
    }

    pub(super) fn clear_exec_state(&mut self) {
        self.env_swapped = false;
        self.av_addr = 0;
        self.ev_addr = 0;
        self.av_save = None;
        self.ev_save = None;
        self.argv = None;
        self.envp = None;
    }

}

pub struct Tracer {
    pub cfg: Config,
    pub table: HashMap<libc::pid_t, Tracee>,
}

/// True when `nr` is one of the exec system calls.
fn is_exec_nr(nr: u64) -> bool {
    nr == arch::SYS_EXECVE || nr == arch::SYS_EXECVEAT
}

impl Tracer {
    pub(crate) fn vlog(&self, args: std::fmt::Arguments) {
        if self.cfg.verbose && !self.cfg.quiet {
            eprintln!("[argvmask {}] {}", std::process::id(), args);
        }
    }

    pub fn new(cfg: Config) -> Tracer {
        Tracer {
            cfg,
            table: HashMap::new(),
        }
    }

    /// Supervise `master` (already forked, before its first exec) until
    /// the whole tree is gone; returns the master's terminal state.
    pub fn supervise(mut self, master: libc::pid_t) -> io::Result<ExitState> {
        // Initial SIGSTOP handshake: configure before the first exec.
        let status = wait_master_stop(master)?;
        if !libc::WIFSTOPPED(status) {
            // died before stopping (e.g. internal error)
            return Ok(finish_status(master, status));
        }
        self.setoptions(master)?;
        self.table.insert(master, Tracee::new(State::Slow));
        let _ = inject::ptrace_syscall(master, 0);

        loop {
            let (pid, status) = wait_any()?;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                };
                vlog!(self, "pid {} gone ({})", pid, code);
                self.table.remove(&pid);
                if pid == master {
                    if libc::WIFSIGNALED(status) {
                        return Ok(ExitState {
                            code,
                            signal: Some(libc::WTERMSIG(status)),
                        });
                    }
                    return Ok(ExitState { code, signal: None });
                }
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let event = (status as u32) >> 16;

            if !self.table.contains_key(&pid) {
                self.on_new_tracee(pid, master);
                continue;
            }

            if sig == libc::SIGTRAP {
                self.on_ptrace_event(pid, event);
                continue;
            }

            if sig == libc::SIGTRAP | 0x80 {
                self.on_syscall_stop(pid);
                continue;
            }

            // Real signal delivery.
            if sig == libc::SIGCHLD {
                let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: pid is a stopped tracee; si is valid storage.
                let rc = unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETSIGINFO,
                        pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        &mut si as *mut libc::siginfo_t as *mut libc::c_void,
                    )
                };
                if rc == 0
                    && matches!(
                        si.si_code,
                        libc::CLD_TRAPPED | libc::CLD_STOPPED | libc::CLD_CONTINUED | libc::CLD_DUMPED
                    )
                {
                    self.cont_generic(pid, 0);
                    continue;
                }
            }
            self.cont_signal(pid, sig);
        }
    }

    // ------------------------------------------------------------- events --

    fn on_new_tracee(&mut self, pid: libc::pid_t, master: libc::pid_t) {
        // Auto-traced newcomer (fork/vfork/clone of an existing tracee).
        if !self.cfg.follow_tree && pid != master {
            // `--no-follow`: descendants are not part of the mask.  Detach
            // them so they run free.  Leaving them attached-but-unredacted
            // instead would keep them in syscall supervision for the rest
            // of their lives (two stops per syscall), which is the most
            // expensive mode rather than the cheapest.
            match inject::ptrace_detach(pid, 0) {
                Ok(()) => {
                    vlog!(self, "pid {}: detached (--no-follow)", pid);
                    return;
                }
                Err(e) => {
                    // Detach refused (the newcomer is stopped at a ptrace
                    // event): keep it attached, never redact it, and let it
                    // run free of syscall stops.
                    vlog!(
                        self,
                        "pid {}: detach failed ({}), running unredacted",
                        pid,
                        e
                    );
                    let mut t = Tracee::new(State::Run);
                    t.no_redact = true;
                    self.table.insert(pid, t);
                    let _ = self.setoptions(pid);
                    let _ = inject::ptrace_cont(pid, 0);
                    return;
                }
            }
        }
        // Syscall supervision until the first exec settles.
        self.table.insert(pid, Tracee::new(State::Slow));
        if let Err(e) = self.setoptions(pid) {
            vlog!(self, "pid {}: setoptions: {}", pid, e);
        }
        let _ = inject::ptrace_syscall(pid, 0);
        vlog!(self, "pid {}: new tracee", pid);
    }

    fn on_ptrace_event(&mut self, pid: libc::pid_t, event: u32) {
        const PTRACE_EVENT_FORK: u32 = 1;
        const PTRACE_EVENT_VFORK: u32 = 2;
        const PTRACE_EVENT_CLONE: u32 = 3;
        const PTRACE_EVENT_EXEC: u32 = 4;
        const PTRACE_EVENT_VFORK_DONE: u32 = 5;
        const PTRACE_EVENT_EXIT: u32 = 6;

        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                let mut cpid: u64 = 0;
                // SAFETY: attached tracee stopped at a fork event.
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETEVENTMSG,
                        pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        &mut cpid as *mut u64 as *mut libc::c_void,
                    )
                };
                vlog!(self, "pid {} forked/cloned -> {}", pid, cpid);
                self.cont_generic(pid, 0);
            }
            PTRACE_EVENT_VFORK_DONE => self.cont_generic(pid, 0),
            PTRACE_EVENT_EXEC => {
                let no_redact = self
                    .table
                    .get(&pid)
                    .map(|t| t.no_redact)
                    .unwrap_or(false);
                if no_redact {
                    let _ = inject::ptrace_cont(pid, 0);
                } else {
                    self.on_exec_complete(pid, false);
                }
            }
            PTRACE_EVENT_EXIT => self.cont_generic(pid, 0),
            _ => self.cont_generic(pid, 0),
        }
    }

    fn on_syscall_stop(&mut self, pid: libc::pid_t) {
        let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
        if inject::get_syscall_info(pid, &mut si).is_err() {
            let _ = inject::ptrace_syscall(pid, 0);
            return;
        }

        // Entry-shaped stops: syscall-entry stops (op ENTRY) and seccomp
        // SECCOMP_RET_TRACE stops (op SECCOMP, same data layout).
        if let Some(nr) = si.entry_nr() {
            let (state, no_redact) = match self.table.get(&pid) {
                Some(t) => (t.state, t.no_redact),
                None => (State::Run, false),
            };
            if is_exec_nr(nr) && no_redact {
                // service the filter's stop without redacting: the exec
                // proceeds normally
                let _ = inject::ptrace_cont(pid, 0);
                return;
            }
            if is_exec_nr(nr) && matches!(state, State::Run | State::Slow) {
                match Regs::get(pid) {
                    Ok(regs) => self.on_exec_entry(pid, nr, &regs),
                    Err(_) => {
                        let _ = inject::ptrace_syscall(pid, 0);
                    }
                }
                return;
            }
            if state == State::Slow {
                let _ = inject::ptrace_syscall(pid, 0);
            } else {
                let _ = inject::ptrace_cont(pid, 0);
            }
            return;
        }

        // syscall exit
        let state = self.table.get(&pid).map(|t| t.state).unwrap_or(State::Run);
        if state == State::Swapped {
            if si.exit_is_error() {
                // exec failed: put the original inline arrays back
                self.restore_orig_arrays(pid);
                self.settle_after_exec(pid);
                self.cont_generic(pid, 0);
            } else {
                // exec succeeded but no PTRACE_EVENT_EXEC stop arrived
                // (kernels skip it for seccomp-resumed entries): do the
                // completion here, at the exit stop.  The new image is
                // mapped and the program has not started yet.
                self.on_exec_complete(pid, true);
            }
        } else if state == State::Drain {
            self.settle_after_exec(pid);
            self.cont_generic(pid, 0);
        } else if state == State::Slow {
            let _ = inject::ptrace_syscall(pid, 0);
        } else {
            let _ = inject::ptrace_cont(pid, 0);
        }
    }

    fn settle_after_exec(&mut self, pid: libc::pid_t) {
        if let Some(t) = self.table.get_mut(&pid) {
            if t.state == State::Swapped || t.state == State::Drain {
                t.state = State::Run;
            }
        }
    }

    // ---------------------------------------------------------- resume ops --

    fn cont_generic(&self, pid: libc::pid_t, sig: libc::c_int) {
        let supervised = self
            .table
            .get(&pid)
            .map(|t| t.state == State::Slow)
            .unwrap_or(false);
        let r = if supervised {
            inject::ptrace_syscall(pid, sig)
        } else {
            inject::ptrace_cont(pid, sig)
        };
        let _ = r;
    }

    /// Resume after a non-trap signal stop, detecting group-stops.
    fn cont_signal(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        if matches!(sig, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) {
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: pid is a stopped tracee; si is valid storage.
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_GETSIGINFO,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    &mut si as *mut libc::siginfo_t as *mut libc::c_void,
                )
            };
            if rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                // group-stop: restart without re-delivering the signal
                self.cont_generic(pid, 0);
                return;
            }
        }
        self.cont_generic(pid, sig);
    }

    // ----------------------------------------------------------- options --

    fn setoptions_with(&self, pid: libc::pid_t) -> io::Result<()> {
        // Fork/vfork/clone tracing is ALWAYS on, independent of
        // `follow_tree`: the tracer must know about every descendant so
        // its first exec is supervised; `follow_tree` only decides
        // whether newcomers are redacted.
        let mut o: libc::c_long = (libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEEXIT
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE) as libc::c_long;
        if self.cfg.exit_kill {
            o |= libc::PTRACE_O_EXITKILL as libc::c_long;
        }
        // SAFETY: pid is an attached, stopped tracee.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                o as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn setoptions(&self, pid: libc::pid_t) -> io::Result<()> {
        self.setoptions_with(pid)
    }
}

/// waitpid(-1, __WALL), EINTR-safe.
fn wait_any() -> io::Result<(libc::pid_t, i32)> {
    loop {
        let mut status = 0i32;
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if e.raw_os_error() == Some(libc::ECHILD) {
                return Err(e);
            }
            return Err(e);
        }
        return Ok((w, status));
    }
}

/// Wait for the master's initial stop (EINTR-safe, ignores other pids).
fn wait_master_stop(pid: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0i32;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(status);
    }
}

fn finish_status(pid: libc::pid_t, status: i32) -> ExitState {
    let _ = pid;
    if libc::WIFEXITED(status) {
        ExitState { code: libc::WEXITSTATUS(status), signal: None }
    } else if libc::WIFSIGNALED(status) {
        ExitState {
            code: 128 + libc::WTERMSIG(status),
            signal: Some(libc::WTERMSIG(status)),
        }
    } else {
        ExitState { code: 255, signal: None }
    }
}

/// Injectable errors that are recoverable mid-session are mapped here so
/// callers can treat `InjectError::TraceeDied` uniformly.
impl Tracer {
    pub fn injection_failed(&self, pid: libc::pid_t, what: &str, e: &InjectError) -> bool {
        // returns true if the tracee died (fatal for that tracee)
        match e {
            InjectError::TraceeDied => {
                vlog!(self, "pid {}: tracee died during {} injection", pid, what);
                true
            }
            InjectError::Io(err) => {
                vlog!(self, "pid {}: {} injection failed: {}", pid, what, err);
                false
            }
        }
    }
}
