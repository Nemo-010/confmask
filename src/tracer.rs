//! The tracer: one thread/process supervising a whole process tree.
//!
//! Every process of the tree is auto-attached (`PTRACE_O_TRACE{FORK,
//! VFORK,CLONE,EXEC,EXIT}`), syscall-supervised until its first exec
//! settles, and redacted at every `execve`/`execveat` — see `execimg`
//! for the image surgery.

use crate::arch::{self, ExecClass, Regs, SyscallInfo};
use crate::inject::{self, InjectError};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

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
    /// Inject `prctl(PR_SET_DUMPABLE, 0)` at every exec completion.
    pub no_dumpable: bool,
    /// The children carry a seccomp filter that traps `prctl(PR_SET_NAME)`
    /// (`SECCOMP_RET_TRACE`); the tracer reverts renames to the label.
    pub watch_prctl: bool,
    /// What happens to the remaining tree when the master exits.
    pub session_end: SessionEnd,
    /// Environment variable names that stay visible in `environ` while
    /// every other variable is redacted.  Empty: none stay visible.
    pub keep_env: Vec<Vec<u8>>,
    /// Test hook: the n-th (1-based) repoint write of a completion stop
    /// fails.  Read from `CONFMASK_FAULT_POKE` by the builder, before the
    /// supervisor's own environment is redacted.
    pub fault_poke_at: u32,
    /// Test hook: skip the vDSO when looking for a syscall instruction.
    /// Read from `CONFMASK_FAULT_NOVDSO` by the builder.
    pub fault_no_vdso: bool,
    /// Pids of every live tracee, kept current by the tracer so the
    /// owner of the session can kill the whole tree from outside.
    pub tree: TreeRegistry,
}

/// Shared set of live tracee pids.
pub type TreeRegistry = std::sync::Arc<std::sync::Mutex<std::collections::HashSet<libc::pid_t>>>;

/// What the session does with descendants still alive when the master
/// process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// `PTRACE_DETACH` every remaining tracee once it is settled (its
    /// image is already redacted and keeps the label).  The session
    /// returns without waiting for them.  Default.
    Detach,
    /// Keep supervising until every descendant has exited.
    WaitTree,
    /// `SIGKILL` every remaining descendant.
    KillTree,
}

/// Terminal state of the supervised master process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitState {
    /// Process exit code, or 128+signal if it died from a signal.
    pub code: i32,
    /// Signal number if the master was killed by a signal.
    pub signal: Option<i32>,
    /// Exec accounting for the whole session.
    pub stats: SessionStats,
}

impl ExitState {
    /// An exit state without exec accounting.
    pub fn plain(code: i32, signal: Option<i32>) -> ExitState {
        ExitState { code, signal, stats: SessionStats::default() }
    }
}

/// Exec accounting: how many execs the session saw and how many of them
/// ran with less than full redaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Execs supervised (entry or completion stops handled).
    pub execs: u32,
    /// Execs that ran through the post-exec path (`#!` scripts, argv too
    /// large for the entry swap).  Redacted, with a short exposure window.
    pub script: u32,
    /// Execs where redaction failed or was skipped: disclosure.
    pub unredacted: u32,
    /// Execs that skipped only the `comm` rename.
    pub comm_skipped: u32,
    /// Foreign-architecture execs refused.
    pub foreign_arch: u32,
    /// Execs of an already settled process: redacted after the exec, with
    /// a short exposure window (no entry swap).
    pub reexec: u32,
    /// Execs with at least one of the degradations above.
    pub degraded: u32,
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
    /// The new image runs another ABI (32-bit): refused, not redacted.
    Foreign,
}

/// Per-tracee bookkeeping.
pub struct Tracee {
    pub state: State,
    /// `--no-follow` mode: the descendant is traced (it has to be, to be
    /// followed at all) but its exec is never redacted.  Its exec stops
    /// are answered and it is then resumed unsupervised.
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

/// Grace period after the master exits during which descendants that
/// have not yet settled their first exec keep their supervision.
const DETACH_GRACE: Duration = Duration::from_secs(1);

pub struct Tracer {
    pub cfg: Config,
    pub table: HashMap<libc::pid_t, Tracee>,
    pub stats: SessionStats,
    /// The master process of the session.
    master: libc::pid_t,
    /// Terminal state of the master, once it has exited.  Its presence
    /// means the session is ending.
    master_exit: Option<ExitState>,
    /// Detach drain: when the grace period ends.
    drain_deadline: Option<Instant>,
    /// Tracees that were sent `PTRACE_INTERRUPT` during the drain.
    interrupted: std::collections::HashSet<libc::pid_t>,
    /// Test hook: the n-th (1-based) repoint write of a completion stop
    /// fails.  Zero: no fault.  Set from `CONFMASK_FAULT_POKE`.
    pub(super) fault_poke_at: u32,
    pub(super) poke_count: u32,
    /// Test hook: skip the vDSO when looking for a syscall instruction.
    /// Set from `CONFMASK_FAULT_NOVDSO`.
    pub(super) fault_no_vdso: bool,
}

impl Tracer {
    pub(crate) fn vlog(&self, args: std::fmt::Arguments) {
        if self.cfg.verbose && !self.cfg.quiet {
            eprintln!("[confmask {}] {}", std::process::id(), args);
        }
    }

    /// A degradation the operator must see even without `--verbose`.
    pub(crate) fn warn(&self, args: std::fmt::Arguments) {
        if !self.cfg.quiet {
            eprintln!("confmask: warning: {}", args);
        }
    }

    pub fn new(cfg: Config) -> Tracer {
        let fault_poke_at = cfg.fault_poke_at;
        let fault_no_vdso = cfg.fault_no_vdso;
        Tracer {
            cfg,
            table: HashMap::new(),
            stats: SessionStats::default(),
            master: 0,
            master_exit: None,
            drain_deadline: None,
            interrupted: std::collections::HashSet::new(),
            fault_poke_at,
            poke_count: 0,
            fault_no_vdso,
        }
    }

    fn register(&mut self, pid: libc::pid_t, t: Tracee) {
        self.table.insert(pid, t);
        if let Ok(mut set) = self.cfg.tree.lock() {
            set.insert(pid);
        }
    }

    fn unregister(&mut self, pid: libc::pid_t) {
        self.table.remove(&pid);
        self.interrupted.remove(&pid);
        if let Ok(mut set) = self.cfg.tree.lock() {
            set.remove(&pid);
        }
    }

    /// Supervise `master` until the session ends; returns the master's
    /// terminal state.
    ///
    /// `master` is forked and blocked reading `go_fd`.  The tracer seizes
    /// it, releases it by writing one byte to `go_fd`, then takes the
    /// child's `SIGSTOP` handshake stop as the point from which the first
    /// exec is supervised.
    pub fn supervise(mut self, master: libc::pid_t, go_fd: RawFd) -> io::Result<ExitState> {
        self.master = master;
        if let Err(e) = self.seize(master) {
            // SAFETY: closing the pipe end owned by this call.
            unsafe { libc::close(go_fd) };
            // Nothing is traced: the child must not run unmasked.
            // SAFETY: plain kill and reap of our own child.
            unsafe {
                libc::kill(master, libc::SIGKILL);
                let mut st = 0i32;
                libc::waitpid(master, &mut st, libc::__WALL);
            }
            return Err(e);
        }
        let byte = [1u8; 1];
        // SAFETY: go_fd is a valid pipe write end owned by this call.
        unsafe {
            libc::write(go_fd, byte.as_ptr() as *const libc::c_void, 1);
            libc::close(go_fd);
        }
        let status = wait_master_stop(master)?;
        if !libc::WIFSTOPPED(status) {
            // died before stopping (for example an internal error)
            return Ok(finish_status(master, status));
        }
        self.register(master, Tracee::new(State::Slow));
        // Signal 0 suppresses the handshake SIGSTOP.
        self.resume(master, 0, true);

        loop {
            if self.master_exit.is_some() && self.table.is_empty() {
                return Ok(self.finish());
            }
            let waited = if self.master_exit.is_some() && self.drain_deadline.is_some() {
                match wait_any_nohang()? {
                    Some(w) => w,
                    None => {
                        self.drain_tick();
                        if self.table.is_empty() {
                            continue;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                }
            } else {
                match wait_any() {
                    Ok(w) => w,
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::ECHILD) && self.master_exit.is_some() {
                            self.table.clear();
                            return Ok(self.finish());
                        }
                        return Err(e);
                    }
                }
            };
            let (pid, status) = waited;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.on_gone(pid, status);
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

            if event == arch::PTRACE_EVENT_STOP {
                self.on_event_stop(pid, sig);
                continue;
            }
            if event == arch::PTRACE_EVENT_SECCOMP {
                self.on_seccomp_stop(pid);
                continue;
            }
            if sig == libc::SIGTRAP && event != 0 {
                self.on_ptrace_event(pid, event);
                continue;
            }
            if sig == libc::SIGTRAP | 0x80 {
                self.on_syscall_stop(pid);
                continue;
            }
            // Real signal delivery, including a SIGTRAP raised by the
            // program itself: pass it on.
            self.resume_state(pid, sig);
        }
    }

    /// Exit state with the session statistics attached; prints the
    /// summary line.
    fn finish(&mut self) -> ExitState {
        let mut st = self.master_exit.unwrap_or_else(|| ExitState::plain(255, None));
        st.stats = self.stats;
        self.print_summary();
        st
    }

    fn print_summary(&self) {
        let s = &self.stats;
        if s.degraded == 0 || self.cfg.quiet {
            return;
        }
        let mut reasons: Vec<String> = Vec::new();
        let mut add = |name: &str, n: u32| {
            if n == 1 {
                reasons.push(name.to_string());
            } else if n > 1 {
                reasons.push(format!("{} x{}", name, n));
            }
        };
        add("script", s.script);
        add("reexec", s.reexec);
        add("unredacted", s.unredacted);
        add("comm", s.comm_skipped);
        add("foreign-arch", s.foreign_arch);
        eprintln!(
            "confmask: {} of {} execs unredacted ({})",
            s.degraded,
            s.execs,
            reasons.join(", ")
        );
    }

    fn seize(&self, pid: libc::pid_t) -> io::Result<()> {
        // SAFETY: seizing our own, running child; the options word is
        // passed in the data slot as the kernel API requires.
        let rc = unsafe {
            libc::ptrace(
                arch::PTRACE_SEIZE as _,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                self.options() as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // ------------------------------------------------------------- events --

    fn on_gone(&mut self, pid: libc::pid_t, status: i32) {
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        vlog!(self, "pid {} gone ({})", pid, code);
        self.unregister(pid);
        if pid == self.master && self.master_exit.is_none() {
            let signal = if libc::WIFSIGNALED(status) {
                Some(libc::WTERMSIG(status))
            } else {
                None
            };
            self.master_exit = Some(ExitState::plain(code, signal));
            self.begin_session_end();
        }
    }

    /// The master has exited: apply the session-end policy to what is left.
    fn begin_session_end(&mut self) {
        match self.cfg.session_end {
            SessionEnd::WaitTree => {}
            SessionEnd::KillTree => {
                let pids: Vec<libc::pid_t> = self.table.keys().copied().collect();
                for p in pids {
                    // SAFETY: plain kill(2) of a tracee of this session.
                    unsafe { libc::kill(p, libc::SIGKILL) };
                }
            }
            SessionEnd::Detach => {
                if !self.table.is_empty() {
                    vlog!(self, "master gone: detaching {} descendant(s)", self.table.len());
                    self.drain_deadline = Some(Instant::now() + DETACH_GRACE);
                    self.drain_tick();
                }
            }
        }
    }

    fn draining(&self) -> bool {
        self.master_exit.is_some() && self.drain_deadline.is_some()
    }

    fn grace_over(&self) -> bool {
        match self.drain_deadline {
            Some(d) => Instant::now() >= d,
            None => false,
        }
    }

    /// May this tracee be detached now?  Settled tracees always; tracees
    /// still waiting for their first exec only after the grace period; a
    /// tracee inside an exec never (the exec must finish its redaction).
    fn detachable(&self, pid: libc::pid_t) -> bool {
        if !self.draining() {
            return false;
        }
        match self.table.get(&pid).map(|t| t.state) {
            Some(State::Run) => true,
            Some(State::Slow) => self.grace_over(),
            _ => false,
        }
    }

    /// Ask running, detachable tracees to stop so they can be detached.
    fn drain_tick(&mut self) {
        let pids: Vec<libc::pid_t> = self.table.keys().copied().collect();
        for pid in pids {
            if self.interrupted.contains(&pid) || !self.detachable(pid) {
                continue;
            }
            // SAFETY: PTRACE_INTERRUPT on a seized tracee; harmless when
            // the tracee is already stopped.
            let rc = unsafe {
                libc::ptrace(
                    arch::PTRACE_INTERRUPT as _,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc == 0 {
                self.interrupted.insert(pid);
            } else {
                // not ptrace-stoppable (gone): drop it from the table
                // when it no longer exists
                if !proc_exists(pid) {
                    self.unregister(pid);
                }
            }
        }
    }

    fn detach(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        // SAFETY: the tracee is in a ptrace-stop at every call site.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                sig as *mut libc::c_void,
            )
        };
        if rc == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                self.warn(format_args!("pid {}: detach failed: {}", pid, e));
            }
        } else {
            vlog!(self, "pid {}: detached", pid);
        }
        self.unregister(pid);
    }

    fn on_new_tracee(&mut self, pid: libc::pid_t, master: libc::pid_t) {
        // Auto-traced newcomer (fork/vfork/clone of an existing tracee).
        // Syscall supervision until its first exec settles.
        let unmasked = !self.cfg.follow_tree && pid != master;
        // An unmasked descendant never needs syscall supervision: it is
        // redacted at no point, so it starts free-running (Run) rather
        // than paying a stop per syscall until an exec it does not care
        // about.
        let mut t = Tracee::new(if unmasked { State::Run } else { State::Slow });
        t.no_redact = unmasked;
        self.register(pid, t);
        vlog!(
            self,
            "pid {}: new tracee{}",
            pid,
            if unmasked { " (unmasked: --no-follow)" } else { "" }
        );
        self.resume_state(pid, 0);
    }

    /// `PTRACE_EVENT_STOP`: a group-stop, the answer to a
    /// `PTRACE_INTERRUPT`, or the initial stop of a seized tracee.
    fn on_event_stop(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        let was_interrupted = self.interrupted.remove(&pid);
        if sig != libc::SIGTRAP {
            // Group-stop: keep the tracee stopped, but let SIGCONT and the
            // real parent's job control see it (PTRACE_LISTEN).
            if self.detachable(pid) {
                self.detach(pid, 0);
                return;
            }
            // SAFETY: tracee is in a seized group-stop.
            let rc = unsafe {
                libc::ptrace(
                    arch::PTRACE_LISTEN as _,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc == -1 {
                self.warn(format_args!(
                    "pid {}: PTRACE_LISTEN failed: {}; resuming instead",
                    pid,
                    io::Error::last_os_error()
                ));
                self.resume_state(pid, 0);
            }
            return;
        }
        let _ = was_interrupted;
        self.resume_state(pid, 0);
    }

    fn on_ptrace_event(&mut self, pid: libc::pid_t, event: u32) {
        const PTRACE_EVENT_FORK: u32 = 1;
        const PTRACE_EVENT_VFORK: u32 = 2;
        const PTRACE_EVENT_CLONE: u32 = 3;
        const PTRACE_EVENT_EXEC: u32 = 4;
        const PTRACE_EVENT_VFORK_DONE: u32 = 5;

        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                let cpid = self.event_msg(pid);
                vlog!(self, "pid {} forked/cloned -> {}", pid, cpid);
                self.resume_state(pid, 0);
            }
            PTRACE_EVENT_EXEC => {
                // For an exec by a non-leader thread the kernel resets the
                // tid to the leader's; the former tid is in the event
                // message and holds the entry-stop bookkeeping.
                let former = self.event_msg(pid) as libc::pid_t;
                if former != pid && former > 0 {
                    if let Some(t) = self.table.remove(&former) {
                        vlog!(self, "pid {}: exec by non-leader thread {}", pid, former);
                        if let Ok(mut set) = self.cfg.tree.lock() {
                            set.remove(&former);
                        }
                        self.interrupted.remove(&former);
                        self.table.insert(pid, t);
                    }
                }
                let no_redact = self.table.get(&pid).map(|t| t.no_redact).unwrap_or(false);
                if no_redact {
                    self.set_state(pid, State::Run);
                    self.resume_state(pid, 0);
                } else {
                    self.on_exec_complete(pid, false);
                }
            }
            PTRACE_EVENT_VFORK_DONE => self.resume_state(pid, 0),
            _ => self.resume_state(pid, 0),
        }
    }

    fn event_msg(&self, pid: libc::pid_t) -> u64 {
        let mut msg: u64 = 0;
        // SAFETY: attached tracee stopped at an event stop.
        unsafe {
            libc::ptrace(
                libc::PTRACE_GETEVENTMSG,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                &mut msg as *mut u64 as *mut libc::c_void,
            )
        };
        msg
    }

    /// `PTRACE_EVENT_SECCOMP`: the children carry a filter that traps
    /// `prctl(PR_SET_NAME)` only.  The rename is redirected to the label.
    fn on_seccomp_stop(&mut self, pid: libc::pid_t) {
        let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
        if inject::get_syscall_info(pid, &mut si).is_ok()
            && si.entry_nr() == Some(arch::SYS_PRCTL)
            && self.cfg.watch_prctl
        {
            // SAFETY: the union holds entry-shaped data at a seccomp stop.
            let opt = unsafe { si.detail.seccomp.args[0] };
            if opt == libc::PR_SET_NAME as u64 {
                self.redirect_rename(pid, &si);
            }
        }
        self.resume_state(pid, 0);
    }

    /// Point `prctl(PR_SET_NAME, ...)` at a label buffer just below the
    /// tracee's stack pointer (outside the red zone).
    fn redirect_rename(&mut self, pid: libc::pid_t, si: &SyscallInfo) {
        let Ok(mut regs) = Regs::get(pid) else { return };
        let mut buf = [0u8; 16];
        let n = self.cfg.label_comm.len().min(15);
        buf[..n].copy_from_slice(&self.cfg.label_comm[..n]);
        let addr = (si.stack_pointer.wrapping_sub(512)) & !15u64;
        if crate::remote::write_mem(pid, addr, &buf) != buf.len() as isize {
            self.warn(format_args!("pid {}: cannot redirect a rename to the label", pid));
            return;
        }
        regs.set_arg(2, addr);
        if regs.put(pid).is_ok() {
            vlog!(self, "pid {}: rename redirected to the label", pid);
        }
    }

    fn on_syscall_stop(&mut self, pid: libc::pid_t) {
        let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
        if inject::get_syscall_info(pid, &mut si).is_err() {
            self.resume_state(pid, 0);
            return;
        }

        // Entry-shaped stops.  Only op ENTRY occurs for our own tracees
        // (the optional filter traps prctl only); op SECCOMP is accepted
        // too so a tracee already under a foreign RET_TRACE filter is
        // handled.
        if let Some(nr) = si.entry_nr() {
            let (state, no_redact) = match self.table.get(&pid) {
                Some(t) => (t.state, t.no_redact),
                None => (State::Run, false),
            };
            let class = arch::classify_exec(si.arch, nr);
            if class != ExecClass::NotExec && no_redact {
                // no redaction wanted: settle to Run and let the exec
                // proceed normally
                self.set_state(pid, State::Run);
                self.resume_state(pid, 0);
                return;
            }
            if class == ExecClass::Foreign && matches!(state, State::Run | State::Slow) {
                // The register layout and the argument ABI differ.  The
                // exec runs unswapped; the completion stop decides
                // whether the new image can be redacted.
                vlog!(self, "pid {}: foreign-ABI exec entry (arch {:#x}, nr {})", pid, si.arch, nr);
                if let Some(t) = self.table.get_mut(&pid) {
                    t.clear_exec_state();
                }
                self.set_state(pid, State::Script);
                self.resume(pid, 0, true);
                return;
            }
            if class == ExecClass::Native && matches!(state, State::Run | State::Slow) {
                match Regs::get(pid) {
                    Ok(regs) => self.on_exec_entry(pid, nr, &regs),
                    Err(_) => {
                        self.set_state(pid, State::Script);
                        self.resume(pid, 0, true);
                    }
                }
                return;
            }
            self.resume_state(pid, 0);
            return;
        }

        // syscall exit
        let state = self.table.get(&pid).map(|t| t.state).unwrap_or(State::Run);
        match state {
            State::Swapped | State::Script => {
                if si.exit_is_error() {
                    // exec failed: put the original inline arrays back
                    // and keep the process syscall-supervised: its first
                    // exec has not settled.
                    self.restore_orig_arrays(pid);
                    if let Some(t) = self.table.get_mut(&pid) {
                        t.clear_exec_state();
                    }
                    self.set_state(pid, State::Slow);
                    self.resume(pid, 0, true);
                } else {
                    // exec succeeded but no PTRACE_EVENT_EXEC stop
                    // arrived: do the completion here, at the exit stop.
                    // The new image is mapped and the program has not
                    // started yet.
                    self.on_exec_complete(pid, true);
                }
            }
            _ => self.resume_state(pid, 0),
        }
    }

    // ---------------------------------------------------------- resume ops --

    /// Resume a tracee in the mode its state asks for, delivering `sig`.
    /// During the detach drain a settled tracee is detached instead.
    pub(super) fn resume_state(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        let slow = self.table.get(&pid).map(|t| t.state == State::Slow).unwrap_or(false);
        self.resume(pid, sig, slow);
    }

    /// Resume a tracee.  Every resume goes through here so a failure is
    /// reported rather than dropped: a tracee left stopped-and-forgotten
    /// wedges the whole tree.
    ///
    /// ESRCH means either "gone" or "not stopped".  A probe of
    /// `/proc/<pid>` tells them apart; a live tracee that cannot be
    /// resumed is reported.
    pub(super) fn resume(&mut self, pid: libc::pid_t, sig: libc::c_int, syscall: bool) {
        if self.detachable(pid) {
            self.detach(pid, sig);
            return;
        }
        let r = if syscall {
            inject::ptrace_syscall(pid, sig)
        } else {
            inject::ptrace_cont(pid, sig)
        };
        if let Err(e) = r {
            if e.raw_os_error() == Some(libc::ESRCH) && !proc_alive(pid) {
                return;
            }
            self.warn(format_args!("pid {}: resume failed: {}", pid, e));
        }
    }

    // ----------------------------------------------------------- options --

    fn options(&self) -> libc::c_long {
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
        if self.cfg.watch_prctl {
            o |= arch::PTRACE_O_TRACESECCOMP;
        }
        o
    }
}

/// True when `/proc/<pid>` exists and the task is not a zombie or dead.
fn proc_alive(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    match stat.rfind(')') {
        Some(i) => !matches!(stat[i + 1..].trim_start().chars().next(), Some('Z') | Some('X') | None),
        None => false,
    }
}

fn proc_exists(pid: libc::pid_t) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// waitpid(-1, __WALL), EINTR-safe.
fn wait_any() -> io::Result<(libc::pid_t, i32)> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok((w, status));
    }
}

/// waitpid(-1, __WALL | WNOHANG): `None` when nothing is ready.  ECHILD
/// reads as "nothing left" and is returned as `None` too.
fn wait_any_nohang() -> io::Result<Option<(libc::pid_t, i32)>> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if e.raw_os_error() == Some(libc::ECHILD) {
                return Ok(None);
            }
            return Err(e);
        }
        if w == 0 {
            return Ok(None);
        }
        return Ok(Some((w, status)));
    }
}

/// Wait for the master's initial stop (EINTR-safe, ignores other pids).
fn wait_master_stop(pid: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
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
        ExitState::plain(libc::WEXITSTATUS(status), None)
    } else if libc::WIFSIGNALED(status) {
        ExitState::plain(128 + libc::WTERMSIG(status), Some(libc::WTERMSIG(status)))
    } else {
        ExitState::plain(255, None)
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
