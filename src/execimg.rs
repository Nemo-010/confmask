//! exec-image surgery: redacting argv/envp at system call entry and
//! re-injecting the real arguments into hidden stack space at exec
//! completion.
//!
//! Entry (ELF targets): the inline `argv[]`/`envp[]` pointer arrays in
//! the *old* image are rewritten to point at a label string / empty
//! strings in scratch space, so the kernel never copies the real command
//! line or environment into the new image.  There is no window, however
//! short, in which the real data is visible through /proc.
//!
//! Completion (`PTRACE_EVENT_EXEC`): the saved real argv/envp strings are
//! written into scratch space below the new image's initial SP and the
//! stack's inline arrays are repointed there.  `argc`, the array
//! positions and the auxiliary vector stay untouched, so every libc
//! (glibc, musl, static) starts up normally and sees its own arguments.
//! `prctl(PR_SET_NAME)` is injected through the tracee's vDSO in the
//! same stop.
//!
//! Scripts (`#!` files) are the exception: the kernel needs the real argv
//! to build the interpreter command line, so for those the copied strings
//! are zeroed and replaced by hidden copies after completion
//! (sub-millisecond exposure for the interpreter line only).

use crate::arch::{self, Regs};
use crate::remote::{
    dup_strings, peek_word, poke_word, read_cstr, read_ptr_array, write_mem, zero_range, MAX_ARGV,
    MAX_ENVV, MAX_HIDDEN, MAX_STRLEN,
};
use crate::tracer::{State, Tracer};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::time::Instant;

/// syscall flavor of the exec currently in flight
#[derive(Clone, Copy, PartialEq)]
enum ExecFlavor {
    Execve,
    Execveat { dirfd: u64, flags: u64 },
}

impl ExecFlavor {
    /// (argv pointer, envp pointer) in the tracee.
    fn args(self, regs: &Regs) -> (u64, u64) {
        match self {
            ExecFlavor::Execve => (regs.arg(2), regs.arg(3)),
            ExecFlavor::Execveat { .. } => (regs.arg(3), regs.arg(4)),
        }
    }
}

fn flavor_of(nr: u64, regs: &Regs) -> ExecFlavor {
    if nr == arch::SYS_EXECVEAT {
        ExecFlavor::Execveat {
            dirfd: regs.arg(1),
            flags: regs.arg(5),
        }
    } else {
        ExecFlavor::Execve
    }
}

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u64 = 0x1000;

struct RedactionBlock {
    str_addrs: Vec<u64>,
    comm_addr: u64,
}

/// Why a completion stop could not fully redact an exec.
enum Fail {
    /// The tracee runs another ABI (32-bit): not redacted.
    Foreign,
    /// Redaction failed or was skipped: disclosure.
    Unredacted(String),
}

/// What a completion stop did short of the zero-exposure path.
#[derive(Default)]
struct ExecFlags {
    script: bool,
    reexec: bool,
    comm_skipped: bool,
    failed: bool,
    foreign: bool,
}

impl Tracer {
    /// execve/execveat entry stop: save the real strings, swap the inline
    /// arrays for ELF targets, defer to post-exec hiding otherwise.
    pub(super) fn on_exec_entry(&mut self, pid: libc::pid_t, nr: u64, regs: &Regs) {
        let flavor = flavor_of(nr, regs);
        let (av, ev) = flavor.args(regs);

        {
            let Some(t) = self.table.get_mut(&pid) else { return };
            t.clear_exec_state();
            t.av_addr = av;
            t.ev_addr = ev;
        }

        let mut overflow = false;
        let avarr = if av != 0 { read_ptr_array(pid, av, MAX_ARGV) } else { None };
        let evarr = if ev != 0 { read_ptr_array(pid, ev, MAX_ENVV) } else { None };
        // An array without its terminator inside the cap is incomplete:
        // the swap would leave the tail entries real.
        if matches!(avarr, Some((_, false))) || matches!(evarr, Some((_, false))) {
            overflow = true;
        }
        let avarr = avarr.map(|(v, _)| v);
        let evarr = evarr.map(|(v, _)| v);

        {
            let Some(t) = self.table.get_mut(&pid) else { return };
            if let Some(arr) = &avarr {
                t.argv = dup_strings(pid, arr, &mut overflow);
                t.av_save = Some(arr.clone());
            }
            if let Some(arr) = &evarr {
                t.envp = dup_strings(pid, arr, &mut overflow);
                t.ev_save = Some(arr.clone());
            }
        }

        let avn = avarr.as_ref().map(|v| v.len()).unwrap_or(0);
        let evn = evarr.as_ref().map(|v| v.len()).unwrap_or(0);

        if overflow || avarr.is_none() {
            vlog!(self, "pid {}: argv unreadable/huge, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let image = self.exec_path(pid, flavor, regs);
        let elf = image
            .as_ref()
            .map(|p| self.path_is_elf(pid, p))
            .unwrap_or(false);
        // A 64-bit supervisor cannot read or write the registers of a
        // 32-bit image, so it cannot redact it.  Refuse loudly instead
        // of swapping argv and then failing: the program keeps its real
        // arguments and the session summary names the exec.
        let foreign_image = elf && image.as_ref().map(|p| self.elf_is_32(pid, p)).unwrap_or(false);
        if foreign_image {
            vlog!(self, "pid {}: 32-bit image, refusal at completion", pid);
            self.set_state(pid, State::Foreign);
            self.resume_exec_entry(pid);
            return;
        }

        if !elf {
            // script / unknown: the kernel needs the real argv to build
            // the interpreter line; redact after completion instead.
            vlog!(self, "pid {}: script/unknown exec, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // scratch below the old SP: [label][NUL][zero-filled remainder]
        let sp = regs.sp();
        let label = self.cfg.label.clone();
        // `fl` is capped at 255 so `empty_str` (base+fl) always lands on a
        // byte inside the zeroed scratch; a longer label would otherwise
        // point at uninitialised stack memory.
        let mut scratch = [0u8; 256];
        let fl = (label.len() + 1).clamp(1, 255);
        scratch[..fl - 1].copy_from_slice(&label[..fl - 1]);
        let base = sp - 4096;
        let fake_str = base;
        let empty_str = base + fl as u64;
        if write_mem(pid, base, &scratch) != scratch.len() as isize {
            vlog!(self, "pid {}: scratch write failed, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // rewrite the inline argv array: label, then empty strings
        let mut nv = vec![empty_str; avn + 1];
        if avn > 0 {
            nv[0] = fake_str;
        }
        nv[avn] = 0;
        let nv_bytes = ptr_words_bytes(&nv);
        if write_mem(pid, av, &nv_bytes) != nv_bytes.len() as isize {
            // A partial write leaves a mix: put the originals back.
            if let Some(t) = self.table.get(&pid) {
                if let Some(save) = &t.av_save {
                    let _ = write_mem(pid, av, &ptr_words_bytes(save));
                }
            }
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // same treatment for the environment, except for variables the
        // caller asked to keep visible
        if self.cfg.redact_environ && evarr.is_some() {
            let envp = self.table.get(&pid).and_then(|t| t.envp.clone()).unwrap_or_default();
            let orig_ptrs = evarr.clone().unwrap_or_default();
            let mut ne = vec![empty_str; evn + 1];
            for (i, slot) in ne.iter_mut().enumerate().take(evn) {
                if self.is_kept_env(envp.get(i)) {
                    *slot = orig_ptrs[i];
                }
            }
            ne[evn] = 0;
            let ne_bytes = ptr_words_bytes(&ne);
            if write_mem(pid, ev, &ne_bytes) == ne_bytes.len() as isize {
                if let Some(t) = self.table.get_mut(&pid) {
                    t.env_swapped = true;
                }
            } else if let Some(t) = self.table.get(&pid) {
                if let Some(save) = &t.ev_save {
                    let _ = write_mem(pid, ev, &ptr_words_bytes(save));
                }
            }
        }

        self.set_state(pid, State::Swapped);
        self.resume_exec_entry(pid);
        vlog!(
            self,
            "pid {}: entry pointer-swap (ELF) argc={} envc={}",
            pid,
            avn,
            evn
        );
    }

    /// Does this environment string name a variable that stays visible?
    fn is_kept_env(&self, s: Option<&Vec<u8>>) -> bool {
        let Some(s) = s else { return false };
        if self.cfg.keep_env.is_empty() {
            return false;
        }
        let name = match s.iter().position(|&b| b == b'=') {
            Some(p) => &s[..p],
            None => &s[..],
        };
        self.cfg.keep_env.iter().any(|k| k.as_slice() == name)
    }

    /// Restore the original inline arrays after a failed exec.
    pub(super) fn restore_orig_arrays(&mut self, pid: libc::pid_t) {
        let (av_addr, av_save, ev_addr, ev_save, env_swapped) = {
            let Some(t) = self.table.get_mut(&pid) else { return };
            if t.state != State::Swapped {
                return;
            }
            (
                t.av_addr,
                t.av_save.clone(),
                t.ev_addr,
                t.ev_save.clone(),
                t.env_swapped,
            )
        };
        if av_addr != 0 {
            if let Some(save) = &av_save {
                let _ = write_mem(pid, av_addr, &ptr_words_bytes(save));
            }
        }
        if env_swapped && ev_addr != 0 {
            if let Some(save) = &ev_save {
                let _ = write_mem(pid, ev_addr, &ptr_words_bytes(save));
            }
        }
        if let Some(t) = self.table.get_mut(&pid) {
            t.av_save = None;
            t.ev_save = None;
            t.argv = None;
            t.envp = None;
            t.env_swapped = false;
        }
    }

    /// exec completed (`PTRACE_EVENT_EXEC`, or the exec's syscall-exit
    /// stop on kernels that skip the event): re-inject the real arguments
    /// below SP, zero the visible copies, inject the comm label.
    ///
    /// Every path ends in `finish_exec_complete`, which resumes the
    /// tracee: a tracee left stopped wedges the whole tree.
    pub(super) fn on_exec_complete(&mut self, pid: libc::pid_t, at_exit_stop: bool) {
        let started = Instant::now();
        let reads0 = crate::remote::READ_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        self.stats.execs += 1;
        let mut flags = ExecFlags::default();
        let mut pending_stop: Option<i32> = None;
        match self.redact_after_exec(pid, &mut flags, &mut pending_stop) {
            Ok(()) => {}
            Err(Fail::Foreign) => {
                flags.foreign = true;
                self.warn(format_args!(
                    "pid {}: 32-bit (foreign ABI) program is not redacted",
                    pid
                ));
            }
            Err(Fail::Unredacted(why)) => {
                flags.failed = true;
                self.warn(format_args!("pid {}: exec not redacted: {}", pid, why));
            }
        }
        self.account(&flags);
        let reads = crate::remote::READ_CALLS.load(std::sync::atomic::Ordering::Relaxed) - reads0;
        vlog!(
            self,
            "pid {}: completion-stop {}us reads={}",
            pid,
            started.elapsed().as_micros(),
            reads
        );
        self.finish_exec_complete(pid, at_exit_stop);
        if let Some(sig) = pending_stop {
            // A group-stop signal that arrived inside the injection
            // window was restarted: raise it again.
            // SAFETY: plain kill(2) of a tracee.
            unsafe { libc::kill(pid, sig) };
        }
    }

    fn account(&mut self, f: &ExecFlags) {
        let s = &mut self.stats;
        if f.script {
            s.script += 1;
        }
        if f.reexec {
            s.reexec += 1;
        }
        if f.comm_skipped {
            s.comm_skipped += 1;
        }
        if f.failed {
            s.unredacted += 1;
        }
        if f.foreign {
            s.foreign_arch += 1;
        }
        if f.script || f.reexec || f.comm_skipped || f.failed || f.foreign {
            s.degraded += 1;
        }
    }

    fn poke(&mut self, pid: libc::pid_t, addr: u64, val: u64) -> bool {
        self.poke_count += 1;
        if self.fault_poke_at != 0 && self.poke_count == self.fault_poke_at {
            vlog!(self, "pid {}: fault injection: repoint write {} fails", pid, self.poke_count);
            return false;
        }
        poke_word(pid, addr, val)
    }

    fn redact_after_exec(
        &mut self,
        pid: libc::pid_t,
        flags: &mut ExecFlags,
        pending_stop: &mut Option<i32>,
    ) -> Result<(), Fail> {
        let orig_regs = match Regs::get(pid) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::Unsupported => return Err(Fail::Foreign),
            Err(e) => return Err(Fail::Unredacted(format!("registers unreadable: {}", e))),
        };
        let sp = orig_regs.sp();

        let state = match self.table.get(&pid) {
            Some(t) => t.state,
            None => return Err(Fail::Unredacted("no bookkeeping for the tracee".into())),
        };
        let reread = state != State::Swapped;
        match state {
            State::Foreign => return Err(Fail::Foreign),
            State::Script => flags.script = true,
            State::Swapped => {}
            State::Run | State::Slow => flags.reexec = true,
        }

        let Some(kargc) = peek_word(pid, sp).filter(|v| *v <= MAX_ARGV as u64) else {
            return Err(Fail::Unredacted("argc unreadable or implausible".into()));
        };
        let kargv = sp + 8;
        let kenvp = kargv + (kargc + 1) * 8;
        let Some((kav, kav_done)) = read_ptr_array(pid, kargv, MAX_ARGV + 1) else {
            return Err(Fail::Unredacted("kernel argv array unreadable".into()));
        };
        let Some((kev, kev_done)) = read_ptr_array(pid, kenvp, MAX_ENVV + 1) else {
            return Err(Fail::Unredacted("kernel envp array unreadable".into()));
        };
        if !kav_done || !kev_done {
            return Err(Fail::Unredacted("argv or envp array too large".into()));
        }

        // Real argv/envp strings: from the saved copy (swapped path) or
        // re-read from the kernel-copied stack (script / missed entry).
        let (argv, envp) = if !reread {
            let t = self.table.get_mut(&pid);
            match t {
                Some(t) => (t.argv.take(), t.envp.take()),
                None => (None, None),
            }
        } else {
            let mut overflow = false;
            let n = kav.len().min(kargc as usize);
            let a = dup_strings(pid, &kav[..n], &mut overflow);
            let e = dup_strings(pid, &kev, &mut overflow);
            if overflow {
                return Err(Fail::Unredacted(
                    "argv/env strings too large to relocate".into(),
                ));
            }
            (a, e)
        };
        let Some(argv) = argv else {
            return Err(Fail::Unredacted("real argv unavailable".into()));
        };
        let envp = envp.unwrap_or_default();
        if argv.len() as u64 != kargc {
            return Err(Fail::Unredacted(format!(
                "argc mismatch: saved {} kernel {}",
                argv.len(),
                kargc
            )));
        }
        let argc = argv.len();
        let envc = envp.len().min(kev.len());
        vlog!(
            self,
            "pid {}: exec-done reread={} argc={} envc={}",
            pid,
            reread as u8,
            kargc,
            envc
        );

        // 1. the visible string regions the kernel filled (zeroed later):
        //    exact bounds from /proc/<pid>/stat; inferred from the pointer
        //    arrays when the kernel hides them (non-dumpable tracee).
        let (arg_lo, arg_hi, env_lo, env_hi) = match proc_stat_bounds(pid, sp) {
            Some(b) => b,
            None => {
                vlog!(self, "pid {}: no stat bounds, inferring string spans", pid);
                let (al, ah) = string_span(pid, &kav);
                let (el, eh) = if self.cfg.redact_environ {
                    string_span(pid, &kev)
                } else {
                    (u64::MAX, 0)
                };
                (al, ah, el, eh)
            }
        };

        // 2. build the redaction block with the real strings below SP
        let block = match self.build_redaction_block(pid, &argv, &envp[..envc], pending_stop) {
            Ok(b) => b,
            Err(e) => {
                // Fail closed on the visible strings: empty is better
                // than real.  The program may misbehave; the secret does
                // not leak.
                return Err(Fail::Unredacted(format!("redaction block failed: {}", e)));
            }
        };

        // 3. repoint the inline arrays at the hidden strings
        let mut repoint_ok = true;
        for i in 0..argc {
            if !self.poke(pid, kargv + (i as u64) * 8, block.str_addrs[i]) {
                repoint_ok = false;
                break;
            }
        }
        if repoint_ok {
            for i in 0..envc {
                if !self.poke(pid, kenvp + (i as u64) * 8, block.str_addrs[argc + i]) {
                    repoint_ok = false;
                    break;
                }
            }
        }
        if !repoint_ok {
            // At least one pointer still names the kernel copy.  Zero the
            // whole kernel region: the worst visible result is empties.
            flags.failed = true;
            self.warn(format_args!(
                "pid {}: repoint failed, zeroing the visible argv and environ",
                pid
            ));
            if arg_lo < arg_hi {
                zero_range(pid, arg_lo, arg_hi);
            }
            if env_lo < env_hi {
                zero_range(pid, env_lo, env_hi);
            }
            return Ok(());
        }

        // 4. zero the visible spans; the label goes into argv[0]'s slot
        let label = self.cfg.label.clone();
        if arg_lo < arg_hi {
            zero_range(pid, arg_lo, arg_hi);
            let mut fl = label.len() + 1;
            if arg_lo + fl as u64 > arg_hi {
                fl = (arg_hi - arg_lo) as usize;
            }
            if fl > 0 {
                let mut lbl = vec![0u8; fl];
                lbl[..fl - 1].copy_from_slice(&label[..(fl - 1).min(label.len())]);
                let _ = write_mem(pid, arg_lo, &lbl);
            }
        }
        if self.cfg.redact_environ {
            if self.cfg.keep_env.is_empty() {
                if env_lo < env_hi {
                    zero_range(pid, env_lo, env_hi);
                }
            } else if reread {
                // The kernel copied every variable: blank the ones that
                // are not kept, one string at a time.
                for i in 0..envc {
                    if !self.is_kept_env(Some(&envp[i])) {
                        zero_range(pid, kev[i], kev[i] + envp[i].len() as u64 + 1);
                    }
                }
            }
            // swapped path with kept variables: everything that is not
            // kept was an empty string already.
        }

        // 5. inject the comm label (and the dumpable flag) via a syscall
        //    instruction of the tracee itself
        let auxv_at = kenvp + (kev.len() as u64 + 1) * 8;
        let Some(site) = crate::inject::find_syscall_site(pid, Some(auxv_at), self.fault_no_vdso) else {
            flags.comm_skipped = true;
            self.warn(format_args!(
                "pid {}: no syscall instruction found; comm not set",
                pid
            ));
            return Ok(());
        };
        let save = match Regs::get(pid) {
            Ok(r) => r,
            Err(_) => {
                flags.comm_skipped = true;
                return Ok(());
            }
        };
        let r1 = crate::inject::run_remote_syscall(
            pid,
            &save,
            arch::SYS_PRCTL,
            [libc::PR_SET_NAME as u64, block.comm_addr, 0, 0, 0, 0],
            site,
            pending_stop,
        );
        let mut tracee_gone = false;
        match r1 {
            Ok(0) => {}
            Ok(rv) => {
                flags.comm_skipped = true;
                self.warn(format_args!("pid {}: PR_SET_NAME returned {}", pid, rv));
            }
            Err(e) => {
                flags.comm_skipped = true;
                tracee_gone = self.injection_failed(pid, "comm", &e);
            }
        }
        if !tracee_gone && self.cfg.no_dumpable {
            let r2 = crate::inject::run_remote_syscall(
                pid,
                &save,
                arch::SYS_PRCTL,
                [libc::PR_SET_DUMPABLE as u64, 0, 0, 0, 0, 0],
                site,
                pending_stop,
            );
            match r2 {
                Ok(0) => {}
                Ok(rv) => {
                    flags.failed = true;
                    self.warn(format_args!("pid {}: PR_SET_DUMPABLE returned {}", pid, rv));
                }
                Err(e) => {
                    flags.failed = true;
                    tracee_gone = self.injection_failed(pid, "dumpable", &e);
                }
            }
        }
        if !tracee_gone {
            // final registers: the pristine exec-exit state
            if orig_regs.put(pid).is_err() {
                vlog!(self, "pid {}: regs restore failed", pid);
            }
            vlog!(self, "pid {}: redacted", pid);
        }
        Ok(())
    }

    // ------------------------------------------------------------ helpers --

    /// Resume from the entry stop; the next stop is either
    /// `PTRACE_EVENT_EXEC` (completion runs there) or, on kernels that
    /// skip the exec event for seccomp-resumed entries, the exec's
    /// syscall-exit stop (completion runs there, for the swapped and the
    /// script path alike).  Both leave the tracee in Run.
    fn resume_exec_entry(&mut self, pid: libc::pid_t) {
        self.resume(pid, 0, true);
    }

    /// Common tail of `on_exec_complete`.
    ///
    /// `at_exit_stop`: the completion is running at the exec's
    /// syscall-exit stop (answering that stop) rather than at
    /// `PTRACE_EVENT_EXEC` (whose syscall-exit stop still has to be
    /// consumed).  In both cases the tracee settles straight back to
    /// Run: the exec is done.
    fn finish_exec_complete(&mut self, pid: libc::pid_t, at_exit_stop: bool) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = State::Run;
            t.clear_exec_state();
        }
        if at_exit_stop {
            self.resume(pid, 0, false);
        } else {
            self.resume(pid, 0, true);
        }
    }

    pub(super) fn set_state(&mut self, pid: libc::pid_t, s: State) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = s;
        }
    }

    /// Build and write the redaction block: the real argv/envp strings
    /// and the comm label, in an anonymous mapping inside the tracee.
    /// Returns absolute tracee addresses.
    fn build_redaction_block(
        &mut self,
        pid: libc::pid_t,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        pending_stop: &mut Option<i32>,
    ) -> io::Result<RedactionBlock> {
        let comm = self.cfg.label_comm.clone();

        // pass 1: layout
        let mut need = 0usize;
        let mut aoff = Vec::with_capacity(argv.len());
        for s in argv {
            aoff.push(need);
            need += s.len() + 1;
        }
        let mut eoff = Vec::with_capacity(envp.len());
        for s in envp {
            eoff.push(need);
            need += s.len() + 1;
        }
        let comm_off = need;
        need += comm.len() + 1;
        if need > MAX_HIDDEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "argv/env too large to relocate",
            ));
        }
        let total = (need + 15) & !15usize;

        // pass 2: fill (buffer starts zeroed: NUL terminators in place)
        let mut buf = vec![0u8; total];
        for (i, s) in argv.iter().enumerate() {
            buf[aoff[i]..aoff[i] + s.len()].copy_from_slice(s);
        }
        for (i, s) in envp.iter().enumerate() {
            buf[eoff[i]..eoff[i] + s.len()].copy_from_slice(s);
        }
        buf[comm_off..comm_off + comm.len()].copy_from_slice(&comm);

        // The strings cannot be parked in the tracee stack: the block
        // would sit below `SP - 4096`, and the tracee's own runtime
        // frames grow downward into exactly that region once it resumes,
        // overwriting the middle of the parked argv and truncating the
        // strings the child reads at startup.  An anonymous mapping is
        // created inside the tracee instead.  It costs one mapping in
        // /proc/<pid>/maps and is stable against stack growth.
        let site = crate::inject::find_syscall_site(pid, None, self.fault_no_vdso)
            .ok_or_else(|| io::Error::other("no syscall instruction for mmap"))?;
        let regs = Regs::get(pid)?;
        let addr = crate::inject::run_remote_syscall(
            pid,
            &regs,
            arch::SYS_MMAP,
            [0, total as u64, libc::PROT_READ as u64 | libc::PROT_WRITE as u64,
             (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64, u64::MAX, 0],
            site,
            pending_stop,
        )
        .map_err(|e| io::Error::other(format!("mmap injection failed: {:?}", e)))?;
        if addr <= 0 {
            return Err(io::Error::other(format!(
                "mmap injection returned {}",
                addr
            )));
        }
        let base = addr as u64;
        write_block(pid, base, &buf)?;
        vlog!(self, "pid {}: hidden block in an anonymous mapping at {:#x}", pid, base);
        Ok(RedactionBlock {
            str_addrs: offsets_to_addrs(&aoff, &eoff, base),
            comm_addr: base + comm_off as u64,
        })
    }

    /// Is the ELF image at `path` 32-bit (`EI_CLASS == ELFCLASS32`)?
    fn elf_is_32(&self, pid: libc::pid_t, path: &[u8]) -> bool {
        let os = std::ffi::OsStr::from_bytes(path);
        let mut candidates: Vec<std::path::PathBuf> = Vec::with_capacity(2);
        if path.first() == Some(&b'/') {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
            p.push(std::ffi::OsStr::from_bytes(&path[1..]));
            candidates.push(p);
        } else {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
            p.push(os);
            candidates.push(p);
        }
        candidates.push(std::path::PathBuf::from(os));
        for c in candidates {
            use std::io::Read;
            let mut f = match std::fs::File::open(&c) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut hdr = [0u8; 20];
            if f.read_exact(&mut hdr).is_ok() && hdr[..4] == [0x7f, b'E', b'L', b'F'] {
                return hdr[4] == 1; // EI_CLASS: 1 = ELFCLASS32
            }
        }
        false
    }

    /// Resolve the executable path of the exec in flight, or `None`.
    fn exec_path(&self, pid: libc::pid_t, flavor: ExecFlavor, regs: &Regs) -> Option<Vec<u8>> {
        match flavor {
            ExecFlavor::Execve => read_cstr(pid, regs.arg(1), 4096),
            ExecFlavor::Execveat { dirfd, flags } => {
                let path = read_cstr(pid, regs.arg(2), 4096).unwrap_or_default();
                let dirfd = dirfd as u32 as i32;
                if dirfd == AT_FDCWD || path.starts_with(b"/") {
                    return Some(path);
                }
                if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
                    return Some(format!("/proc/{}/fd/{}", pid, dirfd).into_bytes());
                }
                let dir = format!("/proc/{}/fd/{}", pid, dirfd);
                let link = std::fs::read_link(&dir).ok()?;
                let mut full = link.as_os_str().to_os_string();
                full.push("/");
                full.push(std::ffi::OsStr::from_bytes(&path));
                Some(full.as_os_str().as_encoded_bytes().to_vec())
            }
        }
    }

    /// Is the file at `path` an ELF image?
    ///
    /// The path is relative to the *tracee*, not to the tracer: after a
    /// `chdir()` inside the supervised tree, `execve("./prog")` must be
    /// resolved against `/proc/<pid>/cwd` (and an absolute path against
    /// `/proc/<pid>/root` for a chrooted tracee).  Opening it relative to
    /// the tracer would misclassify the target and silently drop the
    /// zero-exposure path.
    ///
    /// Unreadable paths are treated as non-ELF (conservative: post-exec
    /// redaction).
    fn path_is_elf(&self, pid: libc::pid_t, path: &[u8]) -> bool {
        let os = std::ffi::OsStr::from_bytes(path);
        if path.first() == Some(&b'/') {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
            p.push(std::ffi::OsStr::from_bytes(&path[1..]));
            if p.exists() {
                return is_elf_file(&p);
            }
            // The root link is hidden (non-dumpable tracee): the absolute
            // path as the supervisor sees it.
            return is_elf_file(std::path::Path::new(os));
        }
        let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
        p.push(os);
        // A hidden cwd link (non-dumpable tracee) cannot be resolved:
        // treat the target as unknown, which takes the safe post-exec path.
        is_elf_file(&p)
    }
}

/// Read the 4-byte magic of `path`; true only for an ELF image.
fn is_elf_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => magic == [0x7f, b'E', b'L', b'F'],
        Err(_) => false,
    }
}

/// Exact bounds of the argv and environment string regions of the new
/// image: `(arg_start, arg_end, env_start, env_end)` from
/// `/proc/<pid>/stat` fields 48 to 51.  `None` when the kernel hides
/// them (they read as zero for a non-dumpable tracee) or they do not lie
/// above `sp`.
fn proc_stat_bounds(pid: libc::pid_t, sp: u64) -> Option<(u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is field 3 (state)
    let get = |n: usize| -> Option<u64> { fields.get(n - 3)?.parse().ok() };
    let (a0, a1, e0, e1) = (get(48)?, get(49)?, get(50)?, get(51)?);
    if a0 == 0 || a1 <= a0 || e1 < e0 || a0 < sp {
        return None;
    }
    Some((a0, a1, e0, e1))
}

/// Min/max span covering all strings behind a pointer array (by current
/// tracee content).  `(u64::MAX, 0)` when empty/unreadable.  Fallback for
/// `proc_stat_bounds`.
fn string_span(pid: libc::pid_t, ptrs: &[u64]) -> (u64, u64) {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for &p in ptrs {
        let l = if p != 0 {
            read_cstr(pid, p, MAX_STRLEN).map(|s| s.len()).unwrap_or(0)
        } else {
            0
        };
        if p < lo {
            lo = p;
        }
        if p + l as u64 + 1 > hi {
            hi = p + l as u64 + 1;
        }
    }
    (lo, hi)
}

/// Write `buf` at `base` in page-sized pieces.  The first failing piece
/// reports its offset, so a refused write names where it stopped.
fn write_block(pid: libc::pid_t, base: u64, buf: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = (buf.len() - done).min(4096);
        let wrote = write_mem(pid, base + done as u64, &buf[done..done + n]);
        if wrote != n as isize {
            return Err(io::Error::other(format!(
                "block write failed at offset {} of {} (wrote {}): {}",
                done,
                buf.len(),
                wrote,
                io::Error::last_os_error()
            )));
        }
        done += n;
    }
    Ok(())
}

/// Absolute addresses of the argv and envp strings in a block at `base`.
fn offsets_to_addrs(aoff: &[usize], eoff: &[usize], base: u64) -> Vec<u64> {
    aoff.iter()
        .chain(eoff.iter())
        .map(|off| base + *off as u64)
        .collect()
}

/// Serialize a NUL-terminated u64 pointer array to bytes.  Both supported
/// targets (x86-64, aarch64) are little-endian, so the byte order of the
/// tracee equals little-endian.
fn ptr_words_bytes(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for &w in v {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}
