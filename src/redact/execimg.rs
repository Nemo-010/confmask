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
//! `prctl(PR_SET_NAME)` is injected through the tracee's vDSO in the same
//! stop, so `/proc/<pid>/comm` — the *Name* column of `top`/`htop` — shows
//! the label too.
//!
//! Scripts (`#!` files) are the exception: the kernel needs the real argv
//! to build the interpreter command line, so for those the copied strings
//! are zeroed and replaced by hidden copies after completion
//! (sub-millisecond exposure for the interpreter line only).

use crate::redact::arch::{self, Regs};
use crate::redact::remote::{
    dup_strings, peek_word, poke_word, read_cstr, read_ptr_array, write_mem, zero_range, MAX_ARGV,
    MAX_ENVV, MAX_HIDDEN, SCRATCH_GUARD,
};
use crate::redact::tracer::{State, Tracer};
use std::io;
use std::os::unix::ffi::OsStrExt;

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

        let elf = self
            .exec_path(pid, flavor, regs)
            .map(|p| self.path_is_elf(&p))
            .unwrap_or(false);

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
        let mut scratch = [0u8; 256];
        let fl = (label.len() + 1).min(scratch.len());
        scratch[..fl - 1].copy_from_slice(&label[..fl - 1]);
        let base = sp - 4096;
        let fake_str = base;
        let empty_str = base + fl as u64;
        if write_mem(pid, base, &scratch) < 0 {
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
        if write_mem(pid, av, &ptr_words_bytes(&nv)) < 0 {
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // same treatment for the environment
        if self.cfg.redact_environ && evarr.is_some() {
            let mut ne = vec![empty_str; evn + 1];
            ne[evn] = 0;
            if write_mem(pid, ev, &ptr_words_bytes(&ne)) >= 0 {
                if let Some(t) = self.table.get_mut(&pid) {
                    t.env_swapped = true;
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

    /// exec completed (`PTRACE_EVENT_EXEC`): re-inject the real arguments
    /// below SP, zero the visible copies, inject the comm label.
    pub(super) fn on_exec_complete(&mut self, pid: libc::pid_t, at_exit_stop: bool) {
        let Ok(orig_regs) = Regs::get(pid) else { return };
        let sp = orig_regs.sp();

        let reread = match self.table.get(&pid) {
            Some(t) => t.state != State::Swapped,
            None => return,
        };

        let Some(kargc) = peek_word(pid, sp).filter(|v| *v <= MAX_ARGV as u64) else {
            vlog!(self, "pid {}: bad argc", pid);
            self.finish_exec_complete(pid, at_exit_stop);
            return;
        };
        let kargv = sp + 8;
        let kenvp = kargv + (kargc + 1) * 8;
        let kav = read_ptr_array(pid, kargv, MAX_ARGV + 1);
        let kev = read_ptr_array(pid, kenvp, MAX_ENVV + 1);

        // Real argv/envp strings: from the saved copy (swapped path) or
        // re-read from the kernel-copied stack (script / missed entry).
        let mut argv: Option<Vec<Vec<u8>>> = None;
        let mut envp: Option<Vec<Vec<u8>>> = None;
        if !reread {
            if let Some(t) = self.table.get_mut(&pid) {
                argv = t.argv.take();
                envp = t.envp.take();
            }
        } else {
            let mut ov = false;
            if let Some(kav) = &kav {
                let n = (kav.len() as u64).min(kargc) as usize;
                argv = dup_strings(pid, &kav[..n], &mut ov);
            }
            if let Some(kev) = &kev {
                envp = dup_strings(pid, kev, &mut ov);
            }
            if argv.is_none() {
                vlog!(self, "pid {}: reread failed", pid);
                self.finish_exec_complete(pid, at_exit_stop);
                return;
            }
        }

        let argc = argv.as_ref().map(|v| v.len()).unwrap_or(0);
        let envc = envp.as_ref().map(|v| v.len()).unwrap_or(0);
        vlog!(
            self,
            "pid {}: exec-done reread={} argc={} envc={}",
            pid,
            reread as u8,
            kargc,
            envc
        );

        // 1. locate the visible argv/env string spans (zeroed later)
        let (arg_lo, arg_hi) = string_span(pid, kav.as_deref());
        let (env_lo, env_hi) = string_span(pid, kev.as_deref());

        // 2. build the redaction block with the real strings below SP
        let empty: Vec<Vec<u8>> = Vec::new();
        let block = match self.build_redaction_block(
            pid,
            sp,
            argv.as_ref().unwrap_or(&empty),
            envp.as_ref().unwrap_or(&empty),
        ) {
            Ok(b) => b,
            Err(e) => {
                vlog!(self, "pid {}: redaction block failed: {}", pid, e);
                self.finish_exec_complete(pid, at_exit_stop);
                return;
            }
        };

        // 3. repoint the inline arrays at the hidden strings
        for i in 0..argc {
            poke_word(pid, kargv + (i as u64) * 8, block.str_addrs[i]);
        }
        for i in 0..envc {
            poke_word(pid, kenvp + (i as u64) * 8, block.str_addrs[argc + i]);
        }

        // 4. zero the visible spans; label goes into argv[0]'s old slot
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
        if self.cfg.redact_environ && env_lo < env_hi {
            zero_range(pid, env_lo, env_hi);
        }

        // 5. inject the comm label via the vDSO
        let evn = kev.as_ref().map(|v| v.len()).unwrap_or(0);
        let auxv_at = kenvp + (evn as u64 + 1) * 8;
        match crate::redact::inject::find_vdso_syscall(pid, auxv_at) {
            None => {
                vlog!(self, "pid {}: no vDSO syscall site; skipping comm+filter", pid);
            }
            Some(vdso_sc) => {
                let Ok(save) = Regs::get(pid) else {
                    self.finish_exec_complete(pid, at_exit_stop);
                    return;
                };
                let comm = block.comm_addr;
                let r1 = crate::redact::inject::run_remote_syscall(
                    pid,
                    &save,
                    arch::SYS_PRCTL,
                    [libc::PR_SET_NAME as u64, comm, 0, 0, 0, 0],
                    vdso_sc,
                );
                if let Err(e) = r1 {
                    if self.injection_failed(pid, "comm", &e) {
                        self.finish_exec_complete(pid, at_exit_stop);
                        return;
                    }
                }
                // final registers: the pristine exec-exit state
                if orig_regs.put(pid).is_err() {
                    vlog!(self, "pid {}: regs restore failed", pid);
                }
                vlog!(self, "pid {}: redacted", pid);
            }
        }

        self.finish_exec_complete(pid, at_exit_stop);
    }

    // ------------------------------------------------------------ helpers --

    /// Resume from the entry stop; the next stop is either
    /// `PTRACE_EVENT_EXEC` (completion runs there) or, on kernels that
    /// skip the exec event for seccomp-resumed entries, the exec's
    /// syscall-exit stop (completion runs there — see the `Swapped`
    /// branch of the exit handling).  Both leave the tracee in Run.
    fn resume_exec_entry(&mut self, pid: libc::pid_t) {
        let _ = crate::redact::inject::ptrace_syscall(pid, 0);
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
        }
        if at_exit_stop {
            let _ = crate::redact::inject::ptrace_cont(pid, 0);
        } else {
            let _ = crate::redact::inject::ptrace_syscall(pid, 0);
        }
    }

    fn set_state(&mut self, pid: libc::pid_t, s: State) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = s;
        }
    }

    /// Build and write the redaction block just below SP: the real
    /// argv/envp strings, the comm label, the seccomp filter and its
    /// `sock_fprog` header.  Returns absolute tracee addresses.
    fn build_redaction_block(
        &self,
        pid: libc::pid_t,
        sp: u64,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> io::Result<RedactionBlock> {
        let comm = &self.cfg.label_comm;

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

        let base = (sp - SCRATCH_GUARD - total as u64) & !15u64;
        if base == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad stack base"));
        }

        // pass 2: fill (buffer starts zeroed: NUL terminators in place)
        let mut buf = vec![0u8; total];
        for (i, s) in argv.iter().enumerate() {
            buf[aoff[i]..aoff[i] + s.len()].copy_from_slice(s);
        }
        for (i, s) in envp.iter().enumerate() {
            buf[eoff[i]..eoff[i] + s.len()].copy_from_slice(s);
        }
        buf[comm_off..comm_off + comm.len()].copy_from_slice(comm);

        if write_mem(pid, base, &buf) != total as isize {
            return Err(io::Error::last_os_error());
        }

        let mut str_addrs = Vec::with_capacity(argv.len() + envp.len());
        for off in aoff.iter().chain(eoff.iter()) {
            str_addrs.push(base + *off as u64);
        }
        Ok(RedactionBlock {
            str_addrs,
            comm_addr: base + comm_off as u64,
        })
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

    /// Is the file at `path` an ELF image?  Unreadable paths are treated
    /// as non-ELF (conservative: post-exec redaction).
    fn path_is_elf(&self, path: &[u8]) -> bool {
        let os = std::ffi::OsStr::from_bytes(path);
        use std::io::Read;
        let mut f = match std::fs::File::open(os) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut magic = [0u8; 4];
        match f.read_exact(&mut magic) {
            Ok(()) => magic == [0x7f, b'E', b'L', b'F'],
            Err(_) => false,
        }
    }
}

/// Min/max span covering all strings behind a pointer array (by current
/// tracee content).  `(u64::MAX, 0)` when empty/unreadable.
fn string_span(pid: libc::pid_t, ptrs: Option<&[u64]>) -> (u64, u64) {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    let Some(ptrs) = ptrs else { return (lo, hi) };
    for &p in ptrs {
        let l = if p != 0 {
            read_cstr(pid, p, 4096).map(|s| s.len()).unwrap_or(0)
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

/// Serialize a NUL-terminated u64 pointer array to little-endian bytes.
fn ptr_words_bytes(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for &w in v {
        out.extend_from_slice(&w.to_ne_bytes());
    }
    out
}
