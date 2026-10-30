//! Remote system call injection into a stopped tracee.
//!
//! `prctl(PR_SET_NAME)` is executed *by the tracee* by pointing its
//! instruction pointer at a `syscall`/`svc #0` instruction inside its own
//! vDSO and stepping over it with `PTRACE_SYSCALL`.
//! No writable+executable memory is created anywhere.

use crate::redact::arch::{self, Regs, SyscallInfo};
use std::io;

/// Where injection stopped being possible.
#[derive(Debug)]
pub enum InjectError {
    /// tracee died mid-injection
    TraceeDied,
    /// a required ptrace call failed
    Io(io::Error),
}

impl From<io::Error> for InjectError {
    fn from(e: io::Error) -> Self {
        InjectError::Io(e)
    }
}

/// Find the address of a `syscall` (x86-64) / `svc #0` (aarch64)
/// instruction inside the tracee's vDSO by walking its auxv
/// (`AT_SYSINFO_EHDR` at `auxv_addr`) and scanning the mapping.
pub fn find_vdso_syscall(pid: libc::pid_t, auxv_addr: u64) -> Option<u64> {
    let mut vdso = 0u64;
    for i in 0..64 {
        let k = crate::redact::remote::peek_word(pid, auxv_addr + (i as u64) * 16)?;
        let v = crate::redact::remote::peek_word(pid, auxv_addr + (i as u64) * 16 + 8)?;
        if k == 0 {
            break; // AT_NULL
        }
        if k == 33 {
            // AT_SYSINFO_EHDR
            vdso = v;
            break;
        }
    }
    if vdso == 0 {
        return None;
    }

    #[cfg(target_arch = "x86_64")]
    const PAT: [u8; 2] = [0x0f, 0x05]; // syscall
    #[cfg(target_arch = "aarch64")]
    const PAT: [u8; 4] = [0x01, 0x00, 0x00, 0xd4]; // svc #0

    let mut scanned = 0u64;
    let mut buf = [0u8; 4096];
    while scanned < 8192 {
        let k = crate::redact::remote::read_mem(pid, vdso + scanned, &mut buf);
        if k <= 0 {
            break;
        }
        let n = k as usize;
        if n >= PAT.len() {
            for i in 0..=(n - PAT.len()) {
                if buf[i..i + PAT.len()] == PAT {
                    return Some(vdso + scanned + i as u64);
                }
            }
        }
        scanned += n as u64;
        if n < buf.len() {
            break;
        }
    }
    None
}

/// Run one system call in the tracee.  `orig` must be the pristine
/// registers captured at the current stop.  Returns the system call's
/// return value.
pub fn run_remote_syscall(
    pid: libc::pid_t,
    orig: &Regs,
    nr: u64,
    args: [u64; 6],
    vdso_sc: u64,
) -> Result<i64, InjectError> {
    let mut r = *orig;
    r.set_syscall(nr, args);
    r.set_ip(vdso_sc);
    r.put(pid)?;
    ptrace_syscall(pid, 0)?;

    let mut want_exit = false;
    loop {
        let (pid_w, status) = wait_stop(pid)?;
        debug_assert_eq!(pid_w, pid);
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(InjectError::TraceeDied);
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        if sig == libc::SIGTRAP | 0x80 {
            let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
            let ok = get_syscall_info(pid, &mut si).is_ok();
            if ok {
                match si.op {
                    arch::syscall_info_op::ENTRY if !want_exit => {
                        ptrace_syscall(pid, 0)?;
                        want_exit = true;
                        continue;
                    }
                    arch::syscall_info_op::EXIT if want_exit => {
                        let t = Regs::get(pid)?;
                        return Ok(t.retval());
                    }
                    _ => {}
                }
            }
            // Unexpected syscall stop (e.g. the pending exec exit that
            // clobbers the return register): re-apply our registers and
            // keep going.
            r.put(pid)?;
            ptrace_syscall(pid, 0)?;
            continue;
        }
        // Forward real signals that arrived mid-injection.
        let deliver = if sig != 0 && sig != libc::SIGTRAP { sig } else { 0 };
        ptrace_syscall(pid, deliver)?;
    }
}

pub fn get_syscall_info(pid: libc::pid_t, si: &mut SyscallInfo) -> io::Result<()> {
    // SAFETY: si is valid for writing; size is passed via the addr slot
    // as the kernel API requires.
    let rc = unsafe {
        libc::ptrace(
            arch::PTRACE_GET_SYSCALL_INFO as _,
            pid,
            std::mem::size_of::<SyscallInfo>(),
            si as *mut SyscallInfo as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resume-until-stop is driven by the caller; this fetches the next stop
/// of `pid` (waitpid with __WALL, EINTR-safe) and returns its status.
pub fn wait_stop(pid: libc::pid_t) -> io::Result<(libc::pid_t, i32)> {
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
        return Ok((w, status));
    }
}

pub fn ptrace_syscall(pid: libc::pid_t, sig: libc::c_int) -> io::Result<()> {
    // SAFETY: pid is an attached, stopped tracee.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Detach a tracee, letting it run unsupervised from now on.
pub fn ptrace_detach(pid: libc::pid_t, sig: libc::c_int) -> io::Result<()> {
    // SAFETY: pid is an attached, stopped tracee.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn ptrace_cont(pid: libc::pid_t, sig: libc::c_int) -> io::Result<()> {
    // SAFETY: pid is an attached, stopped tracee.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            sig as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
