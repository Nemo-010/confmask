//! Remote system call injection into a stopped tracee.
//!
//! `prctl(PR_SET_NAME)` is executed *by the tracee* by pointing its
//! instruction pointer at a `syscall`/`svc #0` instruction inside its
//! own vDSO and stepping over it with `PTRACE_SYSCALL`.  No
//! writable+executable memory is created anywhere.

use crate::arch::{self, Regs, SyscallInfo};
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

#[cfg(target_arch = "x86")]
const PAT: [u8; 2] = [0xcd, 0x80]; // int 0x80
#[cfg(target_arch = "x86_64")]
const PAT: [u8; 2] = [0x0f, 0x05]; // syscall
#[cfg(target_arch = "aarch64")]
const PAT: [u8; 4] = [0x01, 0x00, 0x00, 0xd4]; // svc #0
/// Is `addr` a possible instruction boundary?  x86 instructions are not
/// aligned; aarch64 instructions are 4-byte aligned.
#[cfg(target_arch = "x86_64")]
fn aligned(_addr: u64) -> bool {
    true
}
#[cfg(target_arch = "aarch64")]
fn aligned(addr: u64) -> bool {
    addr % 4 == 0
}
#[cfg(target_arch = "x86")]
fn aligned(_addr: u64) -> bool {
    true
}

/// Cap on the bytes scanned per mapping.
const SCAN_CAP: u64 = 256 * 1024;
/// Cap on the number of mappings scanned by the fallback.
const SCAN_MAPS: usize = 16;

/// Find a `syscall` / `svc #0` instruction in `[base, base + len)` of the
/// tracee.  Chunks overlap by `PAT.len() - 1` bytes so a pattern that
/// straddles a chunk boundary is found.
fn scan_region(pid: libc::pid_t, base: u64, len: u64) -> Option<u64> {
    let mut buf = vec![0u8; 4096];
    let mut scanned = 0u64;
    let mut carry = 0usize; // bytes kept from the previous chunk
    while scanned < len.min(SCAN_CAP) {
        let want = ((len.min(SCAN_CAP) - scanned) as usize).min(buf.len() - carry);
        if want == 0 {
            break;
        }
        let k = crate::remote::read_mem(pid, base + scanned, &mut buf[carry..carry + want]);
        if k <= 0 {
            break;
        }
        let n = carry + k as usize;
        if n >= PAT.len() {
            for i in 0..=(n - PAT.len()) {
                let addr = base + scanned - carry as u64 + i as u64;
                if aligned(addr) && buf[i..i + PAT.len()] == PAT {
                    return Some(addr);
                }
            }
        }
        scanned += k as u64;
        carry = (PAT.len() - 1).min(n);
        let tail: Vec<u8> = buf[n - carry..n].to_vec();
        buf[..carry].copy_from_slice(&tail);
    }
    None
}

/// vDSO base from `/proc/<pid>/auxv` (`AT_SYSINFO_EHDR`).
fn vdso_base_from_auxv(pid: libc::pid_t) -> Option<u64> {
    let data = std::fs::read(format!("/proc/{}/auxv", pid)).ok()?;
    for pair in data.chunks_exact(16) {
        let mut k = [0u8; 8];
        let mut v = [0u8; 8];
        k.copy_from_slice(&pair[..8]);
        v.copy_from_slice(&pair[8..]);
        let k = u64::from_ne_bytes(k);
        let v = u64::from_ne_bytes(v);
        if k == 0 {
            break;
        }
        if k == 33 {
            return Some(v); // AT_SYSINFO_EHDR
        }
    }
    None
}

/// Find the address of a `syscall` (x86-64) / `svc #0` (aarch64)
/// instruction in the tracee.  `skip_vdso` is a test hook that forces
/// step 2.
///
/// 1. the vDSO named by `AT_SYSINFO_EHDR` (from `/proc/<pid>/auxv`, or
///    from the stack auxv at `auxv_addr` when the file is unreadable),
/// 2. fallback: the first executable file mapping of the new image
///    (`/proc/<pid>/maps`), which holds the program or its interpreter.
pub fn find_syscall_site(pid: libc::pid_t, auxv_addr: Option<u64>, skip_vdso: bool) -> Option<u64> {
    let mut vdso = if skip_vdso { 0 } else { vdso_base_from_auxv(pid).unwrap_or(0) };
    if vdso == 0 && !skip_vdso {
        if let Some(auxv_addr) = auxv_addr {
            for i in 0..64 {
                let k = crate::remote::peek_word(pid, auxv_addr + (i as u64) * 16)?;
                let v = crate::remote::peek_word(pid, auxv_addr + (i as u64) * 16 + 8)?;
                if k == 0 {
                    break;
                }
                if k == 33 {
                    vdso = v;
                    break;
                }
            }
        }
    }
    if vdso != 0 {
        if let Some(a) = scan_region(pid, vdso, 64 * 1024) {
            return Some(a);
        }
    }
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;
    let mut tried = 0usize;
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = it.next()?;
        let perms = it.next()?;
        if !perms.starts_with("r-x") {
            continue;
        }
        if line.contains("[vsyscall]") {
            continue;
        }
        let (lo, hi) = range.split_once('-')?;
        let lo = u64::from_str_radix(lo, 16).ok()?;
        let hi = u64::from_str_radix(hi, 16).ok()?;
        if let Some(a) = scan_region(pid, lo, hi - lo) {
            return Some(a);
        }
        tried += 1;
        if tried >= SCAN_MAPS {
            break;
        }
    }
    None
}

/// Run one system call in the tracee.  `orig` must be the pristine
/// registers captured at the current stop.  Returns the system call's
/// return value.
///
/// The first syscall-entry stop must carry `nr`; any other number means
/// the instruction at `site` is not what the scan assumed, and the call
/// fails with the original registers restored.
///
/// A group-stop that arrives inside the window is restarted (the tracee
/// must finish the injection); its signal is stored in `pending_stop` so
/// the caller can raise it again afterwards.
pub fn run_remote_syscall(
    pid: libc::pid_t,
    orig: &Regs,
    nr: u64,
    args: [u64; 6],
    site: u64,
    pending_stop: &mut Option<i32>,
) -> Result<i64, InjectError> {
    let mut r = *orig;
    r.set_syscall(nr, args);
    r.set_ip(site);
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
        let event = (status as u32) >> 16;
        if sig == libc::SIGTRAP | 0x80 {
            let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
            let ok = get_syscall_info(pid, &mut si).is_ok();
            if ok {
                match si.op {
                    arch::syscall_info_op::ENTRY if !want_exit => {
                        if si.entry_nr() != Some(nr) {
                            let _ = orig.put(pid);
                            return Err(InjectError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "injected syscall number mismatch",
                            )));
                        }
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
        if event == arch::PTRACE_EVENT_STOP {
            if sig != libc::SIGTRAP {
                *pending_stop = Some(sig);
            }
            ptrace_syscall(pid, 0)?;
            continue;
        }
        if event != 0 {
            // other ptrace event (for example a seccomp stop for our own
            // prctl): restart without a signal.
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
