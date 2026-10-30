//! Read/write access to a stopped tracee's memory.
//!
//! Primary path is `process_vm_readv`/`process_vm_writev`; if the kernel
//! or sandbox denies those, we fall back to `PTRACE_PEEKDATA` /
//! `PTRACE_POKEDATA`, which always work for an attached tracer.

use std::io;

pub const MAX_ARGV: usize = 8192;
pub const MAX_ENVV: usize = 65536;
/// Cap on saved argv+env string bytes (per exec).
pub const MAX_STR_TOTAL: usize = 6 << 20;
/// Cap on the redaction block written below the tracee's stack pointer.
pub const MAX_HIDDEN: usize = 8 << 20;
/// Keep one page below SP untouched (redaction block starts below it).
pub const SCRATCH_GUARD: u64 = 4096;

/// Copy `buf.len()` bytes from the tracee at `addr`.  Returns bytes copied
/// (short copy possible at an unmapped boundary), or -1 on failure.
pub fn read_mem(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> isize {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let k = unsafe {
        libc::process_vm_readv(pid, &local, 1, &remote, 1, 0)
    };
    if k >= 0 {
        return k;
    }
    let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if matches!(e, libc::ENOSYS | libc::EPERM | libc::EINVAL) {
        return peek_fallback(pid, addr, buf);
    }
    -1
}

fn peek_fallback(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> isize {
    let word = std::mem::size_of::<libc::c_long>();
    let mut done = 0usize;
    while done < buf.len() {
        // SAFETY: tracee is stopped and attached; read-only word peek.
        let w = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, (addr + done as u64) as *mut libc::c_void, std::ptr::null_mut::<libc::c_void>()) };
        if w == -1 && io::Error::last_os_error().raw_os_error() != Some(0) {
            break;
        }
        let bytes = w.to_ne_bytes();
        let c = (buf.len() - done).min(word);
        buf[done..done + c].copy_from_slice(&bytes[..c]);
        done += word;
    }
    if done == 0 {
        -1
    } else {
        done as isize
    }
}

/// Write `data` to the tracee at `addr`.  Returns bytes written or -1.
pub fn write_mem(pid: libc::pid_t, addr: u64, data: &[u8]) -> isize {
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    let k = unsafe {
        libc::process_vm_writev(pid, &local, 1, &remote, 1, 0)
    };
    if k >= 0 {
        return k;
    }
    let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if matches!(e, libc::ENOSYS | libc::EPERM | libc::EINVAL) {
        return poke_fallback(pid, addr, data);
    }
    -1
}

fn poke_fallback(pid: libc::pid_t, addr: u64, data: &[u8]) -> isize {
    let word = std::mem::size_of::<libc::c_long>();
    let mut done = 0usize;
    while done < data.len() {
        let c = (data.len() - done).min(word);
        let mut bytes = [0u8; std::mem::size_of::<libc::c_long>()];
        bytes[..c].copy_from_slice(&data[done..done + c]);
        let w = libc::c_long::from_ne_bytes(bytes);
        // SAFETY: tracee is stopped and attached; single-word write.
        let rc = unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid, (addr + done as u64) as *mut libc::c_void, w as *mut libc::c_void) };
        if rc == -1 {
            break;
        }
        done += word;
    }
    if done == 0 {
        -1
    } else {
        done as isize
    }
}

/// Read a NUL-terminated string; `None` when unreadable.  Length-capped
/// at `max` bytes (the returned string is truncated there, never an error).
pub fn read_cstr(pid: libc::pid_t, addr: u64, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    while out.len() < max {
        let k = read_mem(pid, addr + out.len() as u64, &mut buf);
        if k <= 0 {
            return None;
        }
        if let Some(pos) = buf[..k as usize].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..pos]);
            return Some(out);
        }
        out.extend_from_slice(&buf[..k as usize]);
    }
    out.truncate(max.saturating_sub(1));
    Some(out)
}

/// Read a NUL-terminated pointer array (kernel inline argv[]/envp[] style).
pub fn read_ptr_array(pid: libc::pid_t, addr: u64, maxn: usize) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(64);
    while out.len() < maxn {
        let word = read_word(pid, addr + (out.len() as u64) * 8)?;
        if word == 0 {
            return Some(out);
        }
        out.push(word);
    }
    Some(out)
}

fn read_word(pid: libc::pid_t, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    if read_mem(pid, addr, &mut b) != 8 {
        return None;
    }
    Some(u64::from_ne_bytes(b))
}

pub fn peek_word(pid: libc::pid_t, addr: u64) -> Option<u64> {
    read_word(pid, addr)
}

pub fn poke_word(pid: libc::pid_t, addr: u64, val: u64) -> bool {
    read_write_word(pid, addr, val)
}

fn read_write_word(pid: libc::pid_t, addr: u64, val: u64) -> bool {
    write_mem(pid, addr, &val.to_ne_bytes()) == 8
}

/// Copy the strings behind a pointer array into local memory.
/// Sets `overflow` when the total-size cap is hit mid-way.
pub fn dup_strings(
    pid: libc::pid_t,
    ptrs: &[u64],
    overflow: &mut bool,
) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(ptrs.len());
    let mut total = 0usize;
    for &p in ptrs {
        let s = read_cstr(pid, p, 4096).unwrap_or_default(); // unreadable -> empty
        total += s.len() + 1;
        if total > MAX_STR_TOTAL {
            *overflow = true;
            break;
        }
        out.push(s);
    }
    Some(out)
}

/// Zero every byte in `[lo, hi)` inside the tracee.  Best effort.
pub fn zero_range(pid: libc::pid_t, lo: u64, hi: u64) {
    let zeros = [0u8; 4096];
    let mut a = lo;
    while a < hi {
        let n = ((hi - a) as usize).min(zeros.len());
        if write_mem(pid, a, &zeros[..n]) < 0 {
            return;
        }
        a += n as u64;
    }
}
