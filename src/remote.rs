//! Read/write access to a stopped tracee's memory.
//!
//! Primary path is `process_vm_readv`/`process_vm_writev`; if the kernel
//! or sandbox denies those, we fall back to `PTRACE_PEEKDATA` /
//! `PTRACE_POKEDATA`, which always work for an attached tracer.

use std::io;

/// Largest argv array the session relocates.  The kernel bounds the
/// total argument size by the stack limit, so this is not reachable
/// with the default 8 MiB stack.
pub const MAX_ARGV: usize = 1 << 20;
/// Largest envp array the session relocates.
pub const MAX_ENVV: usize = 1 << 20;
/// Kernel `MAX_ARG_STRLEN`: 32 pages of 4 KiB.
pub const MAX_STRLEN: usize = 32 * 4096;
/// Cap on saved argv+env string bytes (per exec).
pub const MAX_STR_TOTAL: usize = 6 << 20;
/// Cap on the redaction block written below the tracee's stack pointer.
pub const MAX_HIDDEN: usize = 8 << 20;
/// Keep one page below SP untouched (redaction block starts below it).
pub const SCRATCH_GUARD: u64 = 4096;

/// Number of `read_mem` calls so far (process-wide).  The tracer logs the
/// delta per completion stop.
pub static READ_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Copy `buf.len()` bytes from the tracee at `addr`.  Returns bytes copied
/// (short copy possible at an unmapped boundary), or -1 on failure.
pub fn read_mem(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> isize {
    READ_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// Read a NUL-terminated string of at most `max` bytes (without the NUL).
/// Returns `None` when the first byte is unreadable.  The flag is `true`
/// when a NUL was found within the cap, `false` when the string is
/// longer (the returned bytes are then the first `max` bytes).
///
/// The read window starts at 256 bytes and doubles up to 16 KiB, so a
/// string of 4 KiB needs about five reads.
pub fn read_cstr_checked(pid: libc::pid_t, addr: u64, max: usize) -> Option<(Vec<u8>, bool)> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    let mut window = 256usize;
    let mut buf = vec![0u8; 16 * 1024];
    while out.len() <= max {
        let want = window.min(buf.len());
        let k = read_mem(pid, addr + out.len() as u64, &mut buf[..want]);
        if k <= 0 {
            if out.is_empty() {
                return None;
            }
            // Unmapped boundary before a NUL: report as unterminated.
            return Some((out, false));
        }
        let got = k as usize;
        if let Some(pos) = buf[..got].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..pos]);
            if out.len() > max {
                out.truncate(max);
                return Some((out, false));
            }
            return Some((out, true));
        }
        out.extend_from_slice(&buf[..got]);
        if window < buf.len() {
            window *= 2;
        }
    }
    out.truncate(max);
    Some((out, false))
}

/// Read a NUL-terminated string; `None` when unreadable.  The result is
/// cut at `max` bytes.
pub fn read_cstr(pid: libc::pid_t, addr: u64, max: usize) -> Option<Vec<u8>> {
    read_cstr_checked(pid, addr, max).map(|(v, _)| v)
}

/// Read a NUL-terminated pointer array (kernel inline argv[]/envp[] style).
/// The flag is `true` when the terminating NULL was found within `maxn`
/// entries.  Reads in chunks of 512 words.
pub fn read_ptr_array(pid: libc::pid_t, addr: u64, maxn: usize) -> Option<(Vec<u64>, bool)> {
    let mut out: Vec<u64> = Vec::with_capacity(64);
    let mut chunk = [0u8; 4096];
    while out.len() < maxn {
        let at = addr + (out.len() as u64) * 8;
        let words = ((maxn - out.len()).min(512)) * 8;
        let mut k = read_mem(pid, at, &mut chunk[..words]);
        if k < 8 {
            // Near an unmapped boundary: retry one word.
            k = read_mem(pid, at, &mut chunk[..8]);
            if k != 8 {
                if out.is_empty() {
                    return None;
                }
                return None;
            }
        }
        let n = (k as usize) / 8;
        for i in 0..n {
            let mut b = [0u8; 8];
            b.copy_from_slice(&chunk[i * 8..i * 8 + 8]);
            let w = u64::from_ne_bytes(b);
            if w == 0 {
                return Some((out, true));
            }
            out.push(w);
            if out.len() >= maxn {
                break;
            }
        }
    }
    Some((out, false))
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
/// Sets `overflow` when the total-size cap is hit or a string is longer
/// than `MAX_STRLEN`: the copy is then incomplete and the caller must not
/// forward it.
pub fn dup_strings(
    pid: libc::pid_t,
    ptrs: &[u64],
    overflow: &mut bool,
) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(ptrs.len());
    let mut total = 0usize;
    for &p in ptrs {
        let s = match read_cstr_checked(pid, p, MAX_STRLEN) {
            Some((s, complete)) => {
                if !complete {
                    *overflow = true;
                }
                s
            }
            None => Vec::new(), // unreadable -> empty
        };
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
