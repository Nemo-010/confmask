//! Redact this process's own published metadata.
//!
//! The tracer process lives as long as the supervised tree, so it
//! applies the same treatment to itself: its argv strings (and by
//! default its environment strings) are zeroed in place and its `comm`
//! is set to the session label.  This happens *after* the supervised
//! child has been forked, so the child's own exec still sees the real
//! values.

use std::io;

/// Locate `[arg_start, arg_end, env_start, env_end]` of this process via
/// `/proc/self/stat` (fields 48-51; comm may contain spaces/parens, so
/// parse after the last ')').
fn self_arg_env_range() -> io::Result<(u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let after_comm = match stat.rfind(')') {
        Some(i) => &stat[i + 1..],
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad stat")),
    };
    // remainder[0] is field 3 (state)
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let get = |field: usize| -> io::Result<u64> {
        fields
            .get(field - 3)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short stat"))
    };
    Ok((get(48)?, get(49)?, get(50)?, get(51)?))
}

/// Zero the argv string block of this process (the memory
/// `/proc/self/cmdline` is served from).
///
/// # Safety
/// Writes zeros over the process's initial argv string area.  Nothing in
/// the process may rely on `argv` contents afterwards (Rust's `std`
/// copies argv at startup and never re-reads the original block).
pub unsafe fn zero_own_argv() -> io::Result<()> {
    let (arg_start, arg_end, _, _) = self_arg_env_range()?;
    if arg_start < arg_end {
        std::ptr::write_bytes(arg_start as *mut u8, 0, (arg_end - arg_start) as usize);
    }
    Ok(())
}

/// Zero the environment string block of this process (the memory
/// `/proc/self/environ` is served from).
///
/// # Safety
/// See `zero_own_argv`; additionally `std::env::var*` will observe empty
/// values afterwards.
pub unsafe fn zero_own_environ() -> io::Result<()> {
    let (_, _, env_start, env_end) = self_arg_env_range()?;
    if env_start < env_end {
        std::ptr::write_bytes(env_start as *mut u8, 0, (env_end - env_start) as usize);
    }
    Ok(())
}

/// Convenience for callers that already have a `Mask`-style
/// `label_comm` (<= 15 bytes): apply the full self-treatment.
pub fn mask_self(label_comm: &[u8], redact_environ: bool) {
    unsafe {
        let _ = zero_own_argv();
        if redact_environ {
            let _ = zero_own_environ();
        }
    }
    let mut buf = [0u8; 16];
    let n = label_comm.len().min(15);
    buf[..n].copy_from_slice(&label_comm[..n]);
    unsafe {
        libc::prctl(libc::PR_SET_NAME, buf.as_ptr(), 0, 0, 0);
    }
}
