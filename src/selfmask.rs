//! Redact this process's own published metadata.
//!
//! The tracer process lives as long as the supervised tree, so it
//! applies the same treatment to itself: its argv strings (and by
//! default its environment strings) are zeroed in place, the label is
//! written into the zeroed argv block, and its `comm` is set to the
//! session label.
//!
//! The caller snapshots the child's argv and environment first, then
//! calls this module, then forks.  The child's exec therefore still
//! sees the real values.

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

/// Write `label` at `arg_start`, clipped to the argv region and padded
/// with NUL bytes.  The last byte of the region stays NUL, so the kernel
/// serves exactly the label and does not run on into the environment.
///
/// # Safety
/// Same as `zero_own_argv`: the argv region must be zeroed or otherwise
/// unused.
unsafe fn write_own_label(label: &[u8]) -> io::Result<()> {
    let (arg_start, arg_end, _, _) = self_arg_env_range()?;
    if arg_start >= arg_end {
        return Ok(());
    }
    let room = (arg_end - arg_start) as usize;
    let n = label.len().min(room.saturating_sub(1));
    if n > 0 {
        std::ptr::copy_nonoverlapping(label.as_ptr(), arg_start as *mut u8, n);
    }
    Ok(())
}

/// Apply the full self-treatment with an explicit command-line label:
/// zero argv, write `label` into the zeroed block (NUL padded), zero the
/// environment strings when `redact_environ` is set, and set `comm`.
///
/// Every step runs even when an earlier step failed.  The first error is
/// returned.
pub fn mask_self_label(label: &[u8], label_comm: &[u8], redact_environ: bool) -> io::Result<()> {
    let mut first_error: Option<io::Error> = None;
    let mut note = |r: io::Result<()>| {
        if let Err(e) = r {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    };
    // SAFETY: the callers snapshot everything they need from argv and
    // environ before this call (see the module docs).
    unsafe {
        note(zero_own_argv());
        note(write_own_label(label));
        if redact_environ {
            note(zero_own_environ());
        }
    }
    let mut buf = [0u8; 16];
    let n = label_comm.len().min(15);
    buf[..n].copy_from_slice(&label_comm[..n]);
    // SAFETY: buf is NUL terminated and lives for the call.
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr(), 0, 0, 0) };
    if rc == -1 {
        note(Err(io::Error::last_os_error()));
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Apply the full self-treatment with `label_comm` as both the
/// command-line label and the `comm` name.
pub fn mask_self(label_comm: &[u8], redact_environ: bool) -> io::Result<()> {
    mask_self_label(label_comm, label_comm, redact_environ)
}
