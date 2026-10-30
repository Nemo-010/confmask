//! Memory hygiene for secret material.
//!
//! Three things a secret in a normal `Vec<u8>` does not survive on a shared
//! host, all fixed here:
//!
//! * it is written to swap, where it outlives the process;
//! * it lands in a core dump (or in `/proc/<pid>/mem` of anything that can
//!   read the process's memory);
//! * it is readable through the kernel's direct map if the kernel is
//!   compromised, which `memfd_secret` removes by unmapping the pages from
//!   the direct map entirely.
//!
//! [`SecBuf`] is a byte buffer that is `mlock`ed (no swap), marked
//! `MADV_DONTDUMP` (no core), zeroised on drop, and backed by
//! `memfd_secret` when the kernel offers it.  When it does not, the
//! buffer is ordinary memory with the first two properties — which is
//! still strictly better than a `Vec`, and the capability report says
//! which one you got.

use std::io;
use zeroize::Zeroize;

const PAGE: usize = 4096;

/// `memfd_secret(2)`.  Same number on x86-64 and aarch64 (it is in the
/// generic syscall table); not in the `libc` crate's constants yet.
const SYS_MEMFD_SECRET: libc::c_long = 447;

const MFD_CLOEXEC: u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;

const F_ADD_SEALS: libc::c_int = 1033;
const F_SEAL_SEAL: libc::c_int = 0x0001;
const F_SEAL_SHRINK: libc::c_int = 0x0002;
const F_SEAL_GROW: libc::c_int = 0x0004;
const F_SEAL_WRITE: libc::c_int = 0x0008;

enum Backing {
    /// Locked, dump-excluded heap memory.
    Heap(Vec<u8>),
    /// `memfd_secret` mapping: the pages are absent from the kernel's
    /// direct map, so no kernel-side read of physical memory reaches them.
    SecretMmap { ptr: *mut u8, len: usize, fd: libc::c_int },
}

/// A byte buffer for secret material.
pub struct SecBuf {
    inner: Backing,
    /// Logical length; the `memfd_secret` backing rounds the mapping up to
    /// a page, so allocation size and buffer length are not the same.
    len: usize,
    locked: bool,
    secret_mem: bool,
}

// SAFETY: the buffer owns its pages exclusively and hands out `&[u8]` /
// `&mut [u8]` only; nothing is shared between threads without a lock.
unsafe impl Send for SecBuf {}
// SAFETY: `&SecBuf` only ever yields `&[u8]`, and every mutation goes
// through `&mut self`, so a shared reference is safe to hand to another
// thread (this is what lets a daemon serve one unlocked store).
unsafe impl Sync for SecBuf {}

fn round_down(x: usize) -> usize {
    x & !(PAGE - 1)
}

fn round_up(x: usize) -> usize {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Lock and dump-exclude the pages covering `[ptr, ptr+len)`.
fn lock_range(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let lo = round_down(ptr as usize);
    let hi = round_up(ptr as usize + len);
    unsafe {
        let rc = libc::mlock(lo as *const libc::c_void, hi - lo);
        let _ = libc::madvise(lo as *mut libc::c_void, hi - lo, libc::MADV_DONTDUMP);
        rc == 0
    }
}

fn unlock_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let lo = round_down(ptr as usize);
    let hi = round_up(ptr as usize + len);
    unsafe {
        libc::munlock(lo as *const libc::c_void, hi - lo);
    }
}

impl SecBuf {
    /// Allocate `len` zeroed bytes, preferring `memfd_secret`.
    pub fn new(len: usize) -> io::Result<SecBuf> {
        if let Some(buf) = SecBuf::try_secret(len)? {
            return Ok(buf);
        }
        let v = vec![0u8; len];
        let locked = lock_range(v.as_ptr(), v.len());
        Ok(SecBuf {
            inner: Backing::Heap(v),
            len,
            locked,
            secret_mem: false,
        })
    }

    fn try_secret(len: usize) -> io::Result<Option<SecBuf>> {
        let want = if len == 0 { PAGE } else { round_up(len) };
        // SAFETY: plain syscall with constant arguments.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0 as libc::c_long) } as libc::c_int;
        if fd < 0 {
            return Ok(None);
        }
        // A fresh memfd_secret has zero length; mapping more than the file
        // holds faults with SIGBUS on first touch, so size it first.
        // SAFETY: ftruncate on our own anonymous file.
        if unsafe { libc::ftruncate(fd, want as libc::off_t) } == -1 {
            // SAFETY: fd is ours.
            unsafe { libc::close(fd) };
            return Ok(None);
        }
        // SAFETY: fd is a fresh anonymous file we own.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                want,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            // SAFETY: fd is ours and not used further.
            unsafe { libc::close(fd) };
            // A kernel that has memfd_secret compiled out, or a policy that
            // forbids the mapping, is a normal fallback, not an error.
            if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::ENOSYS) {
                return Ok(None);
            }
            return Ok(None);
        }
        Ok(Some(SecBuf {
            inner: Backing::SecretMmap {
                ptr: ptr as *mut u8,
                len: want,
                fd,
            },
            len,
            locked: true,
            secret_mem: true,
        }))
    }

    /// Copy `bytes` into a new [`SecBuf`].
    pub fn from_slice(bytes: &[u8]) -> io::Result<SecBuf> {
        let mut b = SecBuf::new(bytes.len())?;
        b.as_mut_slice().copy_from_slice(bytes);
        Ok(b)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when the pages live in a `memfd_secret` mapping.
    pub fn is_secret_mem(&self) -> bool {
        self.secret_mem
    }

    /// True when the pages are locked (not swappable).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.inner {
            Backing::Heap(v) => &v[..self.len],
            // SAFETY: we own `len` readable bytes at `ptr`.
            Backing::SecretMmap { ptr, .. } => unsafe {
                std::slice::from_raw_parts(*ptr, self.len)
            },
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        match &mut self.inner {
            Backing::Heap(v) => &mut v[..len],
            // SAFETY: as above; `&mut self` makes the access exclusive.
            Backing::SecretMmap { ptr, .. } => unsafe {
                std::slice::from_raw_parts_mut(*ptr, len)
            },
        }
    }

    /// Make the bytes unrecoverable, keeping the allocation.
    pub fn wipe(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for SecBuf {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        match &mut self.inner {
            Backing::Heap(v) => {
                unlock_range(v.as_ptr(), v.len());
            }
            Backing::SecretMmap { ptr, len, fd } => {
                // Wipe the whole mapping, not just the logical length.
                // SAFETY: the mapping is ours and is unmapped once.
                unsafe {
                    std::ptr::write_bytes(*ptr, 0, *len);
                    libc::munmap(*ptr as *mut libc::c_void, *len);
                    libc::close(*fd);
                }
            }
        }
    }
}

impl std::fmt::Debug for SecBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the contents, not even truncated.
        f.debug_struct("SecBuf")
            .field("len", &self.len())
            .field("locked", &self.locked)
            .field("secret_mem", &self.secret_mem)
            .finish()
    }
}

/// A read-only anonymous file holding `bytes`, sealed against writes and
/// size changes, to be inherited by a child as a file descriptor.
///
/// This is how a secret reaches a program without ever being an argument
/// or an environment value: `/proc/<pid>/fd/N` is a symlink readable only
/// by the process owner, and the contents are only obtainable by reading
/// the descriptor.
pub struct SealedFd {
    fd: libc::c_int,
}

impl SealedFd {
    pub fn new(bytes: &[u8]) -> io::Result<SealedFd> {
        let name = c"confmask-secret";
        // SAFETY: constant C string, no aliasing.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_ALLOW_SEALING | MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut off = 0usize;
        while off < bytes.len() {
            // SAFETY: writing to our own memfd from a valid slice.
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // SAFETY: fd is ours.
                unsafe { libc::close(fd) };
                return Err(e);
            }
            off += n as usize;
        }
        // SAFETY: sealing our own memfd.
        let rc = unsafe {
            libc::fcntl(
                fd,
                F_ADD_SEALS,
                F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE,
            )
        };
        if rc == -1 {
            let e = io::Error::last_os_error();
            // SAFETY: fd is ours.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // Rewind so a reader sees the whole secret.
        // SAFETY: lseek on our own fd.
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        Ok(SealedFd { fd })
    }

    pub fn raw(&self) -> libc::c_int {
        self.fd
    }

    /// Hand ownership of the descriptor to the caller (it will not be
    /// closed here).
    pub fn into_raw(mut self) -> libc::c_int {
        let fd = self.fd;
        self.fd = -1;
        fd
    }
}

impl Drop for SealedFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd is ours.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl std::fmt::Debug for SealedFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedFd").field("fd", &self.fd).finish()
    }
}

/// Stop this process (and anything it forks) from being dumped, traced by
/// non-root, or read through `/proc/<pid>/mem` by another process.
pub fn set_non_dumpable() -> io::Result<()> {
    // SAFETY: plain prctl.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort hardening for a process that will hold secrets: no core
/// dumps, no ptrace by non-root.  Failures are reported, never fatal —
/// a host that forbids `PR_SET_DUMPABLE` still gets the locked buffers.
pub fn harden_self() -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = set_non_dumpable() {
        notes.push(format!("PR_SET_DUMPABLE: {}", e));
    }
    // SAFETY: constant rlimit.
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) == -1 {
            notes.push(format!("RLIMIT_CORE: {}", io::Error::last_os_error()));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wipe() {
        let mut b = SecBuf::from_slice(b"hello-secret").unwrap();
        assert_eq!(b.as_slice(), b"hello-secret");
        assert_eq!(b.len(), 12);
        b.wipe();
        assert_eq!(b.as_slice()[..12], [0u8; 12]);
    }

    #[test]
    fn sealed_fd_roundtrip() {
        use std::io::Read;
        let s = SealedFd::new(b"abc123").unwrap();
        let mut f = unsafe {
            use std::os::unix::io::FromRawFd;
            std::fs::File::from_raw_fd(s.into_raw())
        };
        let mut out = String::new();
        f.read_to_string(&mut out).unwrap();
        assert_eq!(out, "abc123");
    }

    #[test]
    fn sealed_fd_is_write_sealed() {
        let s = SealedFd::new(b"abc").unwrap();
        // SAFETY: writing to our own sealed fd must fail.
        let n = unsafe { libc::write(s.raw(), b"x".as_ptr() as *const libc::c_void, 1) };
        assert_eq!(n, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }
}
