//! Copy a program into a sealed memfd so the process runs from it.
//!
//! `prepare` opens the program, checks the ELF magic, copies the bytes into
//! a memfd, and adds all four seals. The caller then runs
//! `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.
//! `/proc/<pid>/exe` then shows `/memfd:<name>` and the maps show no
//! on-disk path.
//!
//! Limits:
//! - `/proc/<pid>/map_files` still resolves the mapped file.
//! - The kernel copies the whole file. A large binary costs memory.
//! - Only ELF files work. A script needs the interpreter to open the path
//!   of a close-on-exec descriptor, which fails. `prepare` refuses such
//!   input.
//! - A kernel with `vm.memfd_noexec` hardening can refuse `memfd_create` or
//!   the later exec. `prepare` returns the kernel error in that case.
//! - Tools that look for `memfd:` executables can flag the process. The
//!   label sets the memfd name.
//!
//! The memfd keeps `FD_CLOEXEC`. The fd stays open across `fork` and closes
//! at the exec. The `Image` type does not close the fd on drop.

use std::ffi::CStr;
use std::io;

const F_ADD_SEALS: libc::c_int = 1033; // F_LINUX_SPECIFIC_BASE + 9
const F_SEAL_SEAL: libc::c_int = 1;
const F_SEAL_SHRINK: libc::c_int = 2;
const F_SEAL_GROW: libc::c_int = 4;
const F_SEAL_WRITE: libc::c_int = 8;

const MFD_CLOEXEC: libc::c_uint = 1;
const MFD_ALLOW_SEALING: libc::c_uint = 2;

/// Longest memfd name that the kernel accepts, without the NUL byte.
const MEMFD_NAME_MAX: usize = 249;

/// A sealed memfd that holds a program image.
#[derive(Debug)]
pub struct Image {
    /// The memfd. The caller owns it and closes it.
    pub fd: libc::c_int,
}

/// Turn a label into a memfd name: printable ASCII only, at most 249 bytes,
/// never empty.
///
/// A byte outside 0x20..=0x7e becomes `_`. An empty result becomes `x`.
pub fn sanitize_name(label: &str) -> String {
    let mut out = String::new();
    for &b in label.as_bytes() {
        if out.len() >= MEMFD_NAME_MAX {
            break;
        }
        if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

/// Return true when a `readlink` target names a memfd.
pub fn is_memfd_path(path: &str) -> bool {
    path.starts_with("/memfd:")
}

/// Return true when `/proc/self/exe` points to a memfd.
///
/// Return false when the link cannot be read.
#[cfg(test)]
pub fn already_in_memfd() -> bool {
    use std::os::unix::ffi::OsStrExt;
    match std::fs::read_link("/proc/self/exe") {
        Ok(target) => match std::str::from_utf8(target.as_os_str().as_bytes()) {
            Ok(s) => is_memfd_path(s),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn close_quiet(fd: libc::c_int) {
    // SAFETY: `fd` is a descriptor this module opened and does not use again.
    unsafe {
        libc::close(fd);
    }
}

fn with_context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", what, err))
}

/// Read exactly `buf.len()` bytes or fewer at end of file.
fn read_some(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is a valid writable slice of the length passed.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

fn write_all_fd(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a valid readable slice of the length passed.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "memfd write returned 0"));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Check the ELF magic at offset 0 without moving the file offset.
fn check_elf_magic(fd: libc::c_int) -> io::Result<()> {
    let mut magic = [0u8; 4];
    loop {
        // SAFETY: `magic` is a valid writable buffer of 4 bytes.
        let n = unsafe { libc::pread(fd, magic.as_mut_ptr() as *mut libc::c_void, 4, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(with_context(err, "read program header"));
        }
        if n == 4 && magic == [0x7f, b'E', b'L', b'F'] {
            return Ok(());
        }
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an ELF image"));
    }
}

fn copy_into(src: libc::c_int, dst: libc::c_int) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = read_some(src, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_all_fd(dst, &buf[..n])?;
    }
}

/// Copy `program` into a sealed memfd named after `label`.
///
/// Returns InvalidInput with "not an ELF image" when the file does not start
/// with the ELF magic. Returns the kernel error when `memfd_create` or the
/// sealing call fails.
pub fn prepare(program: &CStr, label: &str) -> io::Result<Image> {
    // SAFETY: `program` is a valid NUL-terminated string.
    let src = unsafe { libc::open(program.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if src < 0 {
        return Err(with_context(io::Error::last_os_error(), "open program for rexec"));
    }

    if let Err(err) = check_elf_magic(src) {
        close_quiet(src);
        return Err(err);
    }

    let mut name = sanitize_name(label).into_bytes();
    name.push(0);
    // SAFETY: `name` is NUL-terminated and outlives the call. The flags are
    // valid memfd_create flags. The raw syscall avoids a missing libc wrapper.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr() as *const libc::c_char,
            (MFD_CLOEXEC | MFD_ALLOW_SEALING) as libc::c_uint,
        )
    };
    if raw < 0 {
        let err = io::Error::last_os_error();
        close_quiet(src);
        return Err(with_context(err, "memfd_create refused"));
    }
    let fd = raw as libc::c_int;

    let copied = copy_into(src, fd);
    close_quiet(src);
    if let Err(err) = copied {
        close_quiet(fd);
        return Err(err);
    }

    let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    // SAFETY: `fd` is a valid memfd. F_ADD_SEALS takes an int argument.
    let rc = unsafe { libc::fcntl(fd, F_ADD_SEALS, seals) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        close_quiet(fd);
        return Err(with_context(err, "sealing the memfd refused"));
    }
    Ok(Image { fd })
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;
    use super::*;
    use std::ffi::CString;

    #[test]
    fn sanitize_keeps_printable_ascii() {
        assert_eq!(sanitize_name("web server 1"), "web server 1");
    }

    // Mutation control: removing the empty-name fallback makes this fail.
    #[test]
    fn sanitize_never_returns_empty() {
        assert_eq!(sanitize_name(""), "x");
    }

    #[test]
    fn sanitize_replaces_control_and_non_ascii_bytes() {
        assert_eq!(sanitize_name("a\nb\u{e9}"), "a_b__");
    }

    // Mutation control: raising the limit above 249 makes this fail.
    #[test]
    fn sanitize_clips_to_249_bytes() {
        let long = "a".repeat(1000);
        assert_eq!(sanitize_name(&long).len(), 249);
    }

    #[test]
    fn memfd_path_detection() {
        assert!(is_memfd_path("/memfd:label (deleted)"));
        assert!(is_memfd_path("/memfd:"));
        assert!(!is_memfd_path("/usr/bin/memfd:x"));
        assert!(!is_memfd_path("memfd:label"));
        assert!(!is_memfd_path(""));
    }

    #[test]
    fn already_in_memfd_is_false_for_the_test_binary() {
        assert!(!already_in_memfd());
    }

    fn skip_on_memfd_refusal(err: &io::Error) -> bool {
        // `with_context` keeps the error kind but not the raw errno.
        matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
        ) || matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EACCES)
        )
    }

    #[test]
    fn prepare_copies_and_seals() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let image = match prepare(&path, "round trip") {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare failed: {}", e),
        };

        // The content equals the file. Mutation control: a copy loop that
        // drops a short read or stops early makes this fail.
        let original = std::fs::read(&exe).expect("read exe");
        let mut copy = Vec::with_capacity(original.len());
        let mut off: libc::off_t = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: `buf` is a valid writable slice.
            let n = unsafe {
                libc::pread(image.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), off)
            };
            assert!(n >= 0, "pread: {}", io::Error::last_os_error());
            if n == 0 {
                break;
            }
            copy.extend_from_slice(&buf[..n as usize]);
            off += n as libc::off_t;
        }
        assert!(copy == original, "memfd content differs from the file");

        // Sealing blocks a write. Mutation control: omitting F_SEAL_WRITE
        // makes the write succeed and this assertion fail.
        // SAFETY: valid fd and a one byte buffer.
        let n = unsafe { libc::write(image.fd, b"x".as_ptr() as *const libc::c_void, 1) };
        assert_eq!(n, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

        // The link target is a memfd.
        let link = std::fs::read_link(format!("/proc/self/fd/{}", image.fd)).expect("readlink");
        let link = link.to_string_lossy().into_owned();
        assert!(is_memfd_path(&link), "link was {}", link);

        close_quiet(image.fd);
    }

    #[test]
    fn prepare_refuses_non_elf() {
        let dir = std::env::temp_dir().join(format!("confmask-rexec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("script.sh");
        std::fs::write(&file, b"#!/bin/sh\nexit 0\n").expect("write");
        let path = CString::new(file.as_os_str().as_bytes()).expect("no NUL");
        let result = prepare(&path, "script");
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
                assert!(e.to_string().contains("not an ELF image"));
            }
            Ok(i) => {
                close_quiet(i.fd);
                panic!("script was accepted");
            }
        }
    }
}
