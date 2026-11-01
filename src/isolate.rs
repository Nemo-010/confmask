//! Isolation: give the payload its own namespaces, without root.
//!
//! Unprivileged user namespaces let an ordinary account create a mount,
//! PID and network namespace for a child.  What that buys, concretely:
//!
//! * **PID namespace** — the payload's `/proc` lists only the payload.
//!   Code running inside cannot enumerate, or read the command lines of,
//!   the other jobs on the host.
//! * **Mount namespace** — a fresh `procfs` and a private `tmpfs` on
//!   `/tmp`.  Files the payload writes do not land in the host's `/tmp`,
//!   where the other accounts can list them.
//! * **Network namespace** — an empty network stack: nothing but
//!   loopback.  A payload that should not talk to the world cannot.
//!
//! This is the direction metadata redaction does not cover: redaction
//! hides the payload *from* the host, isolation hides the host *from* the
//! payload.  They need different plumbing (a PID namespace requires an
//! extra fork, which a ptrace supervisor cannot drive), so `confmask run`
//! offers them as separate modes and says which one you got.

use crate::ExitState;
use std::ffi::{CStr, CString};
use std::io;

/// Which namespaces to create.  A user namespace is always created (it is
/// what makes the others possible without root).
#[derive(Debug, Clone, Copy)]
pub struct Isolate {
    pub pid: bool,
    pub net: bool,
    pub private_tmp: bool,
}

impl Isolate {
    pub fn all() -> Isolate {
        Isolate {
            pid: true,
            net: true,
            private_tmp: true,
        }
    }

    pub fn describe(&self) -> String {
        let mut parts = vec!["user", "mount"];
        if self.pid {
            parts.push("pid");
        }
        if self.net {
            parts.push("net");
        }
        parts.join("+")
    }
}

fn write_all(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: writing to an fd we opened.
        let n = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

fn write_file(path: &CStr, bytes: &[u8]) -> bool {
    // SAFETY: O_WRONLY|O_CLOEXEC on a kernel-provided file.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let ok = write_all(fd, bytes);
    // SAFETY: fd is ours.
    unsafe { libc::close(fd) };
    ok
}

fn die(what: &str) -> ! {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"confmask: isolation: ");
    msg.extend_from_slice(what.as_bytes());
    msg.extend_from_slice(b": ");
    msg.extend_from_slice(io::Error::last_os_error().to_string().as_bytes());
    msg.push(b'\n');
    // SAFETY: one write to fd 2, then exit.
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(126);
    }
}

/// Unshare the namespaces and tell the parent we are ready for the id
/// maps.  Runs in the first child.
///
/// The maps are written by the *parent*, not here: a process that has
/// already entered a new user namespace cannot write its own `uid_map`
/// (it has no capability over the namespace it just left), which is why
/// every unprivileged sandbox — bubblewrap, runc, util-linux — does the
/// handshake this way.
fn unshare_and_wait_for_maps(iso: &Isolate, ready_w: libc::c_int, go_r: libc::c_int) {
    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if iso.pid {
        flags |= libc::CLONE_NEWPID;
    }
    if iso.net {
        flags |= libc::CLONE_NEWNET;
    }
    // SAFETY: unshare in a child that will fork and then exec.
    if unsafe { libc::unshare(flags) } == -1 {
        die("unshare");
    }
    // SAFETY: one byte to our own pipe.
    unsafe {
        libc::write(ready_w, b"1".as_ptr() as *const libc::c_void, 1);
        let mut b = 0u8;
        libc::read(go_r, &mut b as *mut u8 as *mut libc::c_void, 1);
        libc::close(ready_w);
        libc::close(go_r);
    }

    // Make every mount private so nothing propagates back to the host.
    // SAFETY: plain mount(2) inside our own mount namespace.
    unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        );
    }
}

/// Write `/proc/<pid>/{setgroups,uid_map,gid_map}` from the parent side.
fn write_id_maps(pid: libc::pid_t) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let setgroups = CString::new(format!("/proc/{}/setgroups", pid)).unwrap();
    let uid_map = CString::new(format!("/proc/{}/uid_map", pid)).unwrap();
    let gid_map = CString::new(format!("/proc/{}/gid_map", pid)).unwrap();

    // setgroups must be denied before gid_map can be written by an
    // unprivileged parent; failure is expected when we are root.
    let _ = write_file(&setgroups, b"deny");
    if !write_file(&uid_map, format!("0 {} 1\n", uid).as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("uid_map: {}", io::Error::last_os_error()),
        ));
    }
    if !write_file(&gid_map, format!("0 {} 1\n", gid).as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("gid_map: {}", io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// Prepare the payload's view: its own `/proc`, its own `/tmp`, its fds.
fn setup_payload_view(iso: &Isolate, fds: &[libc::c_int]) {
    if iso.pid {
        // SAFETY: mounting a fresh procfs; the namespace is private and
        // owned by the user namespace we just created.
        let rc = unsafe {
            libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
                std::ptr::null(),
            )
        };
        if rc == -1 {
            die("mount /proc");
        }
    }
    if iso.private_tmp {
        // SAFETY: as above.
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
                c"mode=1777".as_ptr() as *const libc::c_void,
            );
        }
    }
    for (i, fd) in fds.iter().enumerate() {
        let target = 3 + i as libc::c_int;
        // SAFETY: between fork and exec, async-signal-safe calls only.
        unsafe {
            if *fd != target {
                libc::dup2(*fd, target);
            }
            libc::fcntl(target, libc::F_SETFD, 0);
        }
    }
}

/// Run `prog` inside fresh namespaces; `fds` are installed at 3, 4, …
pub fn run(
    iso: &Isolate,
    prog: &CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    fds: &[libc::c_int],
) -> io::Result<ExitState> {
    let mut ready: [libc::c_int; 2] = [-1, -1];
    let mut go: [libc::c_int; 2] = [-1, -1];
    // SAFETY: plain pipe(2) into owned storage.
    unsafe {
        if libc::pipe(ready.as_mut_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::pipe(go.as_mut_ptr()) == -1 {
            libc::close(ready[0]);
            libc::close(ready[1]);
            return Err(io::Error::last_os_error());
        }
    }

    // SAFETY: the child only unshares, forks and execs.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: closing our ends of the handshake pipes.
        unsafe {
            libc::close(ready[0]);
            libc::close(go[1]);
        }
        unshare_and_wait_for_maps(iso, ready[1], go[0]);
        // A PID namespace applies to children, so the payload needs one
        // more fork; the intermediate waits and passes the status up.
        // SAFETY: as above.
        let inner = unsafe { libc::fork() };
        if inner < 0 {
            die("fork");
        }
        if inner == 0 {
            setup_payload_view(iso, fds);
            // SAFETY: final exec of the payload.
            unsafe { libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            die("execve");
        }
        let mut st = 0i32;
        loop {
            // SAFETY: our own child.
            let w = unsafe { libc::waitpid(inner, &mut st, 0) };
            if w == -1 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                unsafe { libc::_exit(126) };
            }
            break;
        }
        let code = if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            128 + libc::WTERMSIG(st)
        };
        // SAFETY: the payload is reaped; nothing left to do.
        unsafe { libc::_exit(code) };
    }

    // ---- parent: write the maps, then let the child continue ----
    // SAFETY: closing our ends of the handshake pipes.
    unsafe {
        libc::close(ready[1]);
        libc::close(go[0]);
    }
    let mut b = 0u8;
    // SAFETY: reading one byte from our own pipe.
    let n = unsafe { libc::read(ready[0], &mut b as *mut u8 as *mut libc::c_void, 1) };
    unsafe { libc::close(ready[0]) };
    if n != 1 {
        // The child died before unsharing; collect it and report.
        let mut st = 0i32;
        unsafe {
            libc::waitpid(pid, &mut st, 0);
            libc::close(go[1]);
        }
        let code = if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            126
        };
        return Ok(ExitState::plain(code, None));
    }
    let map_err = write_id_maps(pid);
    // SAFETY: releasing the child.
    unsafe {
        libc::write(go[1], b"1".as_ptr() as *const libc::c_void, 1);
        libc::close(go[1]);
    }
    if let Err(e) = map_err {
        let mut st = 0i32;
        // SAFETY: reaping the child we just released.
        unsafe { libc::waitpid(pid, &mut st, 0) };
        return Err(e);
    }

    let mut status = 0i32;
    loop {
        // SAFETY: our own child.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        break;
    }
    if libc::WIFEXITED(status) {
        Ok(ExitState::plain(libc::WEXITSTATUS(status), None))
    } else if libc::WIFSIGNALED(status) {
        let s = libc::WTERMSIG(status);
        Ok(ExitState::plain(128 + s, Some(s)))
    } else {
        Ok(ExitState::plain(255, None))
    }
}
