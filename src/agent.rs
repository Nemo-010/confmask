//! The secret agent: one process holds the unlocked store, everything
//! else asks it for what it needs.
//!
//! This is the *secret* side of the daemon story.  `confmaskd` is the
//! other side: it supervises jobs.  They are separate programs on
//! purpose -- one holds long-lived plaintext, the other runs untrusted
//! work -- and they can share a machine without sharing privileges.
//!
//! Why a daemon and not just a file: a store that is unlocked per command
//! means the passphrase is typed into, or read by, every command — and
//! every one of those commands is a process that holds the plaintext for
//! as long as it runs.  A daemon derives the key once, keeps the
//! plaintext in locked, dump-excluded memory, and hands out individual
//! secrets over a socket that only this account can open.
//!
//! Access control is `SO_PEERCRED` (the kernel's word for the connecting
//! process's uid/gid/pid) plus, optionally, an allow-list of peer
//! executables read from `/proc/<pid>/exe` — a path the peer cannot
//! forge.
//!
//! Be clear about the boundary: a peer running as the same account can
//! ask for what the daemon serves, unless you restrict it by executable.
//! The daemon removes the secret from argv, the environment, `ps`, and
//! the disk; it does not and cannot tell two programs of the same account
//! apart when both are allowed to ask.

use crate::mem::SecBuf;
use crate::store::Store;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Where the daemon listens when no `--socket` is given.
pub fn default_socket() -> PathBuf {
    if let Some(p) = std::env::var_os("CONFMASK_SOCKET") {
        return PathBuf::from(p);
    }
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(rt);
        if p.is_dir() {
            return p.join("confmask.sock");
        }
    }
    // A world-writable /tmp is fine here: the socket is 0600 and every
    // connection is checked with SO_PEERCRED.  The directory keeps the
    // path from colliding with another account's.
    PathBuf::from(format!("/tmp/confmask-{}", unsafe { libc::getuid() })).join("daemon.sock")
}

fn peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(stream);
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into owned storage with the right length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(stream);
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: as above.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.pid)
}

/// A running daemon.
pub struct Daemon {
    store: Store,
    socket: PathBuf,
    /// When non-empty, only peers whose `/proc/<pid>/exe` resolves to one
    /// of these paths may ask for secrets.
    allow_exe: Vec<PathBuf>,
}

impl Daemon {
    pub fn new(store: Store, socket: PathBuf, allow_exe: Vec<PathBuf>) -> Daemon {
        Daemon {
            store,
            socket,
            allow_exe,
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Bind, publish, and serve until killed.
    pub fn serve(self) -> io::Result<()> {
        if let Some(dir) = self.socket.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        // A stale socket from a dead daemon would make bind() fail.
        if self.socket.exists() {
            let _ = std::fs::remove_file(&self.socket);
        }
        let listener = UnixListener::bind(&self.socket)?;
        std::fs::set_permissions(&self.socket, std::fs::Permissions::from_mode(0o600))?;

        crate::mem::harden_self();
        eprintln!(
            "confmask: daemon listening on {} ({} secret(s), uid {})",
            self.socket.display(),
            self.store.names().len(),
            unsafe { libc::getuid() }
        );

        let me = unsafe { libc::getuid() };
        let allow = self.allow_exe.clone();
        let store = std::sync::Arc::new(self.store);

        for conn in listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: accept: {}", e);
                    continue;
                }
            };
            let store = std::sync::Arc::clone(&store);
            let allow = allow.clone();
            std::thread::spawn(move || {
                let _ = handle(stream, &store, me, &allow);
            });
        }
        Ok(())
    }
}

fn handle(
    stream: UnixStream,
    store: &Store,
    me: libc::uid_t,
    allow: &[PathBuf],
) -> io::Result<()> {
    let uid = peer_uid(&stream)?;
    if uid != me {
        let mut s = stream;
        let _ = s.write_all(b"ERR peer uid is not the daemon's uid\n");
        return Ok(());
    }
    if !allow.is_empty() {
        let pid = peer_pid(&stream)?;
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();
        let ok = match &exe {
            Some(e) => allow.iter().any(|a| a == e),
            None => false,
        };
        if !ok {
            let mut s = stream;
            let _ = s.write_all(b"ERR peer executable is not on the allow-list\n");
            return Ok(());
        }
    }

    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let cmd = line.trim_end_matches('\n');
        if cmd == "PING" {
            w.write_all(b"OK 0\n")?;
        } else if cmd == "LIST" {
            let names = store.names().join("\n");
            w.write_all(format!("OK {}\n", names.len()).as_bytes())?;
            w.write_all(names.as_bytes())?;
        } else if let Some(name) = cmd.strip_prefix("GET ") {
            match store.get(name) {
                Some(v) => {
                    w.write_all(format!("OK {}\n", v.len()).as_bytes())?;
                    w.write_all(v)?;
                }
                None => {
                    w.write_all(format!("ERR no secret named '{}'\n", name).as_bytes())?;
                }
            }
        } else {
            w.write_all(b"ERR unknown command\n")?;
        }
        w.flush()?;
    }
}

// ------------------------------------------------------------------ client

fn connect(socket: Option<&PathBuf>) -> io::Result<UnixStream> {
    let path = match socket {
        Some(p) => p.clone(),
        None => default_socket(),
    };
    UnixStream::connect(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot reach a confmask agent on {} ({}); start one with `confmask agent`",
                path.display(),
                e
            ),
        )
    })
}

fn read_line(r: &mut BufReader<UnixStream>) -> io::Result<String> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed the connection",
        ));
    }
    Ok(line.trim_end_matches('\n').to_string())
}

fn read_body(r: &mut BufReader<UnixStream>, n: usize) -> io::Result<SecBuf> {
    let mut buf = SecBuf::new(n)?;
    if n > 0 {
        r.read_exact(buf.as_mut_slice())?;
    }
    Ok(buf)
}

fn check_ok(line: &str) -> io::Result<usize> {
    if let Some(rest) = line.strip_prefix("OK ") {
        rest.parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "daemon: bad length"))
    } else if let Some(rest) = line.strip_prefix("ERR ") {
        Err(io::Error::other(rest.to_string()))
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "daemon: bad reply"))
    }
}

/// Ask the daemon for one secret.
pub fn fetch(socket: Option<&PathBuf>, name: &str) -> io::Result<SecBuf> {
    let s = connect(socket)?;
    let mut w = s.try_clone()?;
    let mut r = BufReader::new(s);
    w.write_all(format!("GET {}\n", name).as_bytes())?;
    w.flush()?;
    let n = check_ok(&read_line(&mut r)?)?;
    read_body(&mut r, n)
}

/// List the names the daemon serves.
pub fn list(socket: Option<&PathBuf>) -> io::Result<Vec<String>> {
    let s = connect(socket)?;
    let mut w = s.try_clone()?;
    let mut r = BufReader::new(s);
    w.write_all(b"LIST\n")?;
    w.flush()?;
    let n = check_ok(&read_line(&mut r)?)?;
    let body = read_body(&mut r, n)?;
    Ok(String::from_utf8_lossy(body.as_slice())
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

/// Is a daemon answering?
pub fn ping(socket: Option<&PathBuf>) -> bool {
    (|| -> io::Result<()> {
        let s = connect(socket)?;
        let mut w = s.try_clone()?;
        let mut r = BufReader::new(s);
        w.write_all(b"PING\n")?;
        w.flush()?;
        check_ok(&read_line(&mut r)?)?;
        Ok(())
    })()
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Passphrase;

    #[test]
    fn daemon_serves_and_client_reads() {
        let dir = std::env::temp_dir().join(format!("confmask-daemon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("s.enc");
        let sock = dir.join("d.sock");
        let pp = Passphrase::new(b"pw").unwrap();
        let mut st = Store::create(&sp, &pp).unwrap();
        st.set("TOKEN", b"tok-value").unwrap();
        st.save(&pp).unwrap();
        let store = Store::open(&sp, &pp).unwrap();

        let d = Daemon::new(store, sock.clone(), Vec::new());
        std::thread::spawn(move || {
            let _ = d.serve();
        });
        // Wait for the socket to appear.
        for _ in 0..200 {
            if ping(Some(&sock)) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ping(Some(&sock)));
        assert_eq!(list(Some(&sock)).unwrap(), vec!["TOKEN"]);
        let v = fetch(Some(&sock), "TOKEN").unwrap();
        assert_eq!(v.as_slice(), b"tok-value");
        assert!(fetch(Some(&sock), "NOPE").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
