//! Secrets: where they come from, and how they reach a program without
//! appearing in `argv`, the environment, or `ps` output.
//!
//! A secret is read once, held in a [`SecBuf`] (locked, dump-excluded),
//! and then handed to the child as a **sealed file descriptor**.  The
//! child learns the descriptor number from an environment variable whose
//! *name* describes the secret and whose *value* is the number — neither
//! of which is sensitive:
//!
//! ```text
//! CONFMASK_SECRET_DEPLOY_TOKEN=3
//! ```
//!
//! `/proc/<pid>/environ` therefore discloses the *names* of the secrets a
//! process was given, never their contents, and `/proc/<pid>/cmdline`
//! discloses nothing at all.  A program reads its secret with the one
//! line it would otherwise have read it from the environment:
//!
//! ```sh
//! token=$(confmask read DEPLOY_TOKEN)      # or: cat <&3
//! ```

use crate::mem::{SecBuf, SealedFd};
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Where a secret's bytes come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// `literal:VALUE` — fine for tests, not for real use: the value is
    /// in the shell history and in the argument list of the process that
    /// invoked `confmask`.
    Literal(String),
    /// `file:PATH` — a file readable only by the owner (mode 0600) is the
    /// normal case.
    File(PathBuf),
    /// `env:VAR` — read from confmask's own environment.  The variable is
    /// visible in *confmask's* environ while it runs, so this is a
    /// convenience, not a recommendation.
    Env(String),
    /// `stdin` — read to EOF from standard input.
    Stdin,
    /// `daemon:NAME` — fetched from a running `confmask daemon`.
    Daemon(String),
}

impl Source {
    /// Parse the `NAME=SOURCE` form used by `--secret`.
    pub fn parse(spec: &str) -> io::Result<(String, Source)> {
        let (name, rest) = spec.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("--secret wants NAME=SOURCE, got '{}'", spec),
            )
        })?;
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--secret needs a non-empty NAME",
            ));
        }
        let source = if let Some(v) = rest.strip_prefix("literal:") {
            Source::Literal(v.to_string())
        } else if let Some(p) = rest.strip_prefix("file:") {
            Source::File(PathBuf::from(p))
        } else if let Some(v) = rest.strip_prefix("env:") {
            Source::Env(v.to_string())
        } else if let Some(v) = rest.strip_prefix("daemon:") {
            Source::Daemon(v.to_string())
        } else if rest == "stdin" {
            Source::Stdin
        } else {
            // bare value: treat as a literal, so `--secret TOKEN=abc` works
            Source::Literal(rest.to_string())
        };
        Ok((name.to_string(), source))
    }
}

/// A named secret held in protected memory.
pub struct Secret {
    pub name: String,
    pub(crate) buf: SecBuf,
}

impl Secret {
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> io::Result<Secret> {
        Ok(Secret {
            name: name.into(),
            buf: SecBuf::from_slice(bytes)?,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The value never reaches a log line, an error message or a panic.
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("len", &self.len())
            .finish()
    }
}

/// Read a file as secret material, warning when its mode lets other
/// accounts read it.
pub fn read_secret_file(path: &PathBuf) -> io::Result<SecBuf> {
    let mut f = std::fs::File::open(path)?;
    let md = f.metadata()?;
    if md.mode() & 0o077 != 0 {
        eprintln!(
            "confmask: warning: {} is mode {:04o}; other accounts can read it",
            path.display(),
            md.mode() & 0o777
        );
    }
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    // Trim one trailing newline: `echo token > file` is the common case.
    if v.last() == Some(&b'\n') {
        v.pop();
    }
    let mut b = SecBuf::new(v.len())?;
    b.as_mut_slice().copy_from_slice(&v);
    // The intermediate Vec held the plaintext too.
    use zeroize::Zeroize;
    v.zeroize();
    Ok(b)
}

/// Load one secret from its source.
pub fn load(name: &str, source: &Source, daemon_socket: Option<&PathBuf>) -> io::Result<Secret> {
    let buf = match source {
        Source::Literal(v) => SecBuf::from_slice(v.as_bytes())?,
        Source::File(p) => read_secret_file(p)?,
        Source::Env(var) => match std::env::var_os(var) {
            Some(v) => {
                use std::os::unix::ffi::OsStrExt;
                SecBuf::from_slice(v.as_bytes())?
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("environment variable {} is not set", var),
                ))
            }
        },
        Source::Stdin => {
            let mut v = Vec::new();
            io::stdin().read_to_end(&mut v)?;
            if v.last() == Some(&b'\n') {
                v.pop();
            }
            let mut b = SecBuf::new(v.len())?;
            b.as_mut_slice().copy_from_slice(&v);
            use zeroize::Zeroize;
            v.zeroize();
            b
        }
        Source::Daemon(remote) => crate::daemon::fetch(daemon_socket, remote)?,
    };
    Ok(Secret {
        name: name.to_string(),
        buf,
    })
}

/// The environment variable that tells a child where a secret lives.
pub fn env_var_for(name: &str) -> String {
    let mut s = String::from("CONFMASK_SECRET_");
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_uppercase());
        } else {
            s.push('_');
        }
    }
    s
}

/// Secrets turned into descriptors, ready to be inherited.
pub struct Delivery {
    /// Descriptors in delivery order; index `i` is placed at fd `3 + i`.
    fds: Vec<SealedFd>,
    /// Environment entries telling the child which fd holds which secret.
    env: Vec<(OsString, OsString)>,
    /// The first descriptor number handed out.
    pub first_fd: libc::c_int,
}

impl Delivery {
    /// Build sealed descriptors for every secret and the matching
    /// environment entries.
    pub fn new(secrets: &[Secret]) -> io::Result<Delivery> {
        let first_fd: libc::c_int = 3;
        let mut fds = Vec::with_capacity(secrets.len());
        let mut env = Vec::with_capacity(secrets.len());
        for (i, s) in secrets.iter().enumerate() {
            let fd = SealedFd::new(s.buf.as_slice())?;
            env.push((
                OsString::from(env_var_for(&s.name)),
                OsString::from((first_fd + i as libc::c_int).to_string()),
            ));
            fds.push(fd);
        }
        Ok(Delivery { fds, env, first_fd })
    }

    /// The raw descriptors, in the order they will be placed.
    pub fn raw_fds(&self) -> Vec<libc::c_int> {
        self.fds.iter().map(|f| f.raw()).collect()
    }

    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// Duplicate every descriptor onto `first_fd + i`, clearing
    /// `FD_CLOEXEC` so the child inherits it.
    ///
    /// # Safety
    /// Must be called in the child between `fork` and `exec`, where only
    /// async-signal-safe calls are permitted.
    pub unsafe fn install_in_child(&self) {
        // Move every source above the target range first: the sources are
        // whatever `memfd_create` handed out, which can collide with the
        // targets (a source at fd 3 that has to be installed at fd 4 would
        // otherwise be clobbered by the first `dup2`).
        let mut moved: Vec<(libc::c_int, libc::c_int)> = Vec::with_capacity(self.fds.len());
        for f in &self.fds {
            let hi = libc::fcntl(f.raw(), libc::F_DUPFD, 200);
            moved.push((f.raw(), hi));
        }
        for (i, (_, hi)) in moved.iter().enumerate() {
            if *hi >= 0 {
                let target = self.first_fd + i as libc::c_int;
                libc::dup2(*hi, target);
                libc::close(*hi);
            }
        }
        for i in 0..self.fds.len() {
            let target = self.first_fd + i as libc::c_int;
            libc::fcntl(target, libc::F_SETFD, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing() {
        let (n, s) = Source::parse("TOKEN=file:/tmp/x").unwrap();
        assert_eq!(n, "TOKEN");
        assert!(matches!(s, Source::File(_)));

        let (n, s) = Source::parse("A=literal:hi").unwrap();
        assert_eq!(n, "A");
        assert!(matches!(s, Source::Literal(ref v) if v == "hi"));

        let (n, s) = Source::parse("B=stdin").unwrap();
        assert_eq!(n, "B");
        assert!(matches!(s, Source::Stdin));

        assert!(Source::parse("nope").is_err());
    }

    #[test]
    fn env_var_naming() {
        assert_eq!(env_var_for("deploy-token"), "CONFMASK_SECRET_DEPLOY_TOKEN");
        assert_eq!(env_var_for("a.b"), "CONFMASK_SECRET_A_B");
    }

    #[test]
    fn delivery_installs_onto_fd_3() {
        let s = Secret::from_bytes("X", b"v").unwrap();
        let d = Delivery::new(&[s]).unwrap();
        assert_eq!(d.first_fd, 3);
        assert_eq!(d.env()[0].0, OsString::from("CONFMASK_SECRET_X"));
        assert_eq!(d.env()[0].1, OsString::from("3"));
    }
}
