//! `confmaskd`: run jobs for other local processes without the caller
//! ever holding the secrets.
//!
//! # Why a daemon
//!
//! A CI runner needs a token.  If the runner puts it on a command line,
//! every local account sees it in `ps` for the life of the job.  If it
//! puts it in the environment, `/proc/<pid>/environ` still shows it.
//! With `confmaskd` the secret lives in the daemon's memory and the job's
//! environment, never in the client's argv or environment: the client
//! sends only the command and receives stdio and the exit status.
//!
//! # Trust model
//!
//! An allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.
//!
//! `SO_PEERCRED` decides who is allowed.  By default only the daemon's own
//! uid and root may connect.  `--allow-uid` adds more uids.  A daemon that
//! holds a token and accepts requests from any local user is a
//! privilege-escalation service, so the default is closed.
//!
//! A root daemon started with `--run-as-uid` runs each job with the uid
//! and gid of the client (from `SO_PEERCRED`) instead of root.  The
//! daemon still passes its own environment to the job.
//!
//! The client checks the daemon too.  After `connect` it reads the uid of
//! the socket owner with `SO_PEERCRED`.  [`run_remote`] accepts the
//! client's own uid and root.  [`run_remote_as`] accepts one chosen uid.
//! Any other uid makes the client refuse to send the command.
//!
//! # Wire protocol (v2)
//!
//! Client -> daemon, once, with `SCM_RIGHTS` carrying exactly three
//! descriptors (the client's stdin, stdout and stderr):
//!
//! ```text
//! 1 byte  protocol version (value 2)
//! ```
//!
//! The first byte is the protocol version.  The daemon rejects any other
//! value with a response that has code 255.  A client of the old protocol
//! sent the byte `'C'`; the daemon names that case "protocol mismatch".
//!
//! Then a request frame follows on the same stream:
//!
//! ```text
//! "CMK2"  u8 label_mode  u32 label_len  label bytes
//!         u32 argc       argc * (u32 len, bytes)
//! ```
//!
//! `label_mode` is `0` (use the daemon label, `label_len` must be 0),
//! `1` (empty label, `label_len` must be 0) or `2` (the bytes are the
//! label).
//!
//! daemon -> client:
//!
//! ```text
//! i32 exit_code  u32 has_signal  i32 signal  u32 msg_len  msg bytes
//! ```
//!
//! All integers are little-endian.
//!
//! Limits: `argc <= 4096`, one argument `<= 1 MiB`, the whole request
//! `<= 8 MiB`, label `<= 4096` bytes without NUL, LF or CR.  The daemon
//! also caps the sum of `len + 1` over all job arguments at 1 MiB
//! (`--max-job-bytes`).  It computes the size of the redaction block (job
//! arguments, daemon environment, comm and a margin) before the job
//! starts and refuses a job that would not fit under
//! [`MAX_HIDDEN`](crate::MAX_HIDDEN).  A refused job gets code 255 and a
//! message, and never runs.
//!
//! The daemon sends code 255 with a message for: an unauthorised uid, a
//! wrong protocol version, a descriptor count other than three, a
//! truncated control message, a malformed frame, an oversized job and a
//! failed spawn.  A job killed by `--job-timeout` gets code 137 with
//! signal 9.
//!
//! # Process model
//!
//! The daemon runs one job at a time by default.  A masking session owns
//! the `waitpid(-1)` domain of its process, so sessions cannot overlap in
//! one process.  With `--jobs N` (N > 1) the daemon forks one worker
//! process per connection and runs at most N workers at once.
//!
//! Every descriptor the daemon owns has `FD_CLOEXEC`.  The job gets only
//! the three client descriptors as 0, 1 and 2.  The daemon opens
//! `/dev/null` on any of 0, 1 and 2 that is closed at startup.
//!
//! # Timeouts
//!
//! The accepted socket has `SO_RCVTIMEO` and `SO_SNDTIMEO` set to
//! `--io-timeout` seconds (default 30; 0 means none).  A client that
//! stalls during the request is dropped.  `--job-timeout` limits the job
//! run time.
//!
//! # Socket path
//!
//! The daemon refuses to start when the socket path is a symbolic link or
//! a file that is not a socket.  It connects to an existing socket first
//! and refuses to start when a daemon answers.  It unlinks the socket
//! only after `ECONNREFUSED`.  It binds under `umask 0o077`, then checks
//! with `lstat` that the new file is a socket owned by its euid.
//! `$XDG_RUNTIME_DIR` is used only when it is a directory owned by the
//! euid and not writable by group or other.
//!
//! # Secret store
//!
//! The daemon locks the memory that holds the job environment with
//! `mlock` (a failure is a warning).  On `SIGTERM` or `SIGINT` it stops
//! accepting, kills running jobs, overwrites the stored environment with
//! zeros, removes its socket and exits with code 0.

use crate::mask::{Mask, MaskedChild};
use crate::tracer::ExitState;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Which label the client asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RemoteLabel {
    /// The daemon applies its own configured label.
    #[default]
    Default,
    /// The job gets an empty label.
    Empty,
    /// The job gets this label.
    Text(String),
}

/// Ask a running daemon to run `argv`, with this process's stdio.  The
/// socket owner must be this process's euid or root.
pub fn run_remote(socket: &Path, label: RemoteLabel, argv: &[OsString]) -> io::Result<ExitState> {
    run_remote_as(socket, None, label, argv)
}

/// Like [`run_remote`].  With `Some(uid)` the socket owner must be exactly
/// `uid`.  With `None` the owner must be this process's euid or root.
pub fn run_remote_as(
    socket: &Path,
    expected_uid: Option<u32>,
    label: RemoteLabel,
    argv: &[OsString],
) -> io::Result<ExitState> {
    check_label_text(&label)?;
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
    }
    let mut stream = UnixStream::connect(socket)?;
    let (owner_uid, _gid) = peer_cred(stream.as_raw_fd())?;
    let me = unsafe { libc::geteuid() };
    let owner_ok = match expected_uid {
        Some(want) => owner_uid == want,
        None => owner_uid == me || owner_uid == 0,
    };
    if !owner_ok {
        let want = match expected_uid {
            Some(want) => format!("uid {}", want),
            None => format!("uid {} or root", me),
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the daemon at {} runs as uid {}, expected {}; refusing to send the command",
                socket.display(),
                owner_uid,
                want
            ),
        ));
    }
    let fds = [0 as RawFd, 1, 2];
    send_fds(stream.as_raw_fd(), &fds)?;
    write_request(&mut stream, &label, argv)?;
    let (st, msg) = read_response(&mut stream)?;
    if !msg.is_empty() {
        eprintln!("{}", msg);
    }
    Ok(st)
}

/// Protocol version carried in the first byte of the connection.
pub const PROTOCOL_VERSION: u8 = 2;
/// Version byte of the old protocol (it sent `'C'`).
const OLD_BANNER: u8 = b'C';
pub const MAGIC: &[u8; 4] = b"CMK2";
pub const MAX_ARGC: u32 = 4096;
pub const MAX_ARG: u32 = 1 << 20;
pub const MAX_REQUEST: usize = 8 << 20;
/// Longest label the daemon accepts, in bytes.
pub const MAX_LABEL: usize = 4096;
/// Default cap on the sum of `len + 1` over the job arguments.
pub const MAX_JOB_ARGV: usize = 1 << 20;
/// Bytes kept free in the redaction block for the entries the size
/// precheck does not count (pointer arrays and alignment).
pub const REDACTION_MARGIN: usize = 64 << 10;
/// Number of descriptors a client must send.
const CLIENT_FDS: usize = 3;
/// Response code for a refused or failed request.
const CODE_REFUSED: i32 = 255;

const LABEL_DEFAULT: u8 = 0;
const LABEL_EMPTY: u8 = 1;
const LABEL_TEXT: u8 = 2;

/// Server configuration.
#[derive(Clone)]
pub struct DaemonConfig {
    pub socket: PathBuf,
    /// Presentation label for a job whose client sends no label.
    pub label: String,
    /// Environment every job runs with (see [`job_env`]).
    pub env: Vec<(OsString, OsString)>,
    /// Leave `/proc/<pid>/environ` visible for jobs.
    pub keep_env: bool,
    /// Extra uids allowed to connect (the daemon's uid and root always are).
    pub allow_uids: Vec<u32>,
    /// Socket permission bits, e.g. 0o600.
    pub socket_mode: u32,
    /// Seconds for each read or write on a client socket; 0 means none.
    pub io_timeout_secs: u64,
    /// Seconds a job may run; 0 means no limit.
    pub job_timeout_secs: u64,
    /// Run each job as the uid and gid of its client (root daemon only).
    pub run_as_uid: bool,
    /// Largest number of concurrent jobs; 1 runs jobs in the daemon itself.
    pub jobs: usize,
    /// Cap on the sum of `len + 1` over the job arguments.
    pub max_job_bytes: usize,
    pub verbose: bool,
    pub quiet: bool,
}

impl DaemonConfig {
    pub fn new() -> DaemonConfig {
        DaemonConfig {
            socket: default_socket(),
            label: "confmask-job".to_string(),
            env: Vec::new(),
            keep_env: false,
            allow_uids: Vec::new(),
            socket_mode: 0o600,
            io_timeout_secs: 30,
            job_timeout_secs: 0,
            run_as_uid: false,
            jobs: 1,
            max_job_bytes: MAX_JOB_ARGV,
            verbose: false,
            quiet: false,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig::new()
    }
}

/// True when `dir` is a directory owned by the euid that group and other
/// cannot write to.
fn dir_is_private(dir: &Path) -> bool {
    match std::fs::metadata(dir) {
        Ok(md) => {
            let euid = unsafe { libc::geteuid() };
            md.is_dir() && md.uid() == euid && md.mode() & 0o022 == 0
        }
        Err(_) => false,
    }
}

/// `$XDG_RUNTIME_DIR/confmask.sock` when that directory is private to the
/// euid, else `/run/confmask.sock` for root, else
/// `/tmp/confmask-<uid>.sock`.
pub fn default_socket() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir_is_private(&dir) {
            return dir.join("confmask.sock");
        }
    }
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        PathBuf::from("/run/confmask.sock")
    } else {
        PathBuf::from(format!("/tmp/confmask-{}.sock", uid))
    }
}

// ------------------------------------------------------------ env file --

fn env_line_error(path: &Path, line: usize, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}:{}: {}", path.display(), line, what),
    )
}

/// Parse an environment file.
///
/// Grammar, one entry per line:
///
/// * A blank line or a line whose first non-blank byte is `#` is skipped.
/// * `KEY=VALUE` or `export KEY=VALUE`.
/// * `KEY` has printable ASCII bytes only (0x21 to 0x7e), no space and no
///   `=`, and is not empty.
/// * `VALUE` loses leading and trailing blanks.  When it then starts and
///   ends with the same quote (`'` or `"`), the quotes are removed and the
///   text between them is kept as it is.  There is no escape processing.
/// * A NUL byte anywhere in a line is an error.
///
/// Every error names the file and the line (`file:line: message`).
pub fn parse_env_file(path: &Path) -> io::Result<Vec<(OsString, OsString)>> {
    let mut text = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?;
    let result = parse_env_text(path, &text);
    wipe_bytes(&mut text);
    result
}

fn parse_env_text(path: &Path, text: &[u8]) -> io::Result<Vec<(OsString, OsString)>> {
    let mut out = Vec::new();
    for (index, raw) in text.split(|&b| b == b'\n').enumerate() {
        let lineno = index + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.contains(&0) {
            return Err(env_line_error(path, lineno, "line contains a NUL byte"));
        }
        let mut body = trim(line);
        if body.is_empty() || body[0] == b'#' {
            continue;
        }
        if body.starts_with(b"export") && body.len() > 6 && body[6].is_ascii_whitespace() {
            body = trim(&body[6..]);
        }
        let Some(eq) = body.iter().position(|&b| b == b'=') else {
            return Err(env_line_error(path, lineno, "expected KEY=VALUE"));
        };
        let key = &body[..eq];
        if key.is_empty() {
            return Err(env_line_error(path, lineno, "empty key"));
        }
        if let Some(bad) = key.iter().find(|&&b| !(0x21..=0x7e).contains(&b)) {
            let what = if *bad == b' ' || *bad == b'\t' {
                "key contains a space".to_string()
            } else {
                format!("key contains a non-printable byte (0x{:02x})", bad)
            };
            return Err(env_line_error(path, lineno, &what));
        }
        let value = unquote(trim(&body[eq + 1..]));
        out.push((
            OsString::from_vec(key.to_vec()),
            OsString::from_vec(value.to_vec()),
        ));
    }
    Ok(out)
}

/// Remove one level of matching quotes.
fn unquote(v: &[u8]) -> &[u8] {
    if v.len() >= 2 {
        let first = v[0];
        if (first == b'"' || first == b'\'') && v[v.len() - 1] == first {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &b[start..end]
}

/// True when group or other can read the file (mode bits 0o044).
pub fn env_file_readable_by_others(path: &Path) -> io::Result<bool> {
    let md = std::fs::metadata(path)?;
    Ok(md.mode() & 0o044 != 0)
}

// ---------------------------------------------------------- secret store --

/// Overwrite the bytes with zeros in a way the compiler keeps.
fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b is a valid, exclusive reference to one byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn wipe_os_string(s: &mut OsString) {
    let mut bytes = std::mem::take(s).into_vec();
    wipe_bytes(&mut bytes);
}

/// Overwrite every name and value with zeros and empty the list.
pub fn wipe_env(env: &mut Vec<(OsString, OsString)>) {
    for (k, v) in env.iter_mut() {
        wipe_os_string(k);
        wipe_os_string(v);
    }
    env.clear();
}

/// Lock the memory of every name and value with `mlock`.  Returns the
/// number of buffers the kernel refused to lock.
pub fn lock_env(env: &[(OsString, OsString)]) -> usize {
    let mut failures = 0usize;
    for (k, v) in env {
        for s in [k, v] {
            let bytes = s.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            // SAFETY: the pointer and length describe a live buffer.
            let rc = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
            if rc != 0 {
                failures += 1;
            }
        }
    }
    failures
}

// ------------------------------------------------------------- framing --

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_bytes(r: &mut impl Read, len: usize, budget: &mut usize) -> io::Result<Vec<u8>> {
    if len > *budget {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request too large",
        ));
    }
    *budget -= len;
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn check_label_text(label: &RemoteLabel) -> io::Result<()> {
    if let RemoteLabel::Text(t) = label {
        if t.len() > MAX_LABEL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("label is {} bytes, the limit is {}", t.len(), MAX_LABEL),
            ));
        }
        crate::mask::validate_label(t)?;
    }
    Ok(())
}

/// Read the request frame.  Returns `(label, argv)`.
pub fn read_request(r: &mut impl Read) -> io::Result<(RemoteLabel, Vec<OsString>)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad magic (protocol mismatch?)",
        ));
    }
    let mut mode = [0u8; 1];
    r.read_exact(&mut mode)?;
    let label_len = read_u32(r)? as usize;
    if label_len > MAX_LABEL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("label is {} bytes, the limit is {}", label_len, MAX_LABEL),
        ));
    }
    let mut budget = MAX_REQUEST;
    let label_bytes = read_bytes(r, label_len, &mut budget)?;
    let label = match mode[0] {
        LABEL_DEFAULT | LABEL_EMPTY => {
            if label_len != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "label bytes sent with a label mode that has none",
                ));
            }
            if mode[0] == LABEL_DEFAULT {
                RemoteLabel::Default
            } else {
                RemoteLabel::Empty
            }
        }
        LABEL_TEXT => {
            let text = String::from_utf8(label_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "label is not valid UTF-8")
            })?;
            RemoteLabel::Text(text)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown label mode {}", other),
            ));
        }
    };
    check_label_text(&label).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let argc = read_u32(r)?;
    if argc > MAX_ARGC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "argc too large"));
    }
    let mut argv = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let len = read_u32(r)?;
        if len > MAX_ARG {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "argument too large"));
        }
        argv.push(OsString::from_vec(read_bytes(r, len as usize, &mut budget)?));
    }
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty argv"));
    }
    Ok((label, argv))
}

/// Write the request frame.
pub fn write_request(w: &mut impl Write, label: &RemoteLabel, argv: &[OsString]) -> io::Result<()> {
    check_label_text(label)?;
    w.write_all(MAGIC)?;
    match label {
        RemoteLabel::Default => {
            w.write_all(&[LABEL_DEFAULT])?;
            write_u32(w, 0)?;
        }
        RemoteLabel::Empty => {
            w.write_all(&[LABEL_EMPTY])?;
            write_u32(w, 0)?;
        }
        RemoteLabel::Text(t) => {
            w.write_all(&[LABEL_TEXT])?;
            write_u32(w, t.len() as u32)?;
            w.write_all(t.as_bytes())?;
        }
    }
    write_u32(w, argv.len() as u32)?;
    for a in argv {
        let b = a.as_bytes();
        write_u32(w, b.len() as u32)?;
        w.write_all(b)?;
    }
    Ok(())
}

/// Read the response frame.
pub fn read_response(r: &mut impl Read) -> io::Result<(ExitState, String)> {
    let mut code = [0u8; 4];
    r.read_exact(&mut code)?;
    let code = i32::from_le_bytes(code);
    let has_signal = read_u32(r)?;
    let mut sig = [0u8; 4];
    r.read_exact(&mut sig)?;
    let sig = i32::from_le_bytes(sig);
    let mut budget = MAX_REQUEST;
    let msg_len = read_u32(r)? as usize;
    let msg = String::from_utf8_lossy(&read_bytes(r, msg_len, &mut budget)?).into_owned();
    Ok((
        ExitState::plain(code, if has_signal != 0 { Some(sig) } else { None }),
        msg,
    ))
}

/// Write the response frame in one write.
pub fn write_response(w: &mut impl Write, st: ExitState, msg: &str) -> io::Result<()> {
    let mut frame = Vec::with_capacity(16 + msg.len());
    frame.extend_from_slice(&st.code.to_le_bytes());
    frame.extend_from_slice(&(if st.signal.is_some() { 1u32 } else { 0u32 }).to_le_bytes());
    frame.extend_from_slice(&st.signal.unwrap_or(0).to_le_bytes());
    frame.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    frame.extend_from_slice(msg.as_bytes());
    w.write_all(&frame)
}

// ----------------------------------------------------------- fd passing --

fn send_fds(sock: RawFd, fds: &[RawFd]) -> io::Result<()> {
    let mut payload = [PROTOCOL_VERSION];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of_val(fds),
        );
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// What the first message of a connection carried.
struct FirstMessage {
    /// The version byte.
    version: u8,
    /// Received descriptors.  Each has `FD_CLOEXEC`.
    fds: Vec<RawFd>,
    /// The kernel dropped control data that did not fit (`MSG_CTRUNC`).
    truncated: bool,
}

/// Receive the version byte and at most `max` descriptors.
fn recv_first(sock: RawFd, max: usize) -> io::Result<FirstMessage> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE((max * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
    }
    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = bytes / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    fds.push(std::ptr::read_unaligned(data.add(i)));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(FirstMessage {
        version: payload[0],
        fds,
        truncated: msg.msg_flags & libc::MSG_CTRUNC != 0,
    })
}

/// Uid and gid of the process that created the other end of the socket.
fn peer_cred(sock: RawFd) -> io::Result<(u32, u32)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.gid))
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open `/dev/null` on each of 0, 1 and 2 that is closed, so that a job
/// never gets a descriptor number below 3 that belongs to something else.
pub fn ensure_stdio_open() -> io::Result<()> {
    for fd in 0..3 as RawFd {
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        if open {
            continue;
        }
        let path = b"/dev/null\0";
        let n = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n != fd {
            let rc = unsafe { libc::dup2(n, fd) };
            unsafe { libc::close(n) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------------- server --

/// Set by `SIGTERM` and `SIGINT`.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install the shutdown handler without `SA_RESTART` for `poll` (poll never
/// restarts) and with it for everything else, so a tracer thread that
/// receives the signal does not see `EINTR` from `waitpid`.
fn install_signal_handlers() -> io::Result<()> {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };
        sa.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn log_line(cfg: &DaemonConfig, text: &str) {
    if !cfg.quiet {
        eprintln!("confmaskd: {}", text);
    }
}

/// Restores the previous umask when dropped.
struct UmaskGuard {
    old: libc::mode_t,
}

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> UmaskGuard {
        let old = unsafe { libc::umask(mask) };
        UmaskGuard { old }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.old);
        }
    }
}

fn path_error(path: &Path, what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {}: {}", path.display(), what, e))
}

fn refuse_start(kind: io::ErrorKind, text: String) -> io::Error {
    io::Error::new(kind, format!("refusing to start: {}", text))
}

/// Check the socket path before `bind`.  A symbolic link, a file that is
/// not a socket and a socket with a live daemon are errors.  A socket
/// that refuses connections is stale and is unlinked.
fn prepare_socket_path(path: &Path) -> io::Result<()> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(path_error(path, "cannot inspect the socket path", e)),
    };
    let ft = md.file_type();
    if ft.is_symlink() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    if !ft.is_socket() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            format!("{} exists and is not a socket", path.display()),
        ));
    }
    match UnixStream::connect(path) {
        Ok(_probe) => Err(refuse_start(
            io::ErrorKind::AddrInUse,
            format!("another daemon is already listening on {}", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(path_error(path, "cannot remove the stale socket", e)),
            }
        }
        Err(e) => Err(refuse_start(
            e.kind(),
            format!(
                "cannot tell whether the socket {} is stale ({})",
                path.display(),
                e
            ),
        )),
    }
}

/// A bound listener and the identity of its socket file.
struct BoundSocket {
    listener: UnixListener,
    dev: u64,
    ino: u64,
}

fn bind_socket(cfg: &DaemonConfig) -> io::Result<BoundSocket> {
    let _umask = UmaskGuard::set(0o077);
    if let Some(dir) = cfg.socket.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)
                .map_err(|e| path_error(dir, "cannot create the socket directory", e))?;
        }
    }
    prepare_socket_path(&cfg.socket)?;
    let listener = UnixListener::bind(&cfg.socket)
        .map_err(|e| path_error(&cfg.socket, "cannot bind", e))?;
    set_cloexec(listener.as_raw_fd())?;

    let euid = unsafe { libc::geteuid() };
    let first = std::fs::symlink_metadata(&cfg.socket)
        .map_err(|e| path_error(&cfg.socket, "cannot inspect the new socket", e))?;
    if !first.file_type().is_socket() || first.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: the file after bind is not a socket owned by uid {}",
                cfg.socket.display(),
                euid
            ),
        ));
    }
    set_mode(&cfg.socket, cfg.socket_mode)?;
    let second = std::fs::symlink_metadata(&cfg.socket)
        .map_err(|e| path_error(&cfg.socket, "cannot inspect the new socket", e))?;
    if second.dev() != first.dev() || second.ino() != first.ino() || !second.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: the socket was replaced while starting", cfg.socket.display()),
        ));
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| path_error(&cfg.socket, "cannot set non-blocking mode", e))?;
    Ok(BoundSocket { listener, dev: first.dev(), ino: first.ino() })
}

/// Remove the socket file when it is still the one this daemon bound.
fn remove_own_socket(cfg: &DaemonConfig, bound: &BoundSocket) {
    if let Ok(md) = std::fs::symlink_metadata(&cfg.socket) {
        if md.file_type().is_socket() && md.dev() == bound.dev && md.ino() == bound.ino {
            let _ = std::fs::remove_file(&cfg.socket);
        }
    }
}

/// Bind and serve until `SIGTERM` or `SIGINT`.  With `jobs == 1` one job
/// runs at a time inside this process.  With `jobs > 1` a forked worker
/// handles each connection.
pub fn serve(mut cfg: DaemonConfig) -> io::Result<()> {
    ensure_stdio_open()?;
    let me = unsafe { libc::geteuid() };
    if cfg.jobs == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "--jobs needs a number of at least 1"));
    }
    if cfg.run_as_uid && me != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--run-as-uid needs a daemon that runs as root",
        ));
    }
    crate::mask::validate_label(&cfg.label)?;
    install_signal_handlers()?;
    let bound = bind_socket(&cfg)?;

    let unlocked = lock_env(&cfg.env);
    if unlocked > 0 {
        log_line(
            &cfg,
            &format!("warning: mlock failed for {} environment buffers", unlocked),
        );
    }
    log_line(
        &cfg,
        &format!(
            "listening on {} (uid {}, label '{}', {} env var{}, {} job slot{})",
            cfg.socket.display(),
            me,
            escape_for_log(&cfg.label, 64),
            cfg.env.len(),
            if cfg.env.len() == 1 { "" } else { "s" },
            cfg.jobs,
            if cfg.jobs == 1 { "" } else { "s" }
        ),
    );

    let result = accept_loop(&cfg, &bound.listener, me);

    wipe_env(&mut cfg.env);
    remove_own_socket(&cfg, &bound);
    log_line(&cfg, "stopped");
    result
}

fn accept_loop(cfg: &DaemonConfig, listener: &UnixListener, me: u32) -> io::Result<()> {
    let lfd = listener.as_raw_fd();
    let mut workers: Vec<libc::pid_t> = Vec::new();
    while !SHUTDOWN.load(Ordering::SeqCst) {
        reap_workers(&mut workers);
        let full = cfg.jobs > 1 && workers.len() >= cfg.jobs;
        let mut pfd = libc::pollfd { fd: lfd, events: libc::POLLIN, revents: 0 };
        let rc = if full {
            unsafe { libc::poll(&mut pfd, 0, 200) }
        } else {
            unsafe { libc::poll(&mut pfd, 1, 500) }
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                log_line(cfg, &format!("poll: {}", e));
                std::thread::sleep(Duration::from_millis(200));
            }
            continue;
        }
        if rc == 0 || full {
            continue;
        }
        let stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => {
                log_line(cfg, &format!("accept: {}", e));
                continue;
            }
        };
        if let Err(e) = stream.set_nonblocking(false) {
            log_line(cfg, &format!("accepted socket: {}", e));
            continue;
        }
        if cfg.jobs <= 1 {
            report_conn(cfg, handle_conn(cfg, stream, me));
            continue;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            log_line(cfg, &format!("fork: {}", io::Error::last_os_error()));
            let mut stream = stream;
            reject(&mut stream, "confmaskd: cannot start a worker");
            continue;
        }
        if pid == 0 {
            unsafe { libc::close(lfd) };
            report_conn(cfg, handle_conn(cfg, stream, me));
            unsafe { libc::_exit(0) };
        }
        drop(stream);
        workers.push(pid);
    }
    stop_workers(&mut workers);
    Ok(())
}

fn report_conn(cfg: &DaemonConfig, r: io::Result<()>) {
    if let Err(e) = r {
        if e.kind() == io::ErrorKind::UnexpectedEof && !cfg.verbose {
            return;
        }
        log_line(cfg, &format!("connection: {}", e));
    }
}

/// Collect finished workers without blocking.
fn reap_workers(workers: &mut Vec<libc::pid_t>) {
    workers.retain(|&pid| {
        let mut status = 0 as libc::c_int;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        rc == 0
    });
}

/// Ask every worker to stop and wait for it.
fn stop_workers(workers: &mut Vec<libc::pid_t>) {
    for &pid in workers.iter() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    for &pid in workers.iter() {
        let mut status = 0 as libc::c_int;
        loop {
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc >= 0 {
                break;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
    workers.clear();
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad socket path"))?;
    let rc = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
    if rc < 0 {
        return Err(path_error(path, "cannot set the socket mode", io::Error::last_os_error()));
    }
    Ok(())
}

/// Text that is safe to put in a log line: printable ASCII stays, every
/// other byte becomes `\xNN`, and the result is cut at `limit` bytes.
pub fn escape_for_log(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if out.len() >= limit {
            out.push_str("...");
            break;
        }
        if (0x20..=0x7e).contains(&b) && b != b'\\' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}

/// Send a refusal and close the connection.  The daemon half-closes and
/// reads what the client still sends, so the client reads the refusal
/// instead of a connection reset.
fn reject(stream: &mut UnixStream, msg: &str) {
    let _ = write_response(stream, ExitState::plain(CODE_REFUSED, None), msg);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    while total < MAX_REQUEST {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}

fn close_all(fds: &[RawFd]) {
    for &fd in fds {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Size checks that run before the job starts.  The redaction block holds
/// the real argv, the environment and comm; a job that does not fit would
/// run with its environment visible, so it is refused.
fn check_job_size(cfg: &DaemonConfig, label: &str, argv: &[OsString]) -> Result<(), String> {
    let argv_bytes: usize = argv.iter().map(|a| a.len() + 1).sum();
    if argv_bytes > cfg.max_job_bytes {
        return Err(format!(
            "job arguments are {} bytes, the limit is {}",
            argv_bytes, cfg.max_job_bytes
        ));
    }
    let env_bytes: usize = cfg.env.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    let comm_bytes = label.len().min(crate::COMM_MAX) + 1;
    let need = argv_bytes + env_bytes + comm_bytes + REDACTION_MARGIN;
    if need > crate::MAX_HIDDEN {
        return Err(format!(
            "the redaction block would need {} bytes, the limit is {}",
            need,
            crate::MAX_HIDDEN
        ));
    }
    Ok(())
}

fn handle_conn(cfg: &DaemonConfig, mut stream: UnixStream, daemon_uid: u32) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let timeout = if cfg.io_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(cfg.io_timeout_secs))
    };
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    let (uid, gid) = peer_cred(fd)?;
    let allowed = uid == daemon_uid || uid == 0 || cfg.allow_uids.contains(&uid);
    if !allowed {
        reject(&mut stream, &format!("confmaskd: uid {} is not allowed", uid));
        return Ok(());
    }

    let first = recv_first(fd, CLIENT_FDS)?;
    if first.version != PROTOCOL_VERSION {
        close_all(&first.fds);
        let msg = if first.version == OLD_BANNER {
            format!(
                "confmaskd: protocol mismatch: the client speaks protocol 1, the daemon speaks protocol {}",
                PROTOCOL_VERSION
            )
        } else {
            format!(
                "confmaskd: unsupported protocol version {}, the daemon speaks protocol {}",
                first.version, PROTOCOL_VERSION
            )
        };
        reject(&mut stream, &msg);
        return Ok(());
    }
    if first.truncated {
        close_all(&first.fds);
        reject(
            &mut stream,
            "confmaskd: too many file descriptors (control data truncated); send exactly 3",
        );
        return Ok(());
    }
    if first.fds.len() != CLIENT_FDS {
        let got = first.fds.len();
        close_all(&first.fds);
        reject(
            &mut stream,
            &format!("confmaskd: expected exactly 3 file descriptors, got {}", got),
        );
        return Ok(());
    }

    let (label, argv) = match read_request(&mut stream) {
        Ok(v) => v,
        Err(e) => {
            close_all(&first.fds);
            reject(&mut stream, &format!("confmaskd: bad request: {}", e));
            return Ok(());
        }
    };
    let label_text = match &label {
        RemoteLabel::Default => cfg.label.clone(),
        RemoteLabel::Empty => String::new(),
        RemoteLabel::Text(t) => t.clone(),
    };
    if let Err(why) = check_job_size(cfg, &label_text, &argv) {
        close_all(&first.fds);
        reject(&mut stream, &format!("confmaskd: job refused: {}", why));
        return Ok(());
    }

    if cfg.verbose {
        log_line(
            cfg,
            &format!(
                "uid {} job label '{}' ({} args)",
                uid,
                escape_for_log(&label_text, 64),
                argv.len()
            ),
        );
    }

    match run_job(cfg, uid, gid, &label_text, &argv, &first.fds) {
        Ok((state, msg)) => write_response(&mut stream, state, &msg),
        Err(e) => {
            let msg = format!("confmaskd: {}", e);
            write_response(&mut stream, ExitState::plain(CODE_REFUSED, None), &msg)
        }
    }
}

/// Copy descriptors 0, 1 and 2 to descriptors above 2 with `FD_CLOEXEC`.
fn save_stdio() -> io::Result<Vec<RawFd>> {
    let mut saved = Vec::new();
    for fd in 0..3 as RawFd {
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            let e = io::Error::last_os_error();
            close_all(&saved);
            return Err(e);
        }
        saved.push(copy);
    }
    Ok(saved)
}

fn restore_stdio(saved: &[RawFd]) {
    for (i, &fd) in saved.iter().enumerate() {
        unsafe {
            libc::dup2(fd, i as RawFd);
            libc::close(fd);
        }
    }
}

/// Start one job with the client's stdio on descriptors 0, 1 and 2 and
/// wait for it.  The daemon closes the received descriptors before the
/// job starts, and puts its own 0, 1 and 2 back as soon as the fork is
/// done.  Returns the terminal state and an optional message.
fn run_job(
    cfg: &DaemonConfig,
    uid: u32,
    gid: u32,
    label: &str,
    argv: &[OsString],
    fds: &[RawFd],
) -> io::Result<(ExitState, String)> {
    let saved = match save_stdio() {
        Ok(s) => s,
        Err(e) => {
            close_all(fds);
            return Err(e);
        }
    };
    for (i, &fd) in fds.iter().enumerate() {
        if unsafe { libc::dup2(fd, i as RawFd) } < 0 {
            let e = io::Error::last_os_error();
            close_all(fds);
            restore_stdio(&saved);
            return Err(e);
        }
    }
    close_all(fds);

    let mut mask = Mask::new()
        .label(label)
        .envs(cfg.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    // Job diagnostics belong to the daemon's log, and only when the
    // daemon is verbose: a job that degrades is still reported by the
    // response frame's empty message and the exit status.
    if !cfg.verbose {
        mask = mask.quiet();
    }
    if cfg.keep_env {
        mask = mask.keep_environ_visible();
    }
    if cfg.run_as_uid {
        mask = mask.run_as(uid, gid);
    }
    let rest: Vec<OsString> = argv[1..].to_vec();
    let spawned = mask.spawn(&argv[0], &rest);
    restore_stdio(&saved);
    wait_job(cfg, spawned?)
}

/// Wait for the job.  Kills the whole tree at `--job-timeout` and at
/// daemon shutdown.
fn wait_job(cfg: &DaemonConfig, mut child: MaskedChild) -> io::Result<(ExitState, String)> {
    let deadline = if cfg.job_timeout_secs == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(cfg.job_timeout_secs))
    };
    loop {
        if let Some(state) = child.wait_timeout(Duration::from_millis(250))? {
            return Ok((state, String::new()));
        }
        let timed_out = deadline.is_some_and(|d| Instant::now() >= d);
        let stopping = SHUTDOWN.load(Ordering::SeqCst);
        if timed_out || stopping {
            child.kill_tree();
            let _ = child.wait_timeout(Duration::from_secs(10));
            let msg = if timed_out {
                format!(
                    "confmaskd: job exceeded --job-timeout {} s and was killed",
                    cfg.job_timeout_secs
                )
            } else {
                "confmaskd: daemon is shutting down, job killed".to_string()
            };
            return Ok((ExitState::plain(137, Some(libc::SIGKILL)), msg));
        }
    }
}

/// Build the job environment.  With `inherit` the daemon's own
/// environment comes first and `overrides` replace or extend it.  Without
/// `inherit` the job gets `overrides` only.
pub fn job_env(inherit: bool, overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = if inherit {
        std::env::vars_os().collect()
    } else {
        Vec::new()
    };
    for (k, v) in overrides {
        match out.iter_mut().find(|(ek, _)| ek == k) {
            Some(slot) => slot.1 = v.clone(),
            None => out.push((k.clone(), v.clone())),
        }
    }
    out
}

/// Inherited environment overridden by `--env-file` entries.
pub fn merged_env(overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    job_env(true, overrides)
}

/// Convenience: the argv vector a client sends.
pub fn client_argv(program: &OsStr, args: &[OsString]) -> Vec<OsString> {
    let mut v = Vec::with_capacity(args.len() + 1);
    v.push(program.to_os_string());
    v.extend_from_slice(args);
    v
}
