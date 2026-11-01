//! Kernel audit observer for `tests/audit.sh`.
//!
//! Subcommand: `auditwatch SECONDS OUTFILE`.
//!
//! The command registers as the kernel audit daemon over a NETLINK_AUDIT
//! socket, installs an exit-list rule for execve and execveat, and writes
//! every EXECVE, PROCTITLE and SYSCALL record text to OUTFILE, one record
//! per line. A PROCTITLE record that carries hex gets an extra line that
//! starts with `DECODED ` (hex turned into bytes, NUL turned into space).
//! The command stops after SECONDS, when the file `OUTFILE.stop` exists,
//! or on SIGTERM or SIGINT. On exit it removes the rule, releases the
//! daemon registration and restores the previous enabled flag.
//!
//! The command writes the file `OUTFILE.ready` when the observer is live.
//! The content is one line:
//!
//! - `ok`: the observer is live.
//! - `skip: REASON`: the socket or the rule is not available (no audit
//!   support, no privilege). The command exits with status 1.
//! - `fail: REASON`: another audit daemon is registered (EEXIST). The
//!   command exits with status 1.
//!
//! What this observer proves: the kernel audit subsystem reports, for each
//! execve and execveat it saw, the argument vector that the kernel holds
//! for the new image when the syscall returns. The kernel writes the
//! record before the ptrace syscall-exit stop, so the tracer has not yet
//! changed anything. A masked exec that shows only the label in these
//! records shows that the kernel never copied the real arguments. A
//! control run without masking that shows the real arguments proves that
//! the observer can see them.
//!
//! What this observer does not prove:
//!
//! - It does not prove behaviour on another kernel, another architecture
//!   or another audit configuration. The syscall numbers in the rule are
//!   the x86-64 numbers (59 and 322).
//! - The results were observed on the Alpine linux-virt 6.12 kernel in the
//!   QEMU VM harness under TCG emulation. They carry no statement about
//!   native hardware or other kernels.
//! - Audit records do not contain the environment. The observer says
//!   nothing about environ.
//! - Script execs are an exception. The kernel copies the real argument
//!   vector for a script exec, so the record can show it.
//! - The record is taken once, when the exec syscall returns. It does not
//!   show what a process reads from /proc later.
//! - Only one audit daemon can be registered at a time. The observer
//!   cannot run next to auditd.

use std::fs::{self, File};
use std::io::{self, Write};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// Message types from <linux/audit.h>.
const AUDIT_GET: u16 = 1000;
const AUDIT_SET: u16 = 1001;
const AUDIT_ADD_RULE: u16 = 1011;
const AUDIT_DEL_RULE: u16 = 1012;
const AUDIT_SYSCALL: u16 = 1300;
const AUDIT_EXECVE: u16 = 1309;
const AUDIT_PROCTITLE: u16 = 1327;

// audit_status mask bits.
const AUDIT_STATUS_ENABLED: u32 = 0x0001;
const AUDIT_STATUS_PID: u32 = 0x0004;

// Rule list and action.
const AUDIT_FILTER_EXIT: u32 = 0x04;
const AUDIT_ALWAYS: u32 = 2;
const AUDIT_BITMASK_SIZE: usize = 64;
const AUDIT_MAX_FIELDS: usize = 64;

// Netlink constants.
const NETLINK_AUDIT: libc::c_int = 9;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLMSG_HDRLEN: usize = 16;

// x86-64 syscall numbers.
const SYS_EXECVE: usize = 59;
const SYS_EXECVEAT: usize = 322;

/// struct audit_status from <linux/audit.h> (11 u32 fields, 44 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct AuditStatus {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limit: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
    feature_bitmap: u32,
    backlog_wait_time: u32,
    backlog_wait_time_actual: u32,
}

const _: () = assert!(mem::size_of::<AuditStatus>() == 44);

/// struct audit_rule_data from <linux/audit.h> without the trailing
/// flexible buf[] member.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct AuditRuleData {
    flags: u32,
    action: u32,
    field_count: u32,
    mask: [u32; AUDIT_BITMASK_SIZE],
    fields: [u32; AUDIT_MAX_FIELDS],
    values: [u32; AUDIT_MAX_FIELDS],
    fieldflags: [u32; AUDIT_MAX_FIELDS],
    buflen: u32,
}

const _: () = assert!(mem::size_of::<AuditRuleData>() == 1040);
const _: () = assert!(mem::align_of::<AuditRuleData>() == 4);

/// struct sockaddr_nl, defined here so the layout does not depend on the
/// libc crate version.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrNl {
    nl_family: libc::sa_family_t,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

const _: () = assert!(mem::size_of::<SockaddrNl>() == 12);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Run subcommand `cmd`; `None` when it is not one of ours.
pub fn dispatch(cmd: &str, rest: &[String]) -> Option<i32> {
    match cmd {
        "auditwatch" => Some(auditwatch(rest)),
        _ => None,
    }
}

/// View a plain-data struct (u32 fields only, no padding) as bytes.
fn struct_bytes<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: T is a repr(C) struct made only of u32 values. Every byte
    // is initialised and the slice does not outlive the borrow.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>()) }
}

fn errno_text(errno: i32) -> String {
    format!("{} (errno {})", io::Error::from_raw_os_error(errno), errno)
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn rule_payload() -> AuditRuleData {
    let mut rule = AuditRuleData {
        flags: AUDIT_FILTER_EXIT,
        action: AUDIT_ALWAYS,
        field_count: 0,
        mask: [0u32; AUDIT_BITMASK_SIZE],
        fields: [0u32; AUDIT_MAX_FIELDS],
        values: [0u32; AUDIT_MAX_FIELDS],
        fieldflags: [0u32; AUDIT_MAX_FIELDS],
        buflen: 0,
    };
    for nr in [SYS_EXECVE, SYS_EXECVEAT] {
        rule.mask[nr / 32] |= 1u32 << (nr % 32);
    }
    rule
}

/// Audit record type name, as the kernel's own log would print it.
fn type_name(msg_type: u16) -> &'static str {
    match msg_type {
        AUDIT_SYSCALL => "SYSCALL",
        AUDIT_EXECVE => "EXECVE",
        AUDIT_PROCTITLE => "PROCTITLE",
        _ => "OTHER",
    }
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_ne_bytes(b)
}

fn u16_at(buf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    b.copy_from_slice(&buf[off..off + 2]);
    u16::from_ne_bytes(b)
}

/// An open audit socket plus the output file.
struct Watcher {
    fd: libc::c_int,
    seq: u32,
    out: File,
    status_reply: Option<Vec<u8>>,
    lines: u64,
}

impl Watcher {
    fn open(out: File) -> Result<Watcher, i32> {
        // SAFETY: plain syscall with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            )
        };
        if fd < 0 {
            return Err(last_errno());
        }
        let addr = SockaddrNl {
            nl_family: libc::AF_NETLINK as libc::sa_family_t,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        // SAFETY: addr is a valid sockaddr_nl and the length matches.
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrNl as *const libc::sockaddr,
                mem::size_of::<SockaddrNl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = last_errno();
            // SAFETY: fd is open and owned here.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Watcher {
            fd,
            seq: 0,
            out,
            status_reply: None,
            lines: 0,
        })
    }

    /// Wait up to `timeout_ms` for the socket to become readable.
    fn wait_readable(&self, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid single-element array.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        rc > 0 && (pfd.revents & libc::POLLIN) != 0
    }

    /// Receive one datagram and process every message in it. Returns the
    /// errno of an ack for `want_seq` when one is in the datagram.
    fn receive(&mut self, want_seq: Option<u32>) -> Option<i32> {
        let mut buf = vec![0u8; 65536];
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n <= 0 {
            return None;
        }
        let total = n as usize;
        let mut ack = None;
        let mut off = 0usize;
        while off + NLMSG_HDRLEN <= total {
            let len = u32_at(&buf, off) as usize;
            if len < NLMSG_HDRLEN || off + len > total {
                break;
            }
            let msg_type = u16_at(&buf, off + 4);
            let seq = u32_at(&buf, off + 8);
            let payload = &buf[off + NLMSG_HDRLEN..off + len];
            if std::env::var_os("CONFMASK_AUDIT_LEN").is_some() {
                let mut h = String::new();
                for b in payload.iter().take(64) {
                    h.push_str(&format!("{:02x}", b));
                }
                self.write_line(&format!(
                    "# mtype={} nlmsg_len={} payload_len={} head={}",
                    msg_type,
                    len,
                    payload.len(),
                    h
                ));
            }
            if msg_type == NLMSG_ERROR {
                if Some(seq) == want_seq && payload.len() >= 4 {
                    let raw = u32_at(payload, 0) as i32;
                    ack = Some(-raw);
                }
            } else if msg_type == AUDIT_GET {
                self.status_reply = Some(payload.to_vec());
            } else if msg_type == AUDIT_SYSCALL
                || msg_type == AUDIT_EXECVE
                || msg_type == AUDIT_PROCTITLE
            {
                // The record length in the netlink header is what the
                // kernel sent; it is logged so a truncated record is
                // visible instead of being mistaken for a short argv.
                if std::env::var_os("CONFMASK_AUDIT_LEN").is_some() {
                    self.write_line(&format!(
                        "# type={} nlmsg_len={} payload_len={}",
                        type_name(msg_type),
                        len,
                        payload.len()
                    ));
                }
                self.record(msg_type, payload);
            }
            // NLMSG_ALIGN is 4.
            off += (len + 3) & !3usize;
        }
        ack
    }

    fn write_line(&mut self, line: &str) {
        let mut text = String::with_capacity(line.len() + 1);
        text.push_str(line);
        text.push('\n');
        if self.out.write_all(text.as_bytes()).is_ok() {
            self.lines += 1;
        }
    }

    fn record(&mut self, msg_type: u16, payload: &[u8]) {
        let mut end = payload.len();
        while end > 0 && (payload[end - 1] == 0 || payload[end - 1] == b'\n') {
            end -= 1;
        }
        let payload = &payload[..end];
        // The kernel sends the record type in the netlink header, not in
        // the text, and NUL bytes separate the fields of an EXECVE record.
        // A text prefix makes the log greppable; a NUL is written as a
        // space so one record stays on one line.
        let mut line = String::with_capacity(payload.len() + 16);
        line.push_str(&format!("type={} ", type_name(msg_type)));
        for &b in payload {
            match b {
                0 | b'\n' => line.push(' '),
                _ => line.push(b as char),
            }
        }
        self.write_line(&line);
        if msg_type == AUDIT_PROCTITLE {
            if let Some(decoded) = decode_proctitle(&line) {
                self.write_line(&format!("DECODED {}", decoded));
            }
        }
    }

    /// Send one request with an ack flag and wait for the ack.
    fn request(&mut self, msg_type: u16, payload: &[u8]) -> Result<(), i32> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let len = NLMSG_HDRLEN + payload.len();
        let mut msg = Vec::with_capacity((len + 3) & !3usize);
        msg.extend_from_slice(&(len as u32).to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        while (msg.len() & 3) != 0 {
            msg.push(0);
        }
        let dest = SockaddrNl {
            nl_family: libc::AF_NETLINK as libc::sa_family_t,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        // SAFETY: msg and dest are valid for the given lengths.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &dest as *const SockaddrNl as *const libc::sockaddr,
                mem::size_of::<SockaddrNl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(last_errno());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !self.wait_readable(200) {
                continue;
            }
            if let Some(errno) = self.receive(Some(seq)) {
                return if errno == 0 { Ok(()) } else { Err(errno) };
            }
        }
        Err(libc::ETIMEDOUT)
    }

    fn set_status(&mut self, mask: u32, enabled: u32, pid: u32) -> Result<(), i32> {
        let status = AuditStatus {
            mask,
            enabled,
            failure: 0,
            pid,
            rate_limit: 0,
            backlog_limit: 0,
            lost: 0,
            backlog: 0,
            feature_bitmap: 0,
            backlog_wait_time: 0,
            backlog_wait_time_actual: 0,
        };
        self.request(AUDIT_SET, struct_bytes(&status))
    }

    /// Read the current enabled flag with AUDIT_GET.
    fn get_enabled(&mut self) -> Option<u32> {
        self.status_reply = None;
        self.request(AUDIT_GET, &[]).ok()?;
        // The kernel sends the status reply from a helper thread, so it
        // can arrive after the ack.
        let mut tries = 0;
        while self.status_reply.is_none() && tries < 10 {
            if self.wait_readable(100) {
                self.receive(None);
            }
            tries += 1;
        }
        let reply = self.status_reply.take()?;
        if reply.len() >= 8 {
            Some(u32_at(&reply, 4))
        } else {
            None
        }
    }

    /// Process messages until `deadline`, the stop file or a signal.
    fn pump(&mut self, deadline: Instant, stop_file: &str) {
        let c_stop = format!("{}\0", stop_file);
        while !STOP.load(Ordering::SeqCst) && Instant::now() < deadline {
            // SAFETY: c_stop is NUL terminated.
            let rc = unsafe { libc::access(c_stop.as_ptr() as *const libc::c_char, libc::F_OK) };
            if rc == 0 {
                break;
            }
            if self.wait_readable(100) {
                self.receive(None);
            }
        }
        // Drain what is still queued.
        let mut idle = 0;
        while idle < 3 {
            if self.wait_readable(150) {
                self.receive(None);
                idle = 0;
            } else {
                idle += 1;
            }
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: fd is open and owned by this struct.
        unsafe { libc::close(self.fd) };
    }
}

/// Decode `proctitle=HEX` into text. Returns None when the field is
/// missing, quoted (already text) or not valid hex.
fn decode_proctitle(line: &str) -> Option<String> {
    let start = line.find("proctitle=")? + "proctitle=".len();
    let value = line[start..].split_whitespace().next()?;
    if value.starts_with('"') || value.len() < 2 || (value.len() & 1) != 0 {
        return None;
    }
    let digits = value.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    let mut i = 0;
    while i < digits.len() {
        let hi = hex_val(digits[i])?;
        let lo = hex_val(digits[i + 1])?;
        let b = hi * 16 + lo;
        bytes.push(if b == 0 { b' ' } else { b });
        i += 2;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn write_ready(outfile: &str, text: &str) {
    let path = format!("{}.ready", outfile);
    if let Err(e) = fs::write(&path, format!("{}\n", text)) {
        eprintln!("auditwatch: cannot write {}: {}", path, e);
    }
}

fn auditwatch(rest: &[String]) -> i32 {
    if rest.len() != 2 {
        eprintln!("usage: auditwatch SECONDS OUTFILE");
        return 2;
    }
    let secs: u64 = match rest[0].parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("auditwatch: bad SECONDS: {}", rest[0]);
            return 2;
        }
    };
    let outfile = rest[1].as_str();
    // A stale marker from an earlier run must not stop or ready this run.
    let stop_file = format!("{}.stop", outfile);
    let _ = fs::remove_file(&stop_file);
    let _ = fs::remove_file(format!("{}.ready", outfile));
    let out = match File::create(outfile) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("auditwatch: cannot create {}: {}", outfile, e);
            return 2;
        }
    };

    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_stop_signal as extern "C" fn(libc::c_int) as usize,
        );
        libc::signal(
            libc::SIGINT,
            on_stop_signal as extern "C" fn(libc::c_int) as usize,
        );
    }

    let mut w = match Watcher::open(out) {
        Ok(w) => w,
        Err(errno) => {
            let msg = format!("skip: cannot open audit socket: {}", errno_text(errno));
            eprintln!("auditwatch: {}", msg);
            write_ready(outfile, &msg);
            return 1;
        }
    };

    let previous_enabled = w.get_enabled();
    // SAFETY: getpid has no preconditions.
    let my_pid = unsafe { libc::getpid() } as u32;
    if let Err(errno) = w.set_status(AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID, 1, my_pid) {
        let msg = if errno == libc::EEXIST {
            "fail: another audit daemon (auditd or similar) is already registered; stop it and run again"
                .to_string()
        } else {
            format!("skip: AUDIT_SET refused: {}", errno_text(errno))
        };
        eprintln!("auditwatch: {}", msg);
        write_ready(outfile, &msg);
        return 1;
    }

    let rule = rule_payload();
    let mut rule_added = false;
    match w.request(AUDIT_ADD_RULE, struct_bytes(&rule)) {
        Ok(()) => rule_added = true,
        Err(errno) if errno == libc::EEXIST => {
            // An identical rule exists. It already audits execs, and this
            // command must not delete a rule it did not add.
            eprintln!("auditwatch: identical rule already present, keeping it");
        }
        Err(errno) => {
            let msg = format!("skip: AUDIT_ADD_RULE refused: {}", errno_text(errno));
            eprintln!("auditwatch: {}", msg);
            write_ready(outfile, &msg);
            restore(&mut w, previous_enabled);
            return 1;
        }
    }

    write_ready(outfile, "ok");
    let deadline = Instant::now() + Duration::from_secs(secs);
    w.pump(deadline, &stop_file);

    if rule_added {
        if let Err(errno) = w.request(AUDIT_DEL_RULE, struct_bytes(&rule)) {
            eprintln!("auditwatch: AUDIT_DEL_RULE failed: {}", errno_text(errno));
        }
    }
    restore(&mut w, previous_enabled);
    eprintln!("auditwatch: wrote {} lines to {}", w.lines, outfile);
    0
}

/// Release the daemon registration and put the enabled flag back.
fn restore(w: &mut Watcher, previous_enabled: Option<u32>) {
    let result = match previous_enabled {
        Some(prev) if prev <= 1 => w.set_status(AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID, prev, 0),
        _ => w.set_status(AUDIT_STATUS_PID, 0, 0),
    };
    if let Err(errno) = result {
        eprintln!("auditwatch: restore failed: {}", errno_text(errno));
    }
}
