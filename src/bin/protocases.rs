//! `confmask-protocases`: raw-protocol client for the daemon negative
//! suite (`tests/daemon_neg.sh`).
//!
//! Usage: `confmask-protocases SUBCOMMAND SOCKET [ARGS...]`
//!
//! Every subcommand connects to SOCKET, sends one deliberately shaped
//! request and prints the daemon's response frame as one text line:
//!
//! ```text
//! response code=255 signal=none msg=confmaskd: expected exactly 3 ...
//! ```
//!
//! A connection that ends without a response prints `no-response`.
//! The exit status is 0 when a response arrived, 1 when none arrived,
//! 2 for a usage error and 3 when a setup call failed.
//!
//! Subcommands:
//!   valid SOCKET [ARGV...]       a correct request (default argv: /bin/true)
//!   bad-magic SOCKET             frame magic is not "CMK2"
//!   bad-version SOCKET BYTE      first byte is BYTE (a number, or "old")
//!   argc-4097 SOCKET             argc header above the limit
//!   arg-over-1mib SOCKET         one argument length above 1 MiB
//!   argv-sum-over SOCKET         two arguments, 1.2 MiB in total
//!   label-huge SOCKET            label length of 8 MiB
//!   label-hex SOCKET HEX         explicit label with these bytes
//!   truncated-frame SOCKET       half a frame, then end of stream
//!   connect-and-close SOCKET     connect and close at once
//!   fds SOCKET N [ARGV...]       send N descriptors (0 and 5 are errors)
//!   stall SOCKET                 send fds, then nothing; print the wait
//!   as-uid UID SOCKET [ARGV...]  drop to UID, then send a correct request

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 4] = b"CMK2";
const VERSION: u8 = 2;
const READ_LIMIT: Duration = Duration::from_secs(25);

fn usage(text: &str) -> ! {
    eprintln!("protocases: {}", text);
    exit(2);
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// A complete, correct request frame.
fn frame(label_mode: u8, label: &[u8], argv: &[Vec<u8>]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(MAGIC);
    f.push(label_mode);
    f.extend_from_slice(&u32le(label.len() as u32));
    f.extend_from_slice(label);
    f.extend_from_slice(&u32le(argv.len() as u32));
    for a in argv {
        f.extend_from_slice(&u32le(a.len() as u32));
        f.extend_from_slice(a);
    }
    f
}

/// Frame header up to and including `argc`, with no arguments.
fn header(label_mode: u8, label_len: u32, argc: u32) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(MAGIC);
    f.push(label_mode);
    f.extend_from_slice(&u32le(label_len));
    f.extend_from_slice(&u32le(argc));
    f
}

fn connect(path: &str) -> UnixStream {
    match UnixStream::connect(path) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(READ_LIMIT));
            s
        }
        Err(e) => {
            eprintln!("protocases: connect {}: {}", path, e);
            exit(3);
        }
    }
}

/// Send the version byte with `fds` as SCM_RIGHTS.  With no descriptors
/// the byte goes out as plain data.
fn send_first(stream: &UnixStream, version: u8, fds: &[i32]) {
    let sock = stream.as_raw_fd();
    let mut payload = [version];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let fd_bytes = std::mem::size_of_val(fds);
    let space = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }
    };
    let mut cbuf = vec![0u64; space.div_ceil(8) + 1];
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                fd_bytes,
            );
        }
    }
    let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
    if rc < 0 {
        eprintln!("protocases: sendmsg: {}", std::io::Error::last_os_error());
        exit(3);
    }
}

fn three_fds() -> Vec<i32> {
    vec![0, 1, 2]
}

/// Print the response frame.  Returns the process exit status.
fn print_response(stream: &mut UnixStream) -> i32 {
    let mut head = [0u8; 16];
    if stream.read_exact(&mut head).is_err() {
        println!("no-response");
        return 1;
    }
    let code = i32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let has_signal = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    let signal = i32::from_le_bytes([head[8], head[9], head[10], head[11]]);
    let msg_len = u32::from_le_bytes([head[12], head[13], head[14], head[15]]) as usize;
    let mut msg = vec![0u8; msg_len.min(1 << 20)];
    if stream.read_exact(&mut msg).is_err() {
        println!("no-response (truncated message)");
        return 1;
    }
    let text: String = String::from_utf8_lossy(&msg)
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
    let sig = if has_signal != 0 { signal.to_string() } else { "none".to_string() };
    println!("response code={} signal={} msg={}", code, sig, text);
    0
}

fn argv_from(args: &[String]) -> Vec<Vec<u8>> {
    if args.is_empty() {
        vec![b"/bin/true".to_vec()]
    } else {
        args.iter().map(|a| a.as_bytes().to_vec()).collect()
    }
}

fn hex_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        usage("HEX needs an even number of digits");
    }
    let mut out = Vec::new();
    for pair in bytes.chunks(2) {
        let s = std::str::from_utf8(pair).unwrap_or("zz");
        match u8::from_str_radix(s, 16) {
            Ok(b) => out.push(b),
            Err(_) => usage("HEX has a bad digit"),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage("usage: SUBCOMMAND SOCKET [ARGS...] (see the source header)");
    }
    let sub = args[0].as_str();
    if sub == "as-uid" {
        as_uid(&args[1..]);
    }
    let sock = args[1].as_str();
    let rest = &args[2..];
    let mut stream;
    match sub {
        "valid" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let _ = stream.write_all(&frame(0, b"", &argv_from(rest)));
        }
        "bad-magic" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let mut f = frame(0, b"", &argv_from(&[]));
            f[0..4].copy_from_slice(b"XXXX");
            let _ = stream.write_all(&f);
        }
        "bad-version" => {
            let byte = match rest.first().map(|s| s.as_str()) {
                Some("old") => b'C',
                Some(n) => match n.parse::<u8>() {
                    Ok(v) => v,
                    Err(_) => usage("bad-version needs BYTE or old"),
                },
                None => usage("bad-version needs BYTE or old"),
            };
            stream = connect(sock);
            send_first(&stream, byte, &three_fds());
            let _ = stream.write_all(&frame(0, b"", &argv_from(&[])));
        }
        "argc-4097" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let _ = stream.write_all(&header(0, 0, 4097));
        }
        "arg-over-1mib" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let mut f = header(0, 0, 1);
            f.extend_from_slice(&u32le((1 << 20) + 1));
            let _ = stream.write_all(&f);
        }
        "argv-sum-over" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let big = vec![b'a'; 600 * 1024];
            let _ = stream.write_all(&frame(0, b"", &[big.clone(), big]));
        }
        "label-huge" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let _ = stream.write_all(&header(2, 8 << 20, 0));
        }
        "label-hex" => {
            let label = match rest.first() {
                Some(h) => hex_decode(h),
                None => usage("label-hex needs HEX"),
            };
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let _ = stream.write_all(&frame(2, &label, &argv_from(&[])));
        }
        "truncated-frame" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let f = frame(0, b"", &argv_from(&[]));
            let _ = stream.write_all(&f[..10]);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
        "connect-and-close" => {
            let s = connect(sock);
            drop(s);
            println!("closed");
            exit(0);
        }
        "fds" => {
            let n: usize = match rest.first().map(|s| s.parse::<usize>()) {
                Some(Ok(n)) => n,
                _ => usage("fds needs a count"),
            };
            let list: Vec<i32> = (0..n).map(|i| (i % 3) as i32).collect();
            stream = connect(sock);
            send_first(&stream, VERSION, &list);
            let _ = stream.write_all(&frame(0, b"", &argv_from(&rest[1..])));
        }
        "stall" => {
            stream = connect(sock);
            send_first(&stream, VERSION, &three_fds());
            let start = Instant::now();
            let mut probe = [0u8; 1];
            // Wait for the daemon to send its refusal or close the socket.
            let n = stream.peek_len(&mut probe);
            println!("elapsed_ms={} first_read={}", start.elapsed().as_millis(), n);
            exit(print_response(&mut stream));
        }
        _ => usage("unknown subcommand"),
    }
    exit(print_response(&mut stream));
}

/// `peek` is not on `UnixStream` in the supported Rust versions, so the
/// stall case uses `recv` with `MSG_PEEK` through this small trait.
trait PeekLen {
    fn peek_len(&self, buf: &mut [u8]) -> isize;
}

impl PeekLen for UnixStream {
    fn peek_len(&self, buf: &mut [u8]) -> isize {
        unsafe {
            libc::recv(
                self.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            ) as isize
        }
    }
}

fn as_uid(args: &[String]) -> ! {
    if args.len() < 2 {
        usage("as-uid needs UID SOCKET");
    }
    let uid: u32 = match args[0].parse() {
        Ok(u) => u,
        Err(_) => usage("as-uid needs a numeric UID"),
    };
    let sock = args[1].as_str();
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(uid as libc::gid_t) != 0
            || libc::setuid(uid as libc::uid_t) != 0
        {
            eprintln!("protocases: cannot drop to uid {}: {}", uid, std::io::Error::last_os_error());
            exit(3);
        }
    }
    let mut stream = connect(sock);
    send_first(&stream, VERSION, &three_fds());
    let _ = stream.write_all(&frame(0, b"", &argv_from(&args[2..])));
    exit(print_response(&mut stream));
}
