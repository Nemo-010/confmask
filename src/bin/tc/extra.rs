//! Extra test-case subcommands for the option suites (`tests/options.sh`).
//!
//!   label-nul                    Mask::run and spawn must reject a NUL label
//!   debug-mask KEY VALUE         print `{:?}` of a Mask that holds KEY=VALUE
//!   as-uid UID CMD [ARGS...]     drop to UID (and gid UID), then exec CMD
//!   show-nnp                     print the NoNewPrivs line of /proc/self/status
//!   renamer                      rename itself with PR_SET_NAME, report comm
//!   count-proc                   count the numeric entries of /proc
//!   getenv NAME                  print the value of NAME

use std::ffi::CString;
use std::io::Write;

/// Run subcommand `cmd`; `None` when it is not one of ours.
pub fn dispatch(cmd: &str, rest: &[String]) -> Option<i32> {
    match cmd {
        "label-nul" => Some(label_nul()),
        "debug-mask" => Some(debug_mask(rest)),
        "as-uid" => Some(as_uid(rest)),
        "show-nnp" => Some(show_nnp()),
        "renamer" => Some(renamer()),
        "count-proc" => Some(count_proc()),
        "getenv" => Some(getenv(rest)),
        _ => None,
    }
}

/// A label with a NUL byte must fail at run and at spawn with
/// InvalidInput, before anything is forked.
fn label_nul() -> i32 {
    let no_args: [&str; 0] = [];
    let mut bad = 0;

    match confmask::Mask::new().quiet().label("a\0b").run("true", &no_args) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            println!("label-nul run: rejected ({})", e);
        }
        Err(e) => {
            println!("label-nul run: wrong error kind {:?} ({})", e.kind(), e);
            bad += 1;
        }
        Ok(_) => {
            println!("label-nul run: accepted");
            bad += 1;
        }
    }

    match confmask::Mask::new().quiet().label("a\0b").spawn("true", &no_args) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            println!("label-nul spawn: rejected ({})", e);
        }
        Err(e) => {
            println!("label-nul spawn: wrong error kind {:?} ({})", e.kind(), e);
            bad += 1;
        }
        Ok(child) => {
            drop(child);
            println!("label-nul spawn: accepted");
            bad += 1;
        }
    }
    bad
}

fn debug_mask(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: debug-mask KEY VALUE");
        return 2;
    }
    let mask = confmask::Mask::new()
        .label("dbg")
        .envs([(args[0].as_str(), args[1].as_str())])
        .env(format!("EXTRA_{}", args[0]), args[1].as_str());
    println!("{:?}", mask);
    0
}

fn as_uid(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: as-uid UID CMD [ARGS...]");
        return 2;
    }
    let uid: u32 = match args[0].parse() {
        Ok(u) => u,
        Err(_) => {
            eprintln!("as-uid: bad uid {}", args[0]);
            return 2;
        }
    };
    let cargs: Vec<CString> = match args[1..].iter().map(|a| CString::new(a.as_str())).collect() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("as-uid: NUL in argument");
            return 2;
        }
    };
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: plain credential syscalls, then exec with valid C strings.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) == -1
            || libc::setgid(uid as libc::gid_t) == -1
            || libc::setuid(uid as libc::uid_t) == -1
        {
            eprintln!("as-uid: cannot drop privileges: {}", std::io::Error::last_os_error());
            return 126;
        }
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    eprintln!("as-uid: exec failed: {}", std::io::Error::last_os_error());
    127
}

fn show_nnp() -> i32 {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("show-nnp: {}", e);
            return 1;
        }
    };
    for line in status.lines() {
        if line.starts_with("NoNewPrivs:") {
            println!("{}", line);
            return 0;
        }
    }
    eprintln!("show-nnp: no NoNewPrivs line");
    1
}

fn own_comm() -> String {
    std::fs::read_to_string("/proc/self/comm")
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

/// Settle, rename with PR_SET_NAME, wait, report comm, then park.
fn renamer() -> i32 {
    std::thread::sleep(std::time::Duration::from_millis(500));
    let name = b"other\0";
    // SAFETY: name is NUL terminated.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0);
    }
    std::thread::sleep(std::time::Duration::from_millis(700));
    println!("renamer-comm={}", own_comm());
    let _ = std::io::stdout().flush();
    loop {
        // SAFETY: pause(2) has no preconditions.
        unsafe {
            libc::pause();
        }
    }
}

fn count_proc() -> i32 {
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            eprintln!("count-proc: {}", e);
            return 1;
        }
    };
    let mut n = 0;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            n += 1;
        }
    }
    println!("proc-count={}", n);
    0
}

fn getenv(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: getenv NAME");
        return 2;
    }
    match std::env::var_os(&args[0]) {
        Some(v) => {
            println!("{}={}", args[0], v.to_string_lossy());
            0
        }
        None => {
            println!("{} unset", args[0]);
            1
        }
    }
}
