//! Test cases for the tracer core suite (`tests/core.sh`).
//!
//!   holdargs OUT ARGS...        write argc, per-argument length and the
//!                               last 12 bytes of each argument to OUT,
//!                               then stay alive
//!   threadexec PROG ARGS...     a second thread calls execve(PROG, ARGS)
//!   forkretry MISSING PROG A..  fork; the child execs MISSING (fails) and
//!                               then PROG with the arguments A..
//!   sleepfor SECONDS            sleep, then exit 0
//!   touchloop FILE              append one byte to FILE every 50 ms
//!   threadnames                 print the comm of every thread, then exit
//!   proctitle                   rewrite the argv region setproctitle-style,
//!                               then print argv and PATH
//!   execfn                      print AT_EXECFN
//!   dropto UID CMD ARGS...      setgid/setuid, then execvp CMD
//!   suidprobe                   print uid and euid
//!   execveat PATH ARGS...       execveat(AT_FDCWD, PATH, ARGS)
//!   fexecve PATH ARGS...        open PATH, execveat(fd, "", AT_EMPTY_PATH)
//!   bigenv N                    print N, then stay alive (env supplied by caller)

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

pub fn dispatch(cmd: &str, rest: &[String]) -> Option<i32> {
    Some(match cmd {
        "holdargs" => holdargs(),
        "threadexec" => threadexec(rest),
        "forkretry" => forkretry(rest),
        "sleepfor" => sleepfor(rest),
        "touchloop" => touchloop(rest),
        "threadnames" => threadnames(),
        "proctitle" => proctitle(),
        "execfn" => execfn(),
        "dropto" => dropto(rest),
        "suidprobe" => suidprobe(),
        "manyargs" => manyargs(rest),
        "execveat" => execveat_case(rest, false),
        "fexecve" => execveat_case(rest, true),
        _ => return None,
    })
}

/// `manyargs N OUT MARK`: exec this program as
/// `holdargs OUT 1 2 ... N MARK`.  The exec runs one argv array of
/// N + 4 entries in a single execve, which xargs cannot build (it splits
/// on the command-size limit).
fn manyargs(rest: &[String]) -> i32 {
    if rest.len() < 3 {
        return 2;
    }
    let n: usize = match rest[0].parse() {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let out = cs(&rest[1]);
    let mark = cs(&rest[2]);
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return 2,
    };
    let prog = match CString::new(exe.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return 2,
    };
    let mut av: Vec<CString> = Vec::with_capacity(n + 4);
    av.push(prog.clone());
    av.push(cs("holdargs"));
    av.push(out);
    for i in 1..=n {
        av.push(cs(&i.to_string()));
    }
    av.push(mark);
    let mut ptrs: Vec<*const libc::c_char> = av.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: every pointer is valid for the exec call and the vector is
    // NUL-terminated; the process image is replaced.
    unsafe {
        libc::execv(prog.as_ptr(), ptrs.as_ptr());
    }
    127
}

fn cs(s: &str) -> CString {
    CString::new(s).expect("NUL in argument")
}

fn holdargs() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // args[0] = program, args[1] = "holdargs", args[2] = OUT
    let out = match args.get(2) {
        Some(o) => o.clone(),
        None => return 2,
    };
    let mut text = String::new();
    text.push_str(&format!("argc={}\n", args.len()));
    for (i, a) in args.iter().enumerate().skip(3) {
        let b = a.as_bytes();
        let tail = &b[b.len().saturating_sub(12)..];
        text.push_str(&format!("arg{} len={} tail={}\n", i, b.len(), String::from_utf8_lossy(tail)));
    }
    if std::fs::write(&out, text).is_err() {
        return 3;
    }
    loop {
        unsafe {
            libc::pause();
        }
    }
}

fn threadexec(rest: &[String]) -> i32 {
    if rest.is_empty() {
        return 2;
    }
    let prog = cs(&rest[0]);
    let mut av: Vec<CString> = Vec::new();
    av.push(prog.clone());
    for a in &rest[1..] {
        av.push(cs(a));
    }
    let ctx = Box::new((prog, av));
    let raw = Box::into_raw(ctx);
    unsafe {
        let mut tid: libc::pthread_t = std::mem::zeroed();
        if libc::pthread_create(&mut tid, std::ptr::null(), exec_worker, raw as *mut libc::c_void) != 0 {
            return 1;
        }
        // The execing thread is not the thread-group leader: it replaces
        // the whole process; the leader never returns from here.
        loop {
            libc::pause();
        }
    }

    extern "C" fn exec_worker(p: *mut libc::c_void) -> *mut libc::c_void {
        unsafe {
            let ctx = Box::from_raw(p as *mut (CString, Vec<CString>));
            let (prog, av) = *ctx;
            let mut ptrs: Vec<*const libc::c_char> = av.iter().map(|s| s.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            libc::execv(prog.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
    }
}

fn forkretry(rest: &[String]) -> i32 {
    if rest.len() < 2 {
        return 2;
    }
    let missing = cs(&rest[0]);
    let prog = cs(&rest[1]);
    let mut av: Vec<CString> = vec![prog.clone()];
    for a in &rest[2..] {
        av.push(cs(a));
    }
    let mut ptrs: Vec<*const libc::c_char> = av.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        let p = libc::fork();
        if p == 0 {
            // first exec fails (ENOENT), the retry must still be supervised
            libc::execv(missing.as_ptr(), ptrs.as_ptr());
            libc::execv(prog.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
        let mut st = 0;
        libc::waitpid(p, &mut st, 0);
        if libc::WIFEXITED(st) {
            return libc::WEXITSTATUS(st);
        }
        1
    }
}

fn sleepfor(rest: &[String]) -> i32 {
    let secs: u64 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    std::thread::sleep(std::time::Duration::from_secs(secs));
    0
}

fn touchloop(rest: &[String]) -> i32 {
    use std::io::Write;
    let Some(path) = rest.first() else { return 2 };
    loop {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(b".");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn threadnames() -> i32 {
    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(500))));
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            let p = e.path().join("comm");
            let name = std::fs::read_to_string(p).unwrap_or_default();
            println!("thread-comm={}", name.trim_end());
        }
    }
    for h in handles {
        let _ = h.join();
    }
    0
}

/// `(arg_start, arg_end, env_start, env_end)` of this process.
fn bounds() -> Option<(u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    let get = |n: usize| -> Option<u64> { fields.get(n - 3)?.parse().ok() };
    Some((get(48)?, get(49)?, get(50)?, get(51)?))
}

fn proctitle() -> i32 {
    // Capture argv and PATH first (like a libc that cached them), rewrite
    // the visible argv region, then read them again.
    let before: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let path_before = std::env::var("PATH").unwrap_or_default();
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(i) = stat.rfind(')') {
            let fields: Vec<&str> = stat[i + 1..].split_whitespace().collect();
            let a0: u64 = fields.get(48 - 3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let a1: u64 = fields.get(49 - 3).and_then(|s| s.parse().ok()).unwrap_or(0);
            if a0 != 0 && a1 > a0 {
                let title = b"proctitle: serving";
                let n = ((a1 - a0) as usize).min(title.len());
                // SAFETY: the kernel-served argv region of this process.
                unsafe {
                    std::ptr::write_bytes(a0 as *mut u8, 0, (a1 - a0) as usize);
                    std::ptr::copy_nonoverlapping(title.as_ptr(), a0 as *mut u8, n);
                }
            }
        }
    }
    let after: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let path_after = std::env::var("PATH").unwrap_or_default();
    println!("args-same={} path-same={}", before == after, path_before == path_after);
    println!("path-before-len={} path-after-len={}", path_before.len(), path_after.len());
    println!("bounds={:?}", bounds());
    println!("argv={:?}", after);
    0
}

fn execfn() -> i32 {
    // SAFETY: getauxval(AT_EXECFN) returns a pointer to a NUL-terminated
    // string in the process image, or 0.
    unsafe {
        let p = libc::getauxval(libc::AT_EXECFN) as *const libc::c_char;
        if p.is_null() {
            println!("execfn=<none>");
        } else {
            println!("execfn={}", std::ffi::CStr::from_ptr(p).to_string_lossy());
        }
    }
    0
}

fn dropto(rest: &[String]) -> i32 {
    if rest.len() < 2 {
        return 2;
    }
    let uid: u32 = match rest[0].parse() {
        Ok(u) => u,
        Err(_) => return 2,
    };
    unsafe {
        if libc::setgid(uid) != 0 || libc::setuid(uid) != 0 {
            eprintln!("dropto: setuid failed: {}", std::io::Error::last_os_error());
            return 3;
        }
    }
    let prog = cs(&rest[1]);
    let av: Vec<CString> = rest[1..].iter().map(|s| cs(s)).collect();
    let mut ptrs: Vec<*const libc::c_char> = av.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(prog.as_ptr(), ptrs.as_ptr());
    }
    127
}

fn suidprobe() -> i32 {
    unsafe {
        println!("uid={} euid={}", libc::getuid(), libc::geteuid());
    }
    0
}

fn execveat_case(rest: &[String], via_fd: bool) -> i32 {
    if rest.is_empty() {
        return 2;
    }
    let prog = cs(&rest[0]);
    let av: Vec<CString> = rest.iter().map(|s| cs(s)).collect();
    let mut ptrs: Vec<*const libc::c_char> = av.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let empty = cs("");
    unsafe {
        // The child performs the exec, so it is the first exec of a
        // freshly forked (syscall-supervised) process.
        let child = libc::fork();
        if child != 0 {
            let mut st = 0;
            libc::waitpid(child, &mut st, 0);
            return if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 };
        }
        if via_fd {
            let fd = libc::open(prog.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return 126;
            }
            libc::syscall(libc::SYS_execveat, fd, empty.as_ptr(), ptrs.as_ptr(), envp.as_ptr(), 0x1000);
        } else {
            libc::syscall(libc::SYS_execveat, libc::AT_FDCWD, prog.as_ptr(), ptrs.as_ptr(), envp.as_ptr(), 0);
        }
    }
    127
}
