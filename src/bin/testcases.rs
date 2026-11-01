//! `confmask-testcases` — real spawn-style probes used by the test
//! suites.  Each subcommand exercises one way a process tree can grow,
//! carrying a MARKER argument that the suites must NOT find in /proc
//! while it is under a mask.
//!
//! Subcommands:
//!   sleeper MARK                 stay alive showing MARK in argv
//!   echoargs [ARGS...]           print argv and whether env is intact
//!   echoargsraw [ARGS...]        print every argv entry as hex (byte fidelity)
//!   threadspawn SLEEPER M1 M2    posix_spawn + system() from 4 threads
//!   vforkspawn SLEEPER MARK      vfork() + execv(), twice
//!   daemonspawn SLEEPER MARK     double fork (grandchild reparented to init)
//!   rawspawn SLEEPER MARK        raw clone(2)+execve(2) syscalls from
//!                                threads (the Go-runtime spawn path)

use std::ffi::CString;

#[path = "tc/audit.rs"]
mod audit;
#[path = "tc/corecases.rs"]
mod corecases;
#[path = "tc/extra.rs"]
mod extra;

fn main() {
    // args_os: this probe must survive a non-UTF-8 argument, since one of
    // the things it proves is that such an argument reaches the program
    // byte for byte.
    let argv_os: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let cmd = argv_os
        .first()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let args: Vec<String> = argv_os.iter().map(|s| s.to_string_lossy().into_owned()).collect();
    let rest = &args[1.min(args.len())..];
    let code = match cmd.as_str() {
        "sleeper" => sleeper(),
        "echoargs" => echoargs(rest),
        "echoargsraw" => echoargsraw(),
        "threadspawn" => threadspawn(rest),
        "vforkspawn" => vforkspawn(rest),
        "daemonspawn" => daemonspawn(rest),
        "rawspawn" => rawspawn(rest),
        "ptraceprobe" => ptraceprobe(),
        other => match extra::dispatch(other, rest)
            .or_else(|| audit::dispatch(other, rest))
            .or_else(|| corecases::dispatch(other, rest)) {
            Some(c) => c,
            None => {
                eprintln!("unknown testcase: {}", other);
                2
            }
        },
    };
    std::process::exit(code);
}

fn sleeper() -> i32 {
    loop {
        unsafe {
            libc::pause();
        }
    }
}

/// Print every argv entry (after the program name) as hex, so a caller
/// can assert that non-UTF-8 bytes arrived unchanged.
fn echoargsraw() -> i32 {
    use std::os::unix::ffi::OsStrExt;
    for (i, a) in std::env::args_os().enumerate() {
        let hex: String = a.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        println!("arg{}={}", i, hex);
    }
    0
}

fn echoargs(args: &[String]) -> i32 {
    for (i, a) in std::env::args_os().enumerate() {
        print!("arg{}=[{}] ", i, a.to_string_lossy());
    }
    let env_ok = std::env::var("PATH").is_ok();
    println!("env=[{}]", if env_ok { "ok" } else { "missing" });
    let _ = args;
    0
}

const A_NULL: &std::ffi::CStr = c"a";

fn c(s: &str) -> CString {
    CString::new(s).expect("NUL in argument")
}

// ---------------------------------------------------------------- thread --

fn threadspawn(args: &[String]) -> i32 {
    // threadspawn SLEEPER MARK1 MARK2
    if args.len() < 3 {
        eprintln!("usage: threadspawn SLEEPER MARK1 MARK2");
        return 2;
    }
    let sleeper = c(&args[0]);
    let m1 = c(&args[1]);
    let m2 = c(&args[2]);

    unsafe {
        for _ in 0..2 {
            let tid: *mut libc::pthread_t = Box::into_raw(Box::new(std::mem::zeroed()));
            let ctx = Box::new((
                sleeper.as_ptr(),
                m1.as_ptr(),
                m2.as_ptr(),
            ));
            let rc = libc::pthread_create(
                tid,
                std::ptr::null(),
                thread_worker,
                Box::into_raw(ctx) as *mut libc::c_void,
            );
            if rc != 0 {
                eprintln!("pthread_create failed");
                return 1;
            }
            // keep the join handle alive; leak by design (process parks)
            Box::leak(Box::from_raw(tid));
        }
        // wait for children to be observable, then park
        libc::sleep(2);
        loop {
            libc::pause();
        }
    }

    extern "C" fn thread_worker(p: *mut libc::c_void) -> *mut libc::c_void {
        unsafe {
        let (sleeper, m1, m2) = *(p as *mut (*const libc::c_char, *const libc::c_char, *const libc::c_char));
        // posix_spawn from a secondary thread
        // libc crate models posix_spawn's argv as *mut *mut c_char
        let mut av: Vec<*mut libc::c_char> = vec![
            sleeper as *mut libc::c_char,
            A_NULL.as_ptr() as *mut libc::c_char,
            m1 as *mut libc::c_char,
            std::ptr::null_mut(),
        ];
        let mut child: libc::pid_t = 0;
        if libc::posix_spawn(
            &mut child,
            sleeper,
            std::ptr::null(),
            std::ptr::null(),
            av.as_mut_ptr(),
            std::ptr::null_mut(),
        ) != 0
        {
            eprintln!("posix_spawn failed");
        }
        // system() from a secondary thread
        let cmd = format!(
            "{} a {} &",
            std::ffi::CStr::from_ptr(sleeper).to_string_lossy(),
            std::ffi::CStr::from_ptr(m2).to_string_lossy()
        );
        if let Ok(cs) = CString::new(cmd) {
            libc::system(cs.as_ptr());
        }
        }
        std::ptr::null_mut()
    }
}

// ----------------------------------------------------------------- vfork --

fn vforkspawn(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: vforkspawn SLEEPER MARK");
        return 2;
    }
    let sleeper = c(&args[0]);
    let mark = c(&args[1]);
    for _ in 0..2 {
        unsafe {
            #[allow(deprecated)] // vfork is the spawn style under test
            let pid = libc::vfork();
            if pid == 0 {
                let av: Vec<*const libc::c_char> =
                    vec![sleeper.as_ptr(), A_NULL.as_ptr(), mark.as_ptr(), std::ptr::null()];
                libc::execv(sleeper.as_ptr(), av.as_ptr());
                libc::_exit(127);
            }
        }
    }
    unsafe {
        loop {
            libc::pause();
        }
    }
}

// ---------------------------------------------------------------- daemon --

fn daemonspawn(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: daemonspawn SLEEPER MARK");
        return 2;
    }
    let sleeper = c(&args[0]);
    let mark = c(&args[1]);
    unsafe {
        let p = libc::fork();
        if p < 0 {
            return 1;
        }
        if p == 0 {
            // intermediate child: fork again, parent exits, grandchild
            // is reparented to init while it execs the marker
            let q = libc::fork();
            if q < 0 {
                libc::_exit(1);
            }
            if q > 0 {
                libc::_exit(0);
            }
            let av: Vec<*const libc::c_char> =
                vec![sleeper.as_ptr(), A_NULL.as_ptr(), mark.as_ptr(), std::ptr::null()];
            libc::execv(sleeper.as_ptr(), av.as_ptr());
            libc::_exit(127);
        }
        let mut st = 0;
        libc::waitpid(p, &mut st, 0);
        loop {
            libc::pause();
        }
    }
}

// -------------------------------------------------------------- rawspawn --

fn rawspawn(args: &[String]) -> i32 {
    // The Go-runtime path: secondary threads spawn via raw clone(2) and
    // the child execs via a raw execve(2) syscall — no libc wrappers.
    if args.len() < 2 {
        eprintln!("usage: rawspawn SLEEPER MARK");
        return 2;
    }
    let sleeper = c(&args[0]);
    let mark = c(&args[1]);

    unsafe {
        for _ in 0..4 {
            let tid: *mut libc::pthread_t = Box::into_raw(Box::new(std::mem::zeroed()));
            let ctx: Box<(*const libc::c_char, *const libc::c_char)> =
                Box::new((sleeper.as_ptr(), mark.as_ptr()));
            let rc = libc::pthread_create(
                tid,
                std::ptr::null(),
                raw_worker,
                Box::into_raw(ctx) as *mut libc::c_void,
            );
            if rc != 0 {
                eprintln!("pthread_create failed");
                return 1;
            }
            Box::leak(Box::from_raw(tid));
        }
        libc::sleep(2);
        loop {
            libc::pause();
        }
    }

    extern "C" fn raw_worker(p: *mut libc::c_void) -> *mut libc::c_void {
        unsafe {
        let (sleeper, mark) = *(p as *mut (*const libc::c_char, *const libc::c_char));
        let pid = libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0);
        if pid == 0 {
            let av: [*const libc::c_char; 4] = [sleeper, A_NULL.as_ptr(), mark, std::ptr::null()];
            libc::syscall(libc::SYS_execve, sleeper, av.as_ptr(), std::ptr::null::<*const libc::c_char>());
            libc::_exit(127);
        }
        }
        std::ptr::null_mut()
    }
}

// ------------------------------------------------------------- ptraceprobe

fn ptraceprobe() -> i32 {
    // Reproduce the tracer handshake step by step, printing evidence.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("probe: fork failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        if pid == 0 {
            eprintln!("probe: child side, pid={}", libc::getpid());
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) == -1
            {
                eprintln!("probe: TRACEME failed: {}", std::io::Error::last_os_error());
                libc::_exit(50);
            }
            eprintln!("probe: TRACEME ok");
            libc::raise(libc::SIGSTOP);
            eprintln!("probe: child resumed (should be by tracer)");
            libc::_exit(7);
        }
        eprintln!("probe: parent, child pid={}", pid);
        let mut st: i32 = 0;
        let w = libc::waitpid(pid, &mut st, libc::__WALL);
        let err = std::io::Error::last_os_error();
        eprintln!("probe: waitpid -> {} status={:#010x} err={}", w, st, err);
        if w != pid {
            // check /proc for the child
            eprintln!("probe: child /proc exists: {}", std::path::Path::new(&format!("/proc/{}", pid)).exists());
            libc::_exit(51);
        }
        eprintln!("probe: WIFSTOPPED={} WSTOPSIG={}", libc::WIFSTOPPED(st), libc::WSTOPSIG(st));
        let rc = libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEEXEC) as *mut libc::c_void,
        );
        eprintln!("probe: SETOPTIONS -> {} (err={})", rc, std::io::Error::last_os_error());
        libc::kill(pid, libc::SIGCONT);
        let w = libc::waitpid(pid, &mut st, libc::__WALL);
        eprintln!("probe: after CONT wait -> {} status={:#010x}", w, st);
        let mut code = 0;
        if libc::WIFEXITED(st) {
            code = libc::WEXITSTATUS(st);
        }
        code
    }
}
