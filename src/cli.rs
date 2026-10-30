//! `confmask` command line.

use confmask::caps::Caps;
use confmask::daemon;
use confmask::isolate::Isolate;
use confmask::run::{Mode, Runner};
use confmask::secret::Source;
use confmask::store::{self, Passphrase, Store};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const USAGE: &str = "\
confmask {version} - confidential computing without the hardware

Run a command so that the other accounts on this machine learn as little
as possible about it: its secrets travel as file descriptors instead of
arguments or environment values, its secrets at rest are encrypted, and
where the kernel allows it its whole process tree's /proc metadata
(cmdline, environ, comm) is redacted.

Usage: confmask <command> [options] [--] [command [args...]]

Commands:
  run CMD [ARGS...]     run a command under confmask
  probe                 what this host allows, and what that means
  doctor                check the setup and report what is protected
  store <sub>           manage the encrypted secret store
                          init | set NAME | get NAME | list | rm NAME | path
  daemon                hold the store unlocked and serve it locally
  get NAME              ask a running daemon for one secret
  read NAME             read a secret from an inherited descriptor

run options:
  -l, --label NAME      presentation label for /proc cmdline and comm
      --secret N=SRC    deliver a secret; SRC is
                          file:PATH | env:VAR | daemon:NAME | stdin | literal:VAL
                        (repeatable; arrives at fd 3, 4, ... with
                         CONFMASK_SECRET_<N> naming the descriptor)
      --isolate[=LIST]  private namespaces (default: pid,net,tmp)
      --no-redact       never touch /proc metadata, even where ptrace works
      --keep-env        leave /proc/<pid>/environ visible when redacting
      --no-follow       redact only the direct child
      --no-exit-kill    let the tree survive if confmask dies
      --socket PATH     daemon socket for daemon: sources
  -q, --quiet           no diagnostics
  -v, --verbose         trace what is redacted
  -V, --version         print version
  -h, --help            this help

Examples:
  # a token that must never appear in `ps` output, on any host
  confmask run --secret DEPLOY_TOKEN=file:./token -- ./deploy.sh

  # a long-lived runner: the store is unlocked once, in the daemon
  confmask store init
  confmask store set RUNNER_TOKEN < token.txt
  confmask daemon &
  confmask run --secret RUNNER_TOKEN=daemon:RUNNER_TOKEN -- ./runner

  # untrusted code that should not see the rest of the machine
  confmask run --isolate -- ./build.sh
";

fn help() -> String {
    USAGE.replace("{version}", confmask::VERSION)
}

pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprint!("{}", help());
        return 255;
    }
    match argv[1].as_str() {
        "-h" | "--help" | "help" => {
            print!("{}", help());
            0
        }
        "-V" | "--version" => {
            println!(
                "confmask {} ({})",
                confmask::VERSION,
                std::env::consts::ARCH
            );
            0
        }
        "probe" => cmd_probe(),
        "doctor" => cmd_doctor(),
        "run" => cmd_run(&argv[2..]),
        "store" => cmd_store(&argv[2..]),
        "daemon" => cmd_daemon(&argv[2..]),
        "get" => cmd_get(&argv[2..]),
        "read" => cmd_read(&argv[2..]),
        other => {
            eprintln!("confmask: unknown command '{}'", other);
            eprint!("{}", help());
            255
        }
    }
}

// ------------------------------------------------------------------ probe

fn cmd_probe() -> i32 {
    print!("{}", Caps::detect().report());
    0
}

// ----------------------------------------------------------------- doctor

fn cmd_doctor() -> i32 {
    let caps = Caps::detect();
    print!("{}", caps.report());

    println!("store:");
    let sp = store::default_path();
    match std::fs::metadata(&sp) {
        Ok(md) => {
            use std::os::unix::fs::PermissionsExt;
            println!(
                "  {} ({} bytes, mode {:04o})",
                sp.display(),
                md.len(),
                md.permissions().mode() & 0o777
            );
        }
        Err(_) => println!("  {} (not created yet)", sp.display()),
    }

    let sock = daemon::default_socket();
    println!(
        "daemon:\n  {} {}",
        sock.display(),
        if daemon::ping(None) {
            "(answering)"
        } else {
            "(not running)"
        }
    );

    println!("\nverdict:");
    if caps.ptrace {
        println!("  command lines can be redacted here (ptrace permitted)");
    } else {
        println!("  command lines CANNOT be redacted here (ptrace refused).");
        println!("  keep secrets out of argv: use --secret with file:/daemon: sources,");
        println!("  which deliver over descriptors and work without ptrace.");
    }
    if caps.userns {
        println!("  --isolate is available (unprivileged user namespaces)");
    } else {
        println!("  --isolate is NOT available (no unprivileged user namespaces)");
    }
    0
}

// -------------------------------------------------------------------- run

fn cmd_run(args: &[String]) -> i32 {
    // Options are accumulated here and applied once, so a bad value never
    // loses the ones already parsed.
    let mut label: Option<String> = None;
    let mut secrets: Vec<(String, Source)> = Vec::new();
    let mut no_redact = false;
    let mut keep_env = false;
    let mut no_follow = false;
    let mut no_exit_kill = false;
    let mut socket: Option<PathBuf> = None;
    let mut isolate: Option<Isolate> = None;
    let mut quiet = false;
    let mut verbose = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        match a {
            "-h" | "--help" => {
                print!("{}", help());
                return 0;
            }
            "-V" | "--version" => {
                println!("confmask {} ({})", confmask::VERSION, std::env::consts::ARCH);
                return 0;
            }
            "-q" | "--quiet" => quiet = true,
            "-v" | "--verbose" => verbose = true,
            "--no-redact" => no_redact = true,
            "--keep-env" => keep_env = true,
            "--no-follow" => no_follow = true,
            "--no-exit-kill" | "--no-exitkill" => no_exit_kill = true,
            "--isolate" => isolate = Some(Isolate::all()),
            "-l" | "--label" => match args.get(i + 1) {
                Some(v) => {
                    i += 1;
                    label = Some(v.clone());
                }
                None => return need_value("--label"),
            },
            "--secret" => match args.get(i + 1) {
                Some(v) => {
                    i += 1;
                    match Source::parse(v) {
                        Ok(pair) => secrets.push(pair),
                        Err(e) => {
                            eprintln!("confmask: --secret: {}", e);
                            return 255;
                        }
                    }
                }
                None => return need_value("--secret"),
            },
            "--socket" => match args.get(i + 1) {
                Some(v) => {
                    i += 1;
                    socket = Some(PathBuf::from(v));
                }
                None => return need_value("--socket"),
            },
            _ => {
                if let Some(v) = a.strip_prefix("--label=") {
                    label = Some(v.to_string());
                } else if let Some(v) = a.strip_prefix("--secret=") {
                    match Source::parse(v) {
                        Ok(pair) => secrets.push(pair),
                        Err(e) => {
                            eprintln!("confmask: --secret: {}", e);
                            return 255;
                        }
                    }
                } else if let Some(v) = a.strip_prefix("--isolate=") {
                    match parse_isolate(v) {
                        Some(iso) => isolate = Some(iso),
                        None => {
                            eprintln!("confmask: --isolate={}: want pid,net,tmp,all,none", v);
                            return 255;
                        }
                    }
                } else if let Some(v) = a.strip_prefix("--socket=") {
                    socket = Some(PathBuf::from(v));
                } else if let Some(v) = a.strip_prefix("-l") {
                    label = Some(v.to_string());
                } else {
                    eprintln!("confmask: unknown option '{}'", a);
                    return 255;
                }
            }
        }
        i += 1;
    }

    if i >= args.len() {
        eprintln!("confmask: run needs a command");
        return 255;
    }

    let mut r = Runner::new();
    if let Some(l) = label {
        r = r.label(l);
    }
    for (n, s) in secrets {
        r = r.secret(n, s);
    }
    if let Some(s) = socket {
        r = r.daemon_socket(s);
    }
    if no_redact {
        r = r.no_redaction();
    }
    if keep_env {
        r = r.keep_environ_visible();
    }
    if !no_follow {
        // default is to follow
    } else {
        r = r.follow_tree(false);
    }
    if no_exit_kill {
        r = r.let_tree_survive_self_death();
    }
    if quiet {
        r = r.quiet();
    } else if verbose {
        r = r.verbose();
    }
    if let Some(iso) = isolate {
        r = r.isolate(iso);
    }

    let program = args[i].clone();
    let rest: Vec<std::ffi::OsString> = args[i + 1..]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();

    match r.run(&program, &rest) {
        Ok(outcome) => {
            if !quiet {
                eprintln!(
                    "confmask: mode={} secrets={} exit={}",
                    outcome.mode.as_str(),
                    outcome.secrets_delivered,
                    outcome.exit.code
                );
                for n in &outcome.notes {
                    eprintln!("confmask: note: {}", n);
                }
                if outcome.mode == Mode::Plain {
                    eprintln!(
                        "confmask: note: /proc metadata was not redacted here; \
                         secrets travelled over descriptors, not argv/env"
                    );
                }
            }
            if let Some(sig) = outcome.exit.signal {
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
            }
            outcome.exit.code
        }
        Err(e) => {
            eprintln!("confmask: {}", e);
            255
        }
    }
}

fn parse_isolate(v: &str) -> Option<Isolate> {
    if v == "all" || v.is_empty() {
        return Some(Isolate::all());
    }
    if v == "none" {
        return Some(Isolate {
            pid: false,
            net: false,
            private_tmp: false,
        });
    }
    let mut iso = Isolate {
        pid: false,
        net: false,
        private_tmp: false,
    };
    for part in v.split(',') {
        match part {
            "pid" => iso.pid = true,
            "net" => iso.net = true,
            "tmp" => iso.private_tmp = true,
            _ => return None,
        }
    }
    Some(iso)
}

fn need_value(what: &str) -> i32 {
    eprintln!("confmask: {} needs a value", what);
    255
}

// ------------------------------------------------------------------ store

fn cmd_store(args: &[String]) -> i32 {
    let sub = match args.first() {
        Some(s) => s.as_str(),
        None => {
            eprintln!("confmask: store needs a subcommand (init|set|get|list|rm|path)");
            return 255;
        }
    };
    let mut path = store::default_path();
    let mut pass_file: Option<PathBuf> = None;
    let mut from_file: Option<PathBuf> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--store" => match args.get(i + 1) {
                Some(v) => {
                    path = PathBuf::from(v);
                    i += 1;
                }
                None => return need_value("--store"),
            },
            "--passphrase-file" => match args.get(i + 1) {
                Some(v) => {
                    pass_file = Some(PathBuf::from(v));
                    i += 1;
                }
                None => return need_value("--passphrase-file"),
            },
            "--from-file" => match args.get(i + 1) {
                Some(v) => {
                    from_file = Some(PathBuf::from(v));
                    i += 1;
                }
                None => return need_value("--from-file"),
            },
            s if s.starts_with("--store=") => path = PathBuf::from(&s[8..]),
            s if s.starts_with("--passphrase-file=") => pass_file = Some(PathBuf::from(&s[18..])),
            s if s.starts_with("--from-file=") => from_file = Some(PathBuf::from(&s[12..])),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }

    if sub == "path" {
        println!("{}", path.display());
        return 0;
    }

    let pp = match resolve_passphrase(pass_file.as_deref(), sub == "init") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("confmask: {}", e);
            return 255;
        }
    };

    match sub {
        "init" => {
            if path.exists() {
                eprintln!("confmask: {} already exists", path.display());
                return 255;
            }
            match Store::create(&path, &pp) {
                Ok(_) => {
                    println!("created {}", path.display());
                    0
                }
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    255
                }
            }
        }
        "set" => {
            let name = match positional.first() {
                Some(n) => n.clone(),
                None => {
                    eprintln!("confmask: store set needs a NAME");
                    return 255;
                }
            };
            let mut bytes = match &from_file {
                Some(p) => match std::fs::read(p) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("confmask: {}", e);
                        return 255;
                    }
                },
                None => {
                    let mut v = Vec::new();
                    if let Err(e) = io::stdin().read_to_end(&mut v) {
                        eprintln!("confmask: {}", e);
                        return 255;
                    }
                    v
                }
            };
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            let mut st = match open_or_create(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    return 255;
                }
            };
            if let Err(e) = st.set(&name, &bytes) {
                eprintln!("confmask: {}", e);
                return 255;
            }
            use zeroize::Zeroize;
            bytes.zeroize();
            match st.save(&pp) {
                Ok(()) => {
                    println!("set {}", name);
                    0
                }
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    255
                }
            }
        }
        "get" => {
            let name = match positional.first() {
                Some(n) => n.clone(),
                None => {
                    eprintln!("confmask: store get needs a NAME");
                    return 255;
                }
            };
            let st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    return 255;
                }
            };
            match st.get(&name) {
                Some(v) => {
                    let mut out = io::stdout();
                    let _ = out.write_all(v);
                    let _ = out.write_all(b"\n");
                    0
                }
                None => {
                    eprintln!("confmask: no secret named '{}'", name);
                    1
                }
            }
        }
        "list" => {
            let st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    return 255;
                }
            };
            for n in st.names() {
                println!("{}", n);
            }
            0
        }
        "rm" => {
            let name = match positional.first() {
                Some(n) => n.clone(),
                None => {
                    eprintln!("confmask: store rm needs a NAME");
                    return 255;
                }
            };
            let mut st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    return 255;
                }
            };
            if !st.remove(&name) {
                eprintln!("confmask: no secret named '{}'", name);
                return 1;
            }
            match st.save(&pp) {
                Ok(()) => {
                    println!("removed {}", name);
                    0
                }
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    255
                }
            }
        }
        other => {
            eprintln!("confmask: unknown store subcommand '{}'", other);
            255
        }
    }
}

fn open_or_create(path: &std::path::Path, pp: &Passphrase) -> io::Result<Store> {
    if path.exists() {
        Store::open(path, pp)
    } else {
        Store::create(path, pp)
    }
}

fn resolve_passphrase(explicit: Option<&std::path::Path>, creating: bool) -> io::Result<Passphrase> {
    if let Some(p) = explicit {
        return Passphrase::from_file(p);
    }
    if let Some(p) = std::env::var_os("CONFMASK_PASSPHRASE_FILE") {
        return Passphrase::from_file(&PathBuf::from(p));
    }
    if let Some(v) = std::env::var_os("CONFMASK_PASSPHRASE") {
        eprintln!(
            "confmask: warning: CONFMASK_PASSPHRASE is set; it is visible in this process's environ"
        );
        use std::os::unix::ffi::OsStrExt;
        return Passphrase::new(v.as_bytes());
    }
    prompt_passphrase(creating)
}

/// Read a passphrase from the controlling terminal with echo off.
fn prompt_passphrase(creating: bool) -> io::Result<Passphrase> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no terminal to ask for a passphrase; use --passphrase-file PATH or CONFMASK_PASSPHRASE_FILE",
            )
        })?;
    let fd = tty.as_raw_fd();
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let orig = term;
    if have_term {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut w = &tty;
    let prompt = if creating {
        "new passphrase: "
    } else {
        "passphrase: "
    };
    let _ = w.write_all(prompt.as_bytes());
    let _ = w.flush();

    let mut line = String::new();
    let mut r = io::BufReader::new(&tty);
    let res = r.read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    }
    let _ = w.write_all(b"\n");
    res?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    let pp = Passphrase::new(line.as_bytes())?;
    use zeroize::Zeroize;
    line.zeroize();
    Ok(pp)
}

// ----------------------------------------------------------------- daemon

fn cmd_daemon(args: &[String]) -> i32 {
    let mut path = store::default_path();
    let mut sock = daemon::default_socket();
    let mut pass_file: Option<PathBuf> = None;
    let mut allow: Vec<PathBuf> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--store" => match args.get(i + 1) {
                Some(v) => {
                    path = PathBuf::from(v);
                    i += 1;
                }
                None => return need_value("--store"),
            },
            "--socket" => match args.get(i + 1) {
                Some(v) => {
                    sock = PathBuf::from(v);
                    i += 1;
                }
                None => return need_value("--socket"),
            },
            "--passphrase-file" => match args.get(i + 1) {
                Some(v) => {
                    pass_file = Some(PathBuf::from(v));
                    i += 1;
                }
                None => return need_value("--passphrase-file"),
            },
            "--allow" => match args.get(i + 1) {
                Some(v) => {
                    allow.push(PathBuf::from(v));
                    i += 1;
                }
                None => return need_value("--allow"),
            },
            s if s.starts_with("--store=") => path = PathBuf::from(&s[8..]),
            s if s.starts_with("--socket=") => sock = PathBuf::from(&s[9..]),
            s if s.starts_with("--passphrase-file=") => pass_file = Some(PathBuf::from(&s[18..])),
            s if s.starts_with("--allow=") => allow.push(PathBuf::from(&s[8..])),
            other => {
                eprintln!("confmask: daemon: unknown option '{}'", other);
                return 255;
            }
        }
        i += 1;
    }
    let pp = match resolve_passphrase(pass_file.as_deref(), false) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("confmask: {}", e);
            return 255;
        }
    };
    let st = match Store::open(&path, &pp) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("confmask: {}", e);
            return 255;
        }
    };
    let d = daemon::Daemon::new(st, sock, allow);
    match d.serve() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("confmask: daemon: {}", e);
            255
        }
    }
}

// -------------------------------------------------------------------- get

fn cmd_get(args: &[String]) -> i32 {
    let mut sock: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => match args.get(i + 1) {
                Some(v) => {
                    sock = Some(PathBuf::from(v));
                    i += 1;
                }
                None => return need_value("--socket"),
            },
            s if s.starts_with("--socket=") => sock = Some(PathBuf::from(&s[9..])),
            s => name = Some(s.to_string()),
        }
        i += 1;
    }
    let name = match name {
        Some(n) => n,
        None => {
            eprintln!("confmask: get needs a NAME");
            return 255;
        }
    };
    match daemon::fetch(sock.as_ref(), &name) {
        Ok(v) => {
            let mut out = io::stdout();
            let _ = out.write_all(v.as_slice());
            let _ = out.write_all(b"\n");
            0
        }
        Err(e) => {
            eprintln!("confmask: {}", e);
            1
        }
    }
}

// ------------------------------------------------------------------- read

/// Read a secret that `confmask run` delivered to this process, by name.
fn cmd_read(args: &[String]) -> i32 {
    let name = match args.first() {
        Some(n) => n.clone(),
        None => {
            eprintln!("confmask: read needs a NAME");
            return 255;
        }
    };
    let var = confmask::secret::env_var_for(&name);
    let fd_s = match std::env::var(&var) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "confmask: no secret named '{}' in this process ({} is not set)",
                name, var
            );
            return 1;
        }
    };
    let fd: i32 = match fd_s.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("confmask: {} holds '{}', not a descriptor", var, fd_s);
            return 255;
        }
    };
    let mut out = io::stdout();
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("confmask: read fd {}: {}", fd, e);
            return 1;
        }
        let _ = out.write_all(&buf[..n as usize]);
    }
    let _ = out.write_all(b"\n");
    0
}
