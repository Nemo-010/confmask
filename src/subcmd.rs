//! The subcommands that are not the mask: the encrypted store, the secret
//! agent, the child-side `read`, and the capability report.
//!
//! `confmask` has two faces.  The default face is the mask: `confmask
//! --label L -- cmd` redacts `/proc` metadata.  These subcommands are the
//! other face, the one that turns a secret into a file descriptor, and
//! they are what still works on a host that bans `ptrace`.
//!
//! The dispatcher returns `None` when the argument vector is not a
//! subcommand, so the caller falls through to the mask parser.

use crate::agent;
use crate::caps::Caps;
use crate::isolate::Isolate;
use crate::secret;
use crate::store::{self, Passphrase, Store};
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// The subcommand names.  `run` is handled by the caller (it is the mask
/// parser with secret options), so it is not listed here.
pub fn is_subcommand(word: &OsStr) -> bool {
    matches!(
        word.as_bytes(),
        b"store" | b"agent" | b"get" | b"read" | b"probe" | b"doctor" | b"help" | b"version"
    )
}

/// Run a subcommand.  `argv[0]` is the program name, `argv[1]` the
/// subcommand word.
pub fn dispatch(argv: &[OsString], mask_help: &str) -> i32 {
    let args = &argv[2..];
    match argv.get(1).map(|a| a.as_bytes()) {
        Some(b"store") => cmd_store(args),
        Some(b"agent") => cmd_agent(args),
        Some(b"get") => cmd_get(args),
        Some(b"read") => cmd_read(args),
        Some(b"probe") => cmd_probe(args),
        Some(b"doctor") => cmd_doctor(),
        Some(b"help") => {
            print!("{}", help(mask_help));
            0
        }
        Some(b"version") => {
            println!("confmask {} ({})", crate::VERSION, crate::arch_name());
            0
        }
        _ => 255,
    }
}

fn help(mask_help: &str) -> String {
    format!(
        "{}\n{}",
        mask_help,
        SUBCOMMAND_HELP.replace("{version}", crate::VERSION)
    )
}

const SUBCOMMAND_HELP: &str = "\
Commands (the secret side; these work even where ptrace is refused):
  run [OPTIONS] [--] CMD  run a command; accepts every mask option, plus:
      --secret N=SRC        deliver a secret on descriptor 3, 4, ...; SRC is
                            file:PATH | env:VAR | agent:NAME | stdin | literal:VAL
                            (repeatable; CONFMASK_SECRET_<N> names the descriptor)
      --socket PATH         secret-agent socket for agent:NAME sources
      --isolate[=LIST]      private namespaces: pid,net,tmp | all | none
      --no-redact           never touch /proc metadata, even where ptrace works
  read NAME             print a secret that `run` delivered to this process
  store <sub>           the encrypted store:
      init | set NAME | get NAME | list | rm NAME | path
      --store PATH          store file (default: $XDG_DATA_HOME/confmask/store.enc)
      --passphrase-file P   read the passphrase from P
  agent [OPTIONS]       hold the store unlocked and serve it:
      --store PATH, --socket PATH, --passphrase-file P, --allow EXE
  get NAME [--socket P] ask a running agent for one secret
  probe                 what this host allows, and what that means
  doctor                the store, the agent and the verdict, in one report
";

// ------------------------------------------------------------------ probe

fn cmd_probe(args: &[OsString]) -> i32 {
    let mut json = false;
    for a in args {
        match a.as_bytes() {
            b"--json" => json = true,
            b"-h" | b"--help" => {
                println!("confmask probe [--json]");
                return 0;
            }
            _ => {
                eprintln!(
                    "confmask: probe: unknown option '{}'",
                    a.to_string_lossy()
                );
                return 255;
            }
        }
    }
    let caps = Caps::detect();
    if json {
        print!("{}", caps.report_json());
    } else {
        print!("{}", caps.report());
    }
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

    let sock = agent::default_socket();
    println!(
        "agent:\n  {} {}",
        sock.display(),
        if agent::ping(None) {
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
        println!("  keep secrets out of argv: use --secret with file:/agent: sources,");
        println!("  which deliver over descriptors and work without ptrace.");
    }
    if caps.userns {
        println!("  --isolate is available (unprivileged user namespaces)");
    } else {
        println!("  --isolate is NOT available (no unprivileged user namespaces)");
    }
    0
}

// ------------------------------------------------------------------ store

fn opt_value(args: &[OsString], i: &mut usize, flag: &str) -> Option<OsString> {
    match args.get(*i + 1) {
        Some(v) => {
            *i += 1;
            Some(v.clone())
        }
        None => {
            eprintln!("confmask: {} needs a value", flag);
            None
        }
    }
}

fn inline_arg<'a>(s: &'a [u8], flag: &str) -> Option<&'a [u8]> {
    let p = flag.as_bytes();
    if s.len() > p.len() && s.starts_with(p) && s[p.len()] == b'=' {
        Some(&s[p.len() + 1..])
    } else {
        None
    }
}

fn path_from(v: &OsStr) -> PathBuf {
    PathBuf::from(v)
}

fn cmd_store(args: &[OsString]) -> i32 {
    let sub = match args.first() {
        Some(s) => s.to_string_lossy().into_owned(),
        None => {
            eprintln!("confmask: store needs a subcommand (init|set|get|list|rm|path)");
            return 255;
        }
    };
    let mut path = store::default_path();
    let mut pass_file: Option<PathBuf> = None;
    let mut from_file: Option<PathBuf> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if let Some(v) = inline_arg(b, "--store") {
            path = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--passphrase-file") {
            pass_file = Some(path_from(OsStr::from_bytes(v)));
        } else if let Some(v) = inline_arg(b, "--from-file") {
            from_file = Some(path_from(OsStr::from_bytes(v)));
        } else {
            match b {
                b"--store" => match opt_value(args, &mut i, "--store") {
                    Some(v) => path = path_from(&v),
                    None => return 255,
                },
                b"--passphrase-file" => match opt_value(args, &mut i, "--passphrase-file") {
                    Some(v) => pass_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"--from-file" => match opt_value(args, &mut i, "--from-file") {
                    Some(v) => from_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"-h" | b"--help" => {
                    println!(
                        "confmask store init|set NAME|get NAME|list|rm NAME|path \
                         [--store PATH] [--passphrase-file PATH]"
                    );
                    return 0;
                }
                _ => positional.push(args[i].clone()),
            }
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

    match sub.as_str() {
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
            let Some(name) = positional.first() else {
                eprintln!("confmask: store set needs a NAME");
                return 255;
            };
            let name = name.to_string_lossy().into_owned();
            let mut bytes = match &from_file {
                Some(p) => match std::fs::read(p) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("confmask: {}: {}", p.display(), e);
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
            let Some(name) = positional.first() else {
                eprintln!("confmask: store get needs a NAME");
                return 255;
            };
            let st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confmask: {}", e);
                    return 255;
                }
            };
            match st.get(&name.to_string_lossy()) {
                Some(v) => {
                    let mut out = io::stdout();
                    let _ = out.write_all(v);
                    let _ = out.write_all(b"\n");
                    0
                }
                None => {
                    eprintln!(
                        "confmask: no secret named '{}'",
                        name.to_string_lossy()
                    );
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
            let Some(name) = positional.first() else {
                eprintln!("confmask: store rm needs a NAME");
                return 255;
            };
            let name = name.to_string_lossy().into_owned();
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

fn open_or_create(path: &Path, pp: &Passphrase) -> io::Result<Store> {
    if path.exists() {
        Store::open(path, pp)
    } else {
        Store::create(path, pp)
    }
}

fn resolve_passphrase(explicit: Option<&Path>, creating: bool) -> io::Result<Passphrase> {
    if let Some(p) = explicit {
        return Passphrase::from_file(p);
    }
    if let Some(p) = std::env::var_os("CONFMASK_PASSPHRASE_FILE") {
        return Passphrase::from_file(&path_from(&p));
    }
    if let Some(v) = std::env::var_os("CONFMASK_PASSPHRASE") {
        eprintln!(
            "confmask: warning: CONFMASK_PASSPHRASE is set; it is visible in this process's environ"
        );
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
                "no terminal to ask for a passphrase; use --passphrase-file PATH \
                 or CONFMASK_PASSPHRASE_FILE",
            )
        })?;
    let fd = tty.as_raw_fd();
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr/tcsetattr on the descriptor of an open tty.
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

// ------------------------------------------------------------------ agent

fn cmd_agent(args: &[OsString]) -> i32 {
    let mut path = store::default_path();
    let mut sock = agent::default_socket();
    let mut pass_file: Option<PathBuf> = None;
    let mut allow: Vec<PathBuf> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if let Some(v) = inline_arg(b, "--store") {
            path = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--socket") {
            sock = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--passphrase-file") {
            pass_file = Some(path_from(OsStr::from_bytes(v)));
        } else if let Some(v) = inline_arg(b, "--allow") {
            allow.push(path_from(OsStr::from_bytes(v)));
        } else {
            match b {
                b"--store" => match opt_value(args, &mut i, "--store") {
                    Some(v) => path = path_from(&v),
                    None => return 255,
                },
                b"--socket" => match opt_value(args, &mut i, "--socket") {
                    Some(v) => sock = path_from(&v),
                    None => return 255,
                },
                b"--passphrase-file" => match opt_value(args, &mut i, "--passphrase-file") {
                    Some(v) => pass_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"--allow" => match opt_value(args, &mut i, "--allow") {
                    Some(v) => allow.push(path_from(&v)),
                    None => return 255,
                },
                b"-h" | b"--help" => {
                    println!(
                        "confmask agent [--store PATH] [--socket PATH] \
                         [--passphrase-file PATH] [--allow EXE]..."
                    );
                    return 0;
                }
                other => {
                    eprintln!(
                        "confmask: agent: unknown option '{}'",
                        String::from_utf8_lossy(other)
                    );
                    return 255;
                }
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
    match agent::Daemon::new(st, sock, allow).serve() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("confmask: agent: {}", e);
            255
        }
    }
}

// -------------------------------------------------------------------- get

fn cmd_get(args: &[OsString]) -> i32 {
    let mut sock: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if let Some(v) = inline_arg(b, "--socket") {
            sock = Some(path_from(OsStr::from_bytes(v)));
        } else if b == b"--socket" {
            match opt_value(args, &mut i, "--socket") {
                Some(v) => sock = Some(path_from(&v)),
                None => return 255,
            }
        } else {
            name = Some(args[i].to_string_lossy().into_owned());
        }
        i += 1;
    }
    let Some(name) = name else {
        eprintln!("confmask: get needs a NAME");
        return 255;
    };
    match agent::fetch(sock.as_ref(), &name) {
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
fn cmd_read(args: &[OsString]) -> i32 {
    let Some(name) = args.first() else {
        eprintln!("confmask: read needs a NAME");
        return 255;
    };
    let name = name.to_string_lossy().into_owned();
    let var = secret::env_var_for(&name);
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
        // SAFETY: reading into a local buffer through a descriptor the
        // caller was told about by `run`.
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

/// Parse `--isolate[=LIST]`.
pub fn parse_isolate(v: &[u8]) -> Option<Isolate> {
    if v == b"all" || v.is_empty() {
        return Some(Isolate::all());
    }
    if v == b"none" {
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
    for part in v.split(|&b| b == b',') {
        match part {
            b"pid" => iso.pid = true,
            b"net" => iso.net = true,
            b"tmp" => iso.private_tmp = true,
            _ => return None,
        }
    }
    Some(iso)
}