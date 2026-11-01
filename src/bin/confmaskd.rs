//! `confmaskd`: the long-running half of confmask.
//!
//! Holds the job environment (tokens included) in memory, masks its own
//! `/proc` entry, and runs jobs on request from local clients of the same
//! uid.  An allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.
//! See `confmask::daemon` for the protocol.

use confmask::daemon::{self, DaemonConfig};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::exit;

const HELP: &str = r#"
confmaskd {version} - confidential job supervisor

Runs jobs for local clients without the client ever holding the
environment they need.  The daemon keeps the job environment (loaded
from --env-file, so tokens never appear in a command line), masks its
own /proc entry, and hands each job the client's stdio and exit status.

Warning: an allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.

Usage: confmaskd [OPTIONS]

Options:
  -S, --socket PATH     Unix socket to bind (default: $XDG_RUNTIME_DIR/
                        confmask.sock when that directory is owned by
                        you and not group or other writable, else
                        /run/confmask.sock as root, else
                        /tmp/confmask-<uid>.sock)
  -l, --label NAME      Label for a job whose client sends no label
                        (default: 'confmask-job').  A client --label
                        replaces it.  A client --label-empty gives the
                        job an empty label.  NAME has no NUL, LF or CR.
  -e, --env-file FILE   Load KEY=VALUE lines as the job environment
                        (repeatable; later files win).  Grammar: blank
                        lines and lines that start with # are skipped;
                        'export ' before KEY is allowed; KEY has
                        printable ASCII only, no space and no '=';
                        VALUE loses surrounding blanks, and one pair of
                        matching ' or " quotes around it is removed;
                        there are no escapes; a NUL byte is an error.
                        Errors name the file and the line.  A warning
                        appears when the file is readable by group or
                        other.
      --no-inherit-env  Jobs get the --env-file variables only, not the
                        environment the daemon started with
      --keep-env        Leave /proc/<pid>/environ visible for jobs
      --allow-uid UID   Also accept connections from this uid (repeatable;
                        the daemon's own uid and root are always accepted)
      --run-as-uid      Root daemon only.  Run each job with the uid and
                        gid of the client instead of root.
      --socket-mode OCT Socket permission bits (default: 600)
      --io-timeout SECONDS
                        Drop a client that stalls while it sends its
                        request or reads the response (default: 30;
                        0 means no limit)
      --job-timeout SECONDS
                        Kill a job tree that runs longer than this and
                        return code 137 (default: no limit)
      --jobs N          Run up to N jobs at once, one worker process per
                        connection (default: 1)
      --max-job-bytes N Largest total size of the job arguments, each
                        counted with its NUL byte (default: 1048576)
  -q, --quiet           Suppress diagnostics
  -v, --verbose         Log each accepted job
  -V, --version         Print version
  -h, --help            This help

By default the daemon runs one job at a time: a masking session owns the
process-wide waitpid domain, so sessions cannot overlap in one process.
With --jobs N a forked worker runs each job.

The daemon locks its copy of the job environment in memory.  On SIGTERM
or SIGINT it kills running jobs, overwrites the stored environment,
removes the socket and exits with code 0.

The daemon refuses to start when the socket path is a symbolic link, is
not a socket, or has a live daemon behind it.

Examples:
  # secrets live in a root-owned file; the runner never reads it
  confmaskd --label ci-runner --env-file /etc/confmask/runner.env
  confmask --daemon /run/confmask.sock -- ./deploy.sh --env prod
"#;

struct Args {
    cfg: DaemonConfig,
    env_files: Vec<OsString>,
    no_inherit_env: bool,
}

fn die(text: &str) -> ! {
    eprintln!("confmaskd: {}", text);
    exit(255);
}

fn main() {
    // A closed 0, 1 or 2 would let a later open() return a low number
    // that a job then inherits as its stdio.
    if let Err(e) = daemon::ensure_stdio_open() {
        die(&format!("cannot open /dev/null: {}", e));
    }
    let args = parse();
    let mut overrides: Vec<(OsString, OsString)> = Vec::new();
    for f in &args.env_files {
        let path = std::path::Path::new(f);
        match daemon::parse_env_file(path) {
            Ok(mut vars) => overrides.append(&mut vars),
            Err(e) => die(&e.to_string()),
        }
        if !args.cfg.quiet {
            if let Ok(true) = daemon::env_file_readable_by_others(path) {
                eprintln!(
                    "confmaskd: warning: {} is readable by group or other",
                    path.display()
                );
            }
        }
    }

    // Capture the job environment *before* masking ourselves: after the
    // self-mask this process's own environ is gone by design.
    let mut cfg = args.cfg;
    cfg.env = daemon::job_env(!args.no_inherit_env, &overrides);
    daemon::wipe_env(&mut overrides);

    let comm = cfg.label.as_bytes().iter().take(15).copied().collect::<Vec<u8>>();
    if let Err(e) = confmask::mask_self(&comm, true) {
        if !cfg.quiet {
            eprintln!("confmaskd: warning: self-mask incomplete: {}", e);
        }
    }

    if let Err(e) = daemon::serve(cfg) {
        die(&e.to_string());
    }
}

fn number(flag: &str, text: &str) -> u64 {
    match text.parse::<u64>() {
        Ok(n) => n,
        Err(_) => die(&format!("{} needs a number", flag)),
    }
}

fn parse() -> Args {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let mut cfg = DaemonConfig::new();
    let mut env_files = Vec::new();
    let mut no_inherit_env = false;
    let mut i = 1usize;

    while i < argv.len() {
        let bytes = argv[i].as_bytes().to_vec();
        if bytes.len() < 2 || bytes[0] != b'-' {
            die(&format!("unexpected argument: {}", String::from_utf8_lossy(&bytes)));
        }
        if bytes.starts_with(b"--") {
            let body = &bytes[2..];
            let (name, inline) = match body.iter().position(|&b| b == b'=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_vec())),
                None => (body, None),
            };
            let name = String::from_utf8_lossy(name).into_owned();
            let flag = format!("--{}", name);
            match name.as_str() {
                "socket" => cfg.socket = PathBuf::from(OsString::from_vec(take(&flag, inline, &argv, &mut i))),
                "label" => cfg.label = lossy(take(&flag, inline, &argv, &mut i)),
                "env-file" => env_files.push(OsString::from_vec(take(&flag, inline, &argv, &mut i))),
                "no-inherit-env" => no_inherit_env = true,
                "keep-env" => cfg.keep_env = true,
                "run-as-uid" => cfg.run_as_uid = true,
                "allow-uid" => {
                    let v = lossy(take(&flag, inline, &argv, &mut i));
                    match v.parse::<u32>() {
                        Ok(u) => cfg.allow_uids.push(u),
                        Err(_) => die("--allow-uid needs a number"),
                    }
                }
                "socket-mode" => {
                    let v = lossy(take(&flag, inline, &argv, &mut i));
                    match u32::from_str_radix(v.trim_start_matches("0o"), 8) {
                        Ok(m) => cfg.socket_mode = m,
                        Err(_) => die("--socket-mode needs an octal number"),
                    }
                }
                "io-timeout" => {
                    cfg.io_timeout_secs = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                }
                "job-timeout" => {
                    cfg.job_timeout_secs = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                }
                "jobs" => {
                    let n = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                    if n == 0 {
                        die("--jobs needs a number of at least 1");
                    }
                    cfg.jobs = n as usize;
                }
                "max-job-bytes" => {
                    let n = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                    if n == 0 {
                        die("--max-job-bytes needs a number of at least 1");
                    }
                    cfg.max_job_bytes = n as usize;
                }
                "quiet" => cfg.quiet = true,
                "verbose" => cfg.verbose = true,
                "version" => {
                    println!("confmaskd {} ({})", confmask::VERSION, confmask::arch_name());
                    exit(0);
                }
                "help" => {
                    print_help(true);
                    exit(0);
                }
                _ => die(&format!("unknown option --{}", name)),
            }
            i += 1;
            continue;
        }
        let mut j = 1usize;
        while j < bytes.len() {
            match bytes[j] {
                b'S' => {
                    let inline = if j + 1 < bytes.len() { Some(bytes[j + 1..].to_vec()) } else { None };
                    cfg.socket = PathBuf::from(OsString::from_vec(take("-S", inline, &argv, &mut i)));
                    j = bytes.len();
                    continue;
                }
                b'l' => {
                    let inline = if j + 1 < bytes.len() { Some(bytes[j + 1..].to_vec()) } else { None };
                    cfg.label = lossy(take("-l", inline, &argv, &mut i));
                    j = bytes.len();
                    continue;
                }
                b'e' => {
                    let inline = if j + 1 < bytes.len() { Some(bytes[j + 1..].to_vec()) } else { None };
                    env_files.push(OsString::from_vec(take("-e", inline, &argv, &mut i)));
                    j = bytes.len();
                    continue;
                }
                b'q' => cfg.quiet = true,
                b'v' => cfg.verbose = true,
                b'V' => {
                    println!("confmaskd {} ({})", confmask::VERSION, confmask::arch_name());
                    exit(0);
                }
                b'h' => {
                    print_help(true);
                    exit(0);
                }
                other => die(&format!("unknown option -{}", String::from_utf8_lossy(&[other]))),
            }
            j += 1;
        }
        i += 1;
    }

    Args { cfg, env_files, no_inherit_env }
}

/// Value of an option.  `flag` is the option as the user types it
/// (`-S` or `--socket`), used in the error message.
fn take(flag: &str, inline: Option<Vec<u8>>, argv: &[OsString], i: &mut usize) -> Vec<u8> {
    match inline {
        Some(v) => v,
        None => {
            *i += 1;
            match argv.get(*i) {
                Some(v) => v.as_bytes().to_vec(),
                None => die(&format!("option {} needs a value", flag)),
            }
        }
    }
}

fn lossy(b: Vec<u8>) -> String {
    String::from_utf8_lossy(&b).into_owned()
}

fn print_help(stdout: bool) {
    let text = HELP.replace("{version}", confmask::VERSION);
    if stdout {
        println!("{}", text);
    } else {
        eprintln!("{}", text);
    }
}
