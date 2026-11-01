//! CLI argument parsing for `confmask`.

use confmask::daemon::RemoteLabel;
use confmask::isolate::Isolate;
use confmask::mask::Mask;
use confmask::secret::Source;
use confmask::SessionEnd;
use std::path::PathBuf;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::FromRawFd;
use std::process::exit;

pub const HELP: &str = r#"
confmask {version} ({arch}) - redact the /proc metadata of a whole process tree

Run COMMAND with a presentation label in place of its real command line,
environment and process name as seen through /proc (and therefore ps, top,
htop, btop and any other process monitor).  Every process the command ever
spawns - children, grandchildren, daemons, threads, posix_spawn/system(),
static binaries, scripts - is covered.  Programs keep their real argv/envp
and work completely normally.

Use it to keep secrets off the process table: tokens, passwords or internal
hostnames passed as arguments are otherwise readable by every local account
that can run `ps`, for the whole lifetime of a process.

Usage: confmask [OPTIONS] [--] COMMAND [ARGS...]
       confmask [OPTIONS] --args-from-fd N

Options:
  -l, --label NAME     Presentation label for every process' /proc cmdline
                       and comm (e.g. --label 'ci-runner').  The value '-'
                       gives a blank label (one space); '-l-', '-l -',
                       '--label=-' and '--label -' all mean the same.
                       The label must not contain NUL, LF or CR.
                       Default: keep each program's own name, strip all
                       arguments.
      --label-empty    Empty label (cmdline shows nothing at all).
      --argv0 NAME     argv[0] of the program.  Default: COMMAND exactly as
                       typed (not the resolved path).
      --comm NAME      comm name (what top shows), at most 15 bytes.
                       Default: the label cut to 15 bytes.
      --keep-env       Leave /proc/<pid>/environ visible (default: redacted).
      --keep-env=NAME[,NAME...]
                       Keep only the named variables visible in
                       /proc/<pid>/environ; the rest stays redacted.  The
                       inline '=' form is required.  Repeatable.
      --env K=V        Add or replace one variable for the program.
                       Repeatable.
      --env-file PATH  Read variables for the program from PATH: one KEY=VALUE
                       per line, '#' starts a comment line, blank lines are
                       skipped, no quoting, values are taken as written.
                       Repeatable.
      --args-from-fd N Read the command from file descriptor N: NUL-separated
                       program and arguments.  The secrets then never appear
                       in confmask's own command line:
                         confmask -l ci-runner --args-from-fd 3 3<args.bin
      --on-exit POLICY What happens to descendants still running when the
                       command exits: detach (default), wait or kill.
      --no-follow      Redact only the direct child; descendants run
                       unredacted (still traced, but never redacted).
      --no-exit-kill   Let the tree survive if confmask dies (default: kill
                       the whole tree, so no half-redacted orphans remain).
      --no-dumpable    Set PR_SET_DUMPABLE=0 in every process of the tree.
                       Same-uid observers cannot read environ, maps, exe or
                       fd.  Core dumps and debugger attach stop working.
      --no-new-privs   Set no_new_privs before exec.  Set-uid and file
                       capabilities give nothing, for the whole tree.
      --watch-rename   Keep the label as comm when a program renames itself
                       (prctl PR_SET_NAME).  Uses a seccomp filter; implies
                       --no-new-privs.  If the filter cannot be installed,
                       one line is printed and the program runs without it.
      --rexec          Exec the program from a sealed memfd so that
                       /proc/<pid>/exe names the label, not the file.  On
                       failure one line is printed and the normal exec runs.
      --unshare        Run in new user, pid and mount namespaces with a
                       private /proc, when the kernel allows it.  Otherwise
                       one 'confmask: --unshare unavailable:' line is printed
                       and the run continues without it.
      --scope-name NAME
                       Re-exec once through 'systemd-run --scope' so the tree
                       runs in a transient scope named NAME.  The name is
                       visible in /proc/<pid>/cgroup.  Without systemd one
                       line is printed and the run continues.
  -q, --quiet          Suppress diagnostics.
  -v, --verbose        Trace every redaction event to stderr.
  -V, --version        Print version.
  -h, --help           This help.

Compatibility aliases: -a NAME (= --label), -a- (= -l-), -E (= --keep-env),
-F (= --no-follow), -K (= --no-exit-kill), -f/-c (accepted, no effect).

Label limits: the label is cut at three places.  comm keeps 15 bytes.  The
exec entry path keeps 254 bytes of the label.  The post-exec path (scripts)
cuts the label to the span of the argument area.  A warning is printed once
when the label is longer than 254 bytes.

With --daemon PATH the job runs inside a confmaskd.  The daemon owns the
masking policy and the environment: it refuses an environment from the
client on purpose, so a client cannot change what the job inherits.  Mask
options other than --label and --label-empty have no effect there and
produce a warning.

Environment: CONFMASK_NO_SELFMASK=1 disables the redaction of confmask's own
/proc entry (argv, environ, comm).  Use it only for debugging.

Secret side (works even where ptrace is refused):
  --secret N=SRC       deliver a secret on descriptor 3, 4, ...  SRC is
                       file:PATH | env:VAR | agent:NAME | stdin | literal:VAL.
                       Repeatable; CONFMASK_SECRET_<N> names the descriptor in
                       the child, and `confmask read NAME` prints it there.
  --socket PATH        secret-agent socket for agent:NAME sources.
  --isolate[=LIST]     run the payload in fresh namespaces: pid,net,tmp |
                       all | none (default all).
  --no-redact          never touch /proc metadata, even where ptrace works.

  `confmask run ...` is this same parser; `confmask help` lists the rest
  (store, agent, get, read, probe, doctor).

Examples:
  # a deployment whose token must not land in `ps` output:
  confmask --label 'ci-runner' ./deploy.sh --token "$TOKEN" --env prod

  # long-lived worker started by a service manager:
  confmask -q --label 'app-worker' python worker.py --queue=rediss://...

Honest scope: root on the host always sees THAT a pid exists; confmask
redacts WHAT it is.  /proc/<pid>/exe, maps, open files and cgroups still
describe the real binary unless --rexec, --no-dumpable or --unshare is
used.  Set-uid programs do not gain privileges under supervision (a
general ptrace property)."#;

pub struct Cli {
    pub mask: Mask,
    pub program: OsString,
    pub args: Vec<OsString>,
    /// `--daemon PATH`: ask a running confmaskd to run the job instead of
    /// supervising it here.
    pub daemon: Option<OsString>,
    /// Label to send to the daemon.
    pub remote_label: RemoteLabel,
    /// `-q` is the last of `-q` and `-v`.
    pub quiet: bool,
    /// Mask options given on the command line that a daemon ignores.
    pub mask_opts: Vec<&'static str>,
    /// `--scope-name NAME`.
    pub scope_name: Option<String>,
    /// The command line without `--scope-name`, for the one re-exec.
    pub reexec_argv: Vec<OsString>,
    /// `--args-from-fd N`, until `load_args_fd` has read it.
    pub args_fd: Option<libc::c_int>,
    /// `--secret NAME=SRC`, delivered over descriptors.
    pub secrets: Vec<(String, Source)>,
    /// `--socket PATH`: the secret agent to ask for `agent:NAME` sources.
    pub agent_socket: Option<PathBuf>,
    /// `--isolate[=LIST]`: a private namespace set for the payload.
    pub isolate: Option<Isolate>,
    /// `--no-redact`: never touch /proc metadata.
    pub no_redact: bool,
}

impl Cli {
    /// True when the run needs the secret machinery rather than the plain
    /// mask path: any secret, isolation, or an explicit `--no-redact`.
    pub fn needs_runner(&self) -> bool {
        !self.secrets.is_empty() || self.isolate.is_some() || self.no_redact
    }
}

fn die(msg: &str) -> ! {
    eprintln!("confmask: {}", msg);
    exit(255);
}

/// Fetch an option value: the attached bytes when present, otherwise the
/// next argv element whatever it looks like (`-l -x` labels the process
/// `-x`, matching the C tool).
fn take_value(flag: &str, inline: Option<Vec<u8>>, argv: &[OsString], i: &mut usize) -> Vec<u8> {
    match inline {
        Some(v) => v,
        None => {
            *i += 1;
            match argv.get(*i) {
                Some(v) => v.as_bytes().to_vec(),
                None => {
                    eprintln!("confmask: option {} needs a value", flag);
                    exit(255);
                }
            }
        }
    }
}

/// Labels are presentation text, so they are decoded as UTF-8 (lossily).
/// Program arguments are not: those are passed through byte for byte.
fn label_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The label for a `-l`/`--label` value: `-` means blank (one space) in
/// every spelling.
fn label_arg(bytes: &[u8]) -> String {
    if bytes == b"-" {
        " ".to_string()
    } else {
        label_from(bytes)
    }
}

/// Parse an `--env-file`: `KEY=VALUE` lines, `#` comment lines, blank
/// lines skipped.  Keys must be non-empty and free of NUL; values are
/// taken as written.
fn read_env_file(path: &[u8]) -> Vec<(OsString, OsString)> {
    let shown = String::from_utf8_lossy(path).into_owned();
    let p = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    let data = match std::fs::read(p) {
        Ok(d) => d,
        Err(e) => die(&format!("--env-file {}: {}", shown, e)),
    };
    let mut out = Vec::new();
    for (n, line) in data.split(|&b| b == b'\n').enumerate() {
        let lineno = n + 1;
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line.contains(&0) {
            die(&format!("--env-file {}: line {}: NUL byte", shown, lineno));
        }
        let eq = match line.iter().position(|&b| b == b'=') {
            Some(p) if p > 0 => p,
            _ => die(&format!(
                "--env-file {}: line {}: expected KEY=VALUE",
                shown, lineno
            )),
        };
        out.push((
            OsString::from_vec(line[..eq].to_vec()),
            OsString::from_vec(line[eq + 1..].to_vec()),
        ));
    }
    out
}

fn parse_on_exit(v: &[u8]) -> SessionEnd {
    match v {
        b"detach" => SessionEnd::Detach,
        b"wait" => SessionEnd::WaitTree,
        b"kill" => SessionEnd::KillTree,
        _ => die("--on-exit takes detach, wait or kill"),
    }
}

fn note_opt(list: &mut Vec<&'static str>, name: &'static str) {
    if !list.contains(&name) {
        list.push(name);
    }
}

/// Parse an already-copied argument vector.
///
/// `main` passes the copy it took before it zeroed the kernel-served argv
/// block, so option parsing never depends on the process's own /proc
/// entry.  The vector is `args_os` style: `std::env::args()` panics on a
/// non-UTF-8 argument, and a supervisor must forward bytes exactly.
pub fn parse_from(argv: Vec<OsString>) -> Cli {
    let mut mask = Mask::new();
    let mut daemon: Option<OsString> = None;
    let mut remote_label = RemoteLabel::Default;
    let mut quiet = false;
    let mut mask_opts: Vec<&'static str> = Vec::new();
    let mut scope_name: Option<String> = None;
    let mut skip: Vec<usize> = Vec::new();
    let mut args_fd: Option<libc::c_int> = None;
    let mut secrets: Vec<(String, Source)> = Vec::new();
    let mut agent_socket: Option<PathBuf> = None;
    let mut isolate: Option<Isolate> = None;
    let mut no_redact = false;
    let mut end_opts = false;
    let mut i = 1usize;

    while i < argv.len() {
        let bytes = argv[i].as_bytes().to_vec();
        // A token is an option only if it starts with '-' and has another
        // byte; "-" alone is the command word.
        if end_opts || bytes.len() < 2 || bytes[0] != b'-' {
            break;
        }
        if bytes == b"--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if bytes.starts_with(b"--") {
            let body = &bytes[2..];
            let (name_b, inline) = match body.iter().position(|&b| b == b'=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_vec())),
                None => (body, None),
            };
            let Ok(name) = std::str::from_utf8(name_b) else {
                eprintln!(
                    "confmask: unknown option --{}",
                    String::from_utf8_lossy(name_b)
                );
                exit(255);
            };
            match name {
                "label" => {
                    let v = take_value("--label", inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    mask = mask.label(text);
                }
                "daemon" => {
                    let v = take_value("--daemon", inline, &argv, &mut i);
                    daemon = Some(OsString::from_vec(v));
                }
                "label-empty" => {
                    mask = mask.label("");
                    remote_label = RemoteLabel::Empty;
                }
                "argv0" => {
                    let v = take_value("--argv0", inline, &argv, &mut i);
                    mask = mask.argv0(OsString::from_vec(v));
                    note_opt(&mut mask_opts, "--argv0");
                }
                "comm" => {
                    let v = take_value("--comm", inline, &argv, &mut i);
                    mask = mask.comm(label_from(&v));
                    note_opt(&mut mask_opts, "--comm");
                }
                "keep-env" => {
                    match inline {
                        None => mask = mask.keep_environ_visible(),
                        Some(list) => {
                            let names: Vec<String> = list
                                .split(|&b| b == b',')
                                .filter(|n| !n.is_empty())
                                .map(label_from)
                                .collect();
                            if names.is_empty() {
                                die("--keep-env= needs at least one name");
                            }
                            mask = mask.keep_env_vars(names);
                        }
                    }
                    note_opt(&mut mask_opts, "--keep-env");
                }
                "env" => {
                    let v = take_value("--env", inline, &argv, &mut i);
                    match v.iter().position(|&b| b == b'=') {
                        Some(p) if p > 0 => {
                            mask = mask.env(
                                OsString::from_vec(v[..p].to_vec()),
                                OsString::from_vec(v[p + 1..].to_vec()),
                            );
                        }
                        _ => die("--env needs KEY=VALUE"),
                    }
                    note_opt(&mut mask_opts, "--env");
                }
                "env-file" => {
                    let v = take_value("--env-file", inline, &argv, &mut i);
                    for (k, val) in read_env_file(&v) {
                        mask = mask.env(k, val);
                    }
                    note_opt(&mut mask_opts, "--env-file");
                }
                "args-from-fd" => {
                    let v = take_value("--args-from-fd", inline, &argv, &mut i);
                    let n = std::str::from_utf8(&v)
                        .ok()
                        .and_then(|s| s.parse::<libc::c_int>().ok())
                        .filter(|n| *n >= 0);
                    match n {
                        Some(n) => args_fd = Some(n),
                        None => die("--args-from-fd needs a file descriptor number"),
                    }
                }
                "on-exit" => {
                    let v = take_value("--on-exit", inline, &argv, &mut i);
                    mask = mask.session_end(parse_on_exit(&v));
                    note_opt(&mut mask_opts, "--on-exit");
                }
                "no-follow" => {
                    mask = mask.follow_tree(false);
                    note_opt(&mut mask_opts, "--no-follow");
                }
                "no-exit-kill" | "no-exitkill" => {
                    mask = mask.let_tree_survive_self_death();
                    note_opt(&mut mask_opts, "--no-exit-kill");
                }
                "no-dumpable" => {
                    mask = mask.no_dumpable();
                    note_opt(&mut mask_opts, "--no-dumpable");
                }
                "no-new-privs" => {
                    mask = mask.no_new_privs();
                    note_opt(&mut mask_opts, "--no-new-privs");
                }
                "watch-rename" => {
                    mask = mask.watch_rename();
                    note_opt(&mut mask_opts, "--watch-rename");
                }
                "rexec" => {
                    mask = mask.rexec();
                    note_opt(&mut mask_opts, "--rexec");
                }
                "unshare" => {
                    mask = mask.unshare();
                    note_opt(&mut mask_opts, "--unshare");
                }
                "scope-name" => {
                    let has_inline = inline.is_some();
                    let v = take_value("--scope-name", inline, &argv, &mut i);
                    // i now indexes the value token when it was separate
                    skip.push(i);
                    if !has_inline {
                        skip.push(i - 1);
                    }
                    let text = label_from(&v);
                    mask = mask.scope_name(text.clone());
                    scope_name = Some(text);
                    note_opt(&mut mask_opts, "--scope-name");
                }
                "secret" => {
                    let v = take_value("--secret", inline, &argv, &mut i);
                    match Source::parse(&String::from_utf8_lossy(&v)) {
                        Ok(pair) => secrets.push(pair),
                        Err(e) => die(&format!("--secret: {}", e)),
                    }
                }
                "socket" => {
                    let v = take_value("--socket", inline, &argv, &mut i);
                    agent_socket = Some(PathBuf::from(OsString::from_vec(v)));
                }
                "isolate" => {
                    isolate = match inline {
                        None => Some(Isolate::all()),
                        Some(list) => match confmask::subcmd::parse_isolate(&list) {
                            Some(iso) => Some(iso),
                            None => die("--isolate takes pid,net,tmp,all or none"),
                        },
                    };
                    note_opt(&mut mask_opts, "--isolate");
                }
                "no-redact" => {
                    no_redact = true;
                    note_opt(&mut mask_opts, "--no-redact");
                }
                "quiet" => {
                    mask = mask.quiet();
                    quiet = true;
                }
                "verbose" => {
                    mask = mask.verbose();
                    quiet = false;
                }
                "version" => {
                    println!("confmask {} ({})", confmask::VERSION, arch_name());
                    exit(0);
                }
                "help" => {
                    print_help(true);
                    exit(0);
                }
                _ => {
                    eprintln!("confmask: unknown option --{}", name);
                    exit(255);
                }
            }
            i += 1;
            continue;
        }
        // short cluster: -qv, -afoo, -l-
        let mut j = 1usize;
        while j < bytes.len() {
            match bytes[j] {
                b'l' | b'a' => {
                    let flag = if bytes[j] == b'l' { "-l" } else { "-a" };
                    let inline: Option<Vec<u8>> = if j + 1 < bytes.len() {
                        Some(bytes[j + 1..].to_vec())
                    } else {
                        None
                    };
                    let v = take_value(flag, inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    mask = mask.label(text);
                    j = bytes.len();
                    continue;
                }
                b'E' => {
                    mask = mask.keep_environ_visible();
                    note_opt(&mut mask_opts, "--keep-env");
                }
                b'F' => {
                    mask = mask.follow_tree(false);
                    note_opt(&mut mask_opts, "--no-follow");
                }
                b'K' => {
                    mask = mask.let_tree_survive_self_death();
                    note_opt(&mut mask_opts, "--no-exit-kill");
                }
                b'f' | b'c' => {} // compat no-ops
                b'q' => {
                    mask = mask.quiet();
                    quiet = true;
                }
                b'v' => {
                    mask = mask.verbose();
                    quiet = false;
                }
                b'V' => {
                    println!("confmask {} ({})", confmask::VERSION, arch_name());
                    exit(0);
                }
                b'h' => {
                    print_help(true);
                    exit(0);
                }
                other => {
                    eprintln!(
                        "confmask: unknown option -{}",
                        String::from_utf8_lossy(&[other])
                    );
                    exit(255);
                }
            }
            j += 1;
        }
        i += 1;
    }

    let reexec_argv: Vec<OsString> = argv
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(idx, _)| !skip.contains(idx))
        .map(|(_, a)| a.clone())
        .collect();

    let (program, args) = if args_fd.is_some() {
        if i < argv.len() {
            die("--args-from-fd replaces COMMAND: no command may follow the options");
        }
        (OsString::new(), Vec::new())
    } else {
        if i >= argv.len() {
            print_help(false);
            exit(255);
        }
        // Program and arguments keep their exact bytes.
        (argv[i].clone(), argv[i + 1..].to_vec())
    };

    Cli {
        mask,
        program,
        args,
        daemon,
        remote_label,
        quiet,
        mask_opts,
        scope_name,
        reexec_argv,
        args_fd,
        secrets,
        agent_socket,
        isolate,
        no_redact,
    }
}

impl Cli {
    /// Read the command from the `--args-from-fd` descriptor, when one
    /// was given.  The descriptor is closed afterwards.
    pub fn load_args_fd(&mut self) {
        let Some(fd) = self.args_fd.take() else {
            return;
        };
        // SAFETY: the descriptor number comes from the operator, who
        // passes it open on purpose.  The File closes it after the read.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut data = Vec::new();
        if let Err(e) = file.read_to_end(&mut data) {
            die(&format!("--args-from-fd {}: {}", fd, e));
        }
        drop(file);
        let mut parts: Vec<Vec<u8>> = data.split(|&b| b == 0).map(|s| s.to_vec()).collect();
        if data.last() == Some(&0) {
            parts.pop(); // the empty piece after the final NUL
        }
        if parts.is_empty() || parts[0].is_empty() {
            die(&format!("--args-from-fd {}: no program given", fd));
        }
        let mut it = parts.into_iter();
        self.program = OsString::from_vec(it.next().unwrap_or_default());
        self.args = it.map(OsString::from_vec).collect();
    }
}

/// `-h`/`--help` go to stdout and exit 0; a usage error goes to stderr
/// and exits 255, like the C tool.
/// The mask help text, with version and arch filled in.
pub fn help_text() -> String {
    HELP
        .replace("{version}", confmask::VERSION)
        .replace("{arch}", arch_name())
}

fn print_help(stdout: bool) {
    let text = HELP
        .replace("{version}", confmask::VERSION)
        .replace("{arch}", arch_name());
    if stdout {
        println!("{}", text);
    } else {
        eprintln!("{}", text);
    }
}

fn arch_name() -> &'static str {
    confmask::arch_name()
}
