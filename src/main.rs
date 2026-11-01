//! `confmask` CLI: thin wrapper over the library session API, plus a
//! client for a running `confmaskd`.

use confmask::ExitState;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};

mod cli;

/// pid of the supervised child, for the signal proxy
static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn proxy(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

extern "C" fn ignore_sigpipe(_: libc::c_int) {}

fn install_handlers() {
    const PROXIED: [libc::c_int; 7] = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    unsafe {
        for s in PROXIED {
            libc::signal(s, proxy as *const () as usize);
        }
        libc::signal(libc::SIGPIPE, ignore_sigpipe as *const () as usize);
    }
}

/// Exit the way the supervised program did.
fn finish(st: ExitState) -> ! {
    if let Some(sig) = st.signal {
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    std::process::exit(st.code);
}

/// Print the warning for mask options that a daemon job ignores.
fn warn_daemon_options(opts: &[&'static str], quiet: bool) {
    if opts.is_empty() || quiet {
        return;
    }
    eprintln!(
        "confmask: warning: {} ignored with --daemon (the daemon owns the masking policy)",
        opts.join(", ")
    );
}

/// Re-exec once through `systemd-run --scope`.  The re-exec argv has no
/// `--scope-name`, so the second run cannot take this path again.
fn reexec_in_scope(name: &str, reexec_argv: &[std::ffi::OsString], quiet: bool) {
    use std::os::unix::process::CommandExt;
    let Some(prefix) = confmask::mask::scope_wrap_command(name) else {
        if !quiet {
            eprintln!("confmask: --scope-name unavailable: systemd-run not usable, continuing");
        }
        return;
    };
    if prefix.is_empty() {
        if !quiet {
            eprintln!("confmask: --scope-name unavailable: empty systemd-run command, continuing");
        }
        return;
    }
    let me = match std::env::current_exe() {
        Ok(p) => p.into_os_string(),
        Err(_) => match std::env::args_os().next() {
            Some(a) => a,
            None => return,
        },
    };
    let mut cmd = std::process::Command::new(&prefix[0]);
    cmd.args(&prefix[1..]);
    cmd.arg(me);
    cmd.args(reexec_argv);
    // exec only returns on failure
    let e = cmd.exec();
    if !quiet {
        eprintln!("confmask: --scope-name unavailable: {}, continuing", e);
    }
}

/// The secret side of a local run: descriptor delivery, isolation, or a
/// forced plain exec.  Every mask option parsed from the command line is
/// handed to the session as-is, so `--secret` composes with `--comm`,
/// `--rexec`, `--unshare`, `--no-dumpable` and the rest.
fn run_with_secrets(cli: cli::Cli) -> i32 {
    use confmask::run::{Mode, Runner};
    let mut r = Runner::new().mask(cli.mask);
    for (name, src) in &cli.secrets {
        r = r.secret(name.clone(), src.clone());
    }
    if let Some(sock) = &cli.agent_socket {
        r = r.daemon_socket(sock.clone());
    }
    if let Some(iso) = cli.isolate {
        r = r.isolate(iso);
    }
    if cli.no_redact {
        r = r.no_redaction();
    }
    match r.run(&cli.program, &cli.args) {
        Ok(outcome) => {
            if !cli.quiet {
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
                if outcome.exit.stats.execs > 0 {
                    eprintln!(
                        "confmask: {} of {} execs unredacted",
                        outcome.exit.stats.degraded, outcome.exit.stats.execs
                    );
                }
            }
            if let Some(sig) = outcome.exit.signal {
                // SAFETY: the default handler for a signal the program
                // died from always terminates this process.
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

fn main() {
    // Take an owned copy of the argument vector, then remove the bytes the
    // kernel serves from /proc/<pid>/cmdline.  This is the earliest point a
    // supervisor can redact itself; everything after it (option parsing,
    // executable resolution, probes) runs with the secret already gone
    // from the process table.
    let mut argv = confmask::mask::snapshot_argv();
    if std::env::var_os("CONFMASK_NO_SELFMASK").is_none() {
        let _ = confmask::mask::zero_argv_block();
    }

    // The secret-side subcommands (store, agent, read, probe, ...).  Each
    // one is a distinct verb; the default face of the program is the mask.
    if argv.len() >= 2 && confmask::subcmd::is_subcommand(&argv[1]) {
        std::process::exit(confmask::subcmd::dispatch(&argv, &cli::help_text()));
    }
    // `confmask run ...` is the mask parser with the secret options; the
    // word is dropped so both spellings share one implementation.
    if argv.len() >= 2 && argv[1].as_bytes() == b"run" {
        argv.remove(1);
        if argv.iter().any(|a| a.as_bytes() == b"--run-help") {
            print!("{}", cli::help_text());
            std::process::exit(0);
        }
    }
    let mut cli = cli::parse_from(argv);

    if cli.needs_runner() {
        std::process::exit(run_with_secrets(cli));
    }

    if let Some(socket) = cli.daemon.take() {
        // Remote mode: the daemon holds the environment and supervises
        // the job; this process only forwards argv, stdio and the result.
        warn_daemon_options(&cli.mask_opts, cli.quiet);
        cli.load_args_fd();
        if let confmask::daemon::RemoteLabel::Text(t) = &cli.remote_label {
            if let Err(e) = confmask::mask::validate_label(t) {
                eprintln!("confmask: {}", e);
                std::process::exit(255);
            }
        }
        let argv = confmask::daemon::client_argv(&cli.program, &cli.args);
        let path = std::path::Path::new(&socket);
        match confmask::daemon::run_remote(path, cli.remote_label, &argv) {
            Ok(st) => finish(st),
            Err(e) => {
                eprintln!(
                    "confmask: daemon {}: {}",
                    std::path::Path::new(&socket).display(),
                    e
                );
                std::process::exit(255);
            }
        }
    }

    if let Some(name) = cli.scope_name.clone() {
        reexec_in_scope(&name, &cli.reexec_argv, cli.quiet);
    }
    cli.load_args_fd();

    // Local mode.  Order matters: build the exec plan (argv and a
    // snapshot of the environment) first, redact this process, and only
    // then fork.  The secrets are never in this process's argv or
    // environ once the fork has happened.
    let no_selfmask = std::env::var_os("CONFMASK_NO_SELFMASK").is_some();
    let prepared = match cli.mask.prepare(&cli.program, &cli.args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("confmask: {}: {}", cli.program.to_string_lossy(), e);
            std::process::exit(255);
        }
    };

    if !no_selfmask {
        if let Err(e) = prepared.mask_self() {
            if !cli.quiet {
                eprintln!("confmask: warning: cannot redact own /proc entry: {}", e);
            }
        }
    }

    let child = match cli.mask.spawn_prepared(prepared) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("confmask: {}: {}", cli.program.to_string_lossy(), e);
            std::process::exit(255);
        }
    };

    CHILD.store(child.id() as i32, Ordering::Relaxed);
    install_handlers();

    match child.wait() {
        Ok(st) => finish(st),
        Err(e) => {
            eprintln!("confmask: session error: {}", e);
            std::process::exit(255);
        }
    }
}
