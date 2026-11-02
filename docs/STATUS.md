# Status checkpoint

This file records what is implemented, what is verified, what is not, and
how to resume. Read `docs/AGENTS.md` (map and invariants) and
`docs/DESIGN.md` (model) for the rest.

## Where the tree is

- Branch `main`, remote `https://github.com/Nemo-010/confmask`.
- This tree is the redaction engine (`src/tracer.rs`, `src/execimg.rs`,
  `src/inject.rs`, `src/remote.rs`, `src/arch.rs`, `src/selfmask.rs`,
  `src/seccomp.rs`, `src/rexec.rs`, `src/userns.rs`, `src/scope.rs`) with
  the secret side on top of it (`src/mem.rs`, `src/secret.rs`,
  `src/store.rs`, `src/agent.rs`, `src/subcmd.rs`, `src/caps.rs`,
  `src/isolate.rs`, `src/run.rs`). `src/cli.rs` and `src/main.rs` parse
  and dispatch both: the mask options plus `--secret`, `--socket`,
  `--isolate`, `--no-redact` and the subcommands.
- Two trackers feed this file. The per-issue mapping below is the
  redaction engine's, carried over from its own tracker. The secret
  side's issues are separate and still open on this repository.
- The two halves meet in one process: `src/run.rs` loads secrets,
  hardens the holder (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`) and then
  starts the label session. What is verified end to end is the daemon
  path: `tests/daemon.sh` d1-d3 assert that a labelled job receives a
  daemon-supplied secret and that it appears in no `/proc` entry, in
  both the root and the uid 1000 pass. What is not: no suite passes
  `--secret` on the command line, so that delivery path
  (`secret::load`, `Delivery`, `harden_self`) has unit tests only, and
  no case asserts the label and a sealed descriptor together after a
  single `execve`. See "Not verified".

## How to verify

The build sandbox blocks `ptrace` (seccomp) and has no `/dev/kvm`, so the
suites run inside the QEMU micro-VM under TCG. `qemu-system-x86_64`,
`qemu-system-aarch64`, `cpio`, `curl` and `go` are present.

```sh
cargo clippy --all-targets -- -D warnings     # zero warnings
cargo test --lib                              # 40 unit tests, no ptrace
cargo build --release --target x86_64-unknown-linux-musl --bins
sh vm/run.sh                                  # full gate, ~6 min under TCG
```

`vm/run.sh` boots a pinned Alpine `linux-virt` 6.12 kernel and a static
busybox, runs every suite twice (root, then uid 1000) and exits 0 only
when both passes print `FINAL: ALL-PASS`. Console log:
`vm/cache/vm-output.log`.

Other gates: `sh vm/run.sh --old-kernel` boots the pinned 5.15 kernel,
and `CONFMASK_VM_ARCH=aarch64 sh vm/run.sh` builds and boots the
aarch64 harness from an x86_64 host.

MSRV check. `rust-version` in `Cargo.toml` is the floor, and CI builds
at exactly that version. The floor is set by the dependency set, not by
hand: the secret side pulls `argon2`, `chacha20poly1305` and `zeroize`,
and `zeroize` 1.8 declares `rust-version = "1.85"` with `edition =
"2024"`, which no compiler older than 1.85 can parse. The source also
uses `c"…"` literals (stable since 1.77) instead of `b"…\0"` casts, so
1.85 covers both. Locally:

```sh
rustup toolchain install 1.85 --profile minimal
cargo +1.85 build --bins
```

Both `vm/run.sh` and `vm/common.sh` read the artifact directory from
`CARGO_TARGET_DIR` when the caller sets one, so a shared target dir
works (`env.sh` in the dev sandbox does exactly that).

Disk: `df /workspace` reports the host pool, not the sandbox quota. The
working budget is 10 GiB; keep `target/` and `vm/cache/` trimmed.

## Verified

| check | result |
|---|---|
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --lib` | 40 passed |
| MSRV 1.85.1 build (`--bins`) | clean, no warnings |
| `cargo package` (68 files) | packaged |
| `vm/run.sh` (see below) | all suites pass except the two items in "Not verified" |
| CI on GitHub (push `399f0a0`, run 41270963973) | `msrv`, `build` and `suites-in-vm` all green |

Full VM run of 2026-10-31, kernel 6.12.114-r0, x86_64, QEMU TCG, root
and uid 1000 passes: `validate`, `suite`, `stress`, `edge` (except e7,
now fixed), `daemon`, `options`, `core` all `FAIL=0`; `audit` skipped
with its reason; `daemon_neg` did not exist yet in that run.

Re-run on this tree, 2026-11-01, same pinned kernel (6.12.114-r0,
x86_64, QEMU TCG, root then uid 1000): exit 0, `VM-HARNESS: ALL-PASS`,
392 PASS, 0 FAIL, 5 SKIP, `cargo test --lib` 40 passed, clippy clean.
The secret side is in this run: `daemon` passes d1-d3 for both uids.

CI ran the same tree on GitHub (push `399f0a0`, run 41270963973):
`msrv` 16 s, `build` 57 s, `suites-in-vm` 9 m 14 s, all three green.
The `msrv` job failed on the previous commit, where `rust-version` still
said 1.74 and `cargo build --locked` could not parse `zeroize`'s 2024
edition; it reads the floor out of `Cargo.toml`, so the two cannot
silently disagree again.

Evidence that the hard cases work, from `tests/core.sh` inside the VM:

- 10001 arguments: `argc=10004`, byte-exact tail, 0 sightings. The
  hidden block lives in an injected anonymous mapping: the stack range
  below `sp` is unmapped at that size (the kernel's page pinning does
  not expand a grow-down VMA).
- 5 KB and 100 KB single arguments: byte-exact, no tail leak.
- 32-bit image: refused with one warning, program keeps its real argv,
  `foreign-arch` in the session summary.
- non-leader-thread exec, failed-exec retry, job control (SIGSTOP holds,
  SIGCONT resumes), session-end detach/wait/kill: pass.
- injected repoint failure (`CONFMASK_FAULT_POKE=1`): zeroed visible
  region, one warning, program still runs.
- completion-stop cost with a 4000-entry environment: 11 reads, printed
  as `INFO completion-stop <us>us reads=11`.

## Last full run (2026-10-31, final gate)

`sh vm/run.sh` on this host: exit 0, `VM-HARNESS: ALL-PASS (root and
non-root)`. Kernel 6.12.114-r0, x86_64, QEMU TCG, root pass and uid
1000 pass. 392 PASS lines, 0 FAIL, 5 SKIP (audit in both passes,
n25, o15 and k13 in the uid 1000 pass). `validate`, `suite`, `stress`,
`edge`, `daemon`, `daemon_neg`, `options` and `core` print FAIL=0 in
both passes; `audit` skips with its printed reason.

Suite behaviour worth knowing when a case fails:

- `edge.sh` E7 counts the supervisor's own blank comm plus at least one
  live blank-comm tracee, and skips zombies. A blank label gives exactly
  one of each: the supervisor and the tracee both carry the one-space
  comm.
- `edge.sh` E6 matches the shapes a real argv takes (the probe binary by
  name, the supervisor as a command followed by a flag). A masked label
  that contains the word `confmask`, such as the daemon default label
  `confmask-job`, is not a leak and does not match. E6 waits for the
  supervisor's cmdline to read as the label, and reaps the control
  sleeper before it scans.
- `daemon_neg.sh` passes 25 cases. The double-fork job's master exits
  (`... daemonspawn ... & exit 0`), because a master left in `pause()`
  never answers and the daemon has nothing to return. N25 starts the
  daemon with `--socket-mode 666`, because the default 0600 socket keeps
  another uid out before the peer check ever runs.

Host checks: `cargo clippy --all-targets -- -D warnings` clean,
`cargo test --lib` 40 passed, MSRV 1.85.1 build of all bins clean,
`cargo build --release --examples` clean, `cargo package
--allow-dirty --no-verify` 68 files (650.7 KiB).

Two other gates:

- `sh vm/run.sh --old-kernel` (Alpine v3.17, linux-virt 5.15.208-r0,
  pinned sha256 f7e694a9...): exit 0, `VM-HARNESS: ALL-PASS`, 392 PASS,
  0 FAIL, the same 5 SKIP lines.
- The aarch64 harness boots and works. A smoke boot of the pinned
  aarch64 kernel (6.12.114-r0, `-machine virt -cpu cortex-a57`, TCG)
  ran `uname -m` (aarch64), a masked exec with argv fidelity
  (`arg2=AA1 arg3=AA2 env=[ok]`), zero sightings of the marker, and two
  processes carrying the label comm. `vm/common.sh` now takes
  `CONFMASK_VM_ARCH=aarch64` so the aarch64 harness runs from an x86_64
  host. A full aarch64 suite run did not run.

## Not verified

1. `--run-as-uid` has no suite case: no test starts a root daemon and
   connects as another uid. `--no-dumpable` (O15) and the set-uid case
   (K13) run in the root pass only; the uid 1000 pass prints `SKIP`.
2. `--scope-name` (`src/scope.rs`) has no suite case, and the initramfs
   has no `systemd-run` and no session manager.
3. The environment key validation in `src/mask.rs` has no case that
   feeds a bad key to `--env`.
4. The Go case (`tests/suite.sh` T7b) needs a Go toolchain and runs on a
   host only; the initramfs has none.
5. The full aarch64 suite: only a smoke boot was done (see above), and
   the host this checkpoint was taken on has no `qemu-system-aarch64`.
5. `tests/audit.sh` skips on this kernel: the `EXECVE` netlink record
   stops before the argument text (`payload_len=35`, ends at `a0=`), so
   the control cannot see its own secret. The suite prints the reason and
   the sample record. Options: run it on a host with `auditd` installed,
   or find a kernel that logs the text, or replace the observer with an
   eBPF/kprobe one (`CONFIG_KPROBE_EVENTS` and `BPF_SYSCALL` are on in the
   VM kernel, but no userland tool exists in the initramfs).
6. The secret side beyond the daemon: no suite passes `--secret`, so
   `secret::load`, `Delivery` and the `harden_self` path that precedes a
   labelled session have unit tests only (`src/secret.rs`,
   `src/store.rs`, `src/agent.rs`). No case runs one `execve` and then
   asserts, against the same child, both the label in `/proc/<pid>/cmdline`
   and the sealed descriptor on fd 3 with the secret absent from
   `environ`. Until one does, the two mechanisms are verified separately,
   not together.
7. `--secret` has no burn-after-read form and the descriptor survives
   `exec`, so a descendant the caller did not intend inherits it. A
   same-uid peer can open `/proc/<child>/fd/3` and read the sealed value
   once the child has exec'd (the exec'd child is dumpable by design).
   The README says so; no case distinguishes the three cases.

## Per-issue state

Code + test where a suite exists; "impl" means implemented with a test in
the suite named, "docs" means documentation only.

| # | state | where |
|---|---|---|
| 1 | impl | `PTRACE_GETEVENTMSG` former tid; `core.sh` K1 |
| 2 | impl | `read_cstr_checked`, `MAX_STRLEN`, geometric windows; K2 |
| 3 | impl | `MAX_ARGV = 1<<20`, mmap fallback for the hidden block; K3 |
| 4 | impl | `EI_CLASS` check, `classify_exec`; K4 (needs `tests/testcases32`, built by `vm/run.sh`) |
| 5 | impl | `SessionEnd`, `--on-exit`; K5, `options.sh` O14 |
| 6 | impl | `PTRACE_SEIZE` + `PTRACE_LISTEN`; K6 |
| 7 | impl | exit-stop completion also for `State::Script`; no kernel available to reproduce the missing event |
| 8 | impl | failed exec settles to `Slow`; K8 |
| 9 | impl | checked repoint, `/proc/<pid>/stat` bounds, zero fallback, resumed error paths; K9 |
| 10 | impl | exactly 3 fds, `MSG_CTRUNC`, CLOEXEC, /dev/null stdio; `daemon_neg.sh` N12/N13/N20 |
| 11 | impl | `--io-timeout`, `--job-timeout`; N14, N24 |
| 12 | impl | symlink/plain-file/live-socket/stale-socket rules, `umask 077`; N15 to N18 |
| 13 | impl | warning sentence in help and docs, block-size precheck, 1 MiB argv cap (N7), `--run-as-uid`; run-as-uid has no case |
| 14 | impl | label mode byte, label fallback, 4096-byte cap, NUL/LF/CR rejection, `-` means blank; N22, N23, `edge.sh` E7 |
| 15 | impl | T9 via `env`, stress label truncation, always-rebuild `run.sh`, scoped `kill_comm` |
| 16 | impl | shebang case in `edge.sh`, `vm/cases` folded in, non-root VM pass, aarch64 console, pinned apks, `daemon_neg.sh`, `core.sh`, `options.sh`; the Go case is still host-only |
| 17 | impl | `c""` literals, MSRV floor in `Cargo.toml` and the CI MSRV job that builds at it; see "How to verify" |
| 18 | docs | README threat table, DESIGN trust boundary, script window content, fork-to-entry window, dated run line |
| 19 | impl | early argv snapshot + zero before parsing, label written into the block, `mask_self` returns `Result`, `CONFMASK_NO_SELFMASK` in `--help`; O12, O13 |
| 20 | impl | original program string as `argv[0]`, `--argv0`, `--comm`, redacted `Debug`, NUL/LF/CR validation, truncation caps in help; O2 to O8 |
| 21 | impl | vDSO scan with overlap plus a first-executable-mapping fallback, per-thread comm by inheritance, `--watch-rename`, setproctitle case; K12, O17 |
| 22 | impl | `--no-dumpable`, `PR_SET_DUMPABLE` injection; O15 (root only) |
| 23 | impl | `--rexec`, sealed memfd, loop guard; O18 |
| 24 | impl | `--no-new-privs`, `--watch-rename` filter; O16, O17 |
| 25 | docs + impl | privilege ladder in README and DESIGN; `--unshare`; O19 |
| 26 | impl | `--scope-name` via `systemd-run --scope`, single re-exec; no suite case (no `systemd-run` in the initramfs) |
| 27 | impl | `--env`, `--env-file`, `--keep-env=NAME`, `--args-from-fd`; O9 to O11 |
| 28 | impl | `--no-inherit-env`, mlock plus wipe on SIGTERM, env-file grammar, client peer check, version byte, `MSG_CTRUNC`, `--jobs`, message fix; N1 to N25 |
| 29 | impl | session summary line, `try_wait`, `wait_timeout`, `kill_tree`, little-endian pointer words; K10, K11 |
| 30 | impl | `man/`, `completions/`, readme/documentation metadata, non-Linux `compile_error!`, examples fix, `--daemon` option warning, `cargo package` |
| 31 | docs + impl | comparison table, ATT&CK T1036.011, CI citations, kernel-consistency claim labelled as inference, `tests/audit.sh` (skips here) |
| 32 | impl | CI: `permissions`, actions pinned by SHA (verified against the tags), MSRV job reading `rust-version`, aarch64 `cargo check`, doc tests, explicit QEMU install, pinned VM artifacts |
| 33 | impl | geometric read windows, env span from `/proc/<pid>/stat`, measured completion stop; K11 |
| 34 | impl | `--unshare` (user, pid, mount namespaces, private procfs, opportunistic); O19 |
| 35 | impl | drop-semantics doc, `confstr(_CS_PATH)` for a cleared environment, ESRCH probe, `PTRACE_CONT` for unmasked newcomers, SIGCHLD divergence documented; O9, O10, E11; env key validation has no case |

## Known traps

- `get_user_pages` (behind `process_vm_writev`) does not expand a
  grow-down stack VMA. Any write below `sp` beyond the faulted pages
  returns `EFAULT`, and the tracee's own frames overwrite a parked
  block during its startup. The hidden block therefore always lives in
  an injected `mmap`.
- A 64-bit tracee can exec an ELF32 image; the entry stop still shows a
  native `execve`. Detecting 32-bit tracees by syscall ABI is not enough;
  read `EI_CLASS` of the target.
- `xargs` splits on the command-size limit (10000 arguments became 6347).
  Use `testcases manyargs` or `--args-from-fd` for a single large exec.
- `mask_self` zeroes the environment, so anything the tracer reads from
  its own environment must be read before that point (the fault hooks are
  read in `Mask::to_config` for this reason).
- The Alpine kernel's audit `EXECVE` record stops at `a0=`; the
  `PROCTITLE` payload is hex and also truncated. Do not build assertions
  on argument text from it.
- Under TCG, 0.4 s is not enough for a fresh tracee to appear; wait for
  the observable condition, never for a fixed sleep.
