# confmask: AGENTS router

This file is the entry point for agents working in this repository.
Reading it in full gives you the map, the invariants and the
verification protocol. Everything else is one hop away.

## What this repo is

`confmask` redacts the `/proc` metadata (cmdline, environ, comm) of an
entire Linux process tree while every program keeps its real
`argv`/`envp`. It is confidential execution at the process level, for
machines with no TEE and no hypervisor. Three faces: a library, a CLI
(`confmask`) and a daemon (`confmaskd`).

Language rules for anything you write here (docs, comments, commits):

- Say *redact*, *mask*, *label*, *supervise*, *disclosure surface*,
  *confidential execution*.
- Never claim memory encryption, TEE equivalence, or host-resistance.
  The README's limit table is the contract: root sees that a pid
  exists and can read its memory.
- No "hide from ps/EDR", "stealth", "cloak", "evade", "bypass
  detection". The tool reduces what `/proc` discloses; it does not
  conceal pids, and the docs say so plainly.
- State what is true now. No revision history and no rationale essays.

## Map

| path | role |
|---|---|
| `README.md` | problem, threat boundary, three modes, privilege ladder, verification, limits |
| `docs/DESIGN.md` | threat model, mechanism, daemon protocol, privilege ladder, failure modes |
| `src/lib.rs` | crate docs, public re-exports, non-Linux `compile_error!` |
| `src/mask.rs` | public session API: `Mask` builder, `Prepared`, `MaskedChild`, fork plumbing |
| `src/tracer.rs` | tracee table, exec lifecycle, seizer/waiter loop, session end policies, session counters |
| `src/execimg.rs` | exec-entry swap, exec-completion rebuild, hidden block placement |
| `src/inject.rs` | syscall-site discovery, remote syscall injection |
| `src/remote.rs` | tracee memory read/write (`process_vm_*` with PEEK/POKE fallback) |
| `src/arch.rs` | x86-64, aarch64 and i386 register layouts, syscall numbers, exec classification |
| `src/selfmask.rs` | the supervisor's own metadata treatment |
| `src/seccomp.rs` | the opt-in `prctl(PR_SET_NAME)` watch filter |
| `src/rexec.rs` | sealed memfd image for `--rexec` |
| `src/userns.rs` | opportunistic user, pid and mount namespaces for `--unshare` |
| `src/scope.rs` | `systemd-run --scope` prefix for `--scope-name` |
| `src/daemon.rs` | confmaskd protocol, server, client, env-file parser |
| `src/mem.rs` | locked, wipe-on-drop buffers (`mlock`, `MADV_DONTDUMP`, `PR_SET_DUMPABLE`) |
| `src/secret.rs` | secret sources (`file:`, `env:`, `agent:`, `stdin`, `literal:`) and descriptor delivery |
| `src/store.rs` | the encrypted secret store: Argon2id, ChaCha20-Poly1305, 0600 file |
| `src/agent.rs` | the secret agent: one process holds the unlocked store and answers over a socket |
| `src/subcmd.rs` | `store`, `agent`, `get`, `read`, `probe`, `doctor` |
| `src/caps.rs` | what this host allows, one row per mechanism |
| `src/isolate.rs` | unprivileged namespaces for the payload (pid, net, tmp) |
| `src/run.rs` | mode selection: redaction, secret delivery, isolation |
| `src/cli.rs`, `src/main.rs` | `confmask` (local and `--daemon` client modes) |
| `src/bin/confmaskd.rs` | `confmaskd` argument parsing and startup |
| `src/bin/testcases.rs` | probe dispatcher |
| `src/bin/tc/*.rs` | probe subcommands: spawn styles, core cases, kernel audit client, option cases |
| `src/bin/protocases.rs` | raw protocol client for the daemon negative suite |
| `tests/` | `run.sh` orchestrates validate / suite / stress / edge / daemon / daemon_neg / options / core / audit |
| `vm/` | QEMU micro-VM harness (`run.sh`), shared parts (`common.sh`), debug runner (`debug.sh`) |
| `man/`, `completions/` | man pages and shell completions |
| `examples/` | library examples |
| `docs/STATUS.md` | checkpoint: what is implemented, verified, open, and how to resume |

## Invariants (do not break these)

1. **Tracer thread = forking thread.** `PTRACE_SEIZE` binds the child
   to the *thread* that forked it; ptrace ops from any other thread of
   the tracer return ESRCH. `Mask::spawn_prepared` forks inside the
   tracer thread on purpose. Do not "simplify" this into a shared loop.
2. **Session serialization.** A session owns the calling process's
   `waitpid(-1)` domain; sessions are serialized through
   `SESSION: Mutex<()>`. No concurrent sessions in one process. The
   daemon runs one job at a time unless `--jobs N` gives each job a
   worker process.
3. **No exec-shaped seccomp filter.** Some kernels do not deliver
   `PTRACE_EVENT_EXEC` for execs whose seccomp `RET_TRACE` stop was
   serviced, and an unserviced stop makes `execve` return `ENOSYS` in
   detached descendants. The only filter in the tree matches
   `prctl(PR_SET_NAME)` and is opt-in (`--watch-rename`).
4. **Zero-exposure redaction for every process's first exec** (swap at
   the true syscall-entry stop). Scripts (`#!`), re-execs of a settled
   process and 32-bit images take the post-exec path; a 32-bit image is
   refused loudly and not redacted. Any new spawn path must pick one of
   these explicitly.
5. **State machine**: `Slow → (entry swap) → Swapped → (completion) →
   Run`, with `Script` and `Foreign` as the other entry outcomes and
   failed execs restoring the original inline arrays and settling to
   `Slow`. Every error path must leave a resumed-or-dead tracee behind,
   never a stopped-and-forgotten one; every resume goes through
   `Tracer::resume`.
6. **Exit semantics**: the supervised master's exit status (including
   signal deaths, re-raised by the CLI) passes through untouched, in
   local mode and through the daemon. What happens to the rest of the
   tree is the session-end policy (`detach` default, `wait`, `kill`).
7. **0BSD, no new dependencies.** The only dependency is `libc`. Static
   musl builds must keep working (`vm/run.sh` depends on it).
8. **argv bytes are forwarded exactly.** The CLI parses `args_os()`, not
   `args()`: a non-UTF-8 argument must reach the supervised program
   unchanged. Only the *label* is decoded as text, lossily.
9. **Paths are resolved against the tracee, not the tracer.** ELF
   detection opens `/proc/<pid>/cwd/<path>` (relative) or
   `/proc/<pid>/root<path>` (absolute). After a `chdir()` inside the
   tree the two cwds differ, and opening the tracer's copy silently
   drops the zero-exposure path.
10. **`vm/*.sh` and `tests/*.sh` are POSIX sh.** No brace expansion, no
    `[[`, no `local`: `/bin/sh` is dash on Debian/Ubuntu and busybox ash
    in the VM, where brace expansion creates one literal directory and
    the gate fails before boot.
11. **The daemon's authorisation is `SO_PEERCRED`.** Own uid and root by
    default, `--allow-uid` to widen, socket mode 0600, and the client
    checks the peer uid of the socket it connected to. Never accept a
    request before checking it.
12. **Secrets never enter the supervisor's own `/proc`.** `confmask`
    copies its argv, zeroes the kernel-served block, and only then
    parses options and forks; `confmaskd` builds the job environment,
    then masks itself. Do not reorder either.
13. **Every degradation is visible.** A warning at the default
    verbosity plus a count in the session summary. A silent fallback is
    a defect, not a graceful path.
14. **Fault hooks stay test-only.** `CONFMASK_FAULT_POKE` and
    `CONFMASK_FAULT_NOVDSO` are read once by the builder so the suites
    can drive the failure paths. They change no production behaviour.

## Build and verify

```sh
cargo build --release                                  # host build
cargo clippy --all-targets -- -D warnings              # zero warnings policy
cargo test --lib                                       # ptrace-free unit tests
sh vm/run.sh                                           # FULL verification (works everywhere)
```

`tests/run.sh` runs the same suites directly but needs a host where
ptrace is permitted. Many sandboxes, including the usual dev container,
seccomp-ban ptrace entirely; `vm/run.sh` exists for exactly that case and
is the canonical gate. It boots a pinned kernel and a static busybox
initramfs under QEMU TCG, runs every suite twice (root and uid 1000), and
exits 0 only when both passes report `FINAL: ALL-PASS`.
`vm/debug.sh SCRIPT.sh` boots the same VM for single-command experiments.

Suite design (why a pass means something): every suite runs its battery
*without* confmask first and requires the observer to detect the markers
(negative control), then requires zero sightings under the mask, then
requires the processes to be *alive* under the label (liveness, so "zero
sightings" cannot be vacuous), then checks function (stdio, exit codes,
argv/env fidelity, signals). A case that cannot be decided prints
`SKIP <name> (<reason>)`, never a pass.

## Conventions

- Commits: `Nemo <328747105+Nemo-010@users.noreply.github.com>`,
  plain imperative subject, reason in the body.
- No issue references to upstream projects in docs or code; if a kernel
  behaviour matters, describe the behaviour (version and what it does).
- Keep the repo lean: no CLAUDE.md/AGENTS.md at the root, this file is
  the router. New docs go under `docs/` and get linked here.
