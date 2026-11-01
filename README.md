# confmask

**Confidential execution without trusted hardware.** Run a command, a
binary or a job so that other local users, monitoring agents and pasted
`ps` output cannot read what it is doing, while the program itself keeps
its real arguments and environment and works normally.

```
$ confmask --label ci-runner ./deploy.sh --env prod
```

`ps`, `top`, `htop`, `/proc/<pid>/cmdline`, `/proc/<pid>/environ` and
`/proc/<pid>/comm` show `ci-runner` for that process and everything it
spawns. The program still reads its own `argv`, its own environment, its
own stdin and its own exit code.

---

## Why

Confidential computing today means a TEE: AMD SEV-SNP, Intel TDX, ARM
CCA, SGX enclaves. Those protect memory against the host, and they are
excellent at it. They also require hardware that supports them, a
hypervisor or a guest OS that can launch and attest, an attestation
service and a policy that trusts it, and, for the enclave models, a
rewritten workload.

Most machines have none of that. A self-hosted CI runner, a shared build
host, a lab box, a container, a laptop, a VPS: no TEE, and no way to get
one. The secrets still have to run somewhere.

The leak in those environments is not memory. It is `/proc`:

```
$ ps -eo user,args | grep deploy
ci     ./deploy.sh --token ghp_9f3c... --env prod
```

CI systems document the same hazard. The GitHub Actions security
hardening guide says to avoid passing secrets between processes from the
command line, because command-line processes may be visible to other
users through `ps` or captured by audit events. The CircleCI
documentation warns that any user on the same system can view the
command that started a process. The IEEE S&P 2023 paper "Continuous
Intrusion" records a self-hosted runner registration token passed as a
command-line argument.

`confmask` closes that specific disclosure surface, on hardware you
already have, as an unprivileged user.

## What it is not

It is not a TEE and it does not encrypt memory. The limit table states the
line exactly:

| observer | sees |
|---|---|
| another uid | the label; no argv, no environ, no comm |
| a monitoring agent of the same uid | the label, and also `exe`, `maps`, `fd/*` and `cwd`, which name the real binary |
| the same, with `--no-dumpable` | the label; those files are refused |
| `ps` output pasted into a ticket or a chat | the label |
| root on the host | **that** a pid exists, its `/proc/<pid>/exe`, its `maps`, its open files, its cgroups, and its memory via `PTRACE_ATTACH` |
| anyone with kernel access | everything |

`cmdline` and `comm` carry no ptrace check, so every local account sees
them. `environ`, `exe`, `maps`, `fd/*` and `cwd` require
`PTRACE_MODE_READ_FSCREDS`, which a process of the same uid passes. Yama
restricts `PTRACE_MODE_ATTACH` only, so it does not stop the same-uid
read; `PR_SET_DUMPABLE=0` does, and `--no-dumpable` sets it.

So: confidentiality against other tenants and against casual inspection,
not against the host operator. That is the same trust boundary a
container gives you for the filesystem, applied to process metadata. An
adversary with root on the same kernel needs a TEE or a separate
machine; `confmask` does not address that case.

## Three ways to use it

### 1. CLI: one command under a label

```sh
confmask --label 'ci-runner' ./deploy.sh --token "$TOKEN" --env prod
```

Everything the command spawns inherits the label. A whole shell session
can be wrapped once, and background jobs survive the shell exit:

```sh
exec confmask --label 'dev-shell' bash --login -i
```

Options that matter most:

| option | effect |
|---|---|
| `-l, --label NAME` | the presented command line and comm |
| `--comm NAME` | a comm separate from the label, at most 15 bytes |
| `--argv0 NAME` | argv[0] of the program; the default is the command as typed |
| `--keep-env` | leave `environ` visible |
| `--keep-env=NAME` | keep only the named variables visible, repeatable |
| `--env K=V`, `--env-file PATH` | set the child environment |
| `--args-from-fd N` | read the command from a NUL-separated vector on fd N, so the secret never enters the supervisor's own command line |
| `--on-exit detach\|wait\|kill` | what happens to descendants when the command exits |
| `--no-dumpable` | `PR_SET_DUMPABLE=0`: same-uid observers lose `environ`, `maps`, `exe`, `fd` |
| `--no-new-privs` | set-uid and file capabilities gain nothing |
| `--watch-rename` | keep the label when a program renames itself |
| `--rexec` | run from a sealed memfd, so `exe` names the label |
| `--unshare` | private user, pid and mount namespaces with a private procfs, when the kernel allows it |
| `--scope-name NAME` | one transient systemd scope named NAME |

`--args-from-fd` matters for shell history as well: a token typed after
`--args-from-fd 3` never appears in `ps` or in `.bash_history`.

### 2. Library: supervise from your own program

```toml
[dependencies]
confmask = "0.1"
```

```rust
use confmask::Mask;

let st = Mask::new()
    .label("ci-runner")
    .run("/usr/bin/deploy", &["--token", "SECRET"])?;
println!("exit: {} ({} of {} execs degraded)", st.code, st.stats.degraded, st.stats.execs);
```

`Mask` is a builder. `run` blocks and supervises on the calling thread.
`spawn` returns a `MaskedChild` immediately and runs the tracer on its
own thread; `try_wait` and `wait_timeout` do not block forever, and
`kill_tree` terminates the whole tree. `envs` and `env_clear` replace the
child environment wholesale, `run_as` drops the child to a uid and gid,
and `session_end` selects the policy for descendants.

### 3. Daemon: the secret never enters the caller

This is the case that matters for CI runners. The runner needs a token.
If the token is in the runner's environment, `/proc/<pid>/environ`
publishes it. If it is on a command line, `/proc/<pid>/cmdline` does.

`confmaskd` holds the token instead:

```sh
# root or the runner user, once:
cat > /etc/confmask/runner.env <<'EOF'
CI_TOKEN=ghp_...
EOF
chmod 600 /etc/confmask/runner.env

confmaskd --label ci-runner --env-file /etc/confmask/runner.env

# the runner, for every job:
confmask --daemon /run/confmask.sock -- ./deploy.sh --env prod
```

The client sends only the command. The daemon supplies the environment,
supervises the job with the client's stdio, and returns the exit status.
The token exists in the daemon's memory and in the job's hidden argument
block. It does not exist in the client's argv, the client's environment,
or any `/proc` entry on the machine.

Access is decided by `SO_PEERCRED`: the daemon's own uid and root only,
plus whatever `--allow-uid` adds. The socket is mode 0600 and the client
verifies the peer uid of the socket it connected to.

**Warning:** an allowed uid may execute arbitrary programs with the
daemon's privileges and inherit its environment. Grant `--allow-uid` only
to uids that may already do that. On a root daemon, `--run-as-uid` runs
each job with the client's own uid and gid instead.

## How it works

`confmask` is a `ptrace` supervisor and the parent of the tree:

1. **Follow everything.** `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC,EXIT}`
   attaches to children, grandchildren, threads, `posix_spawn()`,
   `system()`, double-forking daemons, static binaries, Go runtimes and
   `#!` scripts. No `LD_PRELOAD`, no libc dependency.
2. **Zero exposure at exec entry.** Each process is syscall-supervised
   until its first exec settles, so `execve`/`execveat` stops at syscall
   entry. The supervisor swaps the `argv`/`envp` pointer arrays in the
   old image to point at the label and at empty strings. The kernel
   never copies the real command line into the new image of an ELF
   target. The child's old image holds the parent's argv bytes from the
   fork until this stop; the kernel never copies them.
3. **The program still gets its arguments.** At exec completion the
   saved strings are written below the new image's stack pointer, or
   into an injected anonymous mapping when that range is not mapped, and
   the stack's inline arrays are repointed there. `argc`, the stack
   layout and the auxiliary vector are untouched, so glibc, musl and
   static binaries start normally.
4. **The process name is set too.** `prctl(PR_SET_NAME)` runs inside the
   tracee, through a `syscall` instruction in its own vDSO, so
   `/proc/<pid>/comm` shows the label. No writable-and-executable memory
   is created anywhere.
5. **The environment is redacted** from `/proc/<pid>/environ` by the
   same swap, except variables named by `--keep-env=NAME`.
6. **Job control works.** Group-stops are answered with
   `PTRACE_LISTEN`, so `Ctrl-Z`, `kill -STOP` and `SIGCONT` behave in a
   masked shell.
7. **Session end is explicit.** By default, descendants still running
   when the command exits are detached: they keep the label and their
   redacted image, and a later exec in them takes the post-exec path
   because no supervisor watches them any more. `--on-exit wait` and
   `--on-exit kill` are the other two policies.

Scripts and re-execs fall back to post-exec redaction: the kernel needs
the real argv to build an interpreter line, and a settled process no
longer stops at syscall entry. The kernel copies the interpreter command
line, including the script's arguments, and the real environment unless
`--keep-env`; the completion stop zeroes that region. The duration of
that window is not measured.

A 32-bit program is refused, not redacted: one warning names it and the
session summary counts it. The program keeps its real arguments, because
a supervisor that cannot read 32-bit registers must not swap them.

## Privilege ladder

Higher privileges buy more privacy in defined steps. Nothing below rung
2 needs any privilege.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, comm, per-variable environment policy | same-uid observers read `exe`, `maps`, `fd/*`, `cwd` |
| 0 | none | `--no-dumpable` makes those files refused for the same uid | core dumps and debugger attach stop |
| 0 | none | `--rexec`: `exe` names the memfd, not the file | `map_files` still resolves; `vm.memfd_noexec` may refuse |
| 0 | a kernel that allows unprivileged user namespaces | `--unshare`: private pid namespace and private procfs | unavailable on hosts that gate user namespaces; opportunistic by design |
| 0 | none | `--watch-rename`: comm stays the label after a self-rename | traps `prctl(PR_SET_NAME)` only; implies `no_new_privs` |
| 2 | `CAP_SYS_RESOURCE` | `PR_SET_MM_ARG_START/END` relocates what `/proc` reads, without stack surgery | design entry only, not implemented |
| 3 | root on the host | `hidepid=2,gid=` on the system `/proc` removes the tree from every other account | polkit and distribution defaults; Yama scope needs `CAP_SYS_PTRACE`, and scope 3 lasts until reboot |

## Verification

The suites do not ask you to trust this README. Each one runs its battery
*without* `confmask` first and requires the observer to find the markers.
A detector that cannot detect proves nothing, so the negative control
comes first. Then zero sightings under the mask, liveness under the
label, and functional checks on argv, environment, stdio, signals and
exit codes.

```sh
tests/run.sh      # on a host that permits ptrace
vm/run.sh         # anywhere: the same suites inside a QEMU micro-VM
```

`vm/run.sh` fetches a pinned kernel and static busybox by sha256, builds
the musl binaries, packs an initramfs and boots it under QEMU TCG. No
KVM, no host ptrace permission. It runs every suite twice, as root and
as uid 1000, and exits 0 only when both passes report `FINAL: ALL-PASS`.
CI uploads the console log as a build artifact.

| suite | asserts |
|---|---|
| `validate.sh` | marker battery: zero sightings in cmdline, environ and comm; liveness; argv fidelity; exit codes |
| `suite.sh` | spawn styles: threads, `posix_spawn`, `vfork`, double-fork daemons, nested scripts, raw `clone`+`execve`, comm, environ |
| `stress.sh` | race probe against a tight `/proc` observer, 100 sequential execs, `EXITKILL`, signal and stdin passthrough, overhead |
| `edge.sh` | non-UTF-8 argv, tracee-relative exec paths, long labels, label forms, self-mask, shebang scripts, option combinations |
| `daemon.sh` | the job receives the secret; no `/proc` entry shows it; daemon self-mask; stdio and exit status; failure recovery |
| `daemon_neg.sh` | protocol negatives: bad magic, bad version, oversize frames, missing and extra descriptors, unauthorised uid, stalled client, socket squatting, job timeout |
| `options.sh` | every CLI and builder option: argv0, comm, label validation, `--env`, `--env-file`, `--keep-env=NAME`, `--args-from-fd`, self-mask, `--on-exit`, `--no-dumpable`, `--no-new-privs`, `--watch-rename`, `--rexec`, `--unshare` |
| `core.sh` | exec from a non-leader thread, 5 KB and 100 KB arguments, 10001 arguments, 32-bit refusal, session end policies, job control, failed exec retry, injected repoint failure, the session summary, per-thread comm, setproctitle-style rewrite, `AT_EXECFN`, set-uid, `execveat` and `fexecve` |
| `audit.sh` | the kernel's own exec record carries the label, not the real argv, where the kernel sends argument text |

Last run: 2026-10-31, kernel 6.12.114-r0 (Alpine `linux-virt`), x86_64
under QEMU TCG, root pass and uid 1000 pass, `VM-HARNESS: ALL-PASS`,
392 PASS and 0 FAIL. `validate`, `suite`, `stress`, `edge`, `daemon`,
`daemon_neg`, `options` and `core` print FAIL=0 in both passes.
`audit.sh` skipped on that kernel with the printed reason that its
`EXECVE` netlink record stops before the argument text, so the control
could not observe its own secret; the kernel-consistency claim stays an
inference from the mechanism until a kernel that logs the text runs the
suite.

## Honest limits

- Root on the host sees that a pid exists and can read its memory. The
  tool removes *what* a pid is, not *that* it is.
- `cmdline` and `comm` are readable by every local account. `environ`,
  `exe`, `maps`, `fd/*` and `cwd` are readable by the same uid and root,
  unless `--no-dumpable` is set.
- `/proc/<pid>/exe`, `maps`, open files, sockets and cgroups describe
  the real binary unless `--rexec` is set, and `map_files` still does.
- Set-uid and set-gid programs do not gain privileges under supervision,
  with or without `--no-exit-kill`.
- A `#!` script, a second exec in one process, and a 32-bit image take
  the post-exec path or no redaction. The script window covers the
  interpreter command line including the script's arguments and the
  environment, until the completion stop zeroes them; its duration is not
  measured.
- `AT_EXECFN` still points at the real path. It is readable from inside
  the process, not through the `/proc` files `ps` and `top` use.
- A deeply recursive program can overwrite the hidden copies of
  `argv`/`envp` with stack frames long after startup. libc caches both at
  startup, so this rarely matters, and a block placed in an anonymous
  mapping is not affected.
- A `--secret` value is absent from `cmdline`, `environ` and `ps`. It is
  not hidden from the host: the payload holds it on an inherited
  descriptor whose `FD_CLOEXEC` is cleared on purpose, so every
  descendant inherits it, and `/proc/<child>/fd/<N>` names a sealed
  `memfd` that a same-uid peer can open. There is no burn-after-read
  form yet.
- The label is cut at three places: `comm` keeps 15 bytes, the exec
  entry path keeps 254, and the post-exec path cuts it to the argument
  area. A warning appears once for a label longer than 254 bytes.
- A session consumes the `SIGCHLD` notifications `CLD_STOPPED`,
  `CLD_TRAPPED`, `CLD_CONTINUED` and `CLD_DUMPED` for its tracees, so a
  program that watches those codes sees fewer of them.
- Linux 5.3 or newer (`PTRACE_GET_SYSCALL_INFO`), x86-64 or aarch64.
  The aarch64 VM harness boots the pinned aarch64 kernel under TCG and
  runs a masked exec there; a full aarch64 suite run did not run.
- A masking session owns the calling process's `waitpid(-1)` domain, so
  sessions in one process are serialized.

## Related tools

| tool | approach | what it leaves visible |
|---|---|---|
| `hidepid=2` mount option | system-wide `/proc` policy, root only | does not help a same-uid observer; all-or-nothing |
| `setproctitle` | in-process argv rewrite | must trade title length against environment integrity; on Linux the title shares the area with `environ` |
| nginx and PostgreSQL `ps_status` | relocate `environ`, then overwrite argv | in-process, per program, no label for children |
| bubblewrap | unprivileged user-namespace sandbox | does not touch argv, environ or comm |
| firejail | set-uid sandbox | secrets on a command line stay visible in `ps` |
| scriptzteam/Hidden | ptrace supervisor, acts at the exec-exit stop | the kernel has already copied the real argv into the new image, so a window exists |
| `confmask` | ptrace supervisor, entry swap plus below-SP relocation | the window named in the limit list |

Every surveyed in-process technique must choose between title length and
environment integrity. The exec-entry swap plus the relocation of the
real strings is the only surveyed approach that keeps
`/proc/<pid>/environ` intact for the program while removing the real
command line from the new image.

The technique is catalogued: MITRE ATT&CK T1036.011, "Overwrite
Process Arguments" (https://attack.mitre.org/techniques/T1036/011/),
lists the same mechanics. Its detection guidance (NUL runs in
`cmdline`, a comm that does not match the command line, memory writes
shortly after start) applies here in the same way.

## Build

Any Linux 5.3 or newer, x86-64 or aarch64, glibc or musl. Rust 1.74 or
newer (`rust-version` in `Cargo.toml`, checked by a CI job):

```sh
cargo build --release
# static:
cargo build --release --target x86_64-unknown-linux-musl
# tests, unit tests and packaging:
cargo test --lib
cargo package --list
```

Binaries: `confmask` (CLI), `confmaskd` (daemon), `confmask-testcases`
and `confmask-protocases` (probes the suites use). The package also ships
`man/confmask.1`, `man/confmaskd.8` and completions for bash, zsh and
fish.

## Files

```
src/mask.rs        public session API (Mask, Prepared, MaskedChild)
src/tracer.rs      tracee table, exec lifecycle, waitpid loop, session end
src/execimg.rs     exec-entry swap and exec-completion rebuild
src/inject.rs      syscall-site discovery, remote syscall injection
src/remote.rs      tracee memory access
src/arch.rs        x86-64, aarch64 and i386 registers and syscall numbers
src/selfmask.rs    the supervisor's own metadata treatment
src/seccomp.rs     opt-in prctl(PR_SET_NAME) watch filter
src/rexec.rs       sealed memfd image for --rexec
src/userns.rs      opportunistic user, pid and mount namespaces
src/scope.rs       systemd transient scope prefix
src/daemon.rs      confmaskd protocol, server and client
src/mem.rs         locked, wipe-on-drop buffers for secret material
src/secret.rs      secret sources and descriptor delivery
src/store.rs       the encrypted secret store (Argon2id, ChaCha20-Poly1305)
src/agent.rs       the secret agent: one process holds the unlocked store
src/subcmd.rs      store, agent, get, read, probe and doctor subcommands
src/caps.rs        what this host allows, one row per mechanism
src/isolate.rs     namespaces for the payload, without root
src/run.rs         mode selection: redaction, secrets, isolation
src/cli.rs         CLI parsing
src/main.rs        confmask
src/bin/confmaskd.rs  confmaskd
tests/             the nine suites
vm/                QEMU micro-VM harness
man/, completions/ man pages and shell completions
docs/DESIGN.md     threat model and design rationale
docs/AGENTS.md     repository map and invariants
```

## License

0BSD. See `LICENSE`. Use it, ship it, no attribution required.
