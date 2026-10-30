# confmask

**Confidential computing for the hardware you actually have.**

No SGX enclave, no encrypted VM, no root, no hypervisor that promises not
to look. `confmask` reduces what a *shared Linux host* discloses about a
workload — its secrets, its command lines, its files — using mechanisms an
ordinary account already has.

```sh
$ confmask run --secret DEPLOY_TOKEN=file:./token -- ./deploy.sh --env prod
```

While `deploy.sh` runs, the token is on **file descriptor 3**, not in its
argument list, not in its environment, not in `ps` output, and not in
`/proc/<pid>/cmdline`. Every process it spawns inherits the descriptor.
`confmask read DEPLOY_TOKEN` prints it inside the program, and nothing
outside the program can see it.

---

## The problem, concretely

A self-hosted GitHub Actions runner is a good example of the shape:

- The runner holds a registration token and per-job secrets for its whole
  lifetime.
- The machine is shared: other accounts, other jobs, monitoring agents,
  anyone who can run `ps`.
- `/proc/<pid>/cmdline` is world-readable. `/proc/<pid>/environ` is
  readable by everything running as the same account. A plaintext `.env`,
  a `~/.config` file or a token in the runner's configuration is readable
  by any process that can open it — including the job that is supposed to
  be untrusted.
- Deploy scripts pass tokens as arguments, because that is what the tool's
  interface wants: `vault kv get -token=…`, `aws --token …`,
  `curl -H 'Authorization: …'`.

The usual advice — "pass secrets in the environment instead" — only moves
the leak from a world-readable file to a same-account-readable one, and
changes nothing about `ps`.

## What confmask does about it

Four mechanisms. Each one is probed at start-up, reported, and used when
available; none is assumed.

| surface | mechanism | needs |
|---|---|---|
| secrets in argv / environ | **sealed file descriptors**: the secret is read once into locked memory and inherited as an fd; the program is told the fd *number* | nothing |
| secrets at rest | **encrypted store**: XChaCha20-Poly1305 under Argon2id, one file, mode 0600 | nothing |
| command lines and process names | **metadata redaction**: `argv`/`envp` are swapped at `execve` entry so the kernel never copies them into the new image | `ptrace` |
| the host, as seen from inside | **namespaces**: the payload gets its own PID, mount and network view | unprivileged user namespaces |

`confmask probe` tells you which of those you get:

```
confmask capability report
  arch=x86_64 kernel=7.2.2-artix1-1.1

  secret fds             yes  sealed memfds + inherited descriptors (always available)
  memfd_secret           yes  secret pages are absent from the kernel direct map
  mlock                  yes  secrets cannot be swapped out
  non-dumpable           yes  no core dumps, no ptrace of the holder by non-root
  metadata redaction     no   ptrace is banned by a seccomp filter here; command lines stay visible
  isolation              no   no unprivileged user namespaces; the payload sees the host
```

That output is from a container that bans `ptrace` and user namespaces
outright — and `confmask run --secret …` still works there, because
descriptor delivery needs neither.

## Install

```sh
cargo build --release            # → target/release/confmask
cargo install --path .           # or install it
```

Linux, x86-64 or aarch64. The redaction engine needs Linux ≥ 5.3; every
other mode works on anything modern.

## Use

### Keep a token out of `ps`

```sh
install -m 600 /dev/null ./token
printf '%s' "$GITHUB_TOKEN" > ./token

confmask run --secret DEPLOY_TOKEN=file:./token -- ./deploy.sh
```

```sh
# inside deploy.sh
TOKEN=$(confmask read DEPLOY_TOKEN)     # or: cat <&3
```

The descriptor number is published in `CONFMASK_SECRET_DEPLOY_TOKEN`. The
*value* never is.

### A store, so the token is not a plaintext file

```sh
confmask store init                       # asks for a passphrase
confmask store set RUNNER_TOKEN < token.txt
confmask store list
```

The file is Argon2id + XChaCha20-Poly1305, mode 0600. `store get` exists
for debugging; prefer the daemon.

### A daemon, so the passphrase is typed once

```sh
confmask daemon &                                   # unlocks the store once
confmask run --secret RUNNER_TOKEN=daemon:RUNNER_TOKEN -- ./runner
```

The daemon holds the plaintext in locked, non-dumpable memory and serves
individual secrets over a unix socket that only this account can open
(`SO_PEERCRED`, plus an optional allow-list of peer executables).

### Untrusted code that should not see the rest of the machine

```sh
confmask run --isolate -- ./build.sh
```

`build.sh` gets its own PID namespace (its `/proc` lists only itself), a
private `tmpfs` on `/tmp`, and an empty network stack. Files it writes to
`/tmp` never reach the host's `/tmp`.

### Library

```rust
use confmask::{Runner, Source};

let outcome = Runner::new()
    .label("ci-runner")
    .secret("DEPLOY_TOKEN", Source::File("token".into()))
    .run("deploy.sh", &[])?;

println!("mode={:?} exit={}", outcome.mode, outcome.exit.code);
```

## What this is not

Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). The short version:

- **Root and the host kernel always win.** Nothing here hides *that* a
  process exists, and nothing survives a privileged observer.
- **Two programs of the same account are not distinguishable** unless you
  restrict the daemon by executable. `confmask` protects secrets from
  being *disclosed*; it is not a sandbox against code that already runs as
  you.
- **No side channels.** Timing, cache, power and speculative-execution
  attacks are out of scope. That is exactly what TEE hardware is for, and
  this is the version you can run without it.
- **Set-uid binaries do not gain privileges** under redaction (a general
  property of being traced), so don't wrap privilege boundaries with it.

What remains is the largest practical disclosure surface on a shared
host, and the one that turns up in incident reports: secrets sitting in
`ps`, in `/proc`, in `.env` files, in terminal scrollback and in pasted
bug reports.

## Verification

The suites assert behaviour, not intentions. Each one runs the battery
*without* confmask first (a negative control: the observer must be able to
see the leak, or a later "no leak" verdict means nothing), then with it.

```sh
cargo test                      # 12 unit tests
sh tests/run.sh                 # 24 cases; mechanisms the host refuses are SKIPPED, not passed
sh vm/run.sh                    # the same suite inside a QEMU micro-VM
```

`tests/run.sh` on a container that bans `ptrace` and user namespaces:

```
PASS t6-child-reads-secret      the program read its secret from fd 3
PASS t6-env-value-hidden        no process exposed the value
PASS t6-env-name-published      the environ showed CONFMASK_SECRET_TOKEN=3
PASS t6-no-leak                 zero sightings of the value in any /proc
SKIP t10-cmdline (ptrace refused on this host)
SKIP t14-isolate (no unprivileged user namespaces on this host)
== VERDICT: ALL-PASS (skipped 5) ==
```

`vm/run.sh` boots a real 6.12 kernel under QEMU TCG — no KVM, no root — so
the two modes this host refuses are verified there instead:

```
PASS t10-cmdline                no marker visible in any /proc cmdline
PASS t11-comm                   the label is the process name top shows
PASS t12-environ                the environment is not in /proc
PASS t13-redact-secret          redaction does not disturb fd delivery
PASS t14-isolate (inner pids 3 < host pids 65)
PASS t14-private-tmp
PASS t15-isolate-unprivileged   the same, from an unprivileged account
PASS t15-redact-unprivileged
PASS t15-redact-unprivileged-cmdline
== VERDICT: ALL-PASS (skipped 1) ==
```

## The redaction engine

The `ptrace` half is the `argvmask` engine, carried over unchanged: a
tracer that owns the tree, swaps `argv`/`envp` at `execve` entry (so there
is no window at all in which the real command line exists in `/proc`), and
re-injects the real strings below the new image's stack pointer so the
program still sees its own arguments. It covers every spawn style — shell
children, `posix_spawn`, `vfork`, double-forking daemons, threads, static
binaries, Go runtimes, scripts.

It is one provider among four, and nothing else in the crate depends on
it: a host that bans `ptrace` simply does not use that mode.

## Layout

```
src/caps.rs        what this host allows, and what that costs you
src/mem.rs         locked, dump-excluded, memfd_secret-backed buffers
src/secret.rs      sources, and delivery as sealed descriptors
src/store.rs       the encrypted store
src/daemon.rs      the socket server and its client
src/isolate.rs     unprivileged namespaces
src/run.rs         mode selection and the runner
src/redact/        the ptrace redaction engine (arch, remote, inject,
                   execimg, tracer, mask, selfmask)
src/cli.rs         the command line
tests/             the suites (tests/run.sh)
vm/                QEMU micro-VM harness (vm/run.sh, vm/debug.sh)
docs/              threat model, architecture, agent router
```

## Licence

0BSD. See [`LICENSE`](LICENSE).
