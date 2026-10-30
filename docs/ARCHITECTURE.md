# Architecture

Four mechanisms, one runner, and a hard rule: **nothing is assumed to
exist**. Every capability is probed at start-up and every mode degrades
loudly rather than silently.

```
                     ┌──────────────────────────────┐
   confmask run ────►│ run::Runner                  │
                     │  · load secrets (SecBuf)     │
                     │  · build Delivery (SealedFd) │
                     │  · pick a Mode               │
                     └───────────┬──────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   Mode::Redact           Mode::Isolate          Mode::Plain
   redact::mask::Mask     isolate::run           std::process::Command
   ptrace + argv swap     unshare + fork         fd install only
          │                      │                      │
          └──────────────────────┴──────────────────────┘
                                 │
                    fds 3.., CONFMASK_SECRET_<NAME>
                                 ▼
                            the payload
```

## Module map

| module | responsibility |
|---|---|
| `caps` | probe `ptrace`, user namespaces, `memfd_secret`, `mlock`, `PR_SET_DUMPABLE`, and whether a seccomp filter is already installed; render the report |
| `mem` | `SecBuf` (locked, dump-excluded, `memfd_secret`-backed), `SealedFd` (sealed memfd), `harden_self` |
| `secret` | `Source` parsing, loading, and `Delivery` (descriptors + the environment entries that name them) |
| `store` | the encrypted file: Argon2id key, XChaCha20-Poly1305, authenticated header, atomic 0600 write |
| `daemon` | `SO_PEERCRED`-gated unix socket server, plus the client used by `get` and `daemon:` sources |
| `isolate` | the parent-writes-the-map handshake, unshare, and the payload view (fresh `/proc`, private `/tmp`) |
| `run` | mode selection, secret loading, the three dispatch paths |
| `redact` | the `ptrace` engine: arch, remote memory, vDSO injection, exec-image surgery, tracer, session API, self-mask |
| `cli` | argument parsing for `run`, `probe`, `doctor`, `store`, `daemon`, `get`, `read` |

## Design decisions and why

### Secrets travel as descriptors, not as strings

A secret in `argv` is world-readable through `/proc/<pid>/cmdline`. A
secret in the environment is readable by everything running as the same
account. A secret in a file is readable by anything that can open the
file, for as long as it exists.

A descriptor is different in kind: `/proc/<pid>/fd/N` is a symlink, and
reading the *contents* requires opening that descriptor, which requires
being the process or root. It is also the only one of the four that needs
no privilege at all, so it is the mechanism that survives every sandbox.

That is why delivery is a `memfd` sealed with `F_SEAL_WRITE`, and why the
environment carries `CONFMASK_SECRET_DEPLOY_TOKEN=3` — a name and a
number.

### The runner degrades, it never refuses

`--isolate` on a host without user namespaces still runs the command, in
the best mode available, and prints what it substituted. `--no-redact`
exists for the same reason: the user may know that the redaction engine
will be refused and want the deterministic plain path.

A tool that refuses to run because a hardening tier is missing is a tool
that gets removed from the CI image. A tool that reports what it could not
do gets used, and the report is the point.

### Modes are exclusive

Redaction and isolation are offered as alternatives, not as a combination.

Redaction is a `ptrace` supervisor: it forks the payload itself and owns
`waitpid`. Isolation needs a PID namespace, and a PID namespace only takes
effect for a *child*, so the payload must be a grandchild — which breaks
the tracer's assumption that it forked the tracee (ptrace binds to the
forking thread). Making them compose is possible (trace across a PID
namespace from the parent) but it is not a v0.1 feature, and claiming it
without testing it would be worse than not offering it.

The two are complementary in direction: redaction hides the payload *from*
the host, isolation hides the host *from* the payload.

### The store is one file with an authenticated header

A directory format invites partial updates, locking, and stale temp files.
One file plus an atomic `rename` is easier to reason about and impossible
to leave half-written.

The header (magic, KDF parameters, salt, nonce) is passed as AEAD
associated data. An attacker who can edit the file can lower `m_cost` and
`t_cost`, but then the tag fails — so the parameters are as protected as
the ciphertext.

### Argon2id at 19 MiB, not 1 GiB

`m=19456 KiB, t=2, p=1` is the OWASP interactive baseline. It is
deliberately affordable: this tool is meant to run on a CI runner that is
already short of memory, and a store that cannot be opened on the target
machine protects nothing. Raise it if your threat model is an offline
attacker with a GPU farm and your machine can spare the memory.

### Parent writes the id maps

A process that has just called `unshare(CLONE_NEWUSER)` cannot write its
own `uid_map`: it has no capability over the namespace it just left, and
its own uid is unmapped (overflow) inside the new one. Every unprivileged
sandbox solves this the same way — the parent writes
`/proc/<child>/{setgroups,uid_map,gid_map}` — and so does `isolate::run`,
with a two-pipe handshake so the child does not proceed until the maps are
in place.

### The redaction engine is vendored, not rewritten

`src/redact/` is the `argvmask` engine, carried over with module paths
adjusted and nothing else changed. It encodes a lot of hard-won kernel
detail (the exec-completion stack rebuild, the vDSO syscall-site scan, the
group-stop handling, the `PTRACE_EVENT_EXEC`-may-not-arrive case). A
rewrite would have been a regression generator.

Its only coupling to the rest of the crate is `Mask::inherit_fds` and
`Mask::extra_env`, added so a redacted run can still receive secrets.

## Invariants

1. **No secret in `argv`, `environ` (as a value), a log line, or a `Debug`
   impl.** `Secret` and `SecBuf` print their length, never their bytes.
2. **A capability that is missing is reported, never assumed.** See
   `caps::report`.
3. **A skipped test is a `SKIP`, never a pass.** A case that needs a
   mechanism the host refuses prints why; a "no leak" verdict from a
   process that never ran is worthless.
4. **Every path that holds plaintext is non-dumpable.**
5. **0BSD, and the dependency list is short and audited.** `libc`,
   `zeroize`, `argon2`, `chacha20poly1305` — all RustCrypto except `libc`
   and `zeroize`. Hand-rolled crypto would be worse than a dependency.
6. **The store file is 0600, written atomically, and never holds
   plaintext.**

## Testing

| layer | what it proves |
|---|---|
| `cargo test` (12) | buffer semantics, seal behaviour, store round-trip, wrong passphrase, ciphertext has no plaintext, daemon round-trip |
| `tests/run.sh` (25 on an unprivileged host, 28 in the VM) | end-to-end behaviour, with a negative control per case and `SKIP` for refused mechanisms |
| `vm/run.sh` | the same suite inside a real 6.12 kernel under QEMU TCG, which is the only place `ptrace` and user namespaces are available in a locked-down environment |

`vm/debug.sh SCRIPT` boots the same VM and runs one script, for
single-command experiments.
