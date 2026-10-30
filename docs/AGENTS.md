# confmask — agent router

The self-contained entry point for anyone (human or agent) working in this
repository. Reading this file gives you the map, the invariants and the
verification protocol.

**Read this file in full.**

## What this repo is

`confmask` reduces what a shared Linux host discloses about a workload:
its secrets, its command lines, its files. It is confidential computing
without TEE hardware, without a VM, and without root.

Four mechanisms, each optional and each probed at runtime:

1. **sealed descriptor delivery** — secrets arrive as inherited memfds,
   never as `argv` or environment values (needs nothing);
2. **the encrypted store** — Argon2id + XChaCha20-Poly1305, one file
   (needs nothing);
3. **metadata redaction** — `ptrace` swaps `argv`/`envp` at `execve` entry
   (needs `ptrace`);
4. **isolation** — unprivileged user namespaces (needs `unprivileged_userns_clone`).

The redaction engine is the `argvmask` supervisor, vendored under
`src/redact/`. It is one provider; nothing else depends on it.

## Language rules

Write *redact*, *mask*, *presentation label*, *supervise*, *disclosure
surface*, *sealed descriptor*.

Do not write: "hide from ps/EDR", "stealth", "cloak", "fake identity",
"evade", "bypass detection", "undetectable". The tool reduces what `/proc`
discloses; it does not conceal pids, and it does not defeat root. The
README and `docs/THREAT-MODEL.md` say so, and the code comments must not
claim more than they do.

## Map

| path | role |
|---|---|
| `README.md` | the problem, the four mechanisms, quick start, verification status |
| `docs/THREAT-MODEL.md` | adversaries in and out of scope, per-mechanism analysis, the daemon boundary |
| `docs/ARCHITECTURE.md` | module map, design decisions, invariants |
| `src/caps.rs` | capability probe + report |
| `src/mem.rs` | `SecBuf`, `SealedFd`, `harden_self` |
| `src/secret.rs` | `Source`, `Secret`, `Delivery` |
| `src/store.rs` | the encrypted store |
| `src/daemon.rs` | socket server + client |
| `src/isolate.rs` | namespaces, the id-map handshake |
| `src/run.rs` | `Runner`, mode selection, the three dispatch paths |
| `src/redact/` | the ptrace engine (arch, remote, inject, execimg, tracer, mask, selfmask) |
| `src/cli.rs`, `src/main.rs` | the command line |
| `tests/run.sh` | the suite; `tests/lib.sh` has the `/proc` observers |
| `vm/run.sh` | QEMU micro-VM harness for hosts that refuse ptrace/userns |
| `vm/debug.sh` | boot the same VM for one script |

## Invariants (do not break these)

1. **No secret in `argv`, in an environment *value*, in a log line, or in
   a `Debug` impl.** `Secret`/`SecBuf` print lengths, never bytes. A new
   type that wraps secret bytes needs the same treatment.
2. **A missing capability is reported, never assumed.** New mechanisms
   must appear in `caps::Caps` and in `Caps::report`, with the cost of
   their absence spelled out.
3. **A skipped test is `SKIP`, never a pass.** Every suite case that needs
   a mechanism checks for it and says why it skipped. "Zero sightings"
   from a process that never started is not evidence.
4. **Plaintext holders are non-dumpable.** Anything that reads a secret
   calls `mem::harden_self()` before it holds it.
5. **The store is 0600, atomic, and never contains plaintext.** The header
   stays authenticated as AEAD associated data.
6. **Modes are exclusive.** Do not quietly compose redaction with
   isolation: the PID-namespace fork breaks the tracer's ownership
   assumption. If that changes, it needs tests and a threat-model update.
7. **0BSD, short dependency list.** `libc`, `zeroize`, `argon2`,
   `chacha20poly1305`. No hand-rolled crypto, no new dependency without a
   reason written down in the commit.

## Build and verify

```sh
cargo build --release
cargo clippy --all-targets          # zero warnings policy
cargo test                          # 12 unit tests
sh tests/run.sh                     # end-to-end; SKIPs what the host refuses
sh vm/run.sh                        # the same suite in a QEMU micro-VM
```

`vm/run.sh` is the canonical gate on a locked-down host: it fetches an
Alpine `linux-virt` kernel and a static busybox, builds the musl binary,
packs an initramfs and boots it under TCG. It exits 0 only on
`VERDICT: ALL-PASS`. `vm/debug.sh <script>` boots the same VM for one
script.

If `qemu-system-x86_64` is missing and you cannot install it, say so and
report the `tests/run.sh` result plus which cases were skipped. Do not
claim the VM result you did not get.

In a sandbox whose toolchain lives on a noexec mount, `cargo test` reports
two doctest failures with `Failed to spawn rustc: Permission denied`; that
is the harness spawning `rustc` from a path it cannot execute, not a code
problem. `cargo test --lib` is the portable form.

## Conventions

- Commits: imperative subject, reason in the body.
- Docs live under `docs/` and are linked from here and from the README.
- A change to a security claim in `README.md` or `docs/THREAT-MODEL.md`
  needs the test that supports it, in the same commit.
- Keep the repository lean: no root-level `AGENTS.md`/`CLAUDE.md`; this
  file is the router.
