# Threat model

Written to be argued with. If a claim here is wrong, that is a bug worth
filing.

## The claim

`confmask` reduces the **disclosure surface** of a workload on a shared
Linux host: what other accounts, other processes of the same account, and
anything that captures `ps` output can learn about it.

It is *not* a confidentiality guarantee against a privileged observer. It
is the part of confidential computing you can have without special
hardware, and the docs say which part that is.

## Adversaries

### In scope

**A1 — another account on the same machine.** Can read
`/proc/<pid>/cmdline` (world-readable), run `ps` in a loop, list `/tmp`,
and read any file the mode bits allow. This is the co-tenant, the other
CI job's shell, the curious operator.

**A2 — another process of the same account.** Can read
`/proc/<pid>/environ`, `/proc/<pid>/fd/*`, and any file owned by that
account. This is the compromised job step next to the runner, or a
malicious dependency in the build.

**A3 — accidental disclosure.** `ps` output pasted into a bug report,
terminal scrollback, a crash dump, a support bundle, a monitoring agent
that scrapes `/proc`, a `docker inspect` of a container's command line.

### Out of scope

**B1 — root, and the host kernel.** Root reads everything, including
locked pages, through `/proc/<pid>/mem` and `process_vm_readv`. Nothing in
userspace changes that, and `confmask` does not pretend to.

**B2 — the hypervisor, or anything below the kernel.** No TEE. A cloud
operator with access to the physical host can read guest memory.

**B3 — side channels.** Timing, cache occupancy, power, speculative
execution. These are precisely what TEE hardware mitigates and this tool
does not.

**B4 — a compromised confmask binary.** If an attacker can replace the
binary, the game is over before it starts.

**B5 — code running as the same account that is *allowed* to ask the
daemon.** See "The daemon boundary" below. This is the sharpest limit in
the design and it is stated plainly rather than papered over.

## What each mechanism actually buys

### Sealed descriptor delivery

The secret is written into a `memfd` created with `MFD_ALLOW_SEALING`, then
sealed with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`.
The child inherits it at a known descriptor number.

- `ps` / `/proc/<pid>/cmdline`: nothing. The value was never an argument.
- `/proc/<pid>/environ`: the *name* of the secret and the fd number only.
- `/proc/<pid>/fd/N`: a symlink to `/memfd:confmask-secret (deleted)`.
  Reading the contents requires opening the descriptor, which requires
  being the process (A2 can do it — see B5).
- After `exec`, the sealed fd survives; the memory it points at is
  shared, not copied.

**Against A1 and A3: strong.** The value is not in any world-readable
place, and it does not appear in `ps` output, so it cannot be pasted
anywhere.

**Against A2: partial.** A same-account process can still read
`/proc/<pid>/fd/N` of a live holder if it can open that path — the fd
symlink is readable by the owner. This is why the store's passphrase and
the daemon matter: they narrow *when* the plaintext exists at all.

### Locked, dump-excluded memory

`SecBuf` allocates with `mlock` (not swappable), `MADV_DONTDUMP` (not in a
core), and `memfd_secret` when the kernel offers it (pages removed from the
kernel direct map).

- `mlock` stops the value reaching swap, where it would outlive the process.
- `MADV_DONTDUMP` stops it reaching a core file that gets uploaded.
- `memfd_secret` stops a kernel-memory read (a compromised kernel module,
  `/dev/mem`) from finding it. It does **not** stop a privileged
  `process_vm_readv`; the pages are still mapped in the owning process.

`PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` are applied to any process that
holds plaintext, so A2 cannot read its `/proc/<pid>/mem`, `/proc/<pid>/environ`
or core.

### Encrypted store

One file: magic, Argon2id parameters, salt, nonce, ciphertext. The header is
authenticated as AEAD associated data, so the KDF cost cannot be weakened
without the tag failing. Argon2id at m=19 MiB, t=2, p=1 — the OWASP
interactive baseline.

**Against A2 reading the file at rest: strong**, subject to passphrase
strength. An attacker with the file offline can grind the passphrase at
whatever rate Argon2id allows; that is the entire point of the KDF and the
entire limit of it.

**The passphrase itself is the weak link.** `CONFMASK_PASSPHRASE` in the
environment is supported and warned about, because it is visible in that
process's `environ`. `--passphrase-file` with mode 0600 is the
recommendation; the terminal prompt writes nothing to disk.

### Metadata redaction (`ptrace`)

`execve` is stopped at syscall entry and the `argv`/`envp` pointer arrays
are repointed at a label and empty strings before the kernel copies
anything, so there is no window in which the real command line exists in
`/proc`. The real strings are re-injected below the new image's stack
pointer, where the program's own libc finds them.

**Against A1 and A3: strong** for command lines, `environ` and `comm`,
for the whole tree, including static binaries and Go runtimes.

Limits, unchanged from the C implementation this engine came from:

- `/proc/<pid>/exe`, `maps`, open files and cgroups still describe the real
  binary.
- `AT_EXECFN` still holds the real path; it is readable from inside the
  process, not through `/proc` files that `ps` shows.
- A `#!` script's interpreter line is visible for the sub-millisecond
  between the kernel writing it and the tracer's completion stop.
- A re-exec of an already-settled process is redacted at
  `PTRACE_EVENT_EXEC` rather than at entry (sub-millisecond window), which
  is the deliberate trade for kernel-independence.
- Set-uid programs do not gain privileges under a tracer.

**It needs `ptrace`, which many containers ban.** When it is banned,
`confmask` says so and runs anyway; command lines then stay visible, and
the honest answer is "do not put the secret in argv".

### Namespaces

A user namespace (mapped to the caller), a mount namespace, optionally a
PID and network namespace.

**Against A1: strong** for the payload's own files, if it writes them
inside its private `tmpfs`: they are not in the host's `/tmp` and cannot be
listed. Its `/proc` lists only itself, so it cannot enumerate or read the
command lines of other jobs.

**Against A2: nothing.** Namespaces do not distinguish two processes of the
same account.

**Not a sandbox.** A user namespace is not a security boundary against the
kernel; the kernel's user-namespace attack surface is large, and this tool
does not shrink it.

## The daemon boundary

The daemon serves secrets to peers with:

1. the same uid (`SO_PEERCRED`), and
2. if `--allow` is given, an executable path from `/proc/<pid>/exe`.

Point 2 is worth being precise about. `/proc/<pid>/exe` cannot be forged by
the peer, so it is a real restriction. But it does not help when the
untrusted code is a *child* of the allowed program, because the child can
run the allowed program itself.

**So: if a job step can execute the allowed binary, it can fetch the
secret.** The mitigation is architectural, not a flag: do not give the
untrusted code the secret at all. Let the runner hold it and make the
authenticated call itself, or run the trusted step in a process the
untrusted step cannot reach.

`confmask`'s contribution is that the secret can then live in one locked,
non-dumpable process instead of in a plaintext file and in every child's
environment — which is a real reduction, and a smaller claim than "the job
cannot get the token".

## What an attacker on this host still sees

Being explicit, because "it provides some privacy" is easy to over-read:

| question | answer |
|---|---|
| does a process exist? | yes, always |
| which binary is it running? | yes: `/proc/<pid>/exe`, `maps` |
| what are its arguments? | not with redaction; yes without it |
| what is in its environment? | not with redaction; the secret *names* otherwise |
| what is the secret's value? | not through `/proc`, unless it can open the holder's fd |
| which files does it have open? | yes: `/proc/<pid>/fd`, `/proc/<pid>/maps` |
| what is it doing on the network? | yes, if you can see the sockets |
| how much CPU/memory does it use? | yes |

## Reporting

A claim in this document that the code does not support is a security bug.
Open an issue with the mechanism, the test that should have caught it, and
what you observed instead.
