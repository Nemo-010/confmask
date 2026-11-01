# Design

## The problem, stated exactly

A Linux process publishes three things about itself through `/proc` for
its whole lifetime:

- `cmdline`: the `argv` strings, NUL-separated,
- `environ`: the `envp` strings,
- `comm`: a 15-byte name, shown by `top` and `htop`.

`cmdline` and `comm` have no permission check: every local account reads
them. `environ`, `exe`, `maps`, `fd/*` and `cwd` need
`PTRACE_MODE_READ_FSCREDS`, which a process of the same uid and root
pass. Yama restricts `PTRACE_MODE_ATTACH` only, so it does not stop a
same-uid read of `environ` or `maps`.

Secrets passed as arguments are the classic case. The usual advice ("use
environment variables") moves the secret from one readable file to
another.

TEEs solve a different problem: they protect memory from the host. They
need hardware, firmware, a hypervisor, attestation infrastructure, and
often a rewritten workload. On a machine without any of that, the
disclosure above is still real, and it is still the one that exposes
tokens.

`confmask` targets that disclosure, and only that one.

## Trust boundary

The boundary is the same one a container draws for the filesystem:
protection against other tenants and against casual or automated
inspection, not against the host operator.

| adversary | outcome |
|---|---|
| another uid | sees the label; no argv, no environ, no comm |
| a monitoring agent of the same uid | the label, plus `exe`, `maps`, `fd/*` and `cwd`, which name the real binary; with `--no-dumpable` those files are refused as well |
| `ps` output pasted into a ticket or a chat | the label |
| root on the host | sees the pid, `exe`, `maps`, fds, cgroups, and can `PTRACE_ATTACH` |
| kernel-level attacker | everything |

The first three rows are the disclosure `confmask` targets. The last
two are out of scope by construction.

## Non-goals

- Encrypting process memory.
- Hiding that a process exists, or which pid it is.
- Defeating a kernel module, a hypervisor, or an eBPF program attached
  to the host.
- Privilege escalation. A traced process cannot gain set-uid privileges,
  so `sudo` under `confmask` does not elevate.
- Persistence, daemonizing into init, or surviving reboots.

## Mechanism

`confmask` is a `ptrace` supervisor: the parent of the supervised tree.
It seizes the child with `PTRACE_SEIZE` and releases it by writing one
byte to a pipe. The child raises `SIGSTOP` and execs.

### Following the tree

`PTRACE_O_TRACEFORK | TRACEVFORK | TRACECLONE | TRACEEXEC | TRACEEXIT`
auto-attaches every descendant, including every thread. This covers
`fork`, `vfork`, `clone`, `posix_spawn()`, `system()`, `popen()`,
double-forking daemons, static binaries, Go runtimes (raw
`clone`+`execve`) and `#!` scripts, without `LD_PRELOAD` and without a
libc dependency in the tracee.

### Zero exposure at exec entry

A process is syscall-supervised (`PTRACE_SYSCALL`) from the moment it is
attached until its first exec settles. At the `execve`/`execveat` entry
stop, before the kernel has built the new image:

1. read the real `argv`/`envp` pointer arrays and their strings,
2. write a 256-byte scratch block at `sp - 4096` in the old image
   containing the label followed by a NUL,
3. rewrite the old image's inline `argv` array to
   `[label, empty, empty, ..., NULL]` and the `envp` array to all empty
   strings, except variables named by `--keep-env=NAME`,
4. resume.

The kernel then copies the label and empty strings. The real command
line never exists in the new image of an ELF target, so
`/proc/<pid>/cmdline` never shows it, not even briefly.

The child's old image still holds the parent's argv bytes from the fork
until this stop. The kernel never copies them into the new image.

### Restoring the real arguments

At `PTRACE_EVENT_EXEC` the new image is mapped but the program has not
started. The supervisor:

1. reads `argc` from the new stack and locates the inline arrays,
2. builds a block containing the real `argv` strings, the real `envp`
   strings and the comm label, 16-byte aligned, below `sp - 4096`,
3. if that stack range is not mapped, injects `mmap` and uses the new
   anonymous mapping instead. The kernel's page pinning does not expand a
   grow-down stack VMA, and a large argument block leaves the range below
   `sp` unmapped,
4. repoints the inline arrays at those strings, and checks every write,
5. zeroes the visible string region, read from `/proc/<pid>/stat` fields
   48 to 51, and writes the label into `argv[0]`'s old slot,
6. injects `prctl(PR_SET_NAME)` and, with `--no-dumpable`,
   `prctl(PR_SET_DUMPABLE, 0)`, through a `syscall` instruction of the
   tracee,
7. resumes.

`argc`, the array positions and the auxiliary vector are untouched. glibc
and musl cache `argv`/`environ` from the stack at startup, so the
program sees its real values and never notices.

When a repoint write fails, the supervisor zeroes the whole visible
region instead: the worst visible result is empty strings, and the
session summary names the exec.

### Scripts, re-execs and foreign images

The kernel needs the real `argv` to build an interpreter line for a `#!`
script, and a settled process no longer stops at syscall entry. Both
cases take the post-exec path: the kernel copies the real interpreter
command line, including the script's arguments, and, unless
`--keep-env`, the real environment. The completion stop zeroes that
region. The duration of this window is not measured.

A 32-bit image is not redacted. The supervisor reads `EI_CLASS` at the
entry stop, refuses the swap, prints one warning and counts the exec in
the session summary. The program keeps its real arguments. The
alternative, swapping and then failing to read the new registers, hands
the program the label as its argv.

An exec by a non-leader thread resets the tid to the group leader's
before `PTRACE_EVENT_EXEC`. The supervisor reads the former tid with
`PTRACE_GETEVENTMSG` and moves the entry-stop bookkeeping to the leader.

### Process name

`prctl(PR_SET_NAME)` is executed by the tracee, not by the supervisor:
the supervisor points the tracee's instruction pointer at a `syscall`
instruction inside the tracee's own vDSO and steps over it. No
writable-and-executable memory is mapped anywhere, and no assumption is
made about the tracee's libc. If no usable syscall instruction is found
in the vDSO, the supervisor scans the first executable mapping of the
image, and fails loudly when that also fails.

`--watch-rename` adds a seccomp filter that traps `prctl(PR_SET_NAME)`
only and returns the label in its place. The filter never matches
`execve`, so the exec-event behaviour below does not apply.

### Job control

The supervisor seizes tracees, so a group-stop arrives as
`PTRACE_EVENT_STOP`. The supervisor answers it with `PTRACE_LISTEN`, which
keeps the tracee stopped and lets `SIGCONT` and the real parent's job
control see it. `kill -STOP` holds a masked tree and `SIGCONT` resumes
it.

### Why no exec-shaped seccomp filter

A per-process seccomp filter with `SECCOMP_RET_TRACE` on `execve` was
tried in the C predecessor and is not used here, for two reasons that
show up only on some kernels:

1. kernels do not deliver `PTRACE_EVENT_EXEC` for an exec whose seccomp
   stop was serviced, which breaks the completion path;
2. an unserviced `RET_TRACE` stop makes `execve` return `ENOSYS` in a
   descendant that is not being supervised.

Pure `PTRACE_SYSCALL` supervision is identical on every kernel from 5.3
on. The cost is two stops per syscall until a process's first exec
settles, and none afterwards.

### Session end

When the master process exits, the session applies its policy:

| policy | behaviour |
|---|---|
| `detach` (default) | every settled descendant is detached with `PTRACE_INTERRUPT` and `PTRACE_DETACH`; a descendant still waiting for its first exec gets a one-second grace period, then is detached as it is |
| `wait` | the session supervises until the last descendant exits |
| `kill` | every remaining tracee gets `SIGKILL` |

A detached descendant keeps the label and its redacted image. A later
exec in it takes the post-exec path, because no supervisor watches it.

`PTRACE_O_EXITKILL` kills the whole tree if the supervisor dies.
`--no-exit-kill` turns it off for callers that want the tree to survive.

### Session summary

The supervisor counts execs and degradations. At session end it prints
one line unless `--quiet`:

```
confmask: N of M execs unredacted (script, reexec x2, foreign-arch)
```

The counts are also in `ExitState::stats`.

## The daemon

`confmaskd` exists because a CI runner cannot hold the token it needs.
Any secret in the runner's argv or environment is in `/proc`. The daemon
holds the environment instead and runs jobs for clients.

### Protocol

One request per connection, one job per connection.

Client to daemon, with `SCM_RIGHTS` carrying stdin, stdout and stderr:

```
1 byte   version (2)
"CMK1"   u32 label_len  label  u8 label_mode
         u32 argc       argc * (u32 len, bytes)
```

`label_mode` is 0 (daemon label), 1 (empty label) or 2 (the text that
follows). Daemon to client:

```
i32 exit_code  u32 has_signal  i32 signal  u32 msg_len  msg
```

Limits: `argc <= 4096`, one argument `<= 1 MiB`, request `<= 8 MiB`,
label `<= 4096` bytes. Integers are little-endian. The daemon requires
exactly three descriptors and rejects a truncated control message.

### Authorisation

`SO_PEERCRED` on the accepted socket. The daemon accepts its own uid and
root; `--allow-uid` adds more. The socket is created with mode 0600. The
client checks the peer uid of the socket it connected to.

An allowed uid may execute arbitrary programs with the daemon's
privileges and inherit its environment. `--run-as-uid` on a root daemon
runs each job with the client's uid and gid instead.

### Socket safety

The daemon refuses to start when the socket path is a symlink or not a
socket, when a live daemon answers on it, or when the parent directory
is not owned by the effective uid or is group or other writable. It
binds with `umask 077` and verifies the bound socket afterwards.

### Timeouts and concurrency

A client that stalls while sending its request or reading its response
is dropped after `--io-timeout` seconds. `--job-timeout` kills a job
tree that runs too long and returns code 137.

A masking session owns the calling process's `waitpid(-1)` domain. The
library serializes sessions with a process-wide mutex. The daemon
accepts one connection at a time by default; `--jobs N` runs each job in
a worker process, up to N at once.

### Secret handling

The job environment is loaded at startup, kept in memory, and locked
with `mlock`. `--no-inherit-env` makes the job environment exactly the
`--env-file` contents. The daemon wipes the store and exits on
`SIGTERM` or `SIGINT`.

## Privilege ladder

Higher privileges buy more privacy in defined steps.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, comm, per-variable environment policy | same-uid observers still read `exe`, `maps`, `fd/*`, `cwd` |
| 0 + `--no-dumpable` | none | `PR_SET_DUMPABLE=0` makes those files refused for the same uid | core dumps and debugger attach stop |
| 0 + `--rexec` | none | `/proc/<pid>/exe` names the memfd, not the file | `/proc/<pid>/map_files` still resolves; `vm.memfd_noexec` may refuse |
| 0 + `--unshare` | kernel that allows unprivileged user namespaces | private PID namespace and private procfs; the payload sees only itself | unavailable on hosts that gate user namespaces; opportunistic by design |
| 0 + `--watch-rename` | none | comm stays the label when a program renames itself | traps `prctl(PR_SET_NAME)` only; implies `no_new_privs` |
| 0 + `--scope-name` | a user session manager | one consistent name in `/proc/<pid>/cgroup` and `systemctl` | the unit name is world-readable; system-level scopes need root or polkit |
| 2 | `CAP_SYS_RESOURCE` | `PR_SET_MM_ARG_START/END` and `PR_SET_MM_ENV_START/END` relocate what `/proc` reads, without stack surgery | design entry only; not implemented |
| 3 | root on the host | `hidepid=2,gid=` on the system `/proc` removes the tree from every other account | polkit and distribution defaults; Yama scope needs `CAP_SYS_PTRACE` and scope 3 is irreversible until reboot |

## Failure modes and what they do

| failure | behaviour |
|---|---|
| exec fails inside the child | original arrays restored, the process stays syscall-supervised, exit 127 (`ENOENT`) or 126 |
| supervisor killed | tree killed via `PTRACE_O_EXITKILL`, no half-masked orphans |
| tracee dies mid-injection | the tracee is dropped from the table; the tree continues |
| hidden block cannot be placed on the stack | an anonymous mapping is created inside the tracee and used instead |
| hidden block cannot be written at all | the visible region is zeroed, one warning is printed, the session summary names the exec |
| 32-bit image | one warning, not redacted, counted as `foreign-arch` |
| daemon job fails | exit status returned to the client; the daemon keeps serving |
| daemon socket is stale | the daemon connects to it first; a live daemon refuses the start, a refused connection is unlinked |

The rows that degrade to disclosure print a warning at the default
verbosity and appear in the session summary. `tests/core.sh` drives the
repoint failure with an injected fault (`CONFMASK_FAULT_POKE`) and the
missing syscall site with `CONFMASK_FAULT_NOVDSO`.

## Kernel-consistency claim

The kernel never receives the real argv of a masked ELF exec, so an
audit record or an eBPF exec observer reports the label. This is an
inference from the mechanism and the documented record format. The
observer suite (`tests/audit.sh`) checks it where the kernel sends
argument text in its `EXECVE` record; the kernel used for the VM run
truncates that record before the argument text, so the suite skips and
says so.
