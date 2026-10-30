//! What this host actually allows.
//!
//! Every mechanism `confmask` uses is optional, and a host may refuse any
//! of them: seccomp profiles ban `ptrace`, `/proc/sys/kernel/
//! unprivileged_userns_clone` may be 0, `memfd_secret` may be compiled
//! out, `RLIMIT_MEMLOCK` may be 64 KiB.  The tool therefore never assumes
//! a tier exists — it probes, reports, and runs with whatever is left.
//!
//! The probe runs each check in a forked child, so a refused call cannot
//! leave the caller in a half-changed state.

use std::io;
use std::sync::OnceLock;

/// `memfd_secret(2)`; same number on x86-64 and aarch64.
const SYS_MEMFD_SECRET: libc::c_long = 447;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Secrets are delivered as sealed file descriptors and kept in
    /// locked, dump-excluded memory.  Needs nothing beyond a kernel.
    SecretFds,
    /// `memfd_secret` keeps the pages out of the kernel direct map.
    SecretMem,
    /// `/proc` metadata of the whole tree is redacted (needs `ptrace`).
    MetadataRedaction,
    /// A private mount/pid/net namespace for the payload (needs
    /// unprivileged user namespaces).
    Isolation,
}

#[derive(Debug, Clone)]
pub struct Caps {
    pub arch: &'static str,
    pub kernel: String,
    /// `PTRACE_TRACEME` from a child succeeds.
    pub ptrace: bool,
    /// `unshare(CLONE_NEWUSER)` succeeds unprivileged.
    pub userns: bool,
    /// `memfd_secret(2)` returns a usable descriptor.
    pub memfd_secret: bool,
    /// `mlock` on a fresh page succeeds (so secrets cannot be swapped).
    pub mlock: bool,
    /// `PR_SET_DUMPABLE` is permitted.
    pub non_dumpable: bool,
    /// A seccomp filter is already installed on this process, which is
    /// what usually explains a refused `ptrace`.
    pub seccomp_filter: bool,
}

fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: plain uname into owned storage.
    if unsafe { libc::uname(&mut u) } == 0 {
        // SAFETY: release is a NUL-terminated array inside `u`.
        let s = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
        return s.to_string_lossy().into_owned();
    }
    "unknown".to_string()
}

/// Run `f` in a forked child and return its boolean verdict.
fn probe_in_child<F: FnOnce() -> bool>(f: F) -> bool {
    // SAFETY: single-threaded at probe time; the child only runs `f` and
    // `_exit`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let ok = f();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0i32;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        break;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

impl Caps {
    pub fn detect() -> Caps {
        let ptrace = probe_in_child(|| {
            // SAFETY: plain ptrace; the child exits immediately after, so
            // there is no stopped tracee to leave behind.
            unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == 0 }
        });

        let userns = probe_in_child(|| {
            // SAFETY: unshare in a throwaway child.
            unsafe { libc::unshare(libc::CLONE_NEWUSER) == 0 }
        });

        let memfd_secret = {
            // SAFETY: plain syscall; a failure is the answer.
            let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0 as libc::c_long) } as libc::c_int;
            if fd >= 0 {
                // SAFETY: fd is ours.
                unsafe { libc::close(fd) };
                true
            } else {
                false
            }
        };

        let mlock = probe_in_child(|| {
            // SAFETY: anonymous one-page mapping, locked and released.
            unsafe {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return false;
                }
                let ok = libc::mlock(p, 4096) == 0;
                libc::munlock(p, 4096);
                libc::munmap(p, 4096);
                ok
            }
        });

        let non_dumpable = probe_in_child(|| {
            // SAFETY: prctl in a throwaway child.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) == 0 }
        });

        let seccomp_filter = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Seccomp:"))
                    .and_then(|l| l.split_whitespace().nth(1).map(|v| v != "0"))
            })
            .unwrap_or(false);

        Caps {
            arch: std::env::consts::ARCH,
            kernel: kernel_release(),
            ptrace,
            userns,
            memfd_secret,
            mlock,
            non_dumpable,
            seccomp_filter,
        }
    }

    /// The probe is deterministic for the life of the process, and several
    /// code paths want it, so it is computed once.
    pub fn cached() -> &'static Caps {
        static CACHE: OnceLock<Caps> = OnceLock::new();
        CACHE.get_or_init(Caps::detect)
    }

    /// Which mechanisms are available, in the order they matter.
    pub fn tiers(&self) -> Vec<(Tier, bool)> {
        vec![
            (Tier::SecretFds, true),
            (Tier::SecretMem, self.memfd_secret),
            (Tier::MetadataRedaction, self.ptrace),
            (Tier::Isolation, self.userns),
        ]
    }

    /// One line per mechanism: what it is, whether it is available, and
    /// what its absence costs.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "confmask capability report\n  arch={} kernel={}\n\n",
            self.arch, self.kernel
        ));
        let row = |s: &mut String, name: &str, ok: bool, why: &str| {
            s.push_str(&format!(
                "  {:<22} {:<4} {}\n",
                name,
                if ok { "yes" } else { "no" },
                why
            ));
        };
        row(
            &mut s,
            "secret fds",
            true,
            "sealed memfds + inherited descriptors (always available)",
        );
        row(
            &mut s,
            "memfd_secret",
            self.memfd_secret,
            if self.memfd_secret {
                "secret pages are absent from the kernel direct map"
            } else {
                "pages are locked but still reachable by the kernel"
            },
        );
        row(
            &mut s,
            "mlock",
            self.mlock,
            if self.mlock {
                "secrets cannot be swapped out"
            } else {
                "secrets may reach swap (RLIMIT_MEMLOCK too low?)"
            },
        );
        row(
            &mut s,
            "non-dumpable",
            self.non_dumpable,
            if self.non_dumpable {
                "no core dumps, no ptrace of the holder by non-root"
            } else {
                "the holding process may be dumpable"
            },
        );
        row(
            &mut s,
            "metadata redaction",
            self.ptrace,
            if self.ptrace {
                "cmdline/environ/comm of the tree are redacted"
            } else if self.seccomp_filter {
                "ptrace is banned by a seccomp filter here; command lines stay visible"
            } else {
                "ptrace is not permitted here; command lines stay visible"
            },
        );
        row(
            &mut s,
            "isolation",
            self.userns,
            if self.userns {
                "payload can run in a private mount/pid/net namespace"
            } else {
                "no unprivileged user namespaces; the payload sees the host"
            },
        );
        s.push_str(
            "\n  What this means: with no ptrace, a secret passed as a command\n  \
             line argument is visible to every local account through\n  \
             /proc/<pid>/cmdline.  confmask's answer on such a host is to keep\n  \
             secrets out of argv and the environment entirely (fd delivery),\n  \
             which does not need ptrace at all.\n",
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let c = Caps::detect();
        assert!(!c.arch.is_empty());
        assert!(!c.kernel.is_empty());
        assert!(c.report().contains("capability report"));
    }
}
