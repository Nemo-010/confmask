//! A minimal seccomp filter that reports `prctl(PR_SET_NAME)` to the tracer.
//!
//! The filter returns `SECCOMP_RET_TRACE` for one call only:
//! `prctl` with `PR_SET_NAME` as the first argument. It allows every other
//! call. It does not match `execve`, so it does not stop any exec.
//!
//! The filter checks the architecture first. A call from a foreign
//! architecture (for example a 32-bit call on x86_64) is allowed. An x32 call
//! has a different call number and is allowed too.
//!
//! The filter applies to the current architecture only: x86_64, aarch64
//! and i386 (the i686 build exists for the 32-bit probe binary).
//! The caller must set `PR_SET_NO_NEW_PRIVS` before `install`, or the kernel
//! refuses the filter for an unprivileged process.
//!
//! This module does not decide what the tracer does with the stop. It only
//! builds and installs the program.

use std::io;

/// Offset of `nr` in `struct seccomp_data`.
const OFFSET_NR: u32 = 0;
/// Offset of `arch` in `struct seccomp_data`.
const OFFSET_ARCH: u32 = 4;
/// Offset of `args[0]` (low word on little-endian) in `struct seccomp_data`.
const OFFSET_ARG0_LOW: u32 = 16;

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Data value that the tracer sees in the `PTRACE_EVENT_SECCOMP` message.
pub const TRACE_DATA: u32 = 0x70;

const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const PR_SET_NAME: u32 = 15;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_CURRENT: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_CURRENT: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86")]
const AUDIT_ARCH_CURRENT: u32 = 0x4000_0003; // AUDIT_ARCH_I386

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump_eq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JEQ_K,
        jt,
        jf,
        k,
    }
}

/// Build the classic BPF program for the current architecture.
///
/// Layout (index: instruction):
/// 0 load arch, 1 jump if arch matches, 2 load nr, 3 jump if nr is prctl,
/// 4 load args[0], 5 jump if PR_SET_NAME, 6 return TRACE, 7 return ALLOW.
pub fn prctl_watch_filter() -> Vec<libc::sock_filter> {
    let prctl_nr = libc::SYS_prctl as u32;
    vec![
        stmt(BPF_LD_W_ABS, OFFSET_ARCH),
        // match: continue at 2. mismatch: skip 5 to index 7 (allow).
        jump_eq(AUDIT_ARCH_CURRENT, 0, 5),
        stmt(BPF_LD_W_ABS, OFFSET_NR),
        // match: continue at 4. mismatch: skip 3 to index 7.
        jump_eq(prctl_nr, 0, 3),
        stmt(BPF_LD_W_ABS, OFFSET_ARG0_LOW),
        // match: continue at 6. mismatch: skip 1 to index 7.
        jump_eq(PR_SET_NAME, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_TRACE | TRACE_DATA),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]
}

/// Install `filter` on the calling thread with `prctl(PR_SET_SECCOMP)`.
///
/// The program lives on the stack. The function does not allocate, so it is
/// async-signal-safe after `fork`.
///
/// # Safety
///
/// `filter` must be a valid classic BPF program. The caller must have set
/// `PR_SET_NO_NEW_PRIVS` (or hold `CAP_SYS_ADMIN`). The filter stays in force
/// for the thread and all its future children and cannot be removed.
pub unsafe fn install(filter: &[libc::sock_filter]) -> io::Result<()> {
    if filter.is_empty() || filter.len() > u16::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points to `filter`, which outlives the call. The kernel
    // copies the program before prctl returns.
    let rc = libc::prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        &prog as *const libc::sock_fprog as libc::c_ulong,
        0 as libc::c_ulong,
        0 as libc::c_ulong,
    );
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `struct seccomp_data` (64 bytes, little endian).
    fn data(nr: u32, arch: u32, arg0: u64) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&nr.to_le_bytes());
        d[4..8].copy_from_slice(&arch.to_le_bytes());
        d[16..24].copy_from_slice(&arg0.to_le_bytes());
        d
    }

    /// Interpreter for the three instruction kinds the filter uses.
    fn run(prog: &[libc::sock_filter], d: &[u8; 64]) -> u32 {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let ins = &prog[pc];
            match ins.code {
                BPF_LD_W_ABS => {
                    let k = ins.k as usize;
                    let mut w = [0u8; 4];
                    w.copy_from_slice(&d[k..k + 4]);
                    acc = u32::from_le_bytes(w);
                    pc += 1;
                }
                BPF_JEQ_K => {
                    let skip = if acc == ins.k { ins.jt } else { ins.jf };
                    pc += 1 + skip as usize;
                }
                BPF_RET_K => return ins.k,
                other => panic!("unsupported instruction code {:#x}", other),
            }
        }
    }

    // Mutation control: changing `jump_eq(PR_SET_NAME, 0, 1)` to compare
    // PR_SET_DUMPABLE (4), or dropping the arg0 check, makes
    // `set_name_is_traced` or `dumpable_is_allowed` fail.
    #[test]
    fn set_name_is_traced() {
        let prog = prctl_watch_filter();
        let d = data(libc::SYS_prctl as u32, AUDIT_ARCH_CURRENT, 15);
        assert_eq!(run(&prog, &d), SECCOMP_RET_TRACE | TRACE_DATA);
    }

    #[test]
    fn high_word_of_arg0_is_ignored_for_the_match() {
        // Only the low word of args[0] is compared. A set high word still
        // matches, because the kernel passes an int option.
        let prog = prctl_watch_filter();
        let d = data(libc::SYS_prctl as u32, AUDIT_ARCH_CURRENT, (1u64 << 32) | 15);
        assert_eq!(run(&prog, &d), SECCOMP_RET_TRACE | TRACE_DATA);
    }

    #[test]
    fn dumpable_is_allowed() {
        let prog = prctl_watch_filter();
        let d = data(libc::SYS_prctl as u32, AUDIT_ARCH_CURRENT, 4);
        assert_eq!(run(&prog, &d), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn other_syscalls_are_allowed() {
        let prog = prctl_watch_filter();
        for nr in [libc::SYS_execve, libc::SYS_write, libc::SYS_openat] {
            // arg0 equals 15 on purpose: only prctl may match.
            let d = data(nr as u32, AUDIT_ARCH_CURRENT, 15);
            assert_eq!(run(&prog, &d), SECCOMP_RET_ALLOW, "nr {}", nr);
        }
    }

    #[test]
    fn x32_style_number_is_allowed() {
        let prog = prctl_watch_filter();
        let d = data(libc::SYS_prctl as u32 | 0x4000_0000, AUDIT_ARCH_CURRENT, 15);
        assert_eq!(run(&prog, &d), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn foreign_arch_is_allowed() {
        let prog = prctl_watch_filter();
        // AUDIT_ARCH_I386 and the other architecture of this module.
        let other: u32 = if AUDIT_ARCH_CURRENT == 0xC000_003E {
            0xC000_00B7
        } else {
            0xC000_003E
        };
        for arch in [0x4000_0003u32, other] {
            let d = data(libc::SYS_prctl as u32, arch, 15);
            assert_eq!(run(&prog, &d), SECCOMP_RET_ALLOW, "arch {:#x}", arch);
        }
    }

    #[test]
    fn install_rejects_empty_program() {
        // SAFETY: an empty program is rejected before any syscall.
        let r = unsafe { install(&[]) };
        assert!(r.is_err());
    }
}
