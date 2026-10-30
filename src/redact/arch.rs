//! Architecture-specific register layout, syscall numbers and audit arch.
//!
//! The tracer reads and writes tracee registers through
//! `PTRACE_GETREGSET`/`PTRACE_SETREGSET` with `NT_PRSTATUS`, which hands
//! back the raw `user_regs_struct` (x86-64) / `user_pt_regs` (aarch64)
//! kernel layout.  Everything else in the crate talks to this module.

use std::io;

pub const NT_PRSTATUS: usize = 1;

// PTRACE_GETREGSET / PTRACE_SETREGSET (uapi <linux/ptrace.h> since 2.6.14)
pub const PTRACE_GETREGSET: libc::c_uint = 0x4204;
pub const PTRACE_SETREGSET: libc::c_uint = 0x4205;

/// `PTRACE_GET_SYSCALL_INFO` request (Linux >= 5.3).
pub const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;

/// `op` field values of `struct __ptrace_syscall_info`.
pub mod syscall_info_op {
    #[allow(dead_code)]
    pub const NONE: u8 = 0;
    pub const ENTRY: u8 = 1;
    pub const EXIT: u8 = 2;
    pub const SECCOMP: u8 = 3;
}

/// `struct __ptrace_syscall_info` (Linux >= 5.3, <linux/ptrace.h>).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallInfo {
    pub op: u8,
    pub pad: [u8; 3],
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub detail: SyscallDetail,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SyscallDetail {
    /// valid for op == ENTRY
    pub entry: EntryDetail,
    /// valid for op == EXIT
    pub exit: ExitDetail,
    /// valid for op == SECCOMP (same shape as entry)
    pub seccomp: EntryDetail,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EntryDetail {
    pub nr: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitDetail {
    pub rval: i64,
    pub is_error: u8,
}

impl SyscallInfo {
    /// System call number if this stop carries entry-shaped data
    /// (syscall-entry stop or seccomp `SECCOMP_RET_TRACE` stop).
    pub fn entry_nr(&self) -> Option<u64> {
        match self.op {
            syscall_info_op::ENTRY | syscall_info_op::SECCOMP => {
                Some(unsafe { self.detail.seccomp.nr })
            }
            _ => None,
        }
    }

    /// `true` if the completed system call reported an error return.
    pub fn exit_is_error(&self) -> bool {
        self.op == syscall_info_op::EXIT && unsafe { self.detail.exit.is_error } != 0
    }
}

/// Tracee general-purpose registers (kernel layout per architecture).
#[derive(Clone, Copy)]
pub struct Regs {
    pub raw: RawRegs,
}

// ------------------------------------------------------------------ x86_64

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;
    use std::mem;

    pub const ARCH_NAME: &str = "x86_64";

    pub const SYS_EXECVE: u64 = 59;
    pub const SYS_EXECVEAT: u64 = 322;
    pub const SYS_PRCTL: u64 = 157;

    /// `struct user_regs_struct` from <sys/user.h>.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RawRegs {
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub r11: u64,
        pub r10: u64,
        pub r9: u64,
        pub r8: u64,
        pub rax: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub orig_rax: u64,
        pub rip: u64,
        pub cs: u64,
        pub eflags: u64,
        pub rsp: u64,
        pub ss: u64,
        pub fs_base: u64,
        pub gs_base: u64,
        pub ds: u64,
        pub es: u64,
        pub fs: u64,
        pub gs: u64,
    }

    const _: () = assert!(mem::size_of::<RawRegs>() == 27 * 8);

    impl Regs {
        pub fn sp(&self) -> u64 {
            self.raw.rsp
        }
        /// Return value of a completed system call.
        pub fn retval(&self) -> i64 {
            self.raw.rax as i64
        }
        /// 1-based system call argument (arg(1) is the first).
        pub fn arg(&self, n: usize) -> u64 {
            match n {
                1 => self.raw.rdi,
                2 => self.raw.rsi,
                3 => self.raw.rdx,
                4 => self.raw.r10,
                5 => self.raw.r8,
                6 => self.raw.r9,
                _ => 0,
            }
        }
        pub fn set_arg(&mut self, n: usize, v: u64) {
            match n {
                1 => self.raw.rdi = v,
                2 => self.raw.rsi = v,
                3 => self.raw.rdx = v,
                4 => self.raw.r10 = v,
                5 => self.raw.r8 = v,
                6 => self.raw.r9 = v,
                _ => {}
            }
        }
        /// Stage a system call for injection: number goes to `rax`,
        /// arguments to the ABI argument registers.
        pub fn set_syscall(&mut self, nr: u64, args: [u64; 6]) {
            self.raw.rax = nr;
            for (i, a) in args.iter().enumerate() {
                self.set_arg(i + 1, *a);
            }
        }
        pub fn set_ip(&mut self, ip: u64) {
            self.raw.rip = ip;
        }
    }
}

// ----------------------------------------------------------------- aarch64

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    use std::mem;

    pub const ARCH_NAME: &str = "aarch64";

    pub const SYS_EXECVE: u64 = 221;
    pub const SYS_EXECVEAT: u64 = 281;
    pub const SYS_PRCTL: u64 = 167;

    /// `struct user_pt_regs` from <asm/ptrace.h>: the kernel's
    /// `{ __u64 regs[31]; sp; pc; pstate; }` is byte-for-byte identical
    /// to this repr(C) struct of 31 consecutive u64 fields + 3 more.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RawRegs {
        pub x: [u64; 31],
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
    }

    const _: () = assert!(mem::size_of::<RawRegs>() == 34 * 8);

    impl Regs {
        pub fn sp(&self) -> u64 {
            self.raw.sp
        }
        /// Return value of a completed system call.
        pub fn retval(&self) -> i64 {
            self.raw.x[0] as i64
        }
        /// 1-based system call argument (arg(1) is the first).
        pub fn arg(&self, n: usize) -> u64 {
            match n {
                1..=6 => self.raw.x[n - 1],
                _ => 0,
            }
        }
        pub fn set_arg(&mut self, n: usize, v: u64) {
            if (1..=6).contains(&n) {
                self.raw.x[n - 1] = v;
            }
        }
        /// Stage a system call for injection: number goes to `x8`,
        /// arguments to x0..x5.
        pub fn set_syscall(&mut self, nr: u64, args: [u64; 6]) {
            self.raw.x[8] = nr;
            for (i, a) in args.iter().enumerate() {
                self.set_arg(i + 1, *a);
            }
        }
        pub fn set_ip(&mut self, ip: u64) {
            self.raw.pc = ip;
        }
    }
}

pub use imp::*;

impl Regs {
    /// `PTRACE_GETREGSET(NT_PRSTATUS)`.
    pub fn get(pid: libc::pid_t) -> io::Result<Regs> {
        let mut regs: RawRegs = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<RawRegs>(),
        };
        // SAFETY: pid is a stopped tracee we are attached to; iov points
        // at valid memory for the duration of the call.
        let rc = unsafe {
            libc::ptrace(
                PTRACE_GETREGSET as _,
                pid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut libc::iovec as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Regs { raw: regs })
    }

    /// `PTRACE_SETREGSET(NT_PRSTATUS)`.
    pub fn put(&self, pid: libc::pid_t) -> io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: &self.raw as *const _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<RawRegs>(),
        };
        // SAFETY: see `get`.
        let rc = unsafe {
            libc::ptrace(
                PTRACE_SETREGSET as _,
                pid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut libc::iovec as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Architecture name for the version banner.
pub fn arch_name() -> &'static str {
    imp::ARCH_NAME
}
