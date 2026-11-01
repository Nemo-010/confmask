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

pub const PTRACE_SEIZE: libc::c_uint = 0x4206;
pub const PTRACE_INTERRUPT: libc::c_uint = 0x4207;
pub const PTRACE_LISTEN: libc::c_uint = 0x4208;

/// `PTRACE_EVENT_STOP`: group-stop, `PTRACE_INTERRUPT` stop and the
/// initial stop of a seized tracee.
pub const PTRACE_EVENT_STOP: u32 = 128;
/// `PTRACE_EVENT_SECCOMP`
pub const PTRACE_EVENT_SECCOMP: u32 = 7;
/// `PTRACE_O_TRACESECCOMP`
pub const PTRACE_O_TRACESECCOMP: libc::c_long = 0x80;

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
    pub const SYS_MMAP: u64 = 9;
    /// Audit arch of native syscalls.
    pub const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    /// `(audit arch, execve nr, execveat nr)` of every foreign ABI a tracee
    /// of this architecture can use.
    pub const FOREIGN_EXEC: &[(u32, u64, u64)] = &[
        (0x4000_0003, 11, 358), // AUDIT_ARCH_I386
    ];
    /// x32 syscalls carry this bit with the native audit arch.
    pub const X32_BIT: u64 = 0x4000_0000;
    pub const X32_EXECVE: u64 = 520;
    pub const X32_EXECVEAT: u64 = 545;

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

// --------------------------------------------------------------------- x86
//
// The i686 build exists so the probe binary (confmask-testcases) can be
// compiled as a 32-bit program for the foreign-ABI test.  A 32-bit host
// is not a supported configuration for the tool itself, and the tracer
// refuses 32-bit tracees at run time.

#[cfg(target_arch = "x86")]
mod imp {
    use super::*;
    use std::mem;

    pub const ARCH_NAME: &str = "x86";

    pub const SYS_EXECVE: u64 = 11;
    pub const SYS_EXECVEAT: u64 = 358;
    pub const SYS_PRCTL: u64 = 172;
    pub const SYS_MMAP: u64 = 90;

    /// `struct user_regs_struct` of i386, all fields 32 bits.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RawRegs {
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
        pub esi: u32,
        pub edi: u32,
        pub ebp: u32,
        pub eax: u32,
        pub xds: u32,
        pub xes: u32,
        pub xfs: u32,
        pub xgs: u32,
        pub orig_eax: u32,
        pub eip: u32,
        pub xcs: u32,
        pub eflags: u32,
        pub esp: u32,
        pub xss: u32,
    }

    const _: () = assert!(mem::size_of::<RawRegs>() == 17 * 4);

    pub const NATIVE_AUDIT_ARCH: u32 = 0x4000_0003; // AUDIT_ARCH_I386
    pub const FOREIGN_EXEC: &[(u32, u64, u64)] = &[
        (0xC000_003E, 59, 322), // AUDIT_ARCH_X86_64
    ];
    pub const X32_BIT: u64 = 0;
    pub const X32_EXECVE: u64 = u64::MAX;
    pub const X32_EXECVEAT: u64 = u64::MAX;

    impl Regs {
        pub fn sp(&self) -> u64 {
            self.raw.esp as u64
        }
        pub fn retval(&self) -> i64 {
            self.raw.eax as i32 as i64
        }
        pub fn arg(&self, n: usize) -> u64 {
            match n {
                1 => self.raw.ebx as u64,
                2 => self.raw.ecx as u64,
                3 => self.raw.edx as u64,
                4 => self.raw.esi as u64,
                5 => self.raw.edi as u64,
                6 => self.raw.ebp as u64,
                _ => 0,
            }
        }
        pub fn set_arg(&mut self, n: usize, v: u64) {
            match n {
                1 => self.raw.ebx = v as u32,
                2 => self.raw.ecx = v as u32,
                3 => self.raw.edx = v as u32,
                4 => self.raw.esi = v as u32,
                5 => self.raw.edi = v as u32,
                6 => self.raw.ebp = v as u32,
                _ => {}
            }
        }
        pub fn set_syscall(&mut self, nr: u64, args: [u64; 6]) {
            self.raw.eax = nr as u32;
            for (i, a) in args.iter().enumerate() {
                self.set_arg(i + 1, *a);
            }
        }
        pub fn set_ip(&mut self, ip: u64) {
            self.raw.eip = ip as u32;
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
    pub const SYS_MMAP: u64 = 222;
    /// Audit arch of native syscalls.
    pub const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    /// `(audit arch, execve nr, execveat nr)` of every foreign ABI a tracee
    /// of this architecture can use.
    pub const FOREIGN_EXEC: &[(u32, u64, u64)] = &[
        (0x4000_0028, 11, 387), // AUDIT_ARCH_ARM
    ];
    pub const X32_BIT: u64 = 0;
    pub const X32_EXECVE: u64 = u64::MAX;
    pub const X32_EXECVEAT: u64 = u64::MAX;

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

/// Classification of the exec-or-not nature of a syscall entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecClass {
    /// Not an exec system call.
    NotExec,
    /// `execve` / `execveat` of the native ABI.
    Native,
    /// `execve` / `execveat` of another ABI (32-bit or x32).
    Foreign,
}

/// Decide what the syscall `nr` of ABI `arch` is.  Native numbers are only
/// meaningful with the native audit arch: i386 syscall 59 is not `execve`.
pub fn classify_exec(arch: u32, nr: u64) -> ExecClass {
    if arch == NATIVE_AUDIT_ARCH {
        if nr == SYS_EXECVE || nr == SYS_EXECVEAT {
            return ExecClass::Native;
        }
        if X32_BIT != 0 && nr & X32_BIT != 0 {
            let low = nr & !X32_BIT;
            if low == X32_EXECVE || low == X32_EXECVEAT {
                return ExecClass::Foreign;
            }
        }
        return ExecClass::NotExec;
    }
    for &(a, execve, execveat) in FOREIGN_EXEC {
        if a == arch && (nr == execve || nr == execveat) {
            return ExecClass::Foreign;
        }
    }
    ExecClass::NotExec
}

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
        if iov.iov_len != std::mem::size_of::<RawRegs>() {
            // The kernel shrinks iov_len to the size of the tracee's own
            // register set: a 32-bit tracee returns a different layout.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "foreign register layout (32-bit tracee)",
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_exec_numbers_are_exec() {
        assert_eq!(classify_exec(NATIVE_AUDIT_ARCH, SYS_EXECVE), ExecClass::Native);
        assert_eq!(classify_exec(NATIVE_AUDIT_ARCH, SYS_EXECVEAT), ExecClass::Native);
        assert_eq!(classify_exec(NATIVE_AUDIT_ARCH, SYS_PRCTL), ExecClass::NotExec);
    }

    // Defect caught: comparing native numbers without the audit arch made
    // a 32-bit syscall with the same number look like execve.
    #[test]
    fn foreign_abi_numbers_are_not_native_exec() {
        for &(a, execve, execveat) in FOREIGN_EXEC {
            assert_eq!(classify_exec(a, execve), ExecClass::Foreign);
            assert_eq!(classify_exec(a, execveat), ExecClass::Foreign);
            if SYS_EXECVE != execve {
                assert_eq!(classify_exec(a, SYS_EXECVE), ExecClass::NotExec);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_exec_is_foreign() {
        assert_eq!(classify_exec(NATIVE_AUDIT_ARCH, X32_BIT | X32_EXECVE), ExecClass::Foreign);
        assert_eq!(classify_exec(NATIVE_AUDIT_ARCH, X32_BIT | SYS_EXECVE), ExecClass::NotExec);
    }
}
