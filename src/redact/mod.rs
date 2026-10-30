//! The `/proc` metadata redaction engine.
//!
//! This is the `argvmask` supervisor, carried over unchanged apart from
//! module paths: a `ptrace` tracer that owns the process tree and swaps
//! `argv`/`envp` at `execve` entry, so the kernel never copies the real
//! command line into the new image.  It is one provider among several in
//! `confmask`; nothing else in the crate depends on it, and a host that
//! bans `ptrace` simply does not use it.

/// Event logging used by the engine's modules.
#[macro_export]
macro_rules! vlog {
    ($tr:expr, $($arg:tt)*) => {
        $tr.vlog(format_args!($($arg)*))
    };
}

pub mod arch;
pub mod execimg;
pub mod inject;
pub mod mask;
pub mod remote;
pub mod selfmask;
pub mod tracer;

pub use arch::arch_name;
pub use mask::{Mask, MaskedChild};
pub use selfmask::mask_self;
pub use tracer::ExitState;
