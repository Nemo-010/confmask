//! `confmask` — confidential computing without the hardware.
//!
//! Confidential computing normally means a TEE: SGX enclaves, SEV
//! encrypted VMs, a hypervisor that swears it cannot look inside.  All of
//! that needs specific silicon, specific firmware, and usually root.
//!
//! This crate is the version you can actually deploy: it reduces what a
//! *shared Linux host* discloses about a workload, using only mechanisms
//! an ordinary account already has.
//!
//! # What it protects
//!
//! Four disclosure surfaces, each handled by its own mechanism:
//!
//! 1. **Command lines and environments.**  `/proc/<pid>/cmdline` is
//!    world-readable: every local account can watch `ps` and see the
//!    token on a deploy command's argument list.  Where `ptrace` is
//!    permitted, [`run::Runner`] redacts the cmdline, `environ` and
//!    `comm` of the whole process tree while the programs keep their real
//!    `argv`/`envp`.
//!
//! 2. **Secrets in arguments or the environment.**  This is the one that
//!    works everywhere, including sandboxes that ban `ptrace`.  A secret
//!    is read once into a locked, dump-excluded buffer and handed to the
//!    program as a **sealed file descriptor**; the program is told only
//!    the descriptor number.  Nothing sensitive ever enters `argv`,
//!    `environ`, `ps` output or a log line.
//!
//! 3. **Secrets at rest.**  [`store::Store`] is one encrypted file:
//!    XChaCha20-Poly1305 under an Argon2id key, with the header
//!    authenticated.  No plaintext `.env` for the next job to read.
//!
//! 4. **The host itself, seen from inside.**  Where unprivileged user
//!    namespaces are available, [`isolate::Isolate`] gives the payload
//!    its own PID, mount and network namespace: its `/proc` lists only
//!    itself, and its `/tmp` is private.
//!
//! # What it does not protect
//!
//! Read [`docs/THREAT-MODEL.md`] in the repository.  The short version:
//! root and the host kernel always win; nothing here defeats a hardware
//! or microarchitectural side channel; and two programs running as the
//! *same account* are not distinguishable unless you restrict the daemon
//! by executable.  `confmask` reduces disclosure.  It is not a sandbox
//! against a determined attacker who already has code execution as your
//! account.
//!
//! # Example
//!
//! ```no_run
//! use confmask::{Runner, Source};
//!
//! let outcome = Runner::new()
//!     .label("ci-runner")
//!     .secret("DEPLOY_TOKEN", Source::File("token".into()))
//!     .run("deploy.sh", &[])?;
//!
//! println!("{:?} exit={}", outcome.mode, outcome.exit.code);
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! In the child, the token is on descriptor 3 and the name is published
//! in `CONFMASK_SECRET_DEPLOY_TOKEN`:
//!
//! ```sh
//! token=$(confmask read DEPLOY_TOKEN)
//! ```

pub mod caps;
pub mod daemon;
pub mod isolate;
pub mod mem;
pub mod redact;
pub mod run;
pub mod secret;
pub mod store;

pub use caps::{Caps, Tier};
pub use isolate::Isolate;
pub use mem::{SecBuf, SealedFd};
pub use run::{Mode, Outcome, Runner};
pub use secret::{Secret, Source};
pub use store::{Passphrase, Store};

/// Crate version, as reported by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel `comm` limit (15 bytes + NUL).
pub const COMM_MAX: usize = 15;
