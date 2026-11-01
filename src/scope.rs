//! Build the `systemd-run` prefix that starts a command in a transient scope.
//!
//! `wrap_command` returns an argument vector prefix. The caller appends the
//! original command. The prefix starts a user scope named
//! `confmask-<label>-<pid>`.
//!
//! The prefix needs two things: `systemd-run` in a `PATH` directory, and a
//! reachable user manager. This module treats the manager as reachable when
//! `XDG_RUNTIME_DIR` is set and `$XDG_RUNTIME_DIR/systemd` exists. A root
//! process without a user manager gets `None`. This module does not start a
//! system-level scope.
//!
//! Limits:
//! - The unit name is world readable in `/proc/<pid>/cgroup`, unless the
//!   system hides other users' processes. Treat the name as public.
//! - The module checks that the manager directory exists. It does not
//!   check that the manager answers. `systemd-run` can still fail at run
//!   time.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Longest label part of the unit name, in bytes.
const LABEL_MAX: usize = 64;

/// Turn a label into the unit name part.
///
/// Keep `A-Za-z0-9_.-`. Replace every other byte with `-`. Clip to 64
/// bytes. Return `x` for an empty label.
pub fn sanitize_label(label: &str) -> String {
    let mut out = String::new();
    for &b in label.as_bytes() {
        if out.len() >= LABEL_MAX {
            break;
        }
        let keep = b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-';
        out.push(if keep { b as char } else { '-' });
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

fn find_executable(name: &str, path_dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in path_dirs {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        let meta = match std::fs::metadata(&candidate) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
            return Some(candidate);
        }
    }
    None
}

/// Build the prefix from explicit inputs.
///
/// Return `None` when `systemd-run` is not in `path_dirs`, when
/// `xdg_runtime_dir` is `None` or empty, or when
/// `<xdg_runtime_dir>/systemd` is not a directory.
pub fn wrap_command_in(
    label: &str,
    path_dirs: &[PathBuf],
    xdg_runtime_dir: Option<&Path>,
) -> Option<Vec<OsString>> {
    let xdg = xdg_runtime_dir?;
    if xdg.as_os_str().is_empty() {
        return None;
    }
    if !xdg.join("systemd").is_dir() {
        return None;
    }
    find_executable("systemd-run", path_dirs)?;

    let unit = format!("confmask-{}-{}", sanitize_label(label), std::process::id());
    let mut argv: Vec<OsString> = Vec::new();
    argv.push(OsString::from("systemd-run"));
    argv.push(OsString::from("--user"));
    argv.push(OsString::from("--scope"));
    argv.push(OsString::from("--quiet"));
    argv.push(OsString::from("--collect"));
    argv.push(OsString::from(format!("--unit={}", unit)));
    argv.push(OsString::from("--description=confmask"));
    argv.push(OsString::from("--"));
    Some(argv)
}

/// Build the prefix from the process environment (`PATH`,
/// `XDG_RUNTIME_DIR`).
pub fn wrap_command(label: &str) -> Option<Vec<OsString>> {
    let path = std::env::var_os("PATH")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    wrap_command_in(label, &dirs, xdg.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct Fixture {
        root: PathBuf,
        bin: PathBuf,
        xdg: PathBuf,
    }

    impl Fixture {
        fn new(with_binary: bool, with_manager: bool) -> Fixture {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir()
                .join(format!("confmask-scope-{}-{}", std::process::id(), n));
            let bin = root.join("bin");
            let xdg = root.join("run");
            std::fs::create_dir_all(&bin).expect("mkdir bin");
            std::fs::create_dir_all(&xdg).expect("mkdir run");
            if with_binary {
                let exe = bin.join("systemd-run");
                std::fs::write(&exe, b"#!/bin/sh\nexit 0\n").expect("write fake");
                let mut perms = std::fs::metadata(&exe).expect("meta").permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&exe, perms).expect("chmod");
            }
            if with_manager {
                std::fs::create_dir_all(xdg.join("systemd")).expect("mkdir manager");
            }
            Fixture { root, bin, xdg }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn strings(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn builds_prefix_when_binary_and_manager_exist() {
        let f = Fixture::new(true, true);
        let argv = wrap_command_in("web", std::slice::from_ref(&f.bin), Some(&f.xdg)).expect("prefix");
        let s = strings(&argv);
        let unit = format!("--unit=confmask-web-{}", std::process::id());
        assert_eq!(
            s,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                unit.as_str(),
                "--description=confmask",
                "--"
            ]
        );
    }

    // Mutation control: dropping the PATH search makes this fail.
    #[test]
    fn none_without_binary_on_path() {
        let f = Fixture::new(false, true);
        assert!(wrap_command_in("web", std::slice::from_ref(&f.bin), Some(&f.xdg)).is_none());
        assert!(wrap_command_in("web", &[], Some(&f.xdg)).is_none());
    }

    #[test]
    fn none_when_binary_is_not_executable() {
        let f = Fixture::new(true, true);
        let exe = f.bin.join("systemd-run");
        let mut perms = std::fs::metadata(&exe).expect("meta").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&exe, perms).expect("chmod");
        assert!(wrap_command_in("web", std::slice::from_ref(&f.bin), Some(&f.xdg)).is_none());
    }

    // Mutation control: dropping the manager directory check makes this fail.
    #[test]
    fn none_without_user_manager() {
        let f = Fixture::new(true, false);
        assert!(wrap_command_in("web", std::slice::from_ref(&f.bin), Some(&f.xdg)).is_none());
    }

    #[test]
    fn none_without_runtime_dir() {
        let f = Fixture::new(true, true);
        assert!(wrap_command_in("web", std::slice::from_ref(&f.bin), None).is_none());
        assert!(wrap_command_in("web", std::slice::from_ref(&f.bin), Some(Path::new(""))).is_none());
    }

    #[test]
    fn sanitize_replaces_spaces_slashes_and_controls() {
        assert_eq!(sanitize_label("my app/1"), "my-app-1");
        assert_eq!(sanitize_label("a\u{1}b\tc\u{7f}"), "a-b-c-");
        assert_eq!(sanitize_label("../x"), "..-x");
        assert_eq!(sanitize_label("ok_name-1.2"), "ok_name-1.2");
    }

    #[test]
    fn sanitize_never_returns_empty_and_clips() {
        assert_eq!(sanitize_label(""), "x");
        assert_eq!(sanitize_label(&"a".repeat(500)).len(), 64);
    }

    #[test]
    fn unit_name_carries_the_sanitized_label() {
        let f = Fixture::new(true, true);
        let argv = wrap_command_in("a b/c", std::slice::from_ref(&f.bin), Some(&f.xdg)).expect("prefix");
        let unit = argv[5].to_string_lossy().into_owned();
        assert_eq!(unit, format!("--unit=confmask-a-b-c-{}", std::process::id()));
    }
}
