//! Demonstrate that redacted processes still see their real environment.
//!
//! The child prints an environment value that is invisible in
//! /proc/<pid>/environ while it runs (check with:
//! `tr '\0' '\n' < /proc/<pid>/environ` while the example sleeps).
//!
//! ```sh
//! cargo run --example env_redaction
//! ```

use std::io::Write;

fn main() -> std::io::Result<()> {
    let script = r#"
echo "child sees SECRET=$SECRET"
sleep 0.4
"#;

    let mask = confmask::Mask::new()
        .label("example-worker")
        .envs([("SECRET", "hushhush"), ("PATH", "/usr/bin:/bin")]);

    let child = mask.spawn("/bin/sh", &["-c", script])?;

    // While the child sleeps, its /proc environ carries no trace of the
    // secret.  Observe it yourself:
    //   tr '\0' '\n' < /proc/$(pgrep -f example-worker)/environ
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut out = std::io::stdout().lock();
    writeln!(out, "supervisor: child pid {}", child.id())?;
    writeln!(out, "supervisor: scan /proc/{}/environ for 'hushhush'", child.id())?;

    let st = child.wait()?;
    writeln!(out, "supervisor: child exit code {}", st.code)?;
    Ok(())
}
