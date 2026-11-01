//! Supervise a process tree from a library: start a multi-process build
//! under a label, keep working, then collect the exit state.
//!
//! ```sh
//! cargo run --example supervise -- /bin/sh -c 'echo level-1; sh -c "echo level-2"; exit 7'
//! ```

fn main() -> std::io::Result<()> {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        args.push("/bin/echo".into());
        args.push("(no command given)".into());
    }
    let program = args.remove(0);

    let child = confmask::Mask::new()
        .label("supervised-tree")
        .spawn(&program, &args)?;

    println!("tree started, direct child pid = {}", child.id());

    // ... the supervisor can do its own work here ...

    let st = child.wait()?;
    match st.signal {
        Some(sig) => println!("tree killed by signal {sig}"),
        None => println!("tree exited with code {}", st.code),
    }
    Ok(())
}
