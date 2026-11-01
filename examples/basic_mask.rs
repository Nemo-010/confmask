//! Run a command under a label and report its exit code.
//!
//! ```sh
//! cargo run --example basic_mask -- /bin/echo hello
//! cargo run --example basic_mask -- --label worker /bin/echo hello
//! ```

fn main() -> std::io::Result<()> {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

    // optional leading `--label LABEL`
    let mut label: Option<String> = std::env::var("CONFMASK_LABEL").ok();
    if args.first().is_some_and(|a| a == "--label") {
        args.remove(0);
        if args.is_empty() {
            eprintln!("basic_mask: --label needs a value");
            std::process::exit(2);
        }
        label = Some(args.remove(0).to_string_lossy().into_owned());
    }

    if args.is_empty() {
        eprintln!("usage: basic_mask [--label LABEL] PROGRAM [ARGS...]");
        eprintln!("  CONFMASK_LABEL sets the label when --label is absent");
        std::process::exit(2);
    }
    let program = args.remove(0);

    let mut mask = confmask::Mask::new();
    if let Some(label) = label {
        mask = mask.label(label);
    }

    let st = mask.run(&program, &args)?;
    if let Some(sig) = st.signal {
        eprintln!("terminated by signal {sig}");
    }
    std::process::exit(st.code)
}
