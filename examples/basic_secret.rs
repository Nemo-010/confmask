//! Run a command with a secret delivered over a descriptor.
//!
//!     cargo run --example basic_secret -- ./deploy.sh

use confmask::{Runner, Source};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: basic_secret CMD [ARGS...]");
        std::process::exit(2);
    }

    let outcome = Runner::new()
        .label("ci-runner")
        .secret("DEPLOY_TOKEN", Source::File("token".into()))
        .run(&args[0], &args[1..])?;

    eprintln!(
        "mode={:?} secrets={} exit={}",
        outcome.mode, outcome.secrets_delivered, outcome.exit.code
    );
    std::process::exit(outcome.exit.code);
}
