//! `confmask` CLI: a thin wrapper over the library.

mod cli;

fn main() {
    let code = cli::main();
    std::process::exit(code);
}
