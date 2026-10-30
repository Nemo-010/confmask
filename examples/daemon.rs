//! Hold a store unlocked and serve it to other processes of this account.
//!
//!     cargo run --example daemon -- /tmp/store.enc /tmp/confmask.sock

use confmask::{Passphrase, Store};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let store_path = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("usage: daemon STORE SOCKET");
        std::process::exit(2);
    }));
    let socket = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("usage: daemon STORE SOCKET");
        std::process::exit(2);
    }));

    // A real deployment reads this from a 0600 file or the terminal; see
    // `confmask daemon` for the CLI's resolution order.
    let pass = std::env::var("CONFMASK_PASSPHRASE").unwrap_or_else(|_| {
        eprintln!("set CONFMASK_PASSPHRASE (example only)");
        std::process::exit(2);
    });
    let pp = Passphrase::new(pass.as_bytes())?;
    let store = Store::open(&store_path, &pp)?;
    println!("serving {} secret(s) on {}", store.names().len(), socket.display());

    confmask::daemon::Daemon::new(store, socket, Vec::new()).serve()
}
