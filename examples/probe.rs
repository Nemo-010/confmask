//! Report what this host allows before deciding how to deploy.
//!
//!     cargo run --example probe

use confmask::Caps;

fn main() {
    let caps = Caps::detect();
    print!("{}", caps.report());
    println!();
    for (tier, ok) in caps.tiers() {
        println!("  {:?}: {}", tier, if ok { "available" } else { "unavailable" });
    }
}
