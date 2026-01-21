//! # Sello
//!
//! Multi-chain transaction signing service with policy engine.
//!
//! ## Usage
//!
//! ```bash
//! # Start the signing server
//! sello server --config config.yaml
//!
//! # CLI commands
//! sello sign --chain ethereum --tx <transaction>
//! sello verify --chain ethereum --sig <signature>
//! sello policy validate --file policy.yaml
//! ```
//!
//! ## Modules
//!
//! - `cli` - Command-line interface
//! - `server` - HTTP/gRPC signing server

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

mod cli;
mod server;

/// Main entry point for the Sello application.
fn main() {
    println!("Sello - Multi-chain Transaction Signing Service");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("This is a placeholder. Run with --help for usage information.");
}
