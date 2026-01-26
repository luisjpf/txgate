//! # Bitcoin Commands
//!
//! Commands for Bitcoin-related operations.
//!
//! ## Available Commands
//!
//! - [`AddressCommand`] - Display the Bitcoin address (P2WPKH/bech32) derived from the default key
//! - [`SignCommand`] - Sign Bitcoin transactions
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::bitcoin::AddressCommand;
//!
//! let cmd = AddressCommand;
//! cmd.run().expect("address display failed");
//! ```
//!
//! ```no_run
//! use sello::cli::commands::bitcoin::SignCommand;
//! use sello::cli::args::OutputFormat;
//!
//! let cmd = SignCommand::new("0x0100000001...", OutputFormat::Hex);
//! cmd.run().expect("signing failed");
//! ```

pub mod address;
pub mod sign;

// Re-export command types for convenience
pub use address::{AddressCommand, AddressError};
pub use sign::{SignCommand, SignCommandError, SignOutput};
