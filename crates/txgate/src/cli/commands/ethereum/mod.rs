//! # Ethereum Commands
//!
//! Commands for Ethereum-related operations.
//!
//! ## Available Commands
//!
//! - [`AddressCommand`] - Display the Ethereum address derived from the default key
//! - [`SignCommand`] - Sign Ethereum transactions
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::ethereum::AddressCommand;
//!
//! let cmd = AddressCommand;
//! cmd.run().expect("address display failed");
//! ```
//!
//! ```no_run
//! use txgate::cli::commands::ethereum::SignCommand;
//! use txgate::cli::args::OutputFormat;
//!
//! let cmd = SignCommand::new("0xf86c...", OutputFormat::Hex);
//! cmd.run().expect("signing failed");
//! ```

pub mod address;
pub mod sign;

// Re-export command types for convenience
pub use address::{AddressCommand, AddressError};
pub use sign::{SignCommand, SignCommandError, SignOutput};
