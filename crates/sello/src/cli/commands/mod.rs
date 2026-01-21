//! # CLI Command Handlers
//!
//! This module contains the implementation of CLI command handlers.
//!
//! ## Module Structure
//!
//! - [`init`] - Initialize Sello configuration
//! - [`status`] - Display current status
//! - [`config`] - Configuration management
//! - [`ethereum`] - Ethereum-specific commands (address, sign)
//! - [`serve`] - Start the signing server
//!
//! ## Implementation Notes
//!
//! Each command handler is responsible for:
//! 1. Validating command-specific arguments
//! 2. Loading configuration as needed
//! 3. Executing the command logic
//! 4. Formatting and outputting results
//! 5. Handling errors gracefully
//!
//! ## Error Handling
//!
//! Command handlers return `Result<(), CommandError>` where `CommandError`
//! is an enum that covers all possible failure modes. The main function
//! is responsible for converting these errors into appropriate exit codes
//! and user-friendly error messages.

pub mod config;
pub mod ethereum;
pub mod init;
pub mod serve;
pub mod status;

// Re-export command types for convenience
pub use config::{ConfigCommand, ConfigCommandError};
pub use ethereum::{AddressCommand, AddressError, SignCommand, SignCommandError, SignOutput};
pub use init::{InitCommand, InitError};
pub use serve::{ServeCommand, ServeError};
pub use status::{StatusCommand, StatusError};
