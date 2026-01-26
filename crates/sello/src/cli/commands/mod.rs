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
//! - [`bitcoin`] - Bitcoin-specific commands (address, sign)
//! - [`solana`] - Solana-specific commands (address, sign)
//! - [`key`] - Key management commands (list, import, export, delete)
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

pub mod bitcoin;
pub mod config;
pub mod ethereum;
pub mod init;
pub mod key;
pub mod serve;
pub mod solana;
pub mod status;

// Re-export command types for convenience
pub use bitcoin::{
    AddressCommand as BitcoinAddressCommand, AddressError as BitcoinAddressError,
    SignCommand as BitcoinSignCommand, SignCommandError as BitcoinSignCommandError,
    SignOutput as BitcoinSignOutput,
};
pub use config::{ConfigCommand, ConfigCommandError};
pub use ethereum::{AddressCommand, AddressError, SignCommand, SignCommandError, SignOutput};
pub use init::{InitCommand, InitError};
pub use key::{
    DeleteCommand, DeleteError, ExportCommand, ExportError, ImportCommand, ImportError,
    ListCommand, ListError,
};
pub use serve::{ServeCommand, ServeError};
pub use solana::{
    AddressCommand as SolanaAddressCommand, AddressError as SolanaAddressError,
    SignCommand as SolanaSignCommand, SignCommandError as SolanaSignCommandError,
    SignOutput as SolanaSignOutput,
};
pub use status::{StatusCommand, StatusError};
