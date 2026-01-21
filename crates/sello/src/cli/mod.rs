//! # CLI Module
//!
//! Command-line interface for Sello.
//!
//! ## Module Structure
//!
//! - [`args`] - Argument parsing and CLI structure definitions
//! - [`commands`] - Command handler implementations
//!
//! ## Usage
//!
//! ```no_run
//! use clap::Parser;
//! use sello::cli::{Cli, Commands};
//!
//! let cli = Cli::parse();
//!
//! match cli.command {
//!     Commands::Init { force } => {
//!         // Handle init command
//!     }
//!     Commands::Status => {
//!         // Handle status command
//!     }
//!     // ... other commands
//!     _ => {}
//! }
//! ```
//!
//! ## Commands
//!
//! - `sello init [--force]` - Initialize Sello configuration
//! - `sello status` - Display current status
//! - `sello config [edit|path]` - View or edit configuration
//! - `sello serve [--foreground]` - Start the signing server
//! - `sello ethereum address` - Display Ethereum address
//! - `sello ethereum sign <TX_HEX> [--format hex|json]` - Sign a transaction

pub mod args;
pub mod commands;

// Re-export main types for convenience
pub use args::{Cli, Commands, ConfigAction, EthereumCommands, OutputFormat};
