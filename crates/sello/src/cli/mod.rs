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
//! - `sello bitcoin address` - Display Bitcoin address (P2WPKH bech32)
//! - `sello bitcoin sign <TX_HEX> [--format hex|json]` - Sign a Bitcoin transaction
//! - `sello solana address` - Display Solana address (base58 ed25519 pubkey)
//! - `sello solana sign <TX_HEX> [--format hex|json]` - Sign a Solana transaction
//! - `sello key list [--verbose]` - List all stored keys
//! - `sello key import <HEX> [--name NAME]` - Import a private key
//! - `sello key export <NAME> [--output PATH] [--force]` - Export a key
//! - `sello key delete <NAME> [--force]` - Delete a key

pub mod args;
pub mod commands;

// Re-export main types for convenience
pub use args::{
    BitcoinCommands, Cli, Commands, ConfigAction, CurveArg, EthereumCommands, KeyCommands,
    KeyDeleteArgs, KeyExportArgs, KeyImportArgs, KeyListArgs, OutputFormat, SolanaCommands,
};
