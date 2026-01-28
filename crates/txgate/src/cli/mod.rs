//! # CLI Module
//!
//! Command-line interface for `TxGate`.
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
//! use txgate::cli::{Cli, Commands};
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
//! - `txgate init [--force]` - Initialize `TxGate` configuration
//! - `txgate status` - Display current status
//! - `txgate config [edit|path]` - View or edit configuration
//! - `txgate serve [--foreground]` - Start the signing server
//! - `txgate ethereum address` - Display Ethereum address
//! - `txgate ethereum sign <TX_HEX> [--format hex|json]` - Sign a transaction
//! - `txgate bitcoin address` - Display Bitcoin address (P2WPKH bech32)
//! - `txgate bitcoin sign <TX_HEX> [--format hex|json]` - Sign a Bitcoin transaction
//! - `txgate solana address` - Display Solana address (base58 ed25519 pubkey)
//! - `txgate solana sign <TX_HEX> [--format hex|json]` - Sign a Solana transaction
//! - `txgate key list [--verbose]` - List all stored keys
//! - `txgate key import <HEX> [--name NAME]` - Import a private key
//! - `txgate key export <NAME> [--output PATH] [--force]` - Export a key
//! - `txgate key delete <NAME> [--force]` - Delete a key

pub mod args;
pub mod commands;

// Re-export main types for convenience
pub use args::{
    BitcoinCommands, Cli, Commands, ConfigAction, CurveArg, EthereumCommands, KeyCommands,
    KeyDeleteArgs, KeyExportArgs, KeyImportArgs, KeyListArgs, OutputFormat, SolanaCommands,
};
