//! # Solana CLI Commands
//!
//! Implementation of the `txgate solana` CLI commands for address
//! derivation and transaction signing on the Solana network.
//!
//! ## Available Commands
//!
//! - [`AddressCommand`] - Display Solana address (base58-encoded public key)
//! - [`SignCommand`] - Sign Solana transactions
//!
//! ## Key Storage
//!
//! Solana uses ed25519 keys, which are stored separately from secp256k1 keys:
//! - Ed25519 keys: `~/.txgate/keys/default-ed25519.enc`
//! - Secp256k1 keys: `~/.txgate/keys/default.enc`
//!
//! ## Usage
//!
//! ```bash
//! # Display Solana address
//! txgate solana address
//!
//! # Sign a Solana transaction
//! txgate solana sign <TX_HEX>
//! ```

pub mod address;
pub mod sign;

pub use address::{AddressCommand, AddressError};
pub use sign::{SignCommand, SignCommandError, SignOutput};
