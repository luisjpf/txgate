//! # sello-crypto
//!
//! Cryptographic operations for the Sello signing service.
//!
//! This crate provides all cryptographic functionality:
//!
//! ## Modules (planned)
//!
//! - `keys` - Key generation, storage, and management
//! - `signing` - Transaction signing implementations
//! - `verify` - Signature verification
//! - `kms` - Key Management Service integrations (AWS KMS, `HashiCorp` Vault, etc.)
//! - `algorithms` - Supported cryptographic algorithms (ECDSA, `EdDSA`, etc.)
//!
//! ## Supported Algorithms (planned)
//!
//! - ECDSA (secp256k1) - Bitcoin, Ethereum, EVM chains
//! - `EdDSA` (Ed25519) - Solana, NEAR, etc.
//! - SR25519 - Substrate-based chains
//!
//! ## Security
//!
//! This crate follows best practices for cryptographic implementations:
//! - No unsafe code allowed
//! - Constant-time operations where applicable
//! - Secure memory handling for key material

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

// Placeholder for future modules
// pub mod keys;
// pub mod signing;
// pub mod verify;
// pub mod kms;
// pub mod algorithms;
