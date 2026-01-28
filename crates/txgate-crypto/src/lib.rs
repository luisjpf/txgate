//! # txgate-crypto
//!
//! Cryptographic operations for the `TxGate` signing service.
//!
//! ## Internal Crate Warning
//!
//! **This crate is an internal implementation detail of [`txgate`](https://crates.io/crates/txgate).**
//!
//! It is published to crates.io only because Cargo requires all dependencies to be
//! published. The API is **unstable** and may change without notice between any versions,
//! including patch releases.
//!
//! **Do not depend on this crate directly.** Instead:
//! - For the signing server binary: `cargo install txgate`
//! - For programmatic access: Open an issue at <https://github.com/txgate-project/txgate>
//!   to discuss a stable public API.
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

pub mod encryption;
pub mod keypair;
pub mod keys;
pub mod signer;
pub mod store;

// Placeholder for future modules
// pub mod verify;
// pub mod kms;
// pub mod algorithms;

// Re-export commonly used types
pub use encryption::{
    decrypt_key, encrypt_key, EncryptedKey, ENCRYPTED_KEY_LEN, ENCRYPTION_VERSION, NONCE_LEN,
    PLAINTEXT_LEN, SALT_LEN, TAG_LEN,
};
pub use keys::{SecretKey, SecretKeyError, SECRET_KEY_LEN};

// Re-export key pair types
pub use keypair::{
    Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, KeyPair, Secp256k1KeyPair,
    Secp256k1PublicKey, Secp256k1Signature,
};

// Re-export signer types
pub use signer::{Chain, CurveType, Ed25519Signer, Secp256k1Signer, Signer};

// Re-export key store types
pub use store::{FileKeyStore, KeyStore};
