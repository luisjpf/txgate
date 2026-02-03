//! # txgate-core
//!
//! Core types, traits, and error definitions for the `TxGate` signing service.
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
//! - For programmatic access: Open an issue at <https://github.com/luisjpf/txgate>
//!   to discuss a stable public API.
//!
//! This crate provides the foundational types shared across all `TxGate` crates:
//!
//! ## Modules
//!
//! - [`error`] - Error types and result aliases
//! - [`types`] - Core data types ([`ParsedTx`], [`TxType`], [`PolicyResult`])
//! - `traits` - Core trait definitions (planned)
//! - `chain` - Chain identifier types (planned)
//!
//! ## Error Handling
//!
//! The crate provides comprehensive error types for all failure modes:
//!
//! ```rust
//! use txgate_core::error::{TxGateError, ParseError, RpcErrorCode};
//!
//! fn example() -> Result<(), TxGateError> {
//!     // Parse errors automatically convert to TxGateError
//!     let err = ParseError::unsupported_chain("cosmos");
//!
//!     // Get the RPC error code for JSON-RPC responses
//!     let txgate_err: TxGateError = err.into();
//!     let code = RpcErrorCode::from(&txgate_err);
//!     assert_eq!(code, RpcErrorCode::ChainNotSupported);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Core Types
//!
//! The types module provides the foundational data structures:
//!
//! ```rust
//! use txgate_core::{ParsedTx, TxType, PolicyResult, U256};
//! use std::collections::HashMap;
//!
//! // Create a parsed transaction
//! let tx = ParsedTx {
//!     hash: [0u8; 32],
//!     recipient: Some("0x742d35Cc...".to_string()),
//!     amount: Some(U256::from(1_500_000_000_000_000_000u64)),
//!     token: Some("ETH".to_string()),
//!     token_address: None,
//!     tx_type: TxType::Transfer,
//!     chain: "ethereum".to_string(),
//!     nonce: Some(42),
//!     chain_id: Some(1),
//!     metadata: HashMap::new(),
//! };
//!
//! // Check transaction type
//! assert!(tx.is_native_transfer());
//!
//! // Evaluate policy result
//! let result = PolicyResult::Allowed;
//! assert!(result.is_allowed());
//! ```
//!
//! ## Features
//!
//! - `serde` - Enable serde serialization/deserialization
//! - `std` - Enable standard library features (enabled by default)
//!
//! [`ParsedTx`]: types::ParsedTx
//! [`TxType`]: types::TxType
//! [`PolicyResult`]: types::PolicyResult

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod config;
pub mod config_loader;
pub mod error;
pub mod signing;
pub mod types;

// Re-export commonly used error types at crate root for convenience
pub use error::{
    ConfigError, ParseError, PolicyError, Result, RpcErrorCode, SignError, StoreError, TxGateError,
};

// Re-export config types at crate root for convenience
pub use config::{Config, ConfigBuilder, KeysConfig, PolicyConfig, ServerConfig};

// Re-export config loader types at crate root for convenience
pub use config_loader::{expand_path, load_config, ConfigLoader};

// Re-export core types at crate root for convenience
pub use types::{ParsedTx, PolicyResult, TxType};

// Re-export signing types at crate root for convenience
pub use signing::{
    ChainParser, PolicyCheckResult, PolicyEngineExt, SignatureBytes, SignerExt, SigningError,
    SigningResult, SigningService,
};

// Re-export U256 from alloy_primitives for working with amounts
pub use alloy_primitives::U256;

// Placeholder for future modules
// pub mod traits;
// pub mod chain;
