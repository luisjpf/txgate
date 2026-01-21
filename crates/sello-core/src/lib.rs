//! # sello-core
//!
//! Core types, traits, and error definitions for the Sello signing service.
//!
//! This crate provides the foundational types shared across all Sello crates:
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
//! use sello_core::error::{SelloError, ParseError, RpcErrorCode};
//!
//! fn example() -> Result<(), SelloError> {
//!     // Parse errors automatically convert to SelloError
//!     let err = ParseError::unsupported_chain("cosmos");
//!
//!     // Get the RPC error code for JSON-RPC responses
//!     let sello_err: SelloError = err.into();
//!     let code = RpcErrorCode::from(&sello_err);
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
//! use sello_core::{ParsedTx, TxType, PolicyResult, U256};
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
pub mod types;

// Re-export commonly used error types at crate root for convenience
pub use error::{
    ConfigError, ParseError, PolicyError, Result, RpcErrorCode, SelloError, SignError, StoreError,
};

// Re-export config types at crate root for convenience
pub use config::{Config, ConfigBuilder, KeysConfig, PolicyConfig, ServerConfig};

// Re-export config loader types at crate root for convenience
pub use config_loader::{expand_path, load_config, ConfigLoader};

// Re-export core types at crate root for convenience
pub use types::{ParsedTx, PolicyResult, TxType};

// Re-export U256 from alloy_primitives for working with amounts
pub use alloy_primitives::U256;

// Placeholder for future modules
// pub mod traits;
// pub mod chain;
