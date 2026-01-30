//! Policy configuration types for the `TxGate` signing service.
//!
//! This module re-exports [`PolicyConfig`] from [`txgate_core::config`] to provide
//! a convenient access point for policy-related configuration within the `txgate-policy` crate.
//!
//! # Examples
//!
//! ```
//! use txgate_policy::config::PolicyConfig;
//! use alloy_primitives::U256;
//!
//! // Create a basic policy config with builder pattern
//! let config = PolicyConfig::new()
//!     .with_whitelist(vec!["0x742d35Cc6634C0532925a3b844Bc454e7595f".to_string()])
//!     .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64)); // 5 ETH
//!
//! assert!(config.is_whitelisted("0x742d35Cc6634C0532925a3b844Bc454e7595f"));
//! ```

// Re-export PolicyConfig from txgate-core to avoid code duplication.
// The canonical definition lives in txgate_core::config::PolicyConfig.
pub use txgate_core::config::PolicyConfig;
