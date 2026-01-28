//! # txgate-chain
//!
//! Multi-chain transaction parsing and construction for the `TxGate` signing service.
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
//! This crate provides blockchain-specific transaction handling through the
//! [`Chain`] trait and chain-specific parser implementations.
//!
//! ## Core Trait
//!
//! The [`Chain`] trait is the foundation for all blockchain parsers:
//!
//! ```rust
//! use txgate_chain::Chain;
//! use txgate_core::{ParsedTx, TxType, error::ParseError};
//! use txgate_crypto::CurveType;
//!
//! struct MyChainParser;
//!
//! impl Chain for MyChainParser {
//!     fn id(&self) -> &'static str {
//!         "my-chain"
//!     }
//!
//!     fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
//!         // Parse chain-specific transaction format
//!         Ok(ParsedTx {
//!             chain: "my-chain".to_string(),
//!             tx_type: TxType::Transfer,
//!             ..Default::default()
//!         })
//!     }
//!
//!     fn curve(&self) -> CurveType {
//!         CurveType::Secp256k1
//!     }
//! }
//! ```
//!
//! ## Modules (planned)
//!
//! - `evm` - Ethereum and EVM-compatible chains (Polygon, Arbitrum, etc.)
//! - `solana` - Solana transaction parsing
//! - `bitcoin` - Bitcoin transaction handling
//! - `substrate` - Substrate-based chains (Polkadot, etc.)
//! - `cosmos` - Cosmos SDK chains
//!
//! ## Features
//!
//! - Transaction parsing and validation
//! - Human-readable transaction decoding
//! - ABI/IDL decoding for smart contract interactions
//! - Gas estimation helpers
//! - Chain-specific address validation
//!
//! ## Supported Chains (planned)
//!
//! - Ethereum Mainnet and testnets
//! - Polygon, Arbitrum, Optimism, Base
//! - Solana Mainnet and Devnet
//! - Bitcoin Mainnet and Testnet
//!
//! ## Crate Features
//!
//! - `mock` - Enable `MockChain` for use in other crates' tests
//!
//! ## Chain Registry
//!
//! The [`ChainRegistry`] provides runtime lookup of chain parsers:
//!
//! ```rust
//! use txgate_chain::ChainRegistry;
//!
//! let registry = ChainRegistry::new();
//!
//! // List all supported chains
//! for chain_id in registry.supported_chains() {
//!     println!("Supported: {chain_id}");
//! }
//!
//! // Look up a specific chain
//! if let Some(parser) = registry.get("ethereum") {
//!     println!("Found parser for: {}", parser.id());
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod bitcoin;
pub mod chain;
pub mod erc20;
pub mod ethereum;
pub mod registry;
pub mod rlp;
pub mod solana;
pub mod tokens;

// Additional comprehensive tests for 100% coverage
#[cfg(test)]
mod additional_tests;

// Re-export the Chain trait at crate root for convenience
pub use chain::Chain;

// Re-export chain parsers at crate root for convenience
pub use bitcoin::BitcoinParser;
pub use ethereum::EthereumParser;
pub use solana::SolanaParser;

// Re-export ChainRegistry at crate root for convenience
pub use registry::ChainRegistry;

// Re-export token registry types for convenience
pub use tokens::{RiskLevel, TokenInfo, TokenRegistry};

// Re-export ERC-20 parsing types for convenience
pub use erc20::{parse_erc20_call, Erc20Call};

// Re-export MockChain and MockParseError when the mock feature is enabled or in tests
#[cfg(any(test, feature = "mock"))]
pub use chain::{MockChain, MockParseError};

// Re-export CurveType from txgate-crypto for convenience
pub use txgate_crypto::CurveType;

// Placeholder for future modules
// pub mod evm;
// pub mod solana;
// pub mod bitcoin;
// pub mod substrate;
// pub mod cosmos;
