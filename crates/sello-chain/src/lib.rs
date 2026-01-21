//! # sello-chain
//!
//! Multi-chain transaction parsing and construction for the Sello signing service.
//!
//! This crate provides blockchain-specific transaction handling:
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

// Placeholder for future modules
// pub mod evm;
// pub mod solana;
// pub mod bitcoin;
// pub mod substrate;
// pub mod cosmos;
