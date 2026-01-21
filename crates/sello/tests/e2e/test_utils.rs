//! Test utilities for Sello integration tests.
//!
//! This module provides helper functions for creating test environments,
//! test transactions, and mock configurations.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes,
    clippy::redundant_clone,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::cast_possible_truncation,
    clippy::manual_strip,
    clippy::map_unwrap_or,
    dead_code
)]

use alloy_primitives::U256;
use sello_chain::{Chain, EthereumParser};
use sello_core::types::{ParsedTx, TxType};
use sello_policy::config::PolicyConfig;
use sello_policy::engine::DefaultPolicyEngine;
use sello_policy::history::TransactionHistory;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// One ETH in wei (10^18).
pub const ONE_ETH: u64 = 1_000_000_000_000_000_000;

/// Half ETH in wei.
pub const HALF_ETH: u64 = 500_000_000_000_000_000;

/// Well-known test addresses.
pub mod addresses {
    /// A generic test recipient address.
    pub const TEST_RECIPIENT: &str = "0x3535353535353535353535353535353535353535";

    /// A known "safe" address for whitelist testing.
    pub const WHITELISTED_ADDR: &str = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// A known "blacklisted" address for testing.
    pub const BLACKLISTED_ADDR: &str = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// USDC contract address on mainnet.
    pub const USDC_CONTRACT: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

    /// vitalik.eth address.
    pub const VITALIK_ETH: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
}

/// Create a temporary Sello installation for testing.
///
/// This sets up the complete directory structure that Sello expects:
/// - `~/.sello/keys/` - Encrypted key storage
/// - `~/.sello/history.db` - Transaction history
/// - `~/.sello/config.toml` - Configuration file
///
/// # Returns
///
/// A `TempDir` that will be automatically cleaned up when dropped.
pub fn setup_test_env() -> TempDir {
    let temp_dir = tempfile::tempdir().expect("failed to create temp directory");

    // Create directory structure
    let sello_dir = temp_dir.path().join(".sello");
    let keys_dir = sello_dir.join("keys");

    fs::create_dir_all(&keys_dir).expect("failed to create keys directory");

    // Create a minimal config.toml
    let config_content = r#"
# Sello test configuration
[policy]
whitelist_enabled = false

[policy.blacklist]
addresses = []

[policy.whitelist]
addresses = []

[policy.limits]
# No limits by default in test config
"#;

    fs::write(sello_dir.join("config.toml"), config_content).expect("failed to write config.toml");

    temp_dir
}

/// Create a test environment with a specific policy configuration.
///
/// # Arguments
///
/// * `config` - The policy configuration to use
///
/// # Returns
///
/// A tuple containing the `TempDir` and a `DefaultPolicyEngine` instance.
pub fn setup_test_env_with_policy(config: PolicyConfig) -> (TempDir, Arc<DefaultPolicyEngine>) {
    let temp_dir = setup_test_env();

    let history = Arc::new(TransactionHistory::in_memory().expect("failed to create history"));
    let engine = Arc::new(
        DefaultPolicyEngine::new(config, history).expect("failed to create policy engine"),
    );

    (temp_dir, engine)
}

/// Create a test Ethereum transfer transaction.
///
/// Creates an ETH transfer transaction that can be used for testing.
/// This simulates a simple native ETH transfer.
///
/// # Arguments
///
/// * `to` - The recipient address (hex string with or without 0x prefix)
/// * `value` - The value in wei
/// * `nonce` - The transaction nonce
///
/// # Returns
///
/// Raw transaction bytes (RLP-encoded EIP-1559 transaction).
pub fn create_test_transaction(to: &str, value: U256, nonce: u64) -> Vec<u8> {
    let to_normalized = if to.starts_with("0x") {
        to.to_lowercase()
    } else {
        format!("0x{}", to.to_lowercase())
    };

    // Parse the recipient address
    let to_bytes = hex::decode(to_normalized.strip_prefix("0x").unwrap_or(&to_normalized))
        .expect("invalid hex address");

    // Build the value as big-endian bytes (trimmed of leading zeros)
    let value_bytes = encode_u256(value);
    let nonce_bytes = encode_u64(nonce);

    // Build the RLP-encoded transaction
    let chain_id_bytes = vec![0x01]; // mainnet
    let max_priority_fee = encode_u64(2_000_000_000); // 2 gwei
    let max_fee = encode_u64(2_000_000_000); // 2 gwei
    let gas_limit = encode_u64(21000);
    let data: Vec<u8> = vec![];
    let access_list: Vec<u8> = vec![0xc0]; // empty RLP list

    // Signature components (dummy for testing - transaction will still parse)
    let y_parity: Vec<u8> = vec![0x80]; // 0
    let r: Vec<u8> = vec![
        0xa0, // 32-byte string prefix
        0xab, 0xcd, 0x12, 0x34, 0xef, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
        0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef,
    ];
    let s: Vec<u8> = vec![
        0xa0, // 32-byte string prefix
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
        0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef,
    ];

    // Encode the to address (20 bytes)
    let to_encoded = if to_bytes.len() == 20 {
        let mut enc = vec![0x94]; // 20-byte string prefix
        enc.extend_from_slice(&to_bytes);
        enc
    } else {
        panic!("invalid address length");
    };

    // Build the RLP list items
    let items: Vec<Vec<u8>> = vec![
        encode_rlp_item(&chain_id_bytes),
        encode_rlp_item(&nonce_bytes),
        encode_rlp_item(&max_priority_fee),
        encode_rlp_item(&max_fee),
        encode_rlp_item(&gas_limit),
        to_encoded,
        encode_rlp_item(&value_bytes),
        encode_rlp_item(&data),
        access_list.clone(),
        y_parity,
        r,
        s,
    ];

    // Calculate total payload length
    let payload_len: usize = items.iter().map(|item| item.len()).sum();

    // Build the full RLP list
    let mut tx = vec![0x02]; // EIP-1559 type prefix

    // Add list prefix
    if payload_len < 56 {
        tx.push((0xc0 + payload_len) as u8);
    } else {
        let len_bytes = encode_length(payload_len);
        tx.push((0xf7 + len_bytes.len()) as u8);
        tx.extend(len_bytes);
    }

    // Add all items
    for item in items {
        tx.extend(item);
    }

    tx
}

/// Create a test ERC-20 transfer transaction.
///
/// Creates an ERC-20 token transfer transaction.
///
/// # Arguments
///
/// * `token` - The token contract address
/// * `to` - The recipient address for the token transfer
/// * `amount` - The token amount (in smallest units)
/// * `nonce` - The transaction nonce
///
/// # Returns
///
/// Raw transaction bytes (RLP-encoded EIP-1559 transaction with ERC-20 calldata).
pub fn create_erc20_transfer(token: &str, to: &str, amount: U256, nonce: u64) -> Vec<u8> {
    // ERC-20 transfer(address,uint256) function selector: 0xa9059cbb
    let selector = [0xa9, 0x05, 0x9c, 0xbb];

    // Parse the recipient address for the token transfer
    let to_normalized = if to.starts_with("0x") {
        to[2..].to_string()
    } else {
        to.to_string()
    };
    let to_bytes = hex::decode(&to_normalized).expect("invalid hex address");

    // Build the calldata: selector + padded address (32 bytes) + padded amount (32 bytes)
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&selector);

    // Pad address to 32 bytes
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&to_bytes);

    // Pad amount to 32 bytes
    let amount_bytes = amount.to_be_bytes::<32>();
    data.extend_from_slice(&amount_bytes);

    // Now create the transaction with the token contract as recipient
    // and zero ETH value (we're transferring tokens, not ETH)
    create_erc20_tx_internal(token, &data, nonce)
}

/// Internal helper to create an ERC-20 transaction with specific calldata.
fn create_erc20_tx_internal(token: &str, data: &[u8], nonce: u64) -> Vec<u8> {
    let token_normalized = if token.starts_with("0x") {
        token[2..].to_string()
    } else {
        token.to_string()
    };
    let token_bytes = hex::decode(&token_normalized).expect("invalid hex address");

    let nonce_bytes = encode_u64(nonce);
    let chain_id_bytes = vec![0x01]; // mainnet
    let max_priority_fee = encode_u64(2_000_000_000); // 2 gwei
    let max_fee = encode_u64(2_000_000_000); // 2 gwei
    let gas_limit = encode_u64(80_000); // Higher gas for contract calls
    let value_bytes: Vec<u8> = vec![]; // Zero ETH value
    let access_list: Vec<u8> = vec![0xc0]; // empty RLP list

    // Signature components (dummy for testing)
    let y_parity: Vec<u8> = vec![0x80]; // 0
    let r: Vec<u8> = vec![
        0xa0, 0xab, 0xcd, 0x12, 0x34, 0xef, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
        0xab, 0xcd, 0xef,
    ];
    let s: Vec<u8> = vec![
        0xa0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
        0xab, 0xcd, 0xef,
    ];

    // Encode the token address (20 bytes)
    let to_encoded = if token_bytes.len() == 20 {
        let mut enc = vec![0x94];
        enc.extend_from_slice(&token_bytes);
        enc
    } else {
        panic!("invalid address length");
    };

    // Build the RLP list items
    let items: Vec<Vec<u8>> = vec![
        encode_rlp_item(&chain_id_bytes),
        encode_rlp_item(&nonce_bytes),
        encode_rlp_item(&max_priority_fee),
        encode_rlp_item(&max_fee),
        encode_rlp_item(&gas_limit),
        to_encoded,
        encode_rlp_item(&value_bytes),
        encode_rlp_item(data), // ERC-20 calldata
        access_list.clone(),
        y_parity,
        r,
        s,
    ];

    // Calculate total payload length
    let payload_len: usize = items.iter().map(|item| item.len()).sum();

    // Build the full RLP list
    let mut tx = vec![0x02]; // EIP-1559 type prefix

    // Add list prefix
    if payload_len < 56 {
        tx.push((0xc0 + payload_len) as u8);
    } else {
        let len_bytes = encode_length(payload_len);
        tx.push((0xf7 + len_bytes.len()) as u8);
        tx.extend(len_bytes);
    }

    // Add all items
    for item in items {
        tx.extend(item);
    }

    tx
}

/// Create a `ParsedTx` directly for policy testing.
///
/// This bypasses the parsing step and creates a `ParsedTx` directly,
/// useful for testing policy enforcement without needing valid transaction encoding.
///
/// # Arguments
///
/// * `recipient` - The recipient address
/// * `amount` - The transaction amount
/// * `tx_type` - The transaction type
pub fn create_parsed_tx(
    recipient: Option<&str>,
    amount: Option<U256>,
    tx_type: TxType,
) -> ParsedTx {
    ParsedTx {
        hash: [0x42; 32],
        recipient: recipient.map(String::from),
        amount,
        token: Some("ETH".to_string()),
        token_address: None,
        tx_type,
        chain: "ethereum".to_string(),
        nonce: Some(1),
        chain_id: Some(1),
        metadata: HashMap::new(),
    }
}

/// Create a `ParsedTx` for a token transfer.
pub fn create_parsed_token_tx(
    recipient: Option<&str>,
    amount: Option<U256>,
    token_address: &str,
) -> ParsedTx {
    ParsedTx {
        hash: [0x42; 32],
        recipient: recipient.map(String::from),
        amount,
        token: Some("TOKEN".to_string()),
        token_address: Some(token_address.to_string()),
        tx_type: TxType::TokenTransfer,
        chain: "ethereum".to_string(),
        nonce: Some(1),
        chain_id: Some(1),
        metadata: HashMap::new(),
    }
}

/// Load a test fixture from the fixtures directory.
///
/// # Arguments
///
/// * `name` - The fixture filename (without path)
///
/// # Returns
///
/// The raw transaction bytes from the fixture.
pub fn load_fixture(name: &str) -> Vec<u8> {
    // CARGO_MANIFEST_DIR points to crates/sello, go up to workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let manifest_path = std::path::PathBuf::from(manifest_dir);

    let fixture_path = manifest_path
        .parent() // crates
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.join("tests").join("fixtures").join("ethereum").join(name))
        .unwrap_or_else(|| {
            Path::new("tests")
                .join("fixtures")
                .join("ethereum")
                .join(name)
        });

    let content = fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", fixture_path.display(), e));

    let json: serde_json::Value =
        serde_json::from_str(&content).expect("failed to parse fixture JSON");

    let raw_tx = json["raw_tx"]
        .as_str()
        .expect("fixture missing raw_tx field");

    hex::decode(raw_tx.strip_prefix("0x").unwrap_or(raw_tx)).expect("failed to decode raw_tx hex")
}

/// Parse a transaction using the Ethereum parser.
pub fn parse_ethereum_tx(raw: &[u8]) -> Result<ParsedTx, sello_core::error::ParseError> {
    let parser = EthereumParser::new();
    parser.parse(raw)
}

// ============================================================================
// RLP Encoding Helpers
// ============================================================================

/// Encode a u64 as minimal RLP bytes.
fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let trimmed: Vec<u8> = bytes.into_iter().skip_while(|&b| b == 0).collect();
    trimmed
}

/// Encode a U256 as minimal big-endian bytes.
fn encode_u256(value: U256) -> Vec<u8> {
    if value == U256::ZERO {
        return vec![];
    }
    let bytes = value.to_be_bytes::<32>();
    let trimmed: Vec<u8> = bytes.into_iter().skip_while(|&b| b == 0).collect();
    trimmed
}

/// Encode a byte slice as an RLP item.
fn encode_rlp_item(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        vec![0x80] // Empty string
    } else if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]] // Single byte < 0x80
    } else if data.len() < 56 {
        let mut result = vec![(0x80 + data.len()) as u8];
        result.extend_from_slice(data);
        result
    } else {
        let len_bytes = encode_length(data.len());
        let mut result = vec![(0xb7 + len_bytes.len()) as u8];
        result.extend(len_bytes);
        result.extend_from_slice(data);
        result
    }
}

/// Encode a length as big-endian bytes.
fn encode_length(len: usize) -> Vec<u8> {
    if len == 0 {
        return vec![];
    }
    let bytes = (len as u64).to_be_bytes();
    bytes.into_iter().skip_while(|&b| b == 0).collect()
}
