//! Fuzz target for policy rules evaluation.
//!
//! This fuzz target exercises the policy engine with arbitrary inputs to find
//! potential panics, logic errors, or unexpected behavior in policy evaluation.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run policy_rules
//! ```
//!
//! # Security considerations
//!
//! The policy engine is security-critical code. Fuzzing helps ensure:
//! - No panics on malformed policy definitions
//! - No crashes on unexpected transaction data
//! - Consistent evaluation results
//! - No resource exhaustion attacks

#![no_main]

use alloy_primitives::U256;
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use sello_core::types::{ParsedTx, TxType};
use sello_policy::config::PolicyConfig;
use sello_policy::engine::{DefaultPolicyEngine, PolicyEngine};
use sello_policy::history::TransactionHistory;
use std::collections::HashMap;
use std::sync::Arc;

/// Fuzz input representing a policy evaluation request.
///
/// Using `Arbitrary` allows the fuzzer to generate structured inputs
/// that are more likely to exercise interesting code paths.
#[derive(Debug, Arbitrary)]
struct PolicyFuzzInput {
    /// Simulated transaction value (in smallest unit)
    value: u64,
    /// Simulated recipient address as bytes (20 bytes for Ethereum)
    recipient: Option<[u8; 20]>,
    /// Simulated chain ID
    chain_id: u64,
    /// Simulated nonce
    nonce: u64,
    /// Simulated transaction type
    tx_type_selector: u8,
    /// Whether to include token address
    has_token_address: bool,
    /// Token address bytes (if applicable)
    token_address: [u8; 20],
    /// Policy configuration options
    whitelist_enabled: bool,
    /// Whitelist addresses (indices into predefined list)
    whitelist_indices: Vec<u8>,
    /// Blacklist addresses (indices into predefined list)
    blacklist_indices: Vec<u8>,
    /// Transaction limit (if any)
    tx_limit: Option<u64>,
    /// Daily limit (if any)
    daily_limit: Option<u64>,
}

/// Convert bytes to hex address string
fn bytes_to_hex_address(bytes: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Predefined addresses for whitelist/blacklist testing
const PREDEFINED_ADDRESSES: [&str; 8] = [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003",
    "0x0000000000000000000000000000000000000004",
    "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
];

fuzz_target!(|data: &[u8]| {
    // Try to parse structured input from fuzzer
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = PolicyFuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    // Build policy configuration from fuzz input
    let mut config = PolicyConfig::new();

    // Add whitelist addresses (avoid overlap with blacklist)
    let whitelist: Vec<String> = input
        .whitelist_indices
        .iter()
        .filter_map(|&i| {
            let idx = (i as usize) % PREDEFINED_ADDRESSES.len();
            // Only include in whitelist if not already marked for blacklist
            if !input.blacklist_indices.contains(&i) {
                Some(PREDEFINED_ADDRESSES[idx].to_string())
            } else {
                None
            }
        })
        .collect();

    if !whitelist.is_empty() {
        config = config.with_whitelist(whitelist);
    }

    if input.whitelist_enabled {
        config = config.with_whitelist_enabled(true);
    }

    // Add blacklist addresses
    let blacklist: Vec<String> = input
        .blacklist_indices
        .iter()
        .filter_map(|&i| {
            let idx = (i as usize) % PREDEFINED_ADDRESSES.len();
            // Only include in blacklist if not in whitelist
            if !input.whitelist_indices.contains(&i) {
                Some(PREDEFINED_ADDRESSES[idx].to_string())
            } else {
                None
            }
        })
        .collect();

    if !blacklist.is_empty() {
        config = config.with_blacklist(blacklist);
    }

    // Add limits
    if let Some(limit) = input.tx_limit {
        config = config.with_transaction_limit("ETH", U256::from(limit));
    }

    if let Some(limit) = input.daily_limit {
        config = config.with_daily_limit("ETH", U256::from(limit));
    }

    // Try to create the policy engine (may fail if config is invalid, e.g., overlap)
    let history = match TransactionHistory::in_memory() {
        Ok(h) => Arc::new(h),
        Err(_) => return,
    };

    let engine = match DefaultPolicyEngine::new(config, history) {
        Ok(e) => e,
        Err(_) => return, // Invalid config (e.g., address in both lists) is expected
    };

    // Build a ParsedTx from fuzz input
    let tx_type = match input.tx_type_selector % 5 {
        0 => TxType::Transfer,
        1 => TxType::ContractCall,
        2 => TxType::Deployment,
        3 => TxType::TokenTransfer,
        _ => TxType::TokenApproval,
    };

    let recipient = input.recipient.map(|r| bytes_to_hex_address(&r));
    let token_address = if input.has_token_address {
        Some(bytes_to_hex_address(&input.token_address))
    } else {
        None
    };

    let tx = ParsedTx {
        hash: [0xab; 32], // Dummy hash
        recipient,
        amount: Some(U256::from(input.value)),
        token: None,
        token_address,
        tx_type,
        chain: "ethereum".to_string(),
        nonce: Some(input.nonce),
        chain_id: Some(input.chain_id),
        metadata: HashMap::new(),
    };

    // Check the transaction against policy - this should never panic
    let result = engine.check(&tx);

    // Verify the result is valid (either Allowed or Denied)
    if let Ok(policy_result) = result {
        // Exercise the is_allowed/is_denied methods
        let _ = policy_result.is_allowed();
        let _ = policy_result.is_denied();

        // If allowed, try recording the transaction
        if policy_result.is_allowed() {
            let _ = engine.record(&tx);
        }
    }
});
