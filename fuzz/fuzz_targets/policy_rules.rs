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

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Fuzz input representing a policy evaluation request.
///
/// Using `Arbitrary` allows the fuzzer to generate structured inputs
/// that are more likely to exercise interesting code paths.
#[derive(Debug, Arbitrary)]
struct PolicyFuzzInput {
    /// Simulated policy rule identifier
    rule_id: u32,
    /// Simulated transaction value (in smallest unit)
    value: u64,
    /// Simulated gas limit
    gas_limit: u64,
    /// Simulated recipient address (20 bytes for Ethereum)
    recipient: [u8; 20],
    /// Simulated sender address
    sender: [u8; 20],
    /// Simulated chain ID
    chain_id: u64,
    /// Whether this is a contract creation
    is_contract_creation: bool,
    /// Arbitrary calldata
    calldata: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // TODO: Once PolicyEngine is implemented in sello-policy, uncomment:
    //
    // ```rust
    // // Parse structured input from fuzzer
    // let Ok(input) = PolicyFuzzInput::arbitrary(&mut Unstructured::new(data)) else {
    //     return;
    // };
    //
    // // Create a mock transaction context
    // let tx_context = TransactionContext {
    //     value: input.value,
    //     gas_limit: input.gas_limit,
    //     recipient: input.recipient,
    //     sender: input.sender,
    //     chain_id: input.chain_id,
    //     is_contract_creation: input.is_contract_creation,
    //     calldata: &input.calldata,
    // };
    //
    // // Evaluate against various policy rules
    // let _ = sello_policy::evaluate(&tx_context, input.rule_id);
    // ```
    //
    // For now, exercise the Arbitrary derive to ensure it works:

    // Try to parse structured input
    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = PolicyFuzzInput::arbitrary(&mut unstructured) {
        // Perform basic validation that would be done in real policy evaluation

        // Check value bounds (simulating spending limit check)
        let _within_limit = input.value <= u64::MAX / 2;

        // Check gas limit reasonableness
        let _reasonable_gas = input.gas_limit <= 30_000_000; // Ethereum block gas limit

        // Check for zero address (often special-cased)
        let _is_zero_recipient = input.recipient == [0u8; 20];
        let _is_zero_sender = input.sender == [0u8; 20];

        // Check calldata size limits
        let _calldata_size_ok = input.calldata.len() <= 128 * 1024; // 128KB limit

        // Simulate chain-specific validation
        match input.chain_id {
            1 => {
                // Ethereum mainnet
                let _mainnet = true;
            }
            5 | 11155111 => {
                // Goerli / Sepolia testnets
                let _testnet = true;
            }
            _ => {
                // Unknown chain
                let _unknown = true;
            }
        }
    }
});
