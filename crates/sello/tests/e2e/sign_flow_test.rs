//! Integration tests for the full signing flow.
//!
//! These tests verify the complete init -> sign flow, including:
//! - Directory structure creation
//! - Transaction parsing
//! - Policy checking
//! - Signature generation

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::missing_const_for_fn,
    dead_code
)]

use alloy_primitives::U256;
use sello_chain::{Chain, EthereumParser};
use sello_core::error::{PolicyError, SignError};
use sello_core::signing::{ChainParser, PolicyEngineExt, SignerExt, SigningService};
use sello_core::types::{ParsedTx, PolicyResult, TxType};
use sello_policy::config::PolicyConfig;
use sello_policy::engine::{DefaultPolicyEngine, PolicyEngine};
use sello_policy::history::TransactionHistory;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::test_utils::{
    addresses, create_erc20_transfer, create_test_transaction, load_fixture, setup_test_env,
    ONE_ETH,
};

// ============================================================================
// Mock Signer for Testing
// ============================================================================

/// A mock signer that produces deterministic signatures for testing.
struct MockSigner {
    sign_count: AtomicU32,
    recovery_id: u8,
}

impl MockSigner {
    fn new() -> Self {
        Self {
            sign_count: AtomicU32::new(0),
            recovery_id: 0,
        }
    }

    fn with_recovery_id(recovery_id: u8) -> Self {
        Self {
            sign_count: AtomicU32::new(0),
            recovery_id,
        }
    }

    fn sign_count(&self) -> u32 {
        self.sign_count.load(Ordering::SeqCst)
    }
}

impl SignerExt for MockSigner {
    fn sign(&self, _hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        self.sign_count.fetch_add(1, Ordering::SeqCst);

        // Return a deterministic 65-byte signature (r || s || v)
        let mut sig = vec![0u8; 65];
        sig[..32].fill(0xab); // r
        sig[32..64].fill(0xcd); // s
        sig[64] = self.recovery_id; // v

        Ok(sig)
    }
}

// ============================================================================
// Adapter to make EthereumParser implement ChainParser
// ============================================================================

struct EthereumChainAdapter(EthereumParser);

impl ChainParser for EthereumChainAdapter {
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, sello_core::error::ParseError> {
        self.0.parse(raw)
    }
}

// ============================================================================
// Adapter to make DefaultPolicyEngine implement PolicyEngineExt
// ============================================================================

struct PolicyEngineAdapter(Arc<DefaultPolicyEngine>);

impl PolicyEngineExt for PolicyEngineAdapter {
    fn check(&self, tx: &ParsedTx) -> Result<PolicyResult, PolicyError> {
        PolicyEngine::check(&*self.0, tx)
    }

    fn record(&self, tx: &ParsedTx) -> Result<(), PolicyError> {
        PolicyEngine::record(&*self.0, tx)
    }
}

// ============================================================================
// Init Flow Tests
// ============================================================================

#[test]
fn test_init_creates_directory_structure() {
    let temp_dir = setup_test_env();
    let sello_dir = temp_dir.path().join(".sello");

    // Verify ~/.sello directory is created
    assert!(sello_dir.exists(), "~/.sello directory should exist");
    assert!(sello_dir.is_dir(), "~/.sello should be a directory");

    // Verify keys/ subdirectory exists
    let keys_dir = sello_dir.join("keys");
    assert!(keys_dir.exists(), "keys/ subdirectory should exist");
    assert!(keys_dir.is_dir(), "keys/ should be a directory");

    // Verify config.toml is created
    let config_file = sello_dir.join("config.toml");
    assert!(config_file.exists(), "config.toml should exist");
    assert!(config_file.is_file(), "config.toml should be a file");

    // Verify config.toml has content
    let config_content = std::fs::read_to_string(&config_file).expect("failed to read config");
    assert!(
        config_content.contains("[policy]"),
        "config should contain [policy] section"
    );
}

// ============================================================================
// ETH Transfer Signing Tests
// ============================================================================

#[test]
fn test_sign_eth_transfer() {
    // Set up test environment with permissive policy
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Create signing components
    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Create ETH transfer transaction
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);

    // Sign the transaction
    let result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify result
    assert!(result.is_allowed(), "transaction should be allowed");
    assert!(result.has_signature(), "signature should be present");
    assert!(result.signature.is_some(), "signature bytes should exist");
    assert!(result.recovery_id.is_some(), "recovery_id should exist");

    // Verify parsed transaction
    assert_eq!(result.parsed_tx.tx_type, TxType::Transfer);
    assert_eq!(result.parsed_tx.chain, "ethereum");
    assert_eq!(result.parsed_tx.nonce, Some(1));

    // Verify signer was called
    assert_eq!(
        service.signer().sign_count(),
        1,
        "signer should have been called once"
    );
}

#[test]
fn test_sign_legacy_transfer_from_fixture() {
    // Load and parse the legacy transfer fixture
    let raw_tx = load_fixture("legacy_transfer.json");

    // Set up test environment
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign the transaction
    let result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify parsing is correct
    assert_eq!(result.parsed_tx.tx_type, TxType::Transfer);
    assert_eq!(
        result.parsed_tx.recipient,
        Some("0x3535353535353535353535353535353535353535".to_string())
    );
    assert_eq!(result.parsed_tx.chain_id, Some(1));
    assert_eq!(result.parsed_tx.nonce, Some(9));

    // Verify signature is present
    assert!(result.has_signature());
}

#[test]
#[ignore = "fixture eip1559_transfer.json has RLP encoding issues that need fixing"]
fn test_sign_eip1559_transfer_from_fixture() {
    // Load and parse the EIP-1559 transfer fixture
    let raw_tx = load_fixture("eip1559_transfer.json");

    // Set up test environment
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign the transaction
    let result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify parsing is correct
    assert_eq!(result.parsed_tx.tx_type, TxType::Transfer);
    assert_eq!(result.parsed_tx.chain_id, Some(1));

    // Verify signature
    assert!(result.has_signature());
    let full_sig = result.signature_with_recovery_id().unwrap();
    assert_eq!(full_sig.len(), 65);
}

// ============================================================================
// ERC-20 Transfer Signing Tests
// ============================================================================

#[test]
fn test_sign_erc20_transfer() {
    // Set up test environment with permissive policy
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Create ERC-20 transfer transaction
    let raw_tx = create_erc20_transfer(
        addresses::USDC_CONTRACT,
        addresses::VITALIK_ETH,
        U256::from(1_000_000u64), // 1 USDC (6 decimals)
        1,
    );

    // Sign the transaction
    let result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify result
    assert!(result.is_allowed());
    assert!(result.has_signature());

    // Verify tx_type is TokenTransfer
    assert_eq!(
        result.parsed_tx.tx_type,
        TxType::TokenTransfer,
        "should be detected as token transfer"
    );

    // Verify token address is extracted
    assert!(
        result.parsed_tx.token_address.is_some(),
        "token_address should be set"
    );
}

#[test]
#[ignore = "fixture erc20_transfer.json has RLP encoding issues that need fixing"]
fn test_sign_erc20_transfer_from_fixture() {
    // Load the ERC-20 transfer fixture
    let raw_tx = load_fixture("erc20_transfer.json");

    // Set up test environment
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign the transaction
    let result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify it's detected as a token transfer
    assert_eq!(result.parsed_tx.tx_type, TxType::TokenTransfer);
    assert!(result.parsed_tx.token_address.is_some());

    // Verify signature
    assert!(result.has_signature());
}

// ============================================================================
// Dry-Run (Check) Tests
// ============================================================================

#[test]
fn test_check_without_signing() {
    // Set up test environment
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Create transaction
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);

    // Check without signing
    let result = service.check(&raw_tx).expect("check should succeed");

    // Verify result
    assert!(result.is_allowed());
    assert!(
        !result.has_signature(),
        "check should not produce signature"
    );
    assert!(result.signature.is_none());

    // Signer should NOT have been called
    assert_eq!(
        service.signer().sign_count(),
        0,
        "signer should not be called for check"
    );
}

// ============================================================================
// Recovery ID Tests
// ============================================================================

#[test]
fn test_recovery_id_passed_through() {
    // Set up test environment with a signer that uses recovery_id = 1
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::with_recovery_id(1);

    let service = SigningService::new(chain, policy, signer);

    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx).expect("signing should succeed");

    assert_eq!(result.recovery_id, Some(1));

    // Verify signature_with_recovery_id combines them correctly
    let full_sig = result.signature_with_recovery_id().unwrap();
    assert_eq!(full_sig[64], 1);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_parse_error_on_invalid_input() {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Try to sign invalid data
    let invalid_tx = vec![0x00, 0x01, 0x02]; // Not valid RLP
    let result = service.sign(&invalid_tx);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, sello_core::signing::SigningError::ParseError(_)),
        "should be ParseError"
    );
}

#[test]
fn test_empty_transaction_fails() {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    let empty_tx: Vec<u8> = vec![];
    let result = service.sign(&empty_tx);

    assert!(result.is_err());
}

// ============================================================================
// Recording Tests
// ============================================================================

#[test]
fn test_sign_records_to_history() {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign a transaction
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let _result = service.sign(&raw_tx).expect("signing should succeed");

    // Verify the transaction was recorded in history
    let daily_total = history.daily_total("ETH").expect("should get daily total");
    assert_eq!(
        daily_total,
        U256::from(ONE_ETH),
        "transaction should be recorded"
    );
}

#[test]
fn test_check_does_not_record() {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Check a transaction (dry run)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let _result = service.check(&raw_tx).expect("check should succeed");

    // Verify nothing was recorded
    let daily_total = history.daily_total("ETH").expect("should get daily total");
    assert_eq!(daily_total, U256::ZERO, "check should not record");
}
