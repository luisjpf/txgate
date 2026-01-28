//! Integration tests for policy enforcement.
//!
//! These tests verify that policy rules are correctly enforced:
//! - Blacklist blocking
//! - Whitelist enforcement
//! - Transaction limit enforcement
//! - Daily limit accumulation and enforcement

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    dead_code
)]

use alloy_primitives::U256;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use txgate_chain::EthereumParser;
use txgate_core::error::{PolicyError, SignError};
use txgate_core::signing::{ChainParser, PolicyEngineExt, SignerExt, SigningService};
use txgate_core::types::{ParsedTx, PolicyResult, TxType};
use txgate_policy::config::PolicyConfig;
use txgate_policy::engine::{DefaultPolicyEngine, PolicyEngine};
use txgate_policy::history::TransactionHistory;

use super::test_utils::{
    addresses, create_parsed_token_tx, create_parsed_tx, create_test_transaction, HALF_ETH, ONE_ETH,
};

// ============================================================================
// Mock Components
// ============================================================================

/// A mock signer for testing.
struct MockSigner {
    sign_count: AtomicU32,
}

impl MockSigner {
    fn new() -> Self {
        Self {
            sign_count: AtomicU32::new(0),
        }
    }

    fn sign_count(&self) -> u32 {
        self.sign_count.load(Ordering::SeqCst)
    }
}

impl SignerExt for MockSigner {
    fn sign(&self, _hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        self.sign_count.fetch_add(1, Ordering::SeqCst);
        let mut sig = vec![0u8; 65];
        sig[..32].fill(0xab);
        sig[32..64].fill(0xcd);
        sig[64] = 0;
        Ok(sig)
    }
}

/// Adapter for EthereumParser.
struct EthereumChainAdapter(EthereumParser);

impl ChainParser for EthereumChainAdapter {
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, txgate_core::error::ParseError> {
        txgate_chain::Chain::parse(&self.0, raw)
    }
}

/// Adapter for DefaultPolicyEngine.
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
// Blacklist Tests
// ============================================================================

#[test]
fn test_blacklist_blocks_transaction() {
    // Set up environment with blacklist containing test address
    let config = PolicyConfig::new().with_blacklist(vec![addresses::BLACKLISTED_ADDR.to_string()]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Try to sign transaction to blacklisted address
    let raw_tx = create_test_transaction(addresses::BLACKLISTED_ADDR, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx);

    // Verify PolicyDenied error
    assert!(result.is_err(), "should be denied");
    let err = result.unwrap_err();
    assert!(err.is_policy_denied(), "should be policy denied");
    assert!(
        err.denial_reason()
            .unwrap()
            .to_lowercase()
            .contains("blacklist"),
        "reason should mention blacklist"
    );

    // Signer should NOT have been called
    assert_eq!(
        service.signer().sign_count(),
        0,
        "signer should not be called for denied transaction"
    );
}

#[test]
fn test_blacklist_case_insensitive() {
    // Blacklist with uppercase address
    let config = PolicyConfig::new().with_blacklist(vec![
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
    ]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Check with lowercase address (should still be blocked)
    let tx = create_parsed_tx(
        Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        Some(U256::from(ONE_ETH)),
        TxType::Transfer,
    );

    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_denied(), "blacklist should be case insensitive");
}

#[test]
fn test_non_blacklisted_address_allowed() {
    let config = PolicyConfig::new().with_blacklist(vec![addresses::BLACKLISTED_ADDR.to_string()]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign to a different address (should be allowed)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx);

    assert!(result.is_ok(), "non-blacklisted should be allowed");
    assert!(result.unwrap().has_signature());
}

// ============================================================================
// Whitelist Tests
// ============================================================================

#[test]
fn test_whitelist_allows_only_listed() {
    // Set up environment with whitelist enabled
    let config = PolicyConfig::new().with_whitelist(vec![addresses::WHITELISTED_ADDR.to_string()]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Try to sign to non-whitelisted address (should be denied)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx);

    assert!(result.is_err(), "non-whitelisted should be denied");
    let err = result.unwrap_err();
    assert!(err.is_policy_denied());
    assert!(
        err.denial_reason()
            .unwrap()
            .to_lowercase()
            .contains("whitelist"),
        "reason should mention whitelist"
    );
}

#[test]
fn test_whitelist_allows_whitelisted_address() {
    let config = PolicyConfig::new().with_whitelist(vec![addresses::WHITELISTED_ADDR.to_string()]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign to whitelisted address (should be allowed)
    let raw_tx = create_test_transaction(addresses::WHITELISTED_ADDR, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx);

    assert!(result.is_ok(), "whitelisted address should be allowed");
    assert!(result.unwrap().has_signature());
}

#[test]
fn test_whitelist_disabled_allows_all() {
    // Create whitelist but disable it
    let config = PolicyConfig::new()
        .with_whitelist(vec![addresses::WHITELISTED_ADDR.to_string()])
        .with_whitelist_enabled(false);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign to any address (should be allowed since whitelist is disabled)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 1);
    let result = service.sign(&raw_tx);

    assert!(
        result.is_ok(),
        "should be allowed when whitelist is disabled"
    );
}

#[test]
fn test_whitelist_case_insensitive() {
    // Whitelist with mixed case
    let config = PolicyConfig::new().with_whitelist(vec![
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    ]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Check with lowercase
    let tx = create_parsed_tx(
        Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some(U256::from(ONE_ETH)),
        TxType::Transfer,
    );

    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_allowed(), "whitelist should be case insensitive");
}

// ============================================================================
// Transaction Limit Tests
// ============================================================================

#[test]
fn test_transaction_limit_enforced() {
    // Set up with 1 ETH transaction limit
    let config = PolicyConfig::new().with_transaction_limit("ETH", U256::from(ONE_ETH));
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(engine);
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Try 0.5 ETH (should be allowed)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(HALF_ETH), 1);
    let result = service.sign(&raw_tx);
    assert!(result.is_ok(), "0.5 ETH should be allowed");

    // Try exactly 1 ETH (should be allowed - at the limit)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(ONE_ETH), 2);
    let result = service.sign(&raw_tx);
    assert!(result.is_ok(), "1 ETH should be allowed (at limit)");

    // Try 2 ETH (should be denied - exceeds limit)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(2 * ONE_ETH), 3);
    let result = service.sign(&raw_tx);

    assert!(result.is_err(), "2 ETH should be denied");
    let err = result.unwrap_err();
    assert!(err.is_policy_denied());
    assert!(
        err.denial_reason()
            .unwrap()
            .to_lowercase()
            .contains("limit")
            || err
                .denial_reason()
                .unwrap()
                .to_lowercase()
                .contains("exceeds"),
        "reason should mention limit"
    );
}

#[test]
fn test_transaction_limit_per_token() {
    // Set up with different limits for ETH and USDC
    let usdc_limit = U256::from(1_000_000u64); // 1 USDC (6 decimals)
    let config = PolicyConfig::new()
        .with_transaction_limit("ETH", U256::from(ONE_ETH))
        .with_transaction_limit(addresses::USDC_CONTRACT, usdc_limit);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Test ETH limit with parsed tx
    let eth_tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(2 * ONE_ETH)), // Over ETH limit
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &eth_tx).unwrap();
    assert!(result.is_denied(), "ETH over limit should be denied");

    // Test USDC limit with parsed token tx
    let usdc_tx = create_parsed_token_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(2_000_000u64)), // Over USDC limit
        addresses::USDC_CONTRACT,
    );
    let result = PolicyEngine::check(&*engine, &usdc_tx).unwrap();
    assert!(result.is_denied(), "USDC over limit should be denied");

    // Test USDC under limit
    let usdc_tx = create_parsed_token_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(500_000u64)), // Under USDC limit
        addresses::USDC_CONTRACT,
    );
    let result = PolicyEngine::check(&*engine, &usdc_tx).unwrap();
    assert!(result.is_allowed(), "USDC under limit should be allowed");
}

// ============================================================================
// Daily Limit Tests
// ============================================================================

#[test]
fn test_daily_limit_accumulates() {
    // Set up with 1 ETH daily limit
    let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(ONE_ETH));
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    let chain = EthereumChainAdapter(EthereumParser::new());
    let policy = PolicyEngineAdapter(Arc::clone(&engine));
    let signer = MockSigner::new();

    let service = SigningService::new(chain, policy, signer);

    // Sign 0.5 ETH (should be allowed - total: 0.5)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(HALF_ETH), 1);
    let result = service.sign(&raw_tx);
    assert!(result.is_ok(), "first 0.5 ETH should be allowed");

    // Sign another 0.5 ETH (should be allowed - total: 1.0)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(HALF_ETH), 2);
    let result = service.sign(&raw_tx);
    assert!(result.is_ok(), "second 0.5 ETH should be allowed");

    // Verify daily total in history
    let daily_total = history.daily_total("ETH").unwrap();
    assert_eq!(
        daily_total,
        U256::from(ONE_ETH),
        "daily total should be 1 ETH"
    );

    // Try to sign another 0.5 ETH (should be denied - would exceed daily limit)
    let raw_tx = create_test_transaction(addresses::TEST_RECIPIENT, U256::from(HALF_ETH), 3);
    let result = service.sign(&raw_tx);

    assert!(
        result.is_err(),
        "third 0.5 ETH should be denied (exceeds daily)"
    );
    let err = result.unwrap_err();
    assert!(err.is_policy_denied());
    assert!(
        err.denial_reason()
            .unwrap()
            .to_lowercase()
            .contains("daily")
            || err
                .denial_reason()
                .unwrap()
                .to_lowercase()
                .contains("limit"),
        "reason should mention daily limit"
    );
}

#[test]
fn test_daily_limit_per_token() {
    // Set up with different daily limits
    let config = PolicyConfig::new()
        .with_daily_limit("ETH", U256::from(ONE_ETH))
        .with_daily_limit(addresses::USDC_CONTRACT, U256::from(1_000_000u64));
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Record some ETH transactions
    let eth_tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(ONE_ETH)),
        TxType::Transfer,
    );
    PolicyEngine::record(&*engine, &eth_tx).unwrap();

    // ETH daily limit should now be reached
    let eth_tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(HALF_ETH)),
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &eth_tx).unwrap();
    assert!(result.is_denied(), "ETH daily limit should be reached");

    // But USDC should still be available
    let usdc_tx = create_parsed_token_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(500_000u64)),
        addresses::USDC_CONTRACT,
    );
    let result = PolicyEngine::check(&*engine, &usdc_tx).unwrap();
    assert!(
        result.is_allowed(),
        "USDC should still have daily allowance"
    );
}

#[test]
fn test_daily_limit_zero_blocks_all() {
    // Set daily limit to zero
    let config = PolicyConfig::new().with_daily_limit("ETH", U256::ZERO);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Any amount should be denied
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(1u64)),
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(
        result.is_denied(),
        "zero daily limit should block everything"
    );

    // But zero amount should be allowed
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::ZERO),
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_allowed(), "zero amount should be allowed");
}

// ============================================================================
// Combined Rule Tests
// ============================================================================

#[test]
fn test_blacklist_takes_precedence_over_limits() {
    // Set up with both blacklist and generous limits
    let config = PolicyConfig::new()
        .with_blacklist(vec![addresses::BLACKLISTED_ADDR.to_string()])
        .with_transaction_limit("ETH", U256::MAX)
        .with_daily_limit("ETH", U256::MAX);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Even with generous limits, blacklisted address should be denied
    let tx = create_parsed_tx(
        Some(addresses::BLACKLISTED_ADDR),
        Some(U256::from(1u64)), // Tiny amount
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_denied());
    if let PolicyResult::Denied { rule, .. } = result {
        assert_eq!(rule, "blacklist", "should be denied by blacklist rule");
    }
}

#[test]
fn test_whitelist_takes_precedence_over_tx_limit() {
    // Set up with whitelist and transaction limit
    let config = PolicyConfig::new()
        .with_whitelist(vec![addresses::WHITELISTED_ADDR.to_string()])
        .with_transaction_limit("ETH", U256::from(ONE_ETH));
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Non-whitelisted address should be denied by whitelist, not tx_limit
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(2 * ONE_ETH)), // Over tx limit
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_denied());
    if let PolicyResult::Denied { rule, .. } = result {
        assert_eq!(rule, "whitelist", "should be denied by whitelist first");
    }
}

#[test]
fn test_tx_limit_takes_precedence_over_daily_limit() {
    // Set up so tx_limit would deny before daily_limit
    let config = PolicyConfig::new()
        .with_transaction_limit("ETH", U256::from(HALF_ETH))
        .with_daily_limit("ETH", U256::from(ONE_ETH));
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Record 0.4 ETH first
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(HALF_ETH - 100_000_000_000_000_000)), // 0.4 ETH
        TxType::Transfer,
    );
    PolicyEngine::record(&*engine, &tx).unwrap();

    // Now try 0.6 ETH - would exceed both limits, but should be denied by tx_limit first
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::from(HALF_ETH + 100_000_000_000_000_000)), // 0.6 ETH
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_denied());
    if let PolicyResult::Denied { rule, .. } = result {
        assert_eq!(rule, "tx_limit", "should be denied by tx_limit first");
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_policy_allows_everything() {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Should allow any transaction
    let tx = create_parsed_tx(
        Some(addresses::TEST_RECIPIENT),
        Some(U256::MAX),
        TxType::Transfer,
    );
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_allowed(), "empty policy should allow everything");
}

#[test]
fn test_no_recipient_skips_address_checks() {
    // Set up with strict whitelist
    let config = PolicyConfig::new().with_whitelist(vec![addresses::WHITELISTED_ADDR.to_string()]);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Transaction with no recipient (e.g., contract deployment)
    let tx = create_parsed_tx(None, Some(U256::from(ONE_ETH)), TxType::Deployment);
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(
        result.is_allowed(),
        "no recipient should skip whitelist check"
    );
}

#[test]
fn test_no_amount_skips_limit_checks() {
    // Set up with zero limit
    let config = PolicyConfig::new()
        .with_transaction_limit("ETH", U256::ZERO)
        .with_daily_limit("ETH", U256::ZERO);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = Arc::new(DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap());

    // Transaction with no amount
    let tx = create_parsed_tx(Some(addresses::TEST_RECIPIENT), None, TxType::ContractCall);
    let result = PolicyEngine::check(&*engine, &tx).unwrap();
    assert!(result.is_allowed(), "no amount should skip limit checks");
}
