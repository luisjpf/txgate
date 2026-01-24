//! Persistence integration tests for daily limit survival across restarts.
//!
//! These tests verify that the SQLite-backed transaction history correctly
//! persists daily totals and that policy limits survive server restarts.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::redundant_clone
)]

use alloy_primitives::U256;
use sello_policy::config::PolicyConfig;
use sello_policy::engine::{DefaultPolicyEngine, PolicyEngine};
use sello_policy::history::TransactionHistory;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

use super::test_utils::{addresses, create_parsed_tx, ONE_ETH};

/// Create a file-based history at the given path.
fn create_persistent_history(db_path: &Path) -> Arc<TransactionHistory> {
    Arc::new(TransactionHistory::new(db_path).expect("create history"))
}

/// Create a policy engine with file-based history.
fn create_engine_with_history(
    config: PolicyConfig,
    history: Arc<TransactionHistory>,
) -> DefaultPolicyEngine {
    DefaultPolicyEngine::new(config, history).expect("create engine")
}

// =============================================================================
// Daily Limit Persistence Tests
// =============================================================================

#[test]
fn test_daily_total_persists_across_history_instances() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // First instance: record some transactions
    {
        let history = create_persistent_history(&db_path);

        history
            .record("ETH", U256::from(ONE_ETH), "0xabc123")
            .expect("record tx 1");
        history
            .record("ETH", U256::from(ONE_ETH), "0xdef456")
            .expect("record tx 2");

        let total = history.daily_total("ETH").expect("daily total");
        assert_eq!(total, U256::from(2 * ONE_ETH));
    }

    // Second instance: should see the persisted totals
    {
        let history = create_persistent_history(&db_path);

        let total = history.daily_total("ETH").expect("daily total");
        assert_eq!(total, U256::from(2 * ONE_ETH));

        // Add another transaction
        history
            .record("ETH", U256::from(ONE_ETH), "0xghi789")
            .expect("record tx 3");

        let total = history.daily_total("ETH").expect("daily total");
        assert_eq!(total, U256::from(3 * ONE_ETH));
    }
}

#[test]
fn test_daily_limit_enforcement_survives_restart() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // Set daily limit to 2 ETH
    let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(2 * ONE_ETH));

    // First engine instance: use 1.5 ETH
    {
        let history = create_persistent_history(&db_path);
        let engine = create_engine_with_history(config.clone(), history);

        // Transaction for 1.5 ETH should be allowed
        let tx = create_parsed_tx(
            Some(addresses::TEST_RECIPIENT),
            Some(U256::from(ONE_ETH + ONE_ETH / 2)),
            sello_core::types::TxType::Transfer,
        );

        let result = engine.check(&tx).expect("check");
        assert!(result.is_allowed(), "first transaction should be allowed");

        engine.record(&tx).expect("record");
    }

    // Second engine instance: should still know about the previous spending
    {
        let history = create_persistent_history(&db_path);
        let engine = create_engine_with_history(config.clone(), history);

        // Transaction for 1 ETH should be denied (would exceed 2 ETH daily limit)
        let tx = create_parsed_tx(
            Some(addresses::TEST_RECIPIENT),
            Some(U256::from(ONE_ETH)),
            sello_core::types::TxType::Transfer,
        );

        let result = engine.check(&tx).expect("check");
        assert!(
            result.is_denied(),
            "Transaction should be denied due to daily limit persistence"
        );

        // But a smaller transaction (0.4 ETH) should still be allowed
        let small_tx = create_parsed_tx(
            Some(addresses::TEST_RECIPIENT),
            Some(U256::from(ONE_ETH * 4 / 10)), // 0.4 ETH
            sello_core::types::TxType::Transfer,
        );

        let result = engine.check(&small_tx).expect("check");
        assert!(
            result.is_allowed(),
            "small transaction should still be allowed"
        );
    }
}

#[test]
fn test_multiple_token_totals_persist_independently() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // First instance: record spending for multiple tokens
    {
        let history = create_persistent_history(&db_path);

        // Record ETH spending
        history
            .record("ETH", U256::from(3 * ONE_ETH), "0xeth1")
            .expect("record eth");

        // Record USDC spending
        history
            .record("USDC", U256::from(500_000_000u64), "0xusdc1")
            .expect("record usdc");

        // Record DAI spending
        history
            .record("DAI", U256::from(100_000_000_000_000_000_000u128), "0xdai1")
            .expect("record dai");
    }

    // Second instance: verify all tokens are tracked independently
    {
        let history = create_persistent_history(&db_path);

        // Check ETH daily total
        let eth_total = history.daily_total("ETH").expect("eth total");
        assert_eq!(eth_total, U256::from(3 * ONE_ETH));

        // Check USDC daily total
        let usdc_total = history.daily_total("USDC").expect("usdc total");
        assert_eq!(usdc_total, U256::from(500_000_000u64));

        // Check DAI daily total
        let dai_total = history.daily_total("DAI").expect("dai total");
        assert_eq!(dai_total, U256::from(100_000_000_000_000_000_000u128));

        // Unknown token should have zero total
        let unknown_total = history.daily_total("UNKNOWN").expect("unknown total");
        assert_eq!(unknown_total, U256::ZERO);

        // Add more to one token, verify others unchanged
        history
            .record("ETH", U256::from(ONE_ETH), "0xeth2")
            .expect("record more eth");

        let eth_total = history.daily_total("ETH").expect("eth total");
        assert_eq!(eth_total, U256::from(4 * ONE_ETH));

        // USDC should be unchanged
        let usdc_total = history.daily_total("USDC").expect("usdc total");
        assert_eq!(usdc_total, U256::from(500_000_000u64));
    }
}

// =============================================================================
// Transaction Record Persistence Tests
// =============================================================================

#[test]
fn test_transaction_records_persist() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // Record some transactions
    {
        let history = create_persistent_history(&db_path);

        history
            .record("ETH", U256::from(ONE_ETH), "0xhash1")
            .expect("record 1");
        history
            .record("ETH", U256::from(2 * ONE_ETH), "0xhash2")
            .expect("record 2");
        history
            .record("USDC", U256::from(100_000_000u64), "0xhash3")
            .expect("record 3");
    }

    // Verify records persist
    {
        let history = create_persistent_history(&db_path);

        let eth_records = history.get_transactions("ETH", 100).expect("get eth");
        assert_eq!(eth_records.len(), 2);

        let usdc_records = history.get_transactions("USDC", 100).expect("get usdc");
        assert_eq!(usdc_records.len(), 1);

        // Verify amounts
        let eth_total: U256 = eth_records.iter().map(|r| r.amount).sum();
        assert_eq!(eth_total, U256::from(3 * ONE_ETH));
    }
}

#[test]
fn test_cleanup_preserves_recent_transactions() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // Record a transaction
    {
        let history = create_persistent_history(&db_path);
        history
            .record("ETH", U256::from(ONE_ETH), "0xrecent")
            .expect("record");

        // Cleanup shouldn't remove recent transactions
        history.cleanup().expect("cleanup");
    }

    // Verify transaction still exists
    {
        let history = create_persistent_history(&db_path);
        let records = history.get_transactions("ETH", 100).expect("get");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx_hash, "0xrecent");
    }
}

// =============================================================================
// Database File Handling Tests
// =============================================================================

#[test]
fn test_database_created_if_not_exists() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("new_history.db");

    // Database file should not exist yet
    assert!(!db_path.exists());

    // Create history (should create the database)
    let history = create_persistent_history(&db_path);

    // Database should now exist
    assert!(db_path.exists());

    // Should be able to use it
    history
        .record("ETH", U256::from(ONE_ETH), "0xtest")
        .expect("record");
    let total = history.daily_total("ETH").expect("total");
    assert_eq!(total, U256::from(ONE_ETH));
}

#[test]
fn test_concurrent_access_to_database() {
    use std::thread;

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("concurrent.db");

    // Create initial database
    let _ = create_persistent_history(&db_path);

    // Spawn multiple threads accessing the same database
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let path = db_path.clone();
            thread::spawn(move || {
                let history = TransactionHistory::new(&path).expect("create history");

                // Each thread records some transactions
                for j in 0..10 {
                    let hash = format!("0xthread{i}_tx{j}");
                    history
                        .record("ETH", U256::from(ONE_ETH / 10), &hash)
                        .expect("record");
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().expect("thread join");
    }

    // Verify all transactions were recorded
    let history = create_persistent_history(&db_path);
    let records = history.get_transactions("ETH", 100).expect("get");

    // 5 threads * 10 transactions = 50 total
    assert_eq!(records.len(), 50);

    // Total should be 5 ETH (50 * 0.1 ETH)
    let total = history.daily_total("ETH").expect("total");
    assert_eq!(total, U256::from(5 * ONE_ETH));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_zero_amount_transactions_persist() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    {
        let history = create_persistent_history(&db_path);
        history
            .record("ETH", U256::ZERO, "0xzero")
            .expect("record zero");
        history
            .record("ETH", U256::from(ONE_ETH), "0xone")
            .expect("record one");
    }

    {
        let history = create_persistent_history(&db_path);
        let records = history.get_transactions("ETH", 100).expect("get");
        assert_eq!(records.len(), 2);

        let total = history.daily_total("ETH").expect("total");
        assert_eq!(total, U256::from(ONE_ETH));
    }
}

#[test]
fn test_large_amounts_persist_correctly() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    // Use a very large amount (1 million ETH)
    let large_amount = U256::from(1_000_000u64) * U256::from(ONE_ETH);

    {
        let history = create_persistent_history(&db_path);
        history
            .record("ETH", large_amount, "0xlarge")
            .expect("record large");
    }

    {
        let history = create_persistent_history(&db_path);
        let total = history.daily_total("ETH").expect("total");
        assert_eq!(total, large_amount);
    }
}

#[test]
fn test_special_characters_in_token_name() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history.db");

    {
        let history = create_persistent_history(&db_path);
        history
            .record("TOKEN-V2", U256::from(1000u64), "0xspecial")
            .expect("record special");
    }

    {
        let history = create_persistent_history(&db_path);
        let total = history.daily_total("TOKEN-V2").expect("total");
        assert_eq!(total, U256::from(1000u64));
    }
}
