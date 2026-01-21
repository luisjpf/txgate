//! Performance benchmarks for sello-policy evaluation.
//!
//! This module benchmarks policy engine operations:
//! - Policy rule evaluation (whitelist, blacklist, limits)
//! - Transaction recording for daily limits
//! - Combined policy checks with all rules enabled

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use alloy_primitives::U256;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sello_core::types::{ParsedTx, TxType};
use sello_policy::{
    config::PolicyConfig,
    engine::{DefaultPolicyEngine, PolicyEngine},
    history::TransactionHistory,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Helper to create ETH amounts (in wei) that may exceed u64.
/// Uses multiplication to avoid literal overflow.
fn eth_to_wei(eth: u64) -> U256 {
    U256::from(eth) * U256::from(1_000_000_000_000_000_000u64)
}

/// Helper to create a basic test transaction.
fn create_test_tx(recipient: Option<&str>, amount: Option<U256>) -> ParsedTx {
    ParsedTx {
        hash: [0xab; 32],
        recipient: recipient.map(String::from),
        amount,
        token: Some("ETH".to_string()),
        token_address: None,
        tx_type: TxType::Transfer,
        chain: "ethereum".to_string(),
        nonce: Some(1),
        chain_id: Some(1),
        metadata: HashMap::new(),
    }
}

/// Helper to create a token transfer transaction.
fn create_token_tx(recipient: Option<&str>, amount: Option<U256>, token_address: &str) -> ParsedTx {
    ParsedTx {
        hash: [0xcd; 32],
        recipient: recipient.map(String::from),
        amount,
        token: Some("USDC".to_string()),
        token_address: Some(token_address.to_string()),
        tx_type: TxType::TokenTransfer,
        chain: "ethereum".to_string(),
        nonce: Some(2),
        chain_id: Some(1),
        metadata: HashMap::new(),
    }
}

/// Benchmark policy check with empty configuration (no rules).
///
/// This represents the baseline performance when no policy rules are configured.
fn benchmark_policy_empty_config(c: &mut Criterion) {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    let tx = create_test_tx(
        Some("0xRecipient"),
        Some(U256::from(1_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/empty_config", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark blacklist check.
fn benchmark_policy_blacklist_check(c: &mut Criterion) {
    // Create config with 100 blacklisted addresses
    let blacklist: Vec<String> = (0..100).map(|i| format!("0xBLACKLIST{i:04}")).collect();

    let config = PolicyConfig::new().with_blacklist(blacklist);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    // Transaction to a non-blacklisted address
    let tx = create_test_tx(
        Some("0xGOOD"),
        Some(U256::from(1_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/blacklist_check_allowed", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx)).unwrap();
            black_box(result)
        });
    });

    // Transaction to a blacklisted address
    let tx_blocked = create_test_tx(
        Some("0xBLACKLIST0050"),
        Some(U256::from(1_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/blacklist_check_denied", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_blocked)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark whitelist check.
fn benchmark_policy_whitelist_check(c: &mut Criterion) {
    // Create config with 100 whitelisted addresses
    let whitelist: Vec<String> = (0..100).map(|i| format!("0xWHITELIST{i:04}")).collect();

    let config = PolicyConfig::new().with_whitelist(whitelist);
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    // Transaction to a whitelisted address
    let tx = create_test_tx(
        Some("0xWHITELIST0050"),
        Some(U256::from(1_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/whitelist_check_allowed", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx)).unwrap();
            black_box(result)
        });
    });

    // Transaction to a non-whitelisted address
    let tx_blocked = create_test_tx(
        Some("0xNOT_WHITELISTED"),
        Some(U256::from(1_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/whitelist_check_denied", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_blocked)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark transaction limit check.
fn benchmark_policy_transaction_limit(c: &mut Criterion) {
    let config = PolicyConfig::new()
        .with_transaction_limit("ETH", U256::from(10_000_000_000_000_000_000u64)); // 10 ETH

    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    // Transaction within limit
    let tx_within = create_test_tx(
        Some("0xRecipient"),
        Some(U256::from(5_000_000_000_000_000_000u64)),
    ); // 5 ETH

    c.bench_function("policy/tx_limit_check_allowed", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_within)).unwrap();
            black_box(result)
        });
    });

    // Transaction exceeding limit
    let tx_exceeds = create_test_tx(
        Some("0xRecipient"),
        Some(U256::from(15_000_000_000_000_000_000u64)),
    ); // 15 ETH

    c.bench_function("policy/tx_limit_check_denied", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_exceeds)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark daily limit check (includes history lookup).
fn benchmark_policy_daily_limit(c: &mut Criterion) {
    let config = PolicyConfig::new().with_daily_limit("ETH", eth_to_wei(100)); // 100 ETH

    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

    // Pre-record some transactions to simulate daily usage
    for i in 0..10 {
        let tx = create_test_tx(Some("0xRecipient"), Some(eth_to_wei(5))); // 5 ETH each
        let mut tx_with_hash = tx;
        tx_with_hash.hash = [i; 32]; // Unique hash
        engine.record(&tx_with_hash).unwrap();
    }

    // Transaction within remaining daily limit (50 ETH used, 50 remaining)
    let tx_within = create_test_tx(Some("0xRecipient"), Some(eth_to_wei(30))); // 30 ETH

    c.bench_function("policy/daily_limit_check_allowed", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_within)).unwrap();
            black_box(result)
        });
    });

    // Transaction exceeding daily limit
    let tx_exceeds = create_test_tx(Some("0xRecipient"), Some(eth_to_wei(60))); // 60 ETH

    c.bench_function("policy/daily_limit_check_denied", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_exceeds)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark combined policy check with all rules enabled.
fn benchmark_policy_full_evaluation(c: &mut Criterion) {
    // Create a realistic policy config with all rule types
    let whitelist: Vec<String> = (0..50).map(|i| format!("0xWHITELIST{i:04}")).collect();
    let blacklist: Vec<String> = (0..20).map(|i| format!("0xBLACKLIST{i:04}")).collect();

    let config = PolicyConfig::new()
        .with_whitelist(whitelist)
        .with_blacklist(blacklist)
        .with_transaction_limit("ETH", eth_to_wei(10)) // 10 ETH
        .with_daily_limit("ETH", eth_to_wei(100)); // 100 ETH

    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

    // Transaction that passes all checks
    let tx_allowed = create_test_tx(
        Some("0xWHITELIST0025"),
        Some(U256::from(5_000_000_000_000_000_000u64)),
    );

    c.bench_function("policy/full_evaluation_allowed", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx_allowed)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark transaction recording for daily limit tracking.
fn benchmark_policy_record_transaction(c: &mut Criterion) {
    let config = PolicyConfig::new();
    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    let mut counter = 0u32;

    c.bench_function("policy/record_transaction", |b| {
        b.iter(|| {
            // Create unique transaction for each iteration
            let mut tx = create_test_tx(
                Some("0xRecipient"),
                Some(U256::from(1_000_000_000_000_000_000u64)),
            );
            let bytes = counter.to_be_bytes();
            tx.hash[0..4].copy_from_slice(&bytes);
            counter = counter.wrapping_add(1);

            engine.record(black_box(&tx)).unwrap();
            black_box(())
        });
    });
}

/// Benchmark token-specific limit checks.
fn benchmark_policy_token_limits(c: &mut Criterion) {
    let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC

    let config = PolicyConfig::new()
        .with_transaction_limit(token_address, U256::from(10_000_000_000u64)) // 10,000 USDC
        .with_daily_limit(token_address, U256::from(100_000_000_000u64)); // 100,000 USDC

    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    let tx = create_token_tx(
        Some("0xRecipient"),
        Some(U256::from(5_000_000_000u64)),
        token_address,
    );

    c.bench_function("policy/token_limit_check", |b| {
        b.iter(|| {
            let result = engine.check(black_box(&tx)).unwrap();
            black_box(result)
        });
    });
}

/// Benchmark policy evaluation throughput.
fn benchmark_policy_throughput(c: &mut Criterion) {
    let config = PolicyConfig::new()
        .with_transaction_limit("ETH", U256::from(10_000_000_000_000_000_000u64));

    let history = Arc::new(TransactionHistory::in_memory().unwrap());
    let engine = DefaultPolicyEngine::new(config, history).unwrap();

    let mut group = c.benchmark_group("policy_throughput");

    // Different transaction amounts
    for amount_eth in [1u64, 5, 10] {
        let amount = U256::from(amount_eth * 1_000_000_000_000_000_000u64);
        let tx = create_test_tx(Some("0xRecipient"), Some(amount));

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("amount_eth", amount_eth), &tx, |b, tx| {
            b.iter(|| {
                let result = engine.check(black_box(tx)).unwrap();
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark scaling with number of whitelist entries.
fn benchmark_policy_whitelist_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_whitelist_scaling");

    for size in [10, 50, 100, 500, 1000] {
        let whitelist: Vec<String> = (0..size).map(|i| format!("0xWHITELIST{i:04}")).collect();

        let config = PolicyConfig::new().with_whitelist(whitelist);
        let history = Arc::new(TransactionHistory::in_memory().unwrap());
        let engine = DefaultPolicyEngine::new(config, history).unwrap();

        // Check an address in the middle of the list
        let tx = create_test_tx(
            Some(&format!("0xWHITELIST{:04}", size / 2)),
            Some(U256::from(1u64)),
        );

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("entries", size), &tx, |b, tx| {
            b.iter(|| {
                let result = engine.check(black_box(tx)).unwrap();
                black_box(result)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_policy_empty_config,
    benchmark_policy_blacklist_check,
    benchmark_policy_whitelist_check,
    benchmark_policy_transaction_limit,
    benchmark_policy_daily_limit,
    benchmark_policy_full_evaluation,
    benchmark_policy_record_transaction,
    benchmark_policy_token_limits,
    benchmark_policy_throughput,
    benchmark_policy_whitelist_scaling,
);

criterion_main!(benches);
