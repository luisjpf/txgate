//! End-to-end signing throughput benchmark.
//!
//! This benchmark measures the full signing pipeline:
//! parse transaction → check policy → sign.
//!
//! It uses real implementations of all components (no mocks)
//! to measure true end-to-end throughput.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::too_many_arguments)]

use alloy_primitives::{Address, Bytes, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use txgate_chain::{Chain, EthereumParser};
use txgate_core::error::{ParseError, PolicyError, SignError};
use txgate_core::signing::{ChainParser, PolicyEngineExt, SignerExt, SigningService};
use txgate_core::types::{ParsedTx, PolicyResult};
use txgate_crypto::signer::{Secp256k1Signer, Signer};
use txgate_policy::config::PolicyConfig;
use txgate_policy::engine::{DefaultPolicyEngine, PolicyEngine};

// ============================================================================
// Adapters (bridge crate-local traits to txgate-core traits)
// ============================================================================

struct EthereumChainAdapter(EthereumParser);

impl ChainParser for EthereumChainAdapter {
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
        self.0.parse(raw)
    }
}

struct PolicyEngineAdapter(Arc<DefaultPolicyEngine>);

impl PolicyEngineExt for PolicyEngineAdapter {
    fn check(&self, tx: &ParsedTx) -> Result<PolicyResult, PolicyError> {
        PolicyEngine::check(&*self.0, tx)
    }
}

struct RealSigner(Secp256k1Signer);

impl SignerExt for RealSigner {
    fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        Signer::sign(&self.0, hash)
    }
}

// ============================================================================
// Transaction builders (from parsing_bench.rs)
// ============================================================================

fn fake_signature() -> alloy_primitives::Signature {
    alloy_primitives::Signature::new(
        U256::from(0xffff_ffff_ffff_ffffu64),
        U256::from(0xffff_ffff_ffff_ffffu64),
        false,
    )
}

fn encode_legacy_tx(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<Address>,
    value: U256,
    data: Bytes,
    chain_id: Option<u64>,
) -> Vec<u8> {
    use alloy_consensus::{transaction::RlpEcdsaEncodableTx, TxLegacy};
    use alloy_primitives::TxKind;

    let tx = TxLegacy {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to: to.map_or(TxKind::Create, TxKind::Call),
        value,
        input: data,
    };

    let mut buf = Vec::new();
    tx.rlp_encode_signed(&fake_signature(), &mut buf);
    buf
}

fn encode_eip1559_tx(
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Option<Address>,
    value: U256,
    data: Bytes,
) -> Vec<u8> {
    use alloy_consensus::{transaction::RlpEcdsaEncodableTx, TxEip1559};
    use alloy_primitives::TxKind;

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to: to.map_or(TxKind::Create, TxKind::Call),
        value,
        input: data,
        access_list: Default::default(),
    };

    let mut buf = Vec::new();
    buf.push(0x02);
    tx.rlp_encode_signed(&fake_signature(), &mut buf);
    buf
}

fn erc20_transfer_calldata(to: Address, amount: U256) -> Bytes {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to.as_slice());
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(data)
}

// ============================================================================
// Service factory
// ============================================================================

fn build_service(
    config: PolicyConfig,
) -> SigningService<EthereumChainAdapter, PolicyEngineAdapter, RealSigner> {
    let engine = Arc::new(DefaultPolicyEngine::new(config).unwrap());
    let signer = Secp256k1Signer::generate();

    SigningService::new(
        EthereumChainAdapter(EthereumParser::new()),
        PolicyEngineAdapter(engine),
        RealSigner(signer),
    )
}

// ============================================================================
// Benchmarks
// ============================================================================

/// E2E: parse → policy (empty config) → sign for a simple ETH transfer.
fn bench_e2e_simple_transfer(c: &mut Criterion) {
    let service = build_service(PolicyConfig::new());

    let to_addr = Address::from([0x12; 20]);
    let raw = encode_eip1559_tx(
        1,
        10,
        1_000_000_000,
        100_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64), // 1 ETH
        Bytes::default(),
    );

    c.bench_function("e2e/simple_eth_transfer", |b| {
        b.iter(|| {
            let result = service.sign(black_box(&raw)).unwrap();
            black_box(result)
        });
    });
}

/// E2E: parse → policy (empty config) → sign for a legacy tx.
fn bench_e2e_legacy_transfer(c: &mut Criterion) {
    let service = build_service(PolicyConfig::new());

    let to_addr = Address::from([0x12; 20]);
    let raw = encode_legacy_tx(
        9,
        20_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
        Some(1),
    );

    c.bench_function("e2e/legacy_eth_transfer", |b| {
        b.iter(|| {
            let result = service.sign(black_box(&raw)).unwrap();
            black_box(result)
        });
    });
}

/// E2E: parse → policy (empty config) → sign for an ERC-20 transfer.
fn bench_e2e_erc20_transfer(c: &mut Criterion) {
    let service = build_service(PolicyConfig::new());

    let token_contract = Address::from([0xaa; 20]);
    let recipient = Address::from([0xbb; 20]);
    let calldata = erc20_transfer_calldata(recipient, U256::from(1_000_000u64));

    let raw = encode_eip1559_tx(
        1,
        5,
        1_000_000_000,
        50_000_000_000,
        100_000,
        Some(token_contract),
        U256::ZERO,
        calldata,
    );

    c.bench_function("e2e/erc20_transfer", |b| {
        b.iter(|| {
            let result = service.sign(black_box(&raw)).unwrap();
            black_box(result)
        });
    });
}

/// E2E with full policy: whitelist + transaction limit.
fn bench_e2e_full_policy(c: &mut Criterion) {
    let to_addr = Address::from([0x12; 20]);
    let to_hex = format!("0x{}", hex::encode(to_addr));

    let config = PolicyConfig::new()
        .with_whitelist(vec![to_hex])
        .with_transaction_limit(
            "ETH",
            U256::from(10u64) * U256::from(1_000_000_000_000_000_000u64),
        );

    let service = build_service(config);

    let raw = encode_eip1559_tx(
        1,
        10,
        1_000_000_000,
        100_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
    );

    c.bench_function("e2e/full_policy_eth_transfer", |b| {
        b.iter(|| {
            let result = service.sign(black_box(&raw)).unwrap();
            black_box(result)
        });
    });
}

/// Throughput benchmark: how many signatures per second across tx types.
fn bench_e2e_throughput(c: &mut Criterion) {
    let service = build_service(PolicyConfig::new());
    let to_addr = Address::from([0x12; 20]);

    let mut group = c.benchmark_group("e2e_throughput");

    // EIP-1559 ETH transfer
    let eip1559_raw = encode_eip1559_tx(
        1,
        10,
        1_000_000_000,
        100_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
    );
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("tx_type", "eip1559_eth"),
        &eip1559_raw,
        |b, raw| {
            b.iter(|| {
                let result = service.sign(black_box(raw)).unwrap();
                black_box(result)
            });
        },
    );

    // Legacy ETH transfer
    let legacy_raw = encode_legacy_tx(
        0,
        20_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
        Some(1),
    );
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("tx_type", "legacy_eth"),
        &legacy_raw,
        |b, raw| {
            b.iter(|| {
                let result = service.sign(black_box(raw)).unwrap();
                black_box(result)
            });
        },
    );

    // ERC-20 transfer
    let token_contract = Address::from([0xaa; 20]);
    let recipient = Address::from([0xbb; 20]);
    let calldata = erc20_transfer_calldata(recipient, U256::from(1_000_000u64));
    let erc20_raw = encode_eip1559_tx(
        1,
        5,
        1_000_000_000,
        50_000_000_000,
        100_000,
        Some(token_contract),
        U256::ZERO,
        calldata,
    );
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("tx_type", "erc20_transfer"),
        &erc20_raw,
        |b, raw| {
            b.iter(|| {
                let result = service.sign(black_box(raw)).unwrap();
                black_box(result)
            });
        },
    );

    group.finish();
}

/// Concurrent throughput benchmark: measures aggregate signatures/sec across
/// all available CPU cores. Each iteration dispatches N parallel signing
/// operations (one per core) via `std::thread::scope`, mirroring how the
/// server handles concurrent requests.
fn bench_concurrent_throughput(c: &mut Criterion) {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let to_addr = Address::from([0x12; 20]);
    let to_hex = format!("0x{}", hex::encode(to_addr));

    // Full policy config (whitelist + tx limit)
    let config = PolicyConfig::new()
        .with_whitelist(vec![to_hex])
        .with_transaction_limit(
            "ETH",
            U256::from(10u64) * U256::from(1_000_000_000_000_000_000u64),
        );

    // Shared components (mirrors server's Arc-based sharing)
    let engine = Arc::new(DefaultPolicyEngine::new(config).unwrap());
    let parser = Arc::new(EthereumParser::new());

    // Each core gets its own signer (keys are per-thread in practice)
    let signers: Vec<Arc<Secp256k1Signer>> = (0..num_cores)
        .map(|_| Arc::new(Secp256k1Signer::generate()))
        .collect();

    let raw = encode_eip1559_tx(
        1,
        10,
        1_000_000_000,
        100_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
    );

    let mut group = c.benchmark_group("concurrent_throughput");

    // Benchmark: N parallel signings per iteration
    group.throughput(Throughput::Elements(num_cores as u64));
    group.bench_function(
        BenchmarkId::new("full_policy", format!("{num_cores}_cores")),
        |b| {
            b.iter(|| {
                std::thread::scope(|s| {
                    let handles: Vec<_> = (0..num_cores)
                        .map(|i| {
                            let engine = Arc::clone(&engine);
                            let parser = Arc::clone(&parser);
                            let signer = Arc::clone(&signers[i]);
                            let raw = &raw;
                            s.spawn(move || {
                                let parsed = parser.parse(black_box(raw)).unwrap();
                                let result = PolicyEngine::check(&*engine, &parsed).unwrap();
                                assert!(matches!(result, PolicyResult::Allowed));
                                let sig = Signer::sign(&*signer, &parsed.hash).unwrap();
                                black_box(sig);
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                });
            });
        },
    );

    // Also benchmark without policy for comparison
    let no_policy_engine = Arc::new(DefaultPolicyEngine::new(PolicyConfig::new()).unwrap());

    group.throughput(Throughput::Elements(num_cores as u64));
    group.bench_function(
        BenchmarkId::new("no_policy", format!("{num_cores}_cores")),
        |b| {
            b.iter(|| {
                std::thread::scope(|s| {
                    let handles: Vec<_> = (0..num_cores)
                        .map(|i| {
                            let engine = Arc::clone(&no_policy_engine);
                            let parser = Arc::clone(&parser);
                            let signer = Arc::clone(&signers[i]);
                            let raw = &raw;
                            s.spawn(move || {
                                let parsed = parser.parse(black_box(raw)).unwrap();
                                let result = PolicyEngine::check(&*engine, &parsed).unwrap();
                                assert!(matches!(result, PolicyResult::Allowed));
                                let sig = Signer::sign(&*signer, &parsed.hash).unwrap();
                                black_box(sig);
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                });
            });
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_e2e_simple_transfer,
    bench_e2e_legacy_transfer,
    bench_e2e_erc20_transfer,
    bench_e2e_full_policy,
    bench_e2e_throughput,
    bench_concurrent_throughput,
);

criterion_main!(benches);
