//! Performance benchmarks for sello-chain transaction parsing.
//!
//! This module benchmarks transaction parsing for all supported transaction types:
//! - Legacy (Type 0) transactions
//! - EIP-2930 (Type 1) access list transactions
//! - EIP-1559 (Type 2) dynamic fee transactions
//! - ERC-20 token transfers and approvals

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::too_many_arguments)]

use alloy_primitives::{Address, Bytes, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sello_chain::{Chain, EthereumParser};

/// Helper to create a fake signature for transaction encoding.
fn fake_signature() -> alloy_primitives::Signature {
    alloy_primitives::Signature::new(
        U256::from(0xffff_ffff_ffff_ffffu64),
        U256::from(0xffff_ffff_ffff_ffffu64),
        false,
    )
}

/// Encode a legacy transaction with the given parameters.
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

/// Encode an EIP-2930 transaction with the given parameters.
fn encode_eip2930_tx(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<Address>,
    value: U256,
    data: Bytes,
) -> Vec<u8> {
    use alloy_consensus::{transaction::RlpEcdsaEncodableTx, TxEip2930};
    use alloy_primitives::TxKind;

    let tx = TxEip2930 {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to: to.map_or(TxKind::Create, TxKind::Call),
        value,
        input: data,
        access_list: Default::default(),
    };

    let mut buf = Vec::new();
    buf.push(0x01); // EIP-2930 type prefix
    tx.rlp_encode_signed(&fake_signature(), &mut buf);
    buf
}

/// Encode an EIP-1559 transaction with the given parameters.
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
    buf.push(0x02); // EIP-1559 type prefix
    tx.rlp_encode_signed(&fake_signature(), &mut buf);
    buf
}

/// Create ERC-20 transfer calldata.
fn erc20_transfer_calldata(to: Address, amount: U256) -> Bytes {
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to.as_slice());
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(data)
}

/// Create ERC-20 approve calldata.
fn erc20_approve_calldata(spender: Address, amount: U256) -> Bytes {
    let mut data = vec![0x09, 0x5e, 0xa7, 0xb3]; // approve selector
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(spender.as_slice());
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(data)
}

/// Create ERC-20 transferFrom calldata.
fn erc20_transfer_from_calldata(from: Address, to: Address, amount: U256) -> Bytes {
    let mut data = vec![0x23, 0xb8, 0x72, 0xdd]; // transferFrom selector
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(from.as_slice());
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to.as_slice());
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(data)
}

/// Benchmark parsing legacy (Type 0) transactions.
fn benchmark_parse_legacy_transaction(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let to_addr = Address::from([0x12; 20]);
    let raw = encode_legacy_tx(
        9,                                        // nonce
        20_000_000_000,                           // gas_price (20 gwei)
        21000,                                    // gas_limit
        Some(to_addr),                            // to
        U256::from(1_000_000_000_000_000_000u64), // value (1 ETH)
        Bytes::default(),                         // data
        Some(1),                                  // chain_id
    );

    c.bench_function("parsing/legacy_transfer", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing EIP-2930 (Type 1) transactions.
fn benchmark_parse_eip2930_transaction(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let to_addr = Address::from([0x12; 20]);
    let raw = encode_eip2930_tx(
        1,                                      // chain_id
        5,                                      // nonce
        10_000_000_000,                         // gas_price (10 gwei)
        21000,                                  // gas_limit
        Some(to_addr),                          // to
        U256::from(500_000_000_000_000_000u64), // value (0.5 ETH)
        Bytes::default(),                       // data
    );

    c.bench_function("parsing/eip2930_transfer", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing EIP-1559 (Type 2) transactions.
fn benchmark_parse_eip1559_transaction(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let to_addr = Address::from([0x12; 20]);
    let raw = encode_eip1559_tx(
        1,                                        // chain_id
        10,                                       // nonce
        1_000_000_000,                            // max_priority_fee_per_gas (1 gwei)
        100_000_000_000,                          // max_fee_per_gas (100 gwei)
        21000,                                    // gas_limit
        Some(to_addr),                            // to
        U256::from(1_000_000_000_000_000_000u64), // value (1 ETH)
        Bytes::default(),                         // data
    );

    c.bench_function("parsing/eip1559_transfer", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing contract deployment transactions.
fn benchmark_parse_contract_deployment(c: &mut Criterion) {
    let parser = EthereumParser::new();
    // Simulated bytecode (small for benchmark)
    let bytecode = Bytes::from([0x60, 0x80, 0x60, 0x40, 0x52].repeat(20));
    let raw = encode_eip1559_tx(
        1,              // chain_id
        0,              // nonce
        1_000_000_000,  // max_priority_fee_per_gas
        50_000_000_000, // max_fee_per_gas
        500_000,        // gas_limit (higher for deployment)
        None,           // to = None for deployment
        U256::ZERO,     // value
        bytecode,       // data (bytecode)
    );

    c.bench_function("parsing/contract_deployment", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing ERC-20 transfer transactions.
fn benchmark_parse_erc20_transfer(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let token_contract = Address::from([0xaa; 20]);
    let recipient = Address::from([0xbb; 20]);
    let token_amount = U256::from(1_000_000u64); // 1 USDC

    let calldata = erc20_transfer_calldata(recipient, token_amount);
    let raw = encode_eip1559_tx(
        1,              // chain_id
        5,              // nonce
        1_000_000_000,  // max_priority_fee_per_gas
        50_000_000_000, // max_fee_per_gas
        100_000,        // gas_limit
        Some(token_contract),
        U256::ZERO, // value (no ETH sent)
        calldata,
    );

    c.bench_function("parsing/erc20_transfer", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing ERC-20 approve transactions.
fn benchmark_parse_erc20_approve(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let token_contract = Address::from([0xaa; 20]);
    let spender = Address::from([0xcc; 20]);
    let approval_amount = U256::MAX; // Unlimited approval

    let calldata = erc20_approve_calldata(spender, approval_amount);
    let raw = encode_eip1559_tx(
        1,              // chain_id
        6,              // nonce
        1_000_000_000,  // max_priority_fee_per_gas
        50_000_000_000, // max_fee_per_gas
        60_000,         // gas_limit
        Some(token_contract),
        U256::ZERO,
        calldata,
    );

    c.bench_function("parsing/erc20_approve", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing ERC-20 transferFrom transactions.
fn benchmark_parse_erc20_transfer_from(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let token_contract = Address::from([0xaa; 20]);
    let from_addr = Address::from([0xdd; 20]);
    let to_addr = Address::from([0xee; 20]);
    let token_amount = U256::from(500_000_000_000_000_000u64);

    let calldata = erc20_transfer_from_calldata(from_addr, to_addr, token_amount);
    let raw = encode_eip1559_tx(
        1,              // chain_id
        7,              // nonce
        1_000_000_000,  // max_priority_fee_per_gas
        50_000_000_000, // max_fee_per_gas
        100_000,        // gas_limit
        Some(token_contract),
        U256::ZERO,
        calldata,
    );

    c.bench_function("parsing/erc20_transfer_from", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

/// Benchmark parsing throughput for different transaction types.
fn benchmark_parsing_throughput(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let to_addr = Address::from([0x12; 20]);

    let mut group = c.benchmark_group("parsing_throughput");

    // Legacy transaction
    let legacy = encode_legacy_tx(
        0,
        20_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
        Some(1),
    );
    group.throughput(Throughput::Bytes(legacy.len() as u64));
    group.bench_with_input(BenchmarkId::new("type", "legacy"), &legacy, |b, raw| {
        b.iter(|| {
            let parsed = parser.parse(black_box(raw)).unwrap();
            black_box(parsed)
        });
    });

    // EIP-2930 transaction
    let eip2930 = encode_eip2930_tx(
        1,
        0,
        20_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
    );
    group.throughput(Throughput::Bytes(eip2930.len() as u64));
    group.bench_with_input(BenchmarkId::new("type", "eip2930"), &eip2930, |b, raw| {
        b.iter(|| {
            let parsed = parser.parse(black_box(raw)).unwrap();
            black_box(parsed)
        });
    });

    // EIP-1559 transaction
    let eip1559 = encode_eip1559_tx(
        1,
        0,
        1_000_000_000,
        100_000_000_000,
        21000,
        Some(to_addr),
        U256::from(1_000_000_000_000_000_000u64),
        Bytes::default(),
    );
    group.throughput(Throughput::Bytes(eip1559.len() as u64));
    group.bench_with_input(BenchmarkId::new("type", "eip1559"), &eip1559, |b, raw| {
        b.iter(|| {
            let parsed = parser.parse(black_box(raw)).unwrap();
            black_box(parsed)
        });
    });

    group.finish();
}

/// Benchmark generic contract call parsing (non-ERC-20).
fn benchmark_parse_contract_call(c: &mut Criterion) {
    let parser = EthereumParser::new();
    let contract = Address::from([0x12; 20]);
    // Unknown function selector (not ERC-20)
    let calldata = Bytes::from(vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x00]);

    let raw = encode_eip1559_tx(
        1,              // chain_id
        0,              // nonce
        1_000_000_000,  // max_priority_fee_per_gas
        50_000_000_000, // max_fee_per_gas
        100_000,        // gas_limit
        Some(contract),
        U256::ZERO,
        calldata,
    );

    c.bench_function("parsing/generic_contract_call", |b| {
        b.iter(|| {
            let parsed = parser.parse(black_box(&raw)).unwrap();
            black_box(parsed)
        });
    });
}

criterion_group!(
    benches,
    benchmark_parse_legacy_transaction,
    benchmark_parse_eip2930_transaction,
    benchmark_parse_eip1559_transaction,
    benchmark_parse_contract_deployment,
    benchmark_parse_erc20_transfer,
    benchmark_parse_erc20_approve,
    benchmark_parse_erc20_transfer_from,
    benchmark_parsing_throughput,
    benchmark_parse_contract_call,
);

criterion_main!(benches);
