//! Performance benchmarks for txgate-crypto operations.
//!
//! This module benchmarks critical cryptographic operations:
//! - Key generation (secp256k1)
//! - Key encryption/decryption (ChaCha20-Poly1305 with Argon2id)
//! - Transaction signing (ECDSA secp256k1)

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use txgate_crypto::{
    decrypt_key, encrypt_key,
    keypair::{KeyPair, Secp256k1KeyPair},
    keys::SecretKey,
    signer::{Secp256k1Signer, Signer},
};

/// Benchmark secp256k1 key pair generation.
///
/// This measures the time to generate a new random secp256k1 key pair
/// using cryptographically secure random number generation.
fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation/secp256k1", |b| {
        b.iter(|| {
            let keypair = Secp256k1KeyPair::generate();
            black_box(keypair)
        });
    });
}

/// Benchmark secret key generation.
///
/// This measures the time to generate a raw 32-byte secret key
/// using cryptographically secure random number generation.
fn benchmark_secret_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation/secret_key", |b| {
        b.iter(|| {
            let secret = SecretKey::generate();
            black_box(secret)
        });
    });
}

/// Benchmark key encryption with ChaCha20-Poly1305 and Argon2id KDF.
///
/// This is a relatively slow operation due to the memory-hard Argon2id
/// key derivation function (64 MiB memory, 3 iterations).
fn benchmark_key_encryption(c: &mut Criterion) {
    let secret_key = SecretKey::generate();
    let passphrase = "benchmark-passphrase-test-123!";

    c.bench_function("key_encryption/chacha20_argon2id", |b| {
        b.iter(|| {
            let encrypted = encrypt_key(black_box(&secret_key), black_box(passphrase)).unwrap();
            black_box(encrypted)
        });
    });
}

/// Benchmark key decryption with ChaCha20-Poly1305 and Argon2id KDF.
///
/// This should take approximately the same time as encryption due to
/// the symmetric Argon2id operation.
fn benchmark_key_decryption(c: &mut Criterion) {
    let secret_key = SecretKey::generate();
    let passphrase = "benchmark-passphrase-test-123!";
    let encrypted = encrypt_key(&secret_key, passphrase).unwrap();

    c.bench_function("key_decryption/chacha20_argon2id", |b| {
        b.iter(|| {
            let decrypted = decrypt_key(black_box(&encrypted), black_box(passphrase)).unwrap();
            black_box(decrypted)
        });
    });
}

/// Benchmark transaction signing with secp256k1 ECDSA.
///
/// This measures the time to sign a 32-byte hash using RFC 6979
/// deterministic nonces.
fn benchmark_transaction_signing(c: &mut Criterion) {
    let signer = Secp256k1Signer::generate();
    let hash = [0x42u8; 32]; // Simulated transaction hash

    c.bench_function("signing/secp256k1_ecdsa", |b| {
        b.iter(|| {
            let signature = signer.sign(black_box(&hash)).unwrap();
            black_box(signature)
        });
    });
}

/// Benchmark key pair creation from raw bytes.
///
/// This measures the time to create a key pair from existing
/// secret key bytes (no random generation).
fn benchmark_keypair_from_bytes(c: &mut Criterion) {
    let bytes = [0x42u8; 32];

    c.bench_function("key_creation/from_bytes", |b| {
        b.iter(|| {
            let keypair = Secp256k1KeyPair::from_bytes(black_box(bytes)).unwrap();
            black_box(keypair)
        });
    });
}

/// Benchmark Ethereum address derivation from public key.
///
/// This measures the time to derive an Ethereum address from
/// a secp256k1 public key (Keccak-256 hash).
fn benchmark_ethereum_address_derivation(c: &mut Criterion) {
    let keypair = Secp256k1KeyPair::generate();
    let public_key = keypair.public_key();

    c.bench_function("address_derivation/ethereum", |b| {
        b.iter(|| {
            let address = public_key.ethereum_address();
            black_box(address)
        });
    });
}

/// Benchmark signing throughput with different message sizes.
///
/// Note: ECDSA always signs a 32-byte hash, but this shows
/// signing performance is constant regardless of "message" representation.
fn benchmark_signing_throughput(c: &mut Criterion) {
    let signer = Secp256k1Signer::generate();

    let mut group = c.benchmark_group("signing_throughput");

    // Different hash patterns (all 32 bytes, but shows consistency)
    for pattern in [0x00u8, 0x42u8, 0xffu8] {
        let hash = [pattern; 32];
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("pattern", format!("0x{pattern:02x}")),
            &hash,
            |b, hash| {
                b.iter(|| {
                    let signature = signer.sign(black_box(hash)).unwrap();
                    black_box(signature)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark signature verification.
fn benchmark_signature_verification(c: &mut Criterion) {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];
    let signature = keypair.sign(&hash).unwrap();

    c.bench_function("verification/secp256k1_ecdsa", |b| {
        b.iter(|| {
            let valid = keypair.verify(black_box(&hash), black_box(&signature));
            black_box(valid)
        });
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_secret_key_generation,
    benchmark_key_encryption,
    benchmark_key_decryption,
    benchmark_transaction_signing,
    benchmark_keypair_from_bytes,
    benchmark_ethereum_address_derivation,
    benchmark_signing_throughput,
    benchmark_signature_verification,
);

criterion_main!(benches);
