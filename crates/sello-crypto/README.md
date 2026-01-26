# sello-crypto

[![Crates.io](https://img.shields.io/crates/v/sello-crypto.svg)](https://crates.io/crates/sello-crypto)
[![Documentation](https://docs.rs/sello-crypto/badge.svg)](https://docs.rs/sello-crypto)
[![License](https://img.shields.io/crates/l/sello-crypto.svg)](https://github.com/luisjpf/sello#license)

Cryptographic operations for the [Sello](https://crates.io/crates/sello) transaction signing service.

## Warning

**This is an internal crate with an unstable API.**

This crate is published to crates.io only as a dependency of the `sello` binary. The API may change without notice between versions.

**Do not depend on this crate directly.** Use the [`sello`](https://crates.io/crates/sello) crate instead.

## What's Inside

### Key Management
- `Secp256k1Signer` - ECDSA signing for Ethereum and Bitcoin
- `Ed25519Signer` - EdDSA signing for Solana
- Secure key generation with proper entropy

### Address Derivation
- Ethereum addresses (EIP-55 checksummed)
- Bitcoin P2WPKH addresses (bech32)
- Solana addresses (base58-encoded ed25519 public keys)

### Security Features
- All secret types implement `Zeroize` and `ZeroizeOnDrop`
- Constant-time signature verification
- Argon2id key derivation for encrypted storage
- ChaCha20-Poly1305 authenticated encryption

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
