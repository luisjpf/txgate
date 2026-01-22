# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive server integration tests for concurrent requests and stress testing
- Persistence tests verifying daily limits survive server restarts
- Security policy documentation (`SECURITY.md`)
- Security audit checklist (`docs/SECURITY_AUDIT.md`)
- Release preparation script (`scripts/release.sh`)

### Changed

- Replaced Codecov with native PR coverage comments in CI
- Coverage thresholds enforced per-crate with PR comment reports
- Enabled security audit job (`cargo audit`) in CI

## [0.1.0] - 2025-01-21

### Added

- Initial release of Sello multi-chain transaction signing service
- **sello-core**: Core types, traits, and error definitions
  - Unified error handling with `SelloError`
  - Chain abstraction types (`ChainId`, `Address`, `TransactionData`)
  - Common traits for signing and validation
- **sello-crypto**: Cryptographic operations
  - ECDSA signing with secp256k1 (Ethereum-compatible)
  - Ed25519 signing (Solana-compatible)
  - Secure key storage with ChaCha20-Poly1305 encryption
  - Argon2id key derivation
  - Zeroizing memory for sensitive data
- **sello-chain**: Multi-chain transaction parsing
  - Ethereum transaction parsing (Legacy, EIP-1559, EIP-2930)
  - Transaction field extraction for policy evaluation
  - Extensible chain adapter architecture
- **sello-policy**: Policy engine for signing rules
  - Amount limit policies (per-transaction, daily, weekly, monthly)
  - Address allowlist/blocklist policies
  - Gas limit policies for Ethereum
  - Contract interaction policies
  - Policy composition with AND/OR logic
  - SQLite-backed policy storage with caching
- **sello**: CLI and server binary
  - Key generation and management commands
  - Policy configuration commands
  - Transaction signing commands
  - HTTP server for API access
  - Structured audit logging

### Security

- No unsafe code (`#![forbid(unsafe_code)]`)
- Comprehensive input validation
- Strict clippy lints enabled
- Fuzz testing for parser and policy engine
- 100% test coverage for security-critical crates

[Unreleased]: https://github.com/sello-project/sello/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sello-project/sello/releases/tag/v0.1.0
