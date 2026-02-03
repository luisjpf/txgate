# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-02-02

### Added

- **Claude Code skill**: Added `contrib/claude-skill/` with a skill that teaches Claude how to use the TxGate CLI, including CLI reference and configuration reference.
- **`txgate install-skill` command**: Prints installation instructions for the Claude Code skill. Does not write to the filesystem.

### Fixed

- Fixed `key list --verbose` references in USER_GUIDE.md to `key list --details` (matching actual CLI flag).

## [0.2.0] - 2026-01-30

### Added

- **Multi-chain support**: Added Bitcoin and Solana transaction parsers (`txgate-chain`).
  - `BitcoinParser`: Parses Legacy, SegWit v0, and Taproot transactions.
    - Extracts recipients from P2PKH, P2SH, P2WPKH, P2WSH, P2TR outputs.
    - Computes txid, vsize, weight for fee estimation.
    - Supports mainnet, testnet, signet, and regtest networks.
  - `SolanaParser`: Parses Legacy and Versioned (V0) messages.
    - Detects SOL transfers via System Program.
    - Detects SPL Token transfers (Token and Token-2022 programs).
    - Extracts fee payer, recent blockhash, and instruction details.
  - `ChainRegistry` now registers all three parsers (Ethereum, Bitcoin, Solana) by default.
- Added `.github/CODEOWNERS` for automatic review routing on security-critical paths.

### Changed

- Consolidated all dependencies to workspace-level management.
- **Publishing strategy**: All crates are now published to crates.io to enable
  `cargo install txgate`. Library crates (`txgate-core`, `txgate-crypto`, `txgate-chain`,
  `txgate-policy`) are marked as internal with unstable APIs - users should only
  depend on the `txgate` binary crate directly. Publishing all crates prevents name
  squatting attacks and provides the expected Rust installation experience.

### Removed

- **Daily limits feature**: Removed SQLite-backed transaction history, daily spending limits, `rusqlite`, `r2d2`, and `lru` dependencies. The policy engine is now fully stateless.

## [0.1.0] - 2026-01-23

### Added

#### Core Infrastructure

- Five-crate workspace architecture: `txgate-core`, `txgate-crypto`, `txgate-chain`, `txgate-policy`, and `txgate` binary.
- Comprehensive error types with `thiserror` for all modules.
- Trait-based dependency injection for testability.

#### Cryptography (`txgate-crypto`)

- `SecretKey` type with automatic memory zeroization (`Zeroize`, `ZeroizeOnDrop`).
- Secp256k1 key pair generation and management using `k256`.
- Ed25519 key pair support using `ed25519-dalek`.
- Key encryption at rest with ChaCha20-Poly1305 AEAD.
- Argon2id key derivation (64 MiB memory, 3 iterations, 4 lanes).
- File-based key store with proper permissions (0700 directories, 0600 files).
- Atomic file writes using temp files and rename.
- Constant-time comparisons for cryptographic operations.

#### Transaction Parsing (`txgate-chain`)

- `Chain` trait for pluggable blockchain parsers.
- `ChainRegistry` for runtime chain lookup and management.
- Ethereum transaction parser supporting:
  - Legacy transactions (type 0)
  - EIP-2930 access list transactions (type 1)
  - EIP-1559 dynamic fee transactions (type 2)
- ERC-20 token operation detection:
  - `transfer(address,uint256)` - token transfers
  - `approve(address,uint256)` - spending approvals
  - `transferFrom(address,address,uint256)` - delegated transfers
- Built-in token registry with major stablecoins (USDC, USDT, DAI).

#### Policy Engine (`txgate-policy`)

- `PolicyEngine` trait for configurable transaction approval rules.
- SQLite-backed transaction history for daily limit tracking.
- Policy rules:
  - Address whitelist/blacklist
  - Per-token transaction limits
  - Per-token daily spending limits
- LRU caching for efficient daily total queries.
- Connection pooling with `r2d2` for concurrent access.

#### CLI (`txgate` binary)

- `txgate init` - Initialize TxGate with encrypted key generation.
- `txgate status` - Display current configuration and key status.
- `txgate config` - View and edit configuration.
- `txgate keys list` - List all stored keys.
- `txgate keys generate` - Generate new key pairs.
- `txgate keys import` - Import existing private keys.
- `txgate keys export` - Export public keys or encrypted private keys.
- `txgate keys delete` - Remove keys from storage.
- `txgate ethereum address` - Display Ethereum address for a key.
- `txgate ethereum sign` - Parse, validate, and sign Ethereum transactions.
- `txgate serve` - Start JSON-RPC server on Unix socket.

#### Server

- JSON-RPC 2.0 protocol over Unix socket.
- Concurrent connection handling with Tokio.
- Graceful shutdown on SIGTERM/SIGINT.
- Socket permissions enforcement (0600).

#### Audit Logging

- Tamper-evident audit logs with HMAC chain.
- JSONL format for structured logging.
- Automatic log rotation by size.
- Log verification command for integrity checking.

#### Security

- `unsafe_code = "forbid"` enforced at workspace level.
- Strict Clippy lints: `unwrap_used`, `panic`, `indexing_slicing` denied.
- No `Clone` or `Debug` that exposes secret material.
- Comprehensive input validation at system boundaries.

#### Testing & Quality

- Unit tests with 100% coverage target for critical crates.
- Integration tests for full signing flow.
- Property-based testing with `proptest`.
- Fuzz testing with `cargo-fuzz` for parsers and policy rules.
- Code coverage with `cargo-llvm-cov`.

#### CI/CD

- GitHub Actions workflow for build, test, lint, and coverage.
- Multi-platform release builds (Linux x86_64, macOS x86_64/aarch64).
- Automated security audit with `cargo audit`.
- Scheduled daily fuzz testing with crash reporting.
- Automatic crates.io publishing on release tags.

#### Documentation

- Comprehensive README with installation and quickstart.
- Architecture documentation with diagrams.
- User guide covering all CLI commands.
- Developer guide with IDE setup and debugging.
- Security policy with vulnerability reporting process.
- Contributing guidelines with code style requirements.

### Security

- All cryptographic keys are zeroized on drop.
- File permissions enforced on key storage (0600).
- Constant-time operations for secret comparisons.
- Audit logging provides forensic evidence for security incidents.

[Unreleased]: https://github.com/luisjpf/txgate/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/luisjpf/txgate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/luisjpf/txgate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/luisjpf/txgate/releases/tag/v0.1.0
