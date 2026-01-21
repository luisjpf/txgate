# Sello Project Guidelines

## Project Overview

Sello is a self-hosted, chain-agnostic transaction signing server written in Rust. It parses raw transactions to extract recipients, amounts, and tokens, then enforces configurable policies before signing.

## Architecture

- **5-crate workspace**: `sello-core`, `sello-crypto`, `sello-chain`, `sello-policy`, `sello` (binary)
- **Trait-based DI**: All dependencies injected via traits for testability
- **Static dispatch**: For hot paths (signing), use generics
- **Trait objects**: For runtime chain selection (`Box<dyn Chain>`)

## Code Standards

### Rust Conventions

- Use `thiserror` for error types
- Use `#[derive(Debug, Clone, Serialize, Deserialize)]` where appropriate
- No `unsafe` blocks without explicit justification and audit
- No `.unwrap()` or `.expect()` in production code - use proper error handling
- Use `?` operator for error propagation

### Security Requirements

- All secret types must implement `Zeroize` and `ZeroizeOnDrop`
- No `Clone` or `Debug` that exposes secrets
- Constant-time operations for cryptographic comparisons
- File permissions: directories 0700, files 0600
- Validate all inputs at system boundaries

### Testing Requirements

- 100% coverage on `sello-crypto`, `sello-chain`, `sello-policy`
- Unit tests inline with `#[cfg(test)]` modules
- Integration tests in `tests/integration/`
- Property tests with `proptest` for invariants
- Fuzz tests with `cargo-fuzz` for parsers
- Use `cargo-llvm-cov` for coverage (not tarpaulin)

### Documentation

- All public items must have doc comments
- Include examples in doc comments where helpful
- Module-level documentation explaining purpose

## File Structure

```
crates/
├── sello-core/        # Shared types (ParsedTx, errors)
├── sello-crypto/      # Keys, signing, encryption
├── sello-chain/       # Chain parsers, registry
├── sello-policy/      # Policy engine, history
└── sello/             # Binary (CLI + server modules)
    ├── src/cli/       # CLI commands
    └── src/server/    # Unix socket + HTTP server
```

## Dependencies

### Core Dependencies
- `k256` - secp256k1 operations
- `ed25519-dalek` - ed25519 operations
- `chacha20poly1305` - AEAD encryption
- `argon2` - Key derivation (64 MiB, 3 iterations, 4 lanes)
- `zeroize` - Memory safety
- `alloy-consensus`, `alloy-primitives` - Ethereum types
- `tokio` - Async runtime
- `serde`, `serde_json`, `toml` - Serialization
- `clap` - CLI parsing
- `thiserror` - Error handling
- `rusqlite` - SQLite for transaction history

### Dev Dependencies
- `tempfile` - Test isolation
- `mockall` - Trait mocking
- `proptest` - Property testing
- `criterion` - Benchmarking

## Linting Rules

```toml
[lints.clippy]
unwrap_used = "deny"
panic = "deny"
indexing_slicing = "deny"
expect_used = "warn"
todo = "warn"
```

Run before committing:
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

## Commit Messages

Format:
```
<type>(<scope>): <description>

[optional body]

Generated with [Claude Code](https://claude.ai/code)
via [Happy](https://happy.engineering)

Co-Authored-By: Claude <noreply@anthropic.com>
Co-Authored-By: Happy <yesreply@happy.engineering>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`
Scopes: `core`, `crypto`, `chain`, `policy`, `cli`, `server`

## Task Reference

See `TASKS.md` for the complete task breakdown. Critical path:
```
SELLO-001 → 002 → 005 → 007 → 008 → 010 → 011 → 012 → 012.5 → 014 → 018 → 026 → 028 → 029 → 032
```

## Agent Instructions

When working on this project:

1. **Read TASKS.md** to understand task dependencies before starting
2. **Follow the critical path** - don't skip dependencies
3. **Write tests first** for crypto, chain, and policy code (TDD)
4. **Run lints and tests** before considering work complete
5. **Check coverage** on critical modules with `cargo llvm-cov`
6. **Reference ARCHITECTURE.md** for implementation details

## Security-Critical Tasks

These require extra scrutiny:
- SELLO-007: SecretKey zeroization
- SELLO-010: Key encryption
- SELLO-014: Ethereum parser
- SELLO-015: ERC-20 detection
- SELLO-018: Policy engine
- SELLO-031.5: Audit logging
