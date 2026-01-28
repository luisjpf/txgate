# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in TxGate, please report it by emailing
**security@txgate-project.org**. You should receive a response within 48 hours.

Please include the following information in your report:

- Type of vulnerability (e.g., key leakage, policy bypass, memory safety)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue and how an attacker might exploit it

## Security Model

TxGate is a transaction signing server with the following security boundaries:

### Trust Boundaries

1. **Key Material**: Private keys are encrypted at rest with ChaCha20-Poly1305, derived via Argon2id
2. **Memory Safety**: All secret types implement `Zeroize` and `ZeroizeOnDrop`
3. **Policy Enforcement**: All transactions must pass policy checks before signing
4. **Access Control**: Unix socket with filesystem permissions (0600)

### What TxGate Protects Against

- Unauthorized transaction signing (via policy engine)
- Key material exposure in memory dumps (via zeroization)
- Key theft from disk (via encryption at rest)
- Excessive spending (via transaction and daily limits)
- Transfers to blacklisted addresses

### What TxGate Does NOT Protect Against

- Compromise of the host system
- Physical access to the server
- Side-channel attacks on the host (timing, power analysis)
- Compromise of the passphrase
- Malicious configuration changes by authorized users

## Security-Critical Code

The following modules require extra scrutiny for any changes:

| Module | Path | Concern |
|--------|------|---------|
| SecretKey | `crates/txgate-crypto/src/keys.rs` | Memory zeroization |
| Encryption | `crates/txgate-crypto/src/encryption.rs` | Key derivation, AEAD |
| Ethereum Parser | `crates/txgate-chain/src/ethereum.rs` | Transaction parsing correctness |
| ERC-20 Detection | `crates/txgate-chain/src/erc20.rs` | Token operation detection |
| Policy Engine | `crates/txgate-policy/src/engine.rs` | Policy enforcement |
| Audit Logging | `crates/txgate/src/audit.rs` | Tamper-evident logging |
| Key Import | `crates/txgate/src/cli/commands/key/import.rs` | Secret key handling, zeroization |
| Key Export | `crates/txgate/src/cli/commands/key/export.rs` | Passphrase handling, re-encryption |
| Key Delete | `crates/txgate/src/cli/commands/key/delete.rs` | Confirmation bypass prevention |
| CLI Args | `crates/txgate/src/cli/args.rs` | Secret redaction in Debug |

## Security Testing

- **Unit Tests**: All crypto, parsing, and policy code has 100% test coverage
- **Fuzzing**: Transaction parsers are fuzzed with cargo-fuzz
- **Audit**: Dependencies audited with `cargo audit` on every CI run
- **Static Analysis**: Clippy with strict lints (deny `unwrap_used`, `panic`)

## Dependency Policy

- Cryptographic dependencies are pinned to specific versions
- All dependencies are audited for known vulnerabilities
- Minimal dependency footprint for security-critical crates

## Acknowledgments

We thank the following individuals for responsibly disclosing security issues:

(No reports yet)
