# Security Audit Checklist

This document tracks the security review status of Sello's critical components.

## Audit Status

| Component | Status | Last Reviewed | Reviewer |
|-----------|--------|---------------|----------|
| sello-crypto | Pending | - | - |
| sello-chain | Pending | - | - |
| sello-policy | Pending | - | - |
| sello (binary) | Pending | - | - |

## Cryptographic Code Review

### SecretKey (`crates/sello-crypto/src/keys.rs`)

- [ ] Verify `Zeroize` is correctly derived
- [ ] Verify `ZeroizeOnDrop` is correctly derived
- [ ] Confirm no `Clone` implementation exists
- [ ] Confirm `Debug` implementation does not expose key material
- [ ] Review all code paths that handle raw key bytes
- [ ] Verify constant-time operations where applicable

### Key Encryption (`crates/sello-crypto/src/encryption.rs`)

- [ ] Verify Argon2id parameters meet recommendations (64 MiB, 3 iterations, 4 lanes)
- [ ] Verify salt is generated with CSPRNG
- [ ] Verify nonce is generated with CSPRNG and never reused
- [ ] Verify ChaCha20-Poly1305 is correctly implemented
- [ ] Verify authentication tag is validated before decryption
- [ ] Review encrypted format versioning for future compatibility

### KeyPair and Signer (`crates/sello-crypto/src/keypair.rs`, `signer.rs`)

- [ ] Verify secp256k1 operations use k256 correctly
- [ ] Verify signature format includes recovery ID
- [ ] Verify Ethereum address derivation (keccak256 of uncompressed pubkey)
- [ ] Review key generation entropy source

## Transaction Parser Review

### Ethereum Parser (`crates/sello-chain/src/ethereum.rs`)

- [ ] Verify RLP decoding handles malformed input safely
- [ ] Verify all transaction types are correctly parsed (legacy, EIP-2930, EIP-1559)
- [ ] Verify recipient extraction is correct for all tx types
- [ ] Verify amount extraction is correct
- [ ] Verify transaction hash calculation matches Ethereum spec
- [ ] Review edge cases: zero value, contract creation, max values

### ERC-20 Detection (`crates/sello-chain/src/erc20.rs`)

- [ ] Verify function selector detection (transfer, approve, transferFrom)
- [ ] Verify ABI decoding is correct
- [ ] Verify calldata length validation
- [ ] Review handling of malformed calldata
- [ ] Verify token contract address extraction

## Policy Engine Review

### Policy Enforcement (`crates/sello-policy/src/engine.rs`)

- [ ] Verify blacklist is checked first (highest priority)
- [ ] Verify whitelist logic is correct when enabled
- [ ] Verify transaction limit comparison is correct
- [ ] Verify daily limit accumulation is correct
- [ ] Review rule evaluation order
- [ ] Test policy bypass attempts

### Transaction History (`crates/sello-policy/src/history.rs`)

- [ ] Verify SQLite queries are parameterized (no SQL injection)
- [ ] Verify daily total calculation is correct
- [ ] Verify cleanup of old transactions works
- [ ] Review concurrent access safety

## Binary and Server Review

### Unix Socket Server (`crates/sello/src/server/socket.rs`)

- [ ] Verify socket permissions are set to 0600
- [ ] Verify JSON-RPC parsing handles malformed input
- [ ] Review graceful shutdown handling
- [ ] Verify no sensitive data in error responses

### Audit Logging (`crates/sello/src/audit.rs`)

- [ ] Verify HMAC chain provides tamper evidence
- [ ] Verify log entries include all required fields
- [ ] Verify sensitive data is not logged (keys, passphrases)
- [ ] Review log rotation security

### File Permissions

- [ ] Verify `~/.sello` directory is created with 0700
- [ ] Verify key files are created with 0600
- [ ] Verify config files are created with 0600
- [ ] Verify socket is created with 0600

## Dependency Audit

Run `cargo audit` to check for known vulnerabilities:

```bash
cargo audit
```

### Pinned Cryptographic Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| k256 | 0.13 | secp256k1 operations |
| chacha20poly1305 | 0.10 | AEAD encryption |
| argon2 | 0.5 | Key derivation |
| zeroize | 1.7 | Memory safety |

## Known Issues

(None currently documented)

## Remediation Tracking

| Issue | Severity | Status | Fixed In |
|-------|----------|--------|----------|
| - | - | - | - |

## External Audit

No external security audit has been performed yet. This is recommended before production use with significant value at risk.

### Recommended Audit Scope

1. Cryptographic implementation correctness
2. Memory safety and secret handling
3. Policy bypass vulnerabilities
4. Parser correctness and edge cases
5. Dependency supply chain

## Continuous Security

- [ ] `cargo audit` runs on every CI build
- [ ] Fuzzing runs daily on transaction parsers
- [ ] Coverage enforced at 100% for critical modules
- [ ] Clippy denies `unwrap_used` and `panic` in production code
