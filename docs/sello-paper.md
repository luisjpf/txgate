# Sello

**Secure, Self-Hosted Transaction Signing with Policy Enforcement**

> A chain-agnostic signing oracle that parses transactions, enforces policies, and never exposes private keys.

---

## Abstract

Private key compromise remains the dominant attack vector in cryptocurrency, accounting for 43.8% of stolen funds in 2024 ($2.2B total). Existing solutions are either prohibitively expensive (Fireblocks at $15K+/year), operationally complex (MPC clusters requiring extensive infrastructure), or lack policy enforcement entirely.

Sello is an open-source, self-hosted signing server written in Rust that:

- Parses raw transactions to extract recipient, amount, and token
- Enforces configurable policies (daily limits, whitelists, blacklists)
- Signs only when policy checks pass
- Runs as a single binary with zero external dependencies
- Supports the top 5 chains by transaction volume

The name comes from Spanish: *sello* means "seal" - every transaction gets your seal of approval, but only if policy allows.

The architecture prioritizes simplicity, security, and testability through strict abstraction boundaries and Rust's type system.

---

## Problem

### The Security Gap

| Solution | Self-Hosted | Policy Engine | Simple Setup | Cost |
|----------|-------------|---------------|--------------|------|
| Fireblocks | ✗ | ✓ | ✗ | $15K+/yr |
| BitGo | ✗ | ✓ | ✗ | Enterprise |
| mpcium | ✓ | ✗ | ✗ | Free |
| Gnosis Safe | ✓ | ✗ | ✓ | Free |
| **Sello** | **✓** | **✓** | **✓** | **Free** |

### The Trust Problem

Chain-agnostic signers that only see hashes cannot enforce meaningful policies:

```
Client claims: "Sign 1 ETH to 0xAlice"
Client sends:  hash = 0xabc123...
Reality:       Hash is actually 1000 ETH to 0xAttacker
```

Without parsing the transaction, policy enforcement is theater.

### The Complexity Problem

Existing self-hosted solutions require:
- Multiple nodes (3+ for MPC)
- Message queues (NATS, RabbitMQ)
- Service discovery (Consul, etcd)
- Complex key ceremonies
- Extensive configuration

Time to first signature: 1-2 hours minimum.

---

## Solution

Sello is a single binary that:

1. **Parses** raw transactions using chain-specific modules
2. **Extracts** a unified context (recipient, amount, token)
3. **Enforces** policy rules against the extracted context
4. **Signs** only when all policy checks pass
5. **Logs** everything for audit

```
┌────────────────────────────────────────────────────────────┐
│                         SELLO                              │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │ Ethereum │    │ Bitcoin  │    │  Solana  │   ...       │
│  │  Parser  │    │  Parser  │    │  Parser  │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                    │
│       └───────────────┴───────────────┘                    │
│                       │                                    │
│                       ▼                                    │
│              ┌─────────────────┐                           │
│              │ Unified Context │                           │
│              │   • recipient   │                           │
│              │   • amount      │                           │
│              │   • token       │                           │
│              └────────┬────────┘                           │
│                       │                                    │
│                       ▼                                    │
│              ┌─────────────────┐                           │
│              │  Policy Engine  │                           │
│              └────────┬────────┘                           │
│                       │                                    │
│                       ▼                                    │
│              ┌─────────────────┐                           │
│              │     Signer      │                           │
│              └─────────────────┘                           │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Time to First Signature: 2 Minutes

```bash
curl -sSL https://sello.dev/install.sh | sh
sello init
sello ethereum sign 0x02f8730181...
```

---

## Architecture

### Design Principles

1. **Single Responsibility**: Each module does one thing
2. **Abstraction Boundaries**: Traits define contracts between modules
3. **Dependency Injection**: All dependencies are injected, enabling isolated testing
4. **Zero Unsafe**: No unsafe Rust unless absolutely required (and audited)
5. **Parse, Don't Validate**: Transform raw bytes into typed structures early

### Module Structure

```
src/
├── main.rs                 # Entry point
├── cli.rs                  # Command-line interface
│
├── core/
│   ├── mod.rs
│   ├── types.rs            # Shared types (ParsedTx, PolicyResult, etc.)
│   └── error.rs            # Error types
│
├── crypto/
│   ├── mod.rs
│   ├── keys.rs             # KeyPair trait + implementations
│   ├── signer.rs           # Signer trait + implementations
│   └── store.rs            # KeyStore trait + encrypted file store
│
├── chain/
│   ├── mod.rs              # Chain trait + registry
│   ├── ethereum.rs         # Ethereum parser
│   ├── bitcoin.rs          # Bitcoin parser
│   ├── solana.rs           # Solana parser
│   ├── tron.rs             # Tron parser
│   └── ripple.rs           # Ripple parser
│
├── policy/
│   ├── mod.rs
│   ├── engine.rs           # PolicyEngine trait + implementation
│   ├── rules.rs            # Rule types (limit, whitelist, blacklist)
│   └── history.rs          # Transaction history for rate limiting
│
├── server/
│   ├── mod.rs
│   ├── socket.rs           # Unix socket server
│   └── http.rs             # HTTP server (optional)
│
└── config/
    ├── mod.rs
    └── loader.rs           # Configuration loading
```

### Core Traits

```rust
/// Parses raw transaction bytes into a unified context
pub trait Chain: Send + Sync {
    fn id(&self) -> &'static str;
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError>;
}

/// Signs a message hash
pub trait Signer: Send + Sync {
    fn sign(&self, hash: &[u8; 32]) -> Result<Signature, SignError>;
    fn public_key(&self) -> &PublicKey;
}

/// Stores and retrieves encrypted keys
pub trait KeyStore: Send + Sync {
    fn store(&mut self, name: &str, key: &KeyPair) -> Result<(), StoreError>;
    fn load(&self, name: &str) -> Result<KeyPair, StoreError>;
    fn list(&self) -> Result<Vec<String>, StoreError>;
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;
}

/// Evaluates policy rules against a parsed transaction
pub trait PolicyEngine: Send + Sync {
    fn check(&self, tx: &ParsedTx) -> PolicyResult;
    fn record(&mut self, tx: &ParsedTx) -> Result<(), PolicyError>;
}
```

### Unified Transaction Context

All chain parsers produce the same output:

```rust
pub struct ParsedTx {
    /// Transaction hash (for signing)
    pub hash: [u8; 32],
    
    /// Recipient address (chain-native format)
    pub recipient: Option<String>,
    
    /// Transfer amount in smallest unit (wei, satoshi, lamport)
    pub amount: Option<U256>,
    
    /// Token symbol (ETH, BTC, SOL, USDC, etc.)
    pub token: Option<String>,
    
    /// Token contract address (for token transfers)
    pub token_address: Option<String>,
    
    /// Transaction type
    pub tx_type: TxType,
    
    /// Chain identifier
    pub chain: String,
}

pub enum TxType {
    Transfer,       // Native currency transfer
    TokenTransfer,  // ERC20, SPL, TRC20, etc.
    ContractCall,   // Generic contract interaction
    Other,          // Deployment, staking, etc.
}
```

---

## Supported Chains

| Chain | Curve | Transaction Format | Token Standard |
|-------|-------|-------------------|----------------|
| Ethereum | secp256k1 | EIP-1559, EIP-2930, Legacy | ERC-20 |
| Bitcoin | secp256k1 | PSBT | - |
| Solana | ed25519 | Versioned Transaction | SPL Token |
| Tron | secp256k1 | Protocol Buffers | TRC-20 |
| Ripple | secp256k1 | Binary Codec | Issued Currencies |

**EVM Compatibility**: The Ethereum module supports all EVM-compatible chains (Polygon, Arbitrum, Base, Optimism, BSC, Avalanche C-Chain) as they share the same transaction format.

---

## Policy Engine

### Configuration

```toml
# ~/.sello/config.toml

[policy]
# Addresses that can receive funds
whitelist = [
    "0x742d35Cc6634C0532925a3b844Bc454e7595f...",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "So1anaAddress...",
]

# Addresses that can never receive funds
blacklist = [
    "0xSanctionedAddress...",
]

# Maximum amount per transaction
[policy.tx_limits]
ETH = "5"
BTC = "0.5"
SOL = "500"
USDC = "50000"

# Maximum amount per 24-hour period
[policy.daily_limits]
ETH = "10"
BTC = "1"
SOL = "1000"
USDC = "100000"
```

### Rule Evaluation

```rust
impl PolicyEngine for DefaultPolicyEngine {
    fn check(&self, tx: &ParsedTx) -> PolicyResult {
        // 1. Check blacklist (always first)
        if let Some(ref recipient) = tx.recipient {
            if self.blacklist.contains(recipient) {
                return PolicyResult::Denied {
                    rule: "blacklist",
                    reason: "recipient is blacklisted",
                };
            }
        }

        // 2. Check whitelist (if enabled)
        if !self.whitelist.is_empty() {
            if let Some(ref recipient) = tx.recipient {
                if !self.whitelist.contains(recipient) {
                    return PolicyResult::Denied {
                        rule: "whitelist",
                        reason: "recipient not in whitelist",
                    };
                }
            }
        }

        // 3. Check transaction limit
        if let Some(amount) = tx.amount {
            let token = tx.token.as_deref().unwrap_or("NATIVE");
            if let Some(limit) = self.tx_limits.get(token) {
                if amount > *limit {
                    return PolicyResult::Denied {
                        rule: "tx_limit",
                        reason: format!("amount exceeds tx limit of {}", limit),
                    };
                }
            }
        }

        // 4. Check daily limit
        if let Some(amount) = tx.amount {
            let token = tx.token.as_deref().unwrap_or("NATIVE");
            if let Some(limit) = self.daily_limits.get(token) {
                let spent = self.history.daily_total(token);
                if spent + amount > *limit {
                    return PolicyResult::Denied {
                        rule: "daily_limit",
                        reason: format!("would exceed daily limit of {}", limit),
                    };
                }
            }
        }

        PolicyResult::Allowed
    }
}
```

---

## CLI Design

```
sello <command>

Commands:
    init                Initialize sello
    status              Show status  
    config              View configuration
    config edit         Edit configuration
    serve               Start signing server
    <chain> address     Show address for chain
    <chain> sign <tx>   Parse, verify policy, sign
    help                Show help
```

### Examples

```bash
# Initialize
$ sello init
Enter passphrase: ****
✓ Sello initialized at ~/.sello
✓ Default key created

# Check status  
$ sello status
Sello Status
────────────
Keys:       1 (default)
Chains:     ethereum, bitcoin, solana, tron, ripple
Policy:     10 ETH/day, 5 whitelisted addresses
Signed:     0 transactions
Uptime:     -

# Get addresses
$ sello ethereum address
0x742d35Cc6634C0532925a3b844Bc454e7595f...

$ sello bitcoin address
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Sign transaction
$ sello ethereum sign 0x02f8730181948502540be400...
Parsed:
  Chain:     ethereum
  Type:      transfer
  Recipient: 0x742d35Cc6634C0532925a3b844Bc454e7595f...
  Amount:    1.5 ETH

Policy:
  ✓ Recipient whitelisted
  ✓ Amount under tx limit (5 ETH)
  ✓ Daily limit: 1.5 / 10 ETH

Signature: 0x...

# Policy rejection
$ sello ethereum sign 0x02f8730181...
Parsed:
  Chain:     ethereum
  Type:      transfer
  Recipient: 0xUnknownAddress...
  Amount:    2 ETH

Policy:
  ✗ Recipient not whitelisted

Error: transaction rejected by policy
```

---

## API

### Unix Socket (Default)

```bash
# Default location
~/.sello/sello.sock     # macOS/Linux
```

### Protocol (JSON-RPC)

```json
// Request
{
    "id": "req-001",
    "method": "sign",
    "params": {
        "chain": "ethereum",
        "tx": "0x02f8730181948502540be400..."
    }
}

// Success Response
{
    "id": "req-001",
    "result": {
        "signature": "0x...",
        "parsed": {
            "chain": "ethereum",
            "recipient": "0x742d35Cc...",
            "amount": "1500000000000000000",
            "token": "ETH",
            "tx_type": "transfer"
        },
        "policy": {
            "allowed": true,
            "checks": [
                {"rule": "whitelist", "passed": true},
                {"rule": "tx_limit", "passed": true},
                {"rule": "daily_limit", "passed": true, "remaining": "8.5 ETH"}
            ]
        }
    }
}

// Rejection Response
{
    "id": "req-001",
    "error": {
        "code": "POLICY_DENIED",
        "rule": "whitelist",
        "reason": "recipient not in whitelist"
    }
}
```

### HTTP (Optional)

```bash
# Enable with flag
sello serve --http 127.0.0.1:8080
```

```bash
curl -X POST http://127.0.0.1:8080/sign \
    -H "Content-Type: application/json" \
    -d '{"chain": "ethereum", "tx": "0x02f8730181..."}'
```

---

## Security Model

### Key Storage

```
┌─────────────────────────────────────────────┐
│              Key Encryption                 │
├─────────────────────────────────────────────┤
│  Passphrase                                 │
│       │                                     │
│       ▼                                     │
│  ┌─────────┐                                │
│  │ Argon2id │ (memory-hard KDF)             │
│  └────┬────┘                                │
│       │                                     │
│       ▼                                     │
│  256-bit Key                                │
│       │                                     │
│       ▼                                     │
│  ┌──────────────────┐                       │
│  │ ChaCha20-Poly1305 │ (AEAD encryption)   │
│  └────────┬─────────┘                       │
│           │                                 │
│           ▼                                 │
│  Encrypted key file (~/.sello/keys/*.enc)  │
└─────────────────────────────────────────────┘
```

### Memory Safety

- **Zeroize**: All key material is zeroed on drop
- **No unsafe**: Core cryptographic code uses no unsafe blocks
- **Type safety**: Rust's type system prevents key misuse

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}
```

### Audit Trail

Every operation is logged with:

- Timestamp
- Chain
- Transaction hash
- Parsed context (recipient, amount, token)
- Policy result
- Signature (if allowed)

```json
{
    "timestamp": "2025-01-21T12:00:00Z",
    "chain": "ethereum",
    "tx_hash": "0xabc123...",
    "recipient": "0x742d35Cc...",
    "amount": "1500000000000000000",
    "token": "ETH",
    "policy_result": "allowed",
    "signature": "0x..."
}
```

---

## Testing Strategy

### Philosophy

> "If it's not tested, it's broken."

The architecture enables **100% unit test coverage** through:

1. **Trait-based abstraction**: Every component has a trait
2. **Dependency injection**: All dependencies are passed, not constructed
3. **Mock implementations**: Traits enable trivial mocking
4. **Isolated testing**: Each module tests in isolation

### Test Structure

```
tests/
├── unit/
│   ├── crypto/
│   │   ├── keys_test.rs
│   │   ├── signer_test.rs
│   │   └── store_test.rs
│   ├── chain/
│   │   ├── ethereum_test.rs
│   │   ├── bitcoin_test.rs
│   │   ├── solana_test.rs
│   │   ├── tron_test.rs
│   │   └── ripple_test.rs
│   ├── policy/
│   │   ├── engine_test.rs
│   │   ├── rules_test.rs
│   │   └── history_test.rs
│   └── server/
│       ├── socket_test.rs
│       └── http_test.rs
├── integration/
│   ├── sign_flow_test.rs
│   └── policy_enforcement_test.rs
└── fixtures/
    ├── ethereum_txs.json
    ├── bitcoin_psbts.json
    └── solana_txs.json
```

### Example: Testing Policy Engine in Isolation

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn mock_tx(recipient: &str, amount: u64, token: &str) -> ParsedTx {
        ParsedTx {
            hash: [0u8; 32],
            recipient: Some(recipient.to_string()),
            amount: Some(U256::from(amount)),
            token: Some(token.to_string()),
            token_address: None,
            tx_type: TxType::Transfer,
            chain: "ethereum".to_string(),
        }
    }

    #[test]
    fn test_whitelist_allows_valid_recipient() {
        let engine = DefaultPolicyEngine::new(PolicyConfig {
            whitelist: vec!["0xAlice".to_string()],
            ..Default::default()
        });

        let tx = mock_tx("0xAlice", 1000, "ETH");
        assert!(matches!(engine.check(&tx), PolicyResult::Allowed));
    }

    #[test]
    fn test_whitelist_denies_unknown_recipient() {
        let engine = DefaultPolicyEngine::new(PolicyConfig {
            whitelist: vec!["0xAlice".to_string()],
            ..Default::default()
        });

        let tx = mock_tx("0xBob", 1000, "ETH");
        assert!(matches!(engine.check(&tx), PolicyResult::Denied { rule: "whitelist", .. }));
    }

    #[test]
    fn test_blacklist_overrides_whitelist() {
        let engine = DefaultPolicyEngine::new(PolicyConfig {
            whitelist: vec!["0xAlice".to_string()],
            blacklist: vec!["0xAlice".to_string()],
            ..Default::default()
        });

        let tx = mock_tx("0xAlice", 1000, "ETH");
        assert!(matches!(engine.check(&tx), PolicyResult::Denied { rule: "blacklist", .. }));
    }

    #[test]
    fn test_daily_limit_accumulates() {
        let mut engine = DefaultPolicyEngine::new(PolicyConfig {
            daily_limits: [("ETH".to_string(), U256::from(100))].into(),
            ..Default::default()
        });

        // First transaction: 60 ETH
        let tx1 = mock_tx("0xAlice", 60, "ETH");
        assert!(matches!(engine.check(&tx1), PolicyResult::Allowed));
        engine.record(&tx1).unwrap();

        // Second transaction: 30 ETH (total 90, under limit)
        let tx2 = mock_tx("0xAlice", 30, "ETH");
        assert!(matches!(engine.check(&tx2), PolicyResult::Allowed));
        engine.record(&tx2).unwrap();

        // Third transaction: 20 ETH (total 110, over limit)
        let tx3 = mock_tx("0xAlice", 20, "ETH");
        assert!(matches!(engine.check(&tx3), PolicyResult::Denied { rule: "daily_limit", .. }));
    }
}
```

### Example: Testing Chain Parser with Fixtures

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_eip1559_transfer() {
        let raw = hex::decode("02f8730181...").unwrap();
        let parser = EthereumParser::new();
        
        let parsed = parser.parse(&raw).unwrap();
        
        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.recipient, Some("0x742d35Cc...".to_string()));
        assert_eq!(parsed.amount, Some(U256::from(1_500_000_000_000_000_000u64)));
        assert_eq!(parsed.token, Some("ETH".to_string()));
        assert_eq!(parsed.tx_type, TxType::Transfer);
    }

    #[test]
    fn test_parse_erc20_transfer() {
        let raw = hex::decode("02f8730181...").unwrap(); // ERC20 transfer
        let parser = EthereumParser::new();
        
        let parsed = parser.parse(&raw).unwrap();
        
        assert_eq!(parsed.tx_type, TxType::TokenTransfer);
        assert_eq!(parsed.token_address, Some("0xA0b86991...".to_string())); // USDC
        assert_eq!(parsed.recipient, Some("0xRecipient...".to_string()));
    }

    #[test]
    fn test_parse_invalid_tx_returns_error() {
        let raw = vec![0x00, 0x01, 0x02]; // Invalid
        let parser = EthereumParser::new();
        
        assert!(parser.parse(&raw).is_err());
    }
}
```

### Coverage Target

| Module | Target | Notes |
|--------|--------|-------|
| crypto/ | 100% | Core security, no exceptions |
| chain/ | 100% | Parsing correctness critical |
| policy/ | 100% | Policy enforcement critical |
| server/ | 90%+ | Network edge cases |
| cli/ | 80%+ | UI code |

---

## Development Approach

### AI-Assisted Development

This project is developed with AI assistance ("vibe coded"), with humans providing:

- Architecture decisions
- Security review
- Final approval

AI provides:

- Implementation
- Test generation
- Documentation
- Refactoring

### Contribution Guidelines

1. **Every PR must include tests** for new functionality
2. **No decrease in coverage** allowed
3. **All traits must have mock implementations** for testing
4. **Security-critical code requires human review**

### Code Style

```rust
// Good: Dependency injection, testable
pub struct SigningService<S: Signer, P: PolicyEngine, C: Chain> {
    signer: S,
    policy: P,
    chain: C,
}

impl<S: Signer, P: PolicyEngine, C: Chain> SigningService<S, P, C> {
    pub fn sign(&mut self, raw_tx: &[u8]) -> Result<Signature, SignError> {
        let parsed = self.chain.parse(raw_tx)?;
        
        match self.policy.check(&parsed) {
            PolicyResult::Allowed => {
                self.policy.record(&parsed)?;
                self.signer.sign(&parsed.hash)
            }
            PolicyResult::Denied { rule, reason } => {
                Err(SignError::PolicyDenied { rule, reason })
            }
        }
    }
}

// Bad: Hard-coded dependencies, untestable
pub fn sign(raw_tx: &[u8]) -> Result<Signature, SignError> {
    let key = load_key_from_file()?;  // Can't mock
    let parsed = parse_ethereum(raw_tx)?;  // Can't swap chains
    // ...
}
```

---

## Roadmap

### v0.1.0 - Foundation

- [ ] Core crypto (key generation, storage, signing)
- [ ] Ethereum parser (EIP-1559, ERC-20)
- [ ] Policy engine (whitelist, blacklist, limits)
- [ ] CLI (init, status, sign, address)
- [ ] Unix socket server

### v0.2.0 - Multi-Chain

- [ ] Bitcoin parser (PSBT)
- [ ] Solana parser
- [ ] Tron parser
- [ ] Ripple parser

### v0.3.0 - Production Ready

- [ ] HTTP API with authentication
- [ ] Prometheus metrics
- [ ] Audit log export
- [ ] Systemd integration

### v0.4.0 - Advanced

- [ ] Multi-key support
- [ ] Key rotation
- [ ] Backup/restore
- [ ] Hardware security module (HSM) integration

### Future

- [ ] Multi-node clustering (optional)
- [ ] Threshold signatures (optional)
- [ ] Web UI (optional)

---

## Dependencies

```toml
[dependencies]
# Crypto
k256 = { version = "0.13", features = ["ecdsa"] }
ed25519-dalek = "2"
chacha20poly1305 = "0.10"
argon2 = "0.5"
rand = "0.8"
zeroize = { version = "1", features = ["derive"] }

# Chain parsing
alloy-consensus = "0.8"
alloy-primitives = "0.8"
bitcoin = "0.32"
solana-sdk = "2.0"

# Async runtime
tokio = { version = "1", features = ["rt-multi-thread", "net", "sync", "macros"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
hex = "0.4"

# CLI
clap = { version = "4", features = ["derive"] }

# Error handling
thiserror = "2"

[dev-dependencies]
tempfile = "3"
mockall = "0.13"
```

---

## License

MIT OR Apache-2.0

---

## Contributing

Contributions are welcome. Please read the contribution guidelines and ensure all tests pass before submitting a PR.

```bash
# Run tests
cargo test

# Run with coverage
cargo tarpaulin --out Html

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

---

## Acknowledgments

- [alloy](https://github.com/alloy-rs/alloy) - Ethereum types and parsing
- [bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) - Bitcoin types and parsing
- [solana-sdk](https://github.com/solana-labs/solana) - Solana types and parsing
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic primitives
