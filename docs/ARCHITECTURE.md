# TxGate Architecture

This document provides an architectural overview of TxGate for developers who want to understand the system design, extend functionality, or contribute to the codebase.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Crate Responsibilities](#crate-responsibilities)
3. [Data Flow](#data-flow)
4. [Security Boundaries](#security-boundaries)
5. [Key Abstractions (Traits)](#key-abstractions-traits)
6. [Design Decisions](#design-decisions)

---

## High-Level Architecture

TxGate is a self-hosted, chain-agnostic transaction signing server. Unlike hash-signing solutions that blindly sign whatever clients submit, TxGate **parses raw transactions** to extract recipients, amounts, and tokens, then enforces configurable policies before signing.

```
                                    TXGATE ARCHITECTURE
+-----------------------------------------------------------------------------+
|                                                                             |
|   +-------------+        +-------------+                                    |
|   | CLI Client  |        | Unix Socket |<---- 0600 permissions              |
|   +------+------+        +------+------+      length-prefixed messages      |
|          |                      |                                           |
|          |               +------+------+                                    |
|          |               | HTTP Server |<---- optional, loopback-only       |
|          |               |   (axum)    |      API key auth, rate limiting   |
|          |               +------+------+                                    |
|          |                      |                                           |
|          +----------+-----------+                                           |
|                     |                                                       |
|                     v                                                       |
|          +----------------------------+                                     |
|          |   JSON-RPC 2.0 Handler     |                                     |
|          |  * sign  * parse  * status |                                     |
|          +-------------+--------------+                                     |
|                        |                                                    |
|     +------------------+------------------+                                  |
|     |                  |                  |                                  |
|     v                  v                  v                                  |
| +----------+    +-------------+    +-----------+                            |
| | Chain    |    |   Policy    |    |   Audit   |                            |
| | Registry |    |   Engine    |    |    Log    |                            |
| |          |    |             |    |           |                            |
| | Ethereum |    | Blacklist   |    | JSONL     |                            |
| | Bitcoin  |    | Whitelist   |    | +HMAC     |                            |
| | Solana   |    | Tx Limit    |    | chain     |                            |
| +----+-----+    +------+------+    +-----------+                            |
|      |                 |                                             |
|      |                 |                                                    |
|      +--------+--------+                                                    |
|               |                                                             |
|               v                                                             |
|       +---------------+                                                     |
|       |    Signer     |<---- static dispatch for hot path                   |
|       | (secp256k1 /  |      zeroize on drop                                |
|       |   ed25519)    |                                                     |
|       +-------+-------+                                                     |
|               |                                                             |
|               v                                                             |
|       +---------------+                                                     |
|       |   Key Store   |<---- Argon2id + ChaCha20-Poly1305                   |
|       | (~/.txgate/    |      encrypted key files                            |
|       |   keys/*.enc) |                                                     |
|       +---------------+                                                     |
|                                                                             |
+-----------------------------------------------------------------------------+

All three chains (Ethereum, Bitcoin, Solana) are fully implemented.
```

### Request Flow

```
1. Client submits JSON-RPC request (sign, parse, or status)
2. Server validates request format and routes to handler
3. Chain parser decodes raw transaction bytes into ParsedTx
4. Policy engine evaluates transaction against configured rules
5. If allowed: Signer signs the transaction hash
6. Audit logger records the operation
7. Response returned to client with signature and context
```

---

## Crate Responsibilities

TxGate is organized as a Cargo workspace with 5 crates:

```
txgate/
+-- crates/
    +-- txgate-core/      # Foundation layer
    +-- txgate-crypto/    # Cryptographic operations
    +-- txgate-chain/     # Blockchain transaction parsing
    +-- txgate-policy/    # Policy evaluation engine
    +-- txgate/           # Binary (CLI + Server)
```

### Dependency Graph

```
                    +---------------+
                    |     txgate     |  (binary)
                    +-------+-------+
                            |
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
+---------------+   +---------------+   +---------------+
| txgate-chain   |   | txgate-policy  |   | txgate-crypto  |
+-------+-------+   +-------+-------+   +-------+-------+
        |                   |                   |
        |                   v                   |
        |           +---------------+           |
        +---------->|  txgate-core   |<----------+
                    +---------------+
```

### txgate-core

**Purpose**: Core types, traits, error definitions, and configuration loading.

**Key Exports**:
- `ParsedTx` - Unified transaction representation across all chains
- `TxType` - Transaction type classification (Transfer, TokenTransfer, etc.)
- `PolicyResult` - Policy evaluation outcome (Allowed/Denied)
- `TxGateError`, `ParseError`, `SignError`, `PolicyError` - Error types
- `Config`, `ConfigBuilder` - Configuration management
- `SigningService` - High-level signing orchestration trait

**Modules**:
```
txgate-core/src/
+-- lib.rs           # Public API and re-exports
+-- types.rs         # ParsedTx, TxType, PolicyResult
+-- error.rs         # Error types with thiserror
+-- config.rs        # Configuration structures
+-- config_loader.rs # TOML loading and path expansion
+-- signing.rs       # SigningService trait and abstractions
```

### txgate-crypto

**Purpose**: All cryptographic operations including key management, signing, and encryption.

**Key Exports**:
- `SecretKey` - Zeroizing secret key wrapper
- `KeyPair`, `Secp256k1KeyPair` - Key pair types
- `Signer`, `Secp256k1Signer` - Signing implementations
- `KeyStore`, `FileKeyStore` - Encrypted key storage
- `encrypt_key`, `decrypt_key` - Key encryption utilities

**Modules**:
```
txgate-crypto/src/
+-- lib.rs        # Public API and re-exports
+-- keys.rs       # SecretKey with zeroization
+-- keypair.rs    # KeyPair generation and handling
+-- signer.rs     # Signing trait and implementations
+-- encryption.rs # Argon2id + ChaCha20-Poly1305
+-- store.rs      # Encrypted file-based key storage
```

**Security Features**:
- All secret types implement `Zeroize` and `ZeroizeOnDrop`
- No `Clone` or `Debug` that exposes secrets
- Constant-time operations for cryptographic comparisons
- Argon2id with 64 MiB memory, 3 iterations, 4 lanes

### txgate-chain

**Purpose**: Multi-chain transaction parsing and token detection.

**Key Exports**:
- `Chain` trait - Interface for chain-specific parsers
- `ChainRegistry` - Runtime chain parser lookup
- `EthereumParser` - Ethereum/EVM transaction parsing
- `TokenRegistry`, `TokenInfo` - Token metadata
- `Erc20Call` - ERC-20 call data parsing

**Modules**:
```
txgate-chain/src/
+-- lib.rs        # Public API and re-exports
+-- chain.rs      # Chain trait definition
+-- registry.rs   # ChainRegistry for runtime lookup
+-- ethereum.rs   # EthereumParser implementation
+-- bitcoin.rs    # BitcoinParser implementation
+-- solana.rs     # SolanaParser implementation
+-- erc20.rs      # ERC-20 transfer/approve detection
+-- tokens.rs     # Token registry with risk levels
+-- rlp.rs        # RLP decoding utilities
```

**Supported Transaction Formats**:

*Ethereum*:
- EIP-1559 (Type 2) - Modern Ethereum transactions
- EIP-2930 (Type 1) - Access list transactions
- Legacy (Type 0) - Pre-EIP-1559 transactions
- ERC-20 transfers, approvals, and transferFrom

*Bitcoin*:
- Legacy transactions
- SegWit v0 (P2WPKH, P2WSH)
- Taproot (P2TR)

*Solana*:
- Legacy messages
- Versioned messages (V0)
- System Program transfers
- SPL Token transfers (Token and Token-2022)

### txgate-policy

**Purpose**: Stateless policy engine for transaction approval rules.

**Key Exports**:
- `PolicyEngine`, `DefaultPolicyEngine` - Policy evaluation
- `PolicyConfig` - Policy configuration
- `PolicyCheckResult` - Detailed check results

**Modules**:
```
txgate-policy/src/
+-- lib.rs      # Public API and re-exports
+-- config.rs   # Policy configuration types
+-- engine.rs   # DefaultPolicyEngine implementation
```

**Policy Rules** (evaluated in order):
1. **Blacklist** - Deny if recipient is blacklisted
2. **Whitelist** - Deny if whitelist enabled and recipient not in list
3. **Transaction Limit** - Deny if amount exceeds per-transaction limit

### txgate (binary)

**Purpose**: CLI application and server implementation.

**Key Exports**:
- `Cli`, `Commands` - CLI argument structures
- `LogConfig`, `LogGuard` - Logging configuration
- Server modules for Unix socket and HTTP

**Modules**:
```
txgate/src/
+-- main.rs          # Entry point
+-- lib.rs           # Library exports
+-- cli/
|   +-- mod.rs       # CLI module
|   +-- args.rs      # Clap argument definitions
|   +-- commands/    # Command implementations
|       +-- mod.rs
|       +-- init.rs
|       +-- status.rs
|       +-- config.rs
|       +-- serve.rs
|       +-- ethereum/
|           +-- mod.rs
|           +-- address.rs
|           +-- sign.rs
+-- server/
|   +-- mod.rs       # Server module
|   +-- socket.rs    # Unix socket server
|   +-- http.rs      # HTTP server (axum)
+-- logging.rs       # Structured logging setup
+-- audit.rs         # Audit log implementation
```

---

## Data Flow

### Signing Request Flow

```
+--------+     +--------+     +---------+     +--------+     +--------+
| Client | --> | Server | --> | Parser  | --> | Policy | --> | Signer |
+--------+     +--------+     +---------+     +--------+     +--------+
    |              |              |              |              |
    | JSON-RPC     |              |              |              |
    | sign req     |              |              |              |
    +------------->|              |              |              |
                   |              |              |              |
                   | raw bytes    |              |              |
                   +------------->|              |              |
                                  |              |              |
                                  | ParsedTx     |              |
                                  +------------->|              |
                                                 |              |
                                                 | if Allowed   |
                                                 +------------->|
                                                                |
                                                 | Signature    |
                   +<-------------------------------+-----------+
                   |
    | JSON-RPC     |
    | response     |
    +<-------------+
```

### ParsedTx Structure

The `ParsedTx` is the universal transaction representation:

```rust
pub struct ParsedTx {
    /// Transaction hash (32 bytes)
    pub hash: [u8; 32],

    /// Recipient address (chain-native format)
    pub recipient: Option<String>,

    /// Transfer amount in smallest unit (wei, satoshi, lamport)
    pub amount: Option<U256>,

    /// Token symbol (ETH, BTC, SOL, USDC, etc.)
    pub token: Option<String>,

    /// Token contract address (for token transfers)
    pub token_address: Option<String>,

    /// Transaction type classification
    pub tx_type: TxType,

    /// Chain identifier (e.g., "ethereum", "bitcoin")
    pub chain: String,

    /// Transaction nonce (critical for replay protection)
    pub nonce: Option<u64>,

    /// Chain ID (EIP-155 for Ethereum)
    pub chain_id: Option<u64>,

    /// Chain-specific metadata
    pub metadata: HashMap<String, Value>,
}
```

---

## Security Boundaries

### Trust Boundaries

```
+-------------------------------------------------------------------------+
|  UNTRUSTED                                                              |
|  +-------------------------------------------------------------------+  |
|  |  Client Requests                                                  |  |
|  |  - Raw transaction bytes                                          |  |
|  |  - Chain identifier                                               |  |
|  |  - Key name                                                       |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                                   |
                                   v  Input Validation
+-------------------------------------------------------------------------+
|  VALIDATED                                                              |
|  +-------------------------------------------------------------------+  |
|  |  Parsed & Validated Data                                          |  |
|  |  - ParsedTx with extracted fields                                 |  |
|  |  - Policy evaluation results                                      |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                                   |
                                   v  Policy Enforcement
+-------------------------------------------------------------------------+
|  TRUSTED                                                                |
|  +-------------------------------------------------------------------+  |
|  |  Cryptographic Operations                                         |  |
|  |  - Key material (encrypted at rest)                               |  |
|  |  - Signing operations                                             |  |
|  |  - Audit logs                                                     |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

### Key Protection Layers

1. **At Rest**: Keys encrypted with Argon2id + ChaCha20-Poly1305
2. **In Memory**: `Zeroize` trait ensures secrets cleared on drop
3. **In Transit**: Unix socket with 0600 permissions (local only)
4. **Access Control**: Policy engine gates all signing operations

### File Permissions

| Path | Permission | Purpose |
|------|------------|---------|
| `~/.txgate/` | 0700 | Configuration directory |
| `~/.txgate/keys/*.enc` | 0600 | Encrypted key files |
| `~/.txgate/txgate.sock` | 0600 | Unix socket |
| `~/.txgate/audit/*.jsonl` | 0600 | Audit logs |

---

## Key Abstractions (Traits)

### Chain Trait

Defines the interface for blockchain-specific transaction parsers:

```rust
pub trait Chain: Send + Sync {
    /// Unique identifier for this chain (e.g., "ethereum", "bitcoin")
    fn id(&self) -> &'static str;

    /// Parse raw transaction bytes into a ParsedTx
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError>;

    /// Return the cryptographic curve used by this chain
    fn curve(&self) -> CurveType;
}
```

**Implementations**: `EthereumParser`, `BitcoinParser`, `SolanaParser`, `MockChain` (for testing)

### Signer Trait

Defines the interface for cryptographic signing:

```rust
pub trait Signer: Send + Sync {
    /// Sign a 32-byte hash
    fn sign(&self, hash: &[u8; 32]) -> Result<SignatureBytes, SignError>;

    /// Get the public key
    fn public_key(&self) -> &[u8];

    /// Get the cryptographic curve type
    fn curve(&self) -> CurveType;
}
```

**Implementations**: `Secp256k1Signer`

### KeyStore Trait

Defines the interface for key storage:

```rust
pub trait KeyStore: Send + Sync {
    /// Store a key pair with encryption
    fn store(&self, name: &str, key: &SecretKey, passphrase: &str) -> Result<(), StoreError>;

    /// Load and decrypt a key pair
    fn load(&self, name: &str, passphrase: &str) -> Result<SecretKey, StoreError>;

    /// List all stored key names
    fn list(&self) -> Result<Vec<String>, StoreError>;

    /// Delete a key
    fn delete(&self, name: &str) -> Result<(), StoreError>;

    /// Check if a key exists
    fn exists(&self, name: &str) -> bool;
}
```

**Implementations**: `FileKeyStore`

### PolicyEngine Trait

Defines the interface for policy evaluation:

```rust
pub trait PolicyEngine: Send + Sync {
    /// Check if a transaction is allowed
    fn check(&self, tx: &ParsedTx) -> PolicyCheckResult;
}
```

**Implementations**: `DefaultPolicyEngine`

---

## Design Decisions

### Why Parse Transactions?

Traditional signers accept a hash and sign it blindly. This is dangerous because:

1. Client claims "send 1 ETH" but hash is for 1000 ETH
2. Client claims recipient is "treasury" but hash sends to attacker
3. No audit trail of what was actually signed

TxGate parses the raw transaction to verify claims and enforce policies.

### Why Trait Objects for Chains?

Chain parsers are selected at runtime based on the request, so we use trait objects:

```rust
pub struct ChainRegistry {
    chains: HashMap<String, Box<dyn Chain>>,
}
```

This allows adding new chains without recompiling existing code.

### Why Static Dispatch for Signing?

Signing is on the hot path and benefits from inlining:

```rust
pub struct SigningService<S: Signer, P: PolicyEngine> {
    signer: S,
    policy: P,
}
```

Generics allow the compiler to inline and optimize signing operations.

### Why Unix Socket as Primary Interface?

1. **Security**: No network exposure by default
2. **Performance**: Lower latency than HTTP
3. **Permissions**: OS-level access control via file permissions
4. **Simplicity**: No TLS configuration needed

HTTP is optional for remote access scenarios with proper authentication.

---

## See Also

- [DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md) - Development setup and workflows
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- [TESTING.md](./TESTING.md) - Testing infrastructure
- [FUZZING.md](./FUZZING.md) - Fuzz testing guide
- [../ARCHITECTURE.md](../ARCHITECTURE.md) - Full architecture specification
