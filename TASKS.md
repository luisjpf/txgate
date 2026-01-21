# Sello Development Tasks

This document provides a comprehensive task breakdown for implementing Sello v0.1.0 - Foundation.

## Critical Path

The critical path for v0.1.0 is:

```
SELLO-001 → SELLO-002 → SELLO-005 → SELLO-007 → SELLO-008 → SELLO-010 → SELLO-011 → SELLO-012 → SELLO-012.5 → SELLO-014 → SELLO-018 → SELLO-026 → SELLO-028 → SELLO-029 → SELLO-032
```

This represents: Project Setup → Dependencies → Core Types → SecretKey → KeyPair → Key Encryption → KeyStore → Chain Trait → ChainRegistry → Ethereum Parser → Policy Engine → Signing Flow → JSON-RPC Protocol → Socket Server → Integration Tests

---

## Phase 1: Foundation (v0.1.0)

### Epic 1: Project Infrastructure

#### SELLO-001: Initialize Rust project structure

**Description**: Create the initial Rust project with cargo workspace configuration, directory structure, and basic configuration files.

**Acceptance Criteria**:
- [ ] Cargo workspace created with proper structure
- [ ] All crates defined: `sello-core`, `sello-crypto`, `sello-chain`, `sello-policy`, `sello` (binary)
- [ ] Directory structure matches architecture specification
- [ ] `.gitignore` configured for Rust projects
- [ ] Basic `README.md` created
- [ ] License files (MIT + Apache-2.0) added
- [ ] CI/CD placeholder files created (GitHub Actions)

**Dependencies**: None

**Complexity**: S

**Testing Requirements**:
- Verify `cargo check` passes
- Verify workspace builds with `cargo build`

**Files**:
- Create: `Cargo.toml` (workspace root)
- Create: `crates/sello-core/Cargo.toml`
- Create: `crates/sello-crypto/Cargo.toml`
- Create: `crates/sello-chain/Cargo.toml`
- Create: `crates/sello-policy/Cargo.toml`
- Create: `crates/sello/Cargo.toml` (binary crate with CLI and server modules)
- Create: `.gitignore`
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`
- Create: `.github/workflows/ci.yml`

---

#### SELLO-002: Add core dependencies

**Description**: Add all required dependencies to workspace and crate manifests as specified in the architecture document.

**Acceptance Criteria**:
- [ ] Cryptographic dependencies added (k256, chacha20poly1305, argon2, zeroize)
- [ ] Ethereum parsing dependencies added (alloy-consensus, alloy-primitives)
- [ ] Async runtime added (tokio)
- [ ] Serialization dependencies added (serde, serde_json, toml)
- [ ] CLI dependencies added (clap)
- [ ] Error handling added (thiserror)
- [ ] Dev dependencies added (tempfile, mockall)
- [ ] All dependency versions match specification
- [ ] Feature flags properly configured

**Dependencies**: SELLO-001

**Complexity**: S

**Testing Requirements**:
- Verify `cargo build` succeeds
- Verify no dependency conflicts
- Run `cargo tree` to verify dependency resolution

**Files**:
- Modify: `Cargo.toml` (workspace)
- Modify: `crates/*/Cargo.toml` (all crates)

---

#### SELLO-003: Set up testing infrastructure

**Description**: Create the testing directory structure, test fixtures, and testing utilities for unit, integration, and property-based tests.

**Acceptance Criteria**:
- [ ] Test directory structure created (`tests/unit/`, `tests/integration/`, `tests/fixtures/`)
- [ ] Fixture files created for Ethereum transactions
- [ ] Test utilities module created with mock helpers
- [ ] Coverage configuration added (cargo-llvm-cov)
- [ ] Test runner scripts created
- [ ] Property-based testing framework integrated (proptest)

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Verify `cargo test` runs successfully
- Verify coverage reporting works with `cargo llvm-cov`

**Files**:
- Create: `tests/unit/mod.rs`
- Create: `tests/integration/mod.rs`
- Create: `tests/fixtures/ethereum_txs.json`
- Create: `tests/test_utils.rs`
- Create: `.cargo/config.toml` (with llvm-cov settings)

---

#### SELLO-003.5: Set up fuzzing infrastructure

**Description**: Configure cargo-fuzz for fuzzing transaction parsers and policy rules. Fuzzing is critical for finding edge cases in parsing code.

**Acceptance Criteria**:
- [ ] cargo-fuzz configured in workspace
- [ ] Fuzz target directory structure created
- [ ] Initial fuzz target for Ethereum parser placeholder
- [ ] CI workflow for scheduled fuzzing (1 hour daily)
- [ ] Corpus directory for storing interesting inputs
- [ ] Documentation for running fuzz tests locally

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Verify fuzz targets compile
- Verify CI fuzzing workflow runs

**Files**:
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/ethereum_parser.rs`
- Create: `fuzz/fuzz_targets/policy_rules.rs`
- Create: `.github/workflows/fuzz.yml`
- Create: `docs/FUZZING.md`

---

#### SELLO-004: Configure linting and formatting

**Description**: Set up clippy rules, rustfmt configuration, and pre-commit hooks to enforce code quality standards.

**Acceptance Criteria**:
- [ ] `.clippy.toml` created with strict rules
- [ ] `rustfmt.toml` created with project style
- [ ] Clippy denies warnings configuration added
- [ ] Pre-commit hook script created
- [ ] CI workflow includes linting step
- [ ] All clippy lints pass

**Dependencies**: SELLO-001

**Complexity**: S

**Testing Requirements**:
- Run `cargo clippy -- -D warnings` successfully
- Run `cargo fmt -- --check` successfully

**Files**:
- Create: `.clippy.toml`
- Create: `rustfmt.toml`
- Create: `.git/hooks/pre-commit`
- Modify: `.github/workflows/ci.yml`

---

### Epic 2: Core Types and Errors

#### SELLO-005: Implement core types module

**Description**: Create the core types module with `ParsedTx`, `TxType`, `PolicyResult`, and other shared data structures.

**Security Note**: This is a foundation for all transaction parsing - type safety is critical.

**Acceptance Criteria**:
- [ ] `ParsedTx` struct implemented with all fields
- [ ] `TxType` enum implemented (Transfer, TokenTransfer, ContractCall, Other)
- [ ] `PolicyResult` enum implemented (Allowed, Denied)
- [ ] All types derive necessary traits (Clone, Debug, Serialize, Deserialize)
- [ ] Documentation comments added for all public types
- [ ] Field validation logic included where appropriate

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Unit tests for serialization/deserialization
- Unit tests for type conversions
- Property tests for invariants (e.g., amounts are non-negative)

**Files**:
- Create: `crates/sello-core/src/lib.rs`
- Create: `crates/sello-core/src/types.rs`
- Create: `crates/sello-core/src/types_test.rs`

---

#### SELLO-006: Implement error types

**Description**: Define comprehensive error types for all modules using thiserror, with proper error propagation and context.

**Acceptance Criteria**:
- [ ] `ParseError` enum with variants for all parsing failure modes
- [ ] `SignError` enum with variants for signing failures
- [ ] `StoreError` enum with variants for key storage failures
- [ ] `PolicyError` enum with variants for policy evaluation failures
- [ ] All errors implement `Error` trait via thiserror
- [ ] Error messages are clear and actionable
- [ ] Errors include context where appropriate

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Unit tests for error display messages
- Unit tests for error source chains
- Test error conversion paths

**Files**:
- Create: `crates/sello-core/src/error.rs`
- Create: `crates/sello-core/src/error_test.rs`

---

### Epic 3: Cryptography

#### SELLO-007: Implement SecretKey type with zeroization

**Description**: Create a memory-safe SecretKey type that zeroizes on drop, preventing key material from remaining in memory.

**Security Note**: CRITICAL - This prevents key material from being leaked through memory dumps or swap files.

**Acceptance Criteria**:
- [ ] `SecretKey` struct wraps [u8; 32]
- [ ] Implements `Zeroize` and `ZeroizeOnDrop` traits
- [ ] No `Clone` implementation (keys must be moved)
- [ ] No `Debug` implementation that exposes key material
- [ ] Const-time operations where applicable
- [ ] Documentation warns about security implications

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Unit test verifying memory is zeroed after drop (using unsafe block to check)
- Unit test verifying no accidental clones
- Unit test for serialization is disabled

**Files**:
- Create: `crates/sello-crypto/src/lib.rs`
- Create: `crates/sello-crypto/src/keys.rs`
- Create: `crates/sello-crypto/src/keys_test.rs`

---

#### SELLO-008: Implement KeyPair trait and secp256k1 implementation

**Description**: Define the KeyPair trait and implement it for secp256k1 (used by Ethereum, Bitcoin, Tron, Ripple).

**Acceptance Criteria**:
- [ ] `KeyPair` trait defined with methods: `generate()`, `from_bytes()`, `public_key()`, `sign()`
- [ ] `Secp256k1KeyPair` struct implements `KeyPair`
- [ ] Uses k256 crate for cryptographic operations
- [ ] Private key stored as `SecretKey` type
- [ ] Public key derivation tested against known vectors
- [ ] Trait is `Send + Sync` for multi-threading

**Dependencies**: SELLO-007

**Complexity**: L

**Testing Requirements**:
- Unit tests for key generation (randomness check with multiple samples)
- Unit tests for key serialization/deserialization
- Unit tests with test vectors from secp256k1 specification
- Unit tests for signature generation and verification
- Property tests for sign/verify round-trip

**Files**:
- Modify: `crates/sello-crypto/src/keys.rs`
- Create: `crates/sello-crypto/src/secp256k1.rs`
- Create: `crates/sello-crypto/src/secp256k1_test.rs`

---

#### SELLO-009: Implement Signer trait and implementation

**Description**: Create the Signer trait for signing message hashes and implement it for secp256k1.

**Acceptance Criteria**:
- [ ] `Signer` trait defined with methods: `sign(&[u8; 32])`, `public_key()`, `address(chain)`
- [ ] `Secp256k1Signer` implements `Signer`
- [ ] Signatures include recovery ID for Ethereum compatibility
- [ ] Address derivation for Ethereum (keccak256)
- [ ] Trait is `Send + Sync`
- [ ] Clear documentation on signature format

**Dependencies**: SELLO-008

**Complexity**: M

**Testing Requirements**:
- Unit tests for signature generation
- Unit tests for signature verification
- Unit tests for Ethereum address derivation
- Test vectors from Ethereum signing examples
- Mock implementation for testing

**Files**:
- Create: `crates/sello-crypto/src/signer.rs`
- Create: `crates/sello-crypto/src/signer_test.rs`

---

#### SELLO-010: Implement key encryption with ChaCha20-Poly1305

**Description**: Implement AEAD encryption for key material at rest using ChaCha20-Poly1305 with Argon2id for key derivation.

**Security Note**: CRITICAL - This protects keys at rest. Must use secure parameters.

**Acceptance Criteria**:
- [ ] Argon2id KDF implemented with secure parameters (memory: 64MB, iterations: 3, parallelism: 4)
- [ ] ChaCha20-Poly1305 AEAD encryption implemented
- [ ] Salt generation uses cryptographically secure RNG
- [ ] Nonce generation uses cryptographically secure RNG
- [ ] Encrypted format includes version byte for future compatibility
- [ ] Clear separation between encryption and decryption functions
- [ ] Constant-time comparison where applicable

**Dependencies**: SELLO-007

**Complexity**: L

**Testing Requirements**:
- Unit tests for encryption/decryption round-trip
- Unit tests verifying different passphrases produce different outputs
- Unit tests verifying authentication tag validation
- Unit tests for malformed input handling
- Test with known Argon2id vectors

**Files**:
- Create: `crates/sello-crypto/src/encryption.rs`
- Create: `crates/sello-crypto/src/encryption_test.rs`

---

#### SELLO-011: Implement KeyStore trait and file-based implementation

**Description**: Create the KeyStore trait for persisting encrypted keys and implement a file-based storage backend.

**Acceptance Criteria**:
- [ ] `KeyStore` trait defined with methods: `store()`, `load()`, `list()`, `delete()`
- [ ] `FileKeyStore` implements `KeyStore`
- [ ] Keys stored in `~/.sello/keys/` directory
- [ ] Each key in separate file with `.enc` extension
- [ ] File permissions set to 0600 (owner read/write only)
- [ ] Atomic writes using temp files + rename
- [ ] Trait is `Send + Sync`

**Dependencies**: SELLO-010

**Complexity**: L

**Testing Requirements**:
- Unit tests for store/load round-trip
- Unit tests for list operation
- Unit tests for delete operation
- Unit tests for file permission enforcement
- Unit tests for concurrent access safety
- Integration tests using tempfile
- Mock implementation for testing

**Files**:
- Create: `crates/sello-crypto/src/store.rs`
- Create: `crates/sello-crypto/src/store_test.rs`

---

### Epic 4: Ethereum Chain Parser

#### SELLO-012: Implement Chain trait

**Description**: Define the Chain trait that all blockchain parsers implement.

**Acceptance Criteria**:
- [ ] `Chain` trait defined with methods: `id()`, `parse(&[u8])`
- [ ] Returns `Result<ParsedTx, ParseError>`
- [ ] Trait is `Send + Sync`
- [ ] Clear documentation on parser responsibilities
- [ ] Version handling strategy documented

**Dependencies**: SELLO-005, SELLO-006

**Complexity**: S

**Testing Requirements**:
- Mock implementation created
- Documentation tests compile

**Files**:
- Create: `crates/sello-chain/src/lib.rs`
- Create: `crates/sello-chain/src/chain.rs`

---

#### SELLO-012.5: Implement ChainRegistry

**Description**: Create the ChainRegistry that holds all chain parsers and provides runtime chain lookup.

**Acceptance Criteria**:
- [ ] `ChainRegistry` struct with `HashMap<String, Box<dyn Chain>>`
- [ ] `new()` constructor that registers all supported chains
- [ ] `get(chain_id)` method for chain lookup
- [ ] `supported_chains()` method to list all chains
- [ ] Thread-safe (uses Arc internally for cloning)
- [ ] Default registry with Ethereum parser

**Dependencies**: SELLO-012

**Complexity**: S

**Testing Requirements**:
- Unit tests for chain registration
- Unit tests for chain lookup
- Unit tests for unknown chain handling
- Unit tests for supported chains listing

**Files**:
- Create: `crates/sello-chain/src/registry.rs`
- Create: `crates/sello-chain/src/registry_test.rs`

---

#### SELLO-013: Implement Ethereum RLP decoding utilities

**Description**: Create utilities for RLP (Recursive Length Prefix) decoding needed for Ethereum transaction parsing.

**Acceptance Criteria**:
- [ ] RLP decoding functions implemented
- [ ] Support for lists and byte strings
- [ ] Error handling for malformed RLP
- [ ] Uses alloy-primitives where possible
- [ ] Helper functions for common patterns

**Dependencies**: SELLO-012

**Complexity**: M

**Testing Requirements**:
- Unit tests with RLP test vectors
- Unit tests for error conditions
- Fuzz testing for malformed input

**Files**:
- Create: `crates/sello-chain/src/rlp.rs`
- Create: `crates/sello-chain/src/rlp_test.rs`

---

#### SELLO-013.5: Implement Token Registry

**Description**: Create a registry of known ERC-20 tokens with metadata (symbol, decimals, risk level) for policy enrichment.

**Acceptance Criteria**:
- [ ] `TokenRegistry` struct with `HashMap<Address, TokenInfo>`
- [ ] `TokenInfo` struct with symbol, decimals, risk_level
- [ ] `RiskLevel` enum (Low, Medium, High)
- [ ] Built-in registry with major stablecoins (USDC, USDT, DAI)
- [ ] Method to lookup token by address
- [ ] Method to add custom tokens from config
- [ ] JSON serialization for custom token lists

**Dependencies**: SELLO-012

**Complexity**: S

**Testing Requirements**:
- Unit tests for token lookup
- Unit tests for unknown token handling
- Unit tests for custom token registration
- Unit tests for JSON serialization

**Files**:
- Create: `crates/sello-chain/src/tokens.rs`
- Create: `crates/sello-chain/src/tokens_test.rs`
- Create: `crates/sello-chain/src/tokens/builtin.json`

---

#### SELLO-014: Implement Ethereum parser for legacy and EIP-1559 transactions

**Description**: Parse Ethereum transactions (legacy, EIP-2930, EIP-1559) and extract recipient, amount, and token information.

**Security Note**: CRITICAL - Parser correctness is essential for policy enforcement.

**Acceptance Criteria**:
- [ ] `EthereumParser` implements `Chain` trait
- [ ] Parses legacy transactions (type 0)
- [ ] Parses EIP-2930 transactions (type 1)
- [ ] Parses EIP-1559 transactions (type 2)
- [ ] Correctly extracts recipient address
- [ ] Correctly extracts ETH transfer amount
- [ ] Correctly calculates transaction hash for signing
- [ ] Handles edge cases (0 value, contract creation)

**Dependencies**: SELLO-013

**Complexity**: XL

**Testing Requirements**:
- Unit tests for each transaction type with fixtures
- Unit tests for edge cases (0 value, max value)
- Test vectors from Ethereum specification
- Fuzz testing for malformed transactions
- Property tests for invariants (hash uniqueness)
- Integration tests with real transaction data

**Files**:
- Create: `crates/sello-chain/src/ethereum.rs`
- Create: `crates/sello-chain/src/ethereum_test.rs`
- Create: `tests/fixtures/ethereum_legacy.json`
- Create: `tests/fixtures/ethereum_eip1559.json`

---

#### SELLO-015: Implement ERC-20 token operation detection

**Description**: Detect and parse ERC-20 token operations by decoding `transfer`, `approve`, and `transferFrom` function calls.

**Security Note**: CRITICAL - approve() grants unlimited spending power; transferFrom() moves funds.

**Acceptance Criteria**:
- [ ] Detects `transfer` function selector (0xa9059cbb)
- [ ] Detects `approve` function selector (0x095ea7b3)
- [ ] Detects `transferFrom` function selector (0x23b872dd)
- [ ] Decodes recipient/spender address from calldata
- [ ] Decodes transfer/approval amount from calldata
- [ ] Extracts token contract address (the `to` field of the transaction)
- [ ] Sets `tx_type` to `TokenTransfer` for transfer/transferFrom
- [ ] Sets `tx_type` to `TokenApproval` for approve
- [ ] Handles ABI encoding correctly
- [ ] Validates calldata length (68 bytes for transfer/approve, 100 bytes for transferFrom)

**Dependencies**: SELLO-014, SELLO-013.5

**Complexity**: L

**Testing Requirements**:
- Unit tests with real USDC/USDT transfer transactions
- Unit tests with approve transactions
- Unit tests with transferFrom transactions
- Unit tests for malformed calldata
- Unit tests for other function selectors
- Test against known token transfers on Etherscan
- Fuzz testing for malformed calldata

**Files**:
- Modify: `crates/sello-chain/src/ethereum.rs`
- Create: `tests/fixtures/ethereum_erc20_transfer.json`
- Create: `tests/fixtures/ethereum_erc20_approve.json`
- Create: `tests/fixtures/ethereum_erc20_transfer_from.json`

---

### Epic 5: Policy Engine

#### SELLO-016: Implement policy configuration types

**Description**: Create data structures for policy configuration (whitelist, blacklist, transaction limits, daily limits).

**Acceptance Criteria**:
- [ ] `PolicyConfig` struct with all fields
- [ ] Support for whitelist (Vec<String>)
- [ ] Support for blacklist (Vec<String>)
- [ ] Support for per-token transaction limits (HashMap<String, U256>)
- [ ] Support for per-token daily limits (HashMap<String, U256>)
- [ ] Implements serde for TOML serialization
- [ ] Validation logic for config (e.g., no negative limits)
- [ ] Default implementation with sensible defaults

**Dependencies**: SELLO-005

**Complexity**: M

**Testing Requirements**:
- Unit tests for TOML serialization/deserialization
- Unit tests for validation logic
- Unit tests for defaults

**Files**:
- Create: `crates/sello-policy/src/lib.rs`
- Create: `crates/sello-policy/src/config.rs`
- Create: `crates/sello-policy/src/config_test.rs`

---

#### SELLO-017: Implement transaction history tracking with SQLite

**Description**: Create a transaction history module backed by SQLite to track daily spending for rate limiting. SQLite is required (not in-memory) because daily limits must survive server restarts.

**Acceptance Criteria**:
- [ ] `TransactionHistory` struct wraps SQLite connection
- [ ] SQLite database file at `~/.sello/history.db`
- [ ] Schema: `CREATE TABLE history (id INTEGER PRIMARY KEY, token TEXT, amount TEXT, timestamp INTEGER, tx_hash TEXT)`
- [ ] Method to calculate daily total for a specific token (SQL aggregation)
- [ ] Method to add a transaction to history
- [ ] Automatic cleanup of transactions older than 24 hours (via SQL DELETE)
- [ ] Thread-safe with connection pooling (r2d2 or similar)
- [ ] LRU cache for frequently accessed totals
- [ ] Database migrations support for schema evolution

**Dependencies**: SELLO-005

**Complexity**: L

**Testing Requirements**:
- Unit tests for adding transactions (with tempfile database)
- Unit tests for daily total calculation
- Unit tests for cleanup logic
- Unit tests with clock mocking for time-based tests
- Concurrent access tests
- Tests for database migration
- Tests for persistence across restarts

**Files**:
- Create: `crates/sello-policy/src/history.rs`
- Create: `crates/sello-policy/src/history_test.rs`
- Create: `crates/sello-policy/src/migrations/`

---

#### SELLO-018: Implement PolicyEngine trait and rule evaluation

**Description**: Create the PolicyEngine trait and implement the default policy engine with whitelist, blacklist, and limit enforcement.

**Security Note**: CRITICAL - This is the core security enforcement mechanism.

**Acceptance Criteria**:
- [ ] `PolicyEngine` trait defined with methods: `check()`, `record()`
- [ ] `DefaultPolicyEngine` implements `PolicyEngine`
- [ ] Blacklist checked first (highest priority)
- [ ] Whitelist checked second (if enabled)
- [ ] Transaction limit checked third
- [ ] Daily limit checked fourth
- [ ] Clear error messages indicating which rule failed
- [ ] Rule evaluation order matches specification
- [ ] Trait is `Send + Sync`

**Dependencies**: SELLO-016, SELLO-017

**Complexity**: L

**Testing Requirements**:
- Unit tests for each rule type in isolation
- Unit tests for rule precedence (blacklist > whitelist)
- Unit tests for limit accumulation
- Unit tests for edge cases (zero limits, no limits)
- Integration tests with multiple rules
- Mock implementation for testing

**Files**:
- Create: `crates/sello-policy/src/engine.rs`
- Create: `crates/sello-policy/src/engine_test.rs`

---

### Epic 6: Configuration Management

#### SELLO-019: Implement configuration file structure

**Description**: Define the TOML configuration file structure and schema for `~/.sello/config.toml`.

**Acceptance Criteria**:
- [ ] `Config` struct represents entire configuration
- [ ] Nested structure for policy section
- [ ] Nested structure for server section (socket path)
- [ ] Implements serde for TOML
- [ ] Schema validation
- [ ] Default configuration template

**Dependencies**: SELLO-016

**Complexity**: M

**Testing Requirements**:
- Unit tests for TOML parsing
- Unit tests for invalid configurations
- Unit tests for default values

**Files**:
- Create: `crates/sello-core/src/config.rs`
- Create: `crates/sello-core/src/config_test.rs`

---

#### SELLO-020: Implement configuration loader

**Description**: Create a configuration loader that reads from `~/.sello/config.toml` with proper error handling and defaults.

**Acceptance Criteria**:
- [ ] Reads configuration from `~/.sello/config.toml`
- [ ] Falls back to defaults if file doesn't exist
- [ ] Clear error messages for invalid TOML
- [ ] Expands `~` in paths correctly
- [ ] Validates configuration after loading
- [ ] Function to write default config file

**Dependencies**: SELLO-019

**Complexity**: M

**Testing Requirements**:
- Unit tests with tempfile
- Unit tests for missing file handling
- Unit tests for invalid TOML
- Unit tests for path expansion

**Files**:
- Create: `crates/sello-core/src/config_loader.rs`
- Create: `crates/sello-core/src/config_loader_test.rs`

---

### Epic 7: CLI Interface

#### SELLO-021: Implement CLI argument parsing structure

**Description**: Define the CLI command structure using clap with all subcommands for v0.1.0.

**Acceptance Criteria**:
- [ ] Main CLI struct with subcommands
- [ ] `init` subcommand defined
- [ ] `status` subcommand defined
- [ ] `config` subcommand defined (view/edit)
- [ ] `serve` subcommand defined
- [ ] `ethereum` subcommand group (address, sign)
- [ ] All arguments properly typed
- [ ] Help text for all commands
- [ ] Version information included

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Unit tests for argument parsing
- Unit tests for help text generation
- Integration tests for command validation

**Files**:
- Create: `crates/sello/src/cli/mod.rs`
- Create: `crates/sello/src/cli/args.rs`
- Create: `crates/sello/src/cli/args_test.rs`

---

#### SELLO-021.5: Implement logging infrastructure

**Description**: Set up structured logging with tracing crate for observability.

**Acceptance Criteria**:
- [ ] tracing crate configured for structured logging
- [ ] JSON format for production, pretty format for development
- [ ] Log level configuration via config file and env vars
- [ ] Correlation ID generation for request tracing
- [ ] Log file rotation support
- [ ] Sensitive data redaction (keys, passphrases)

**Dependencies**: SELLO-002

**Complexity**: M

**Testing Requirements**:
- Unit tests for log formatting
- Unit tests for sensitive data redaction
- Tests for log level configuration

**Files**:
- Create: `crates/sello/src/logging.rs`
- Create: `crates/sello/src/logging_test.rs`

---

#### SELLO-022: Implement `sello init` command

**Description**: Implement the initialization command that creates `~/.sello` directory, generates default key, and creates config file.

**Acceptance Criteria**:
- [ ] Prompts for passphrase (with confirmation)
- [ ] Creates `~/.sello` directory structure
- [ ] Creates subdirectories: `keys/`, `logs/`
- [ ] Generates default secp256k1 key pair
- [ ] Encrypts and stores key as `default.enc`
- [ ] Creates default `config.toml`
- [ ] Sets proper file permissions (directory: 0700, files: 0600)
- [ ] Idempotent (doesn't overwrite existing installation)
- [ ] Success message with next steps

**Dependencies**: SELLO-011, SELLO-020, SELLO-021

**Complexity**: L

**Testing Requirements**:
- Integration tests with tempfile
- Tests for permission enforcement
- Tests for idempotency
- Tests for error handling (permission denied, etc.)

**Files**:
- Create: `crates/sello/src/cli/commands/init.rs`
- Create: `crates/sello/src/cli/commands/init_test.rs`

---

#### SELLO-023: Implement `sello status` command

**Description**: Display current status including key count, chains supported, policy summary, and transaction statistics.

**Acceptance Criteria**:
- [ ] Displays number of keys
- [ ] Lists supported chains
- [ ] Shows policy summary (limits, whitelist count)
- [ ] Shows transaction count (from history)
- [ ] Formatted output with sections
- [ ] Handles missing configuration gracefully

**Dependencies**: SELLO-011, SELLO-020, SELLO-021

**Complexity**: M

**Testing Requirements**:
- Unit tests for output formatting
- Integration tests with mock data

**Files**:
- Create: `crates/sello/src/cli/commands/status.rs`
- Create: `crates/sello/src/cli/commands/status_test.rs`

---

#### SELLO-024: Implement `sello config` command

**Description**: View and edit configuration with subcommands for viewing and opening in editor.

**Acceptance Criteria**:
- [ ] `sello config` displays current configuration
- [ ] `sello config edit` opens config in $EDITOR
- [ ] Validates config after edit
- [ ] Pretty-printed TOML output
- [ ] Error handling for invalid editor

**Dependencies**: SELLO-020, SELLO-021

**Complexity**: M

**Testing Requirements**:
- Unit tests for config display
- Integration tests for edit flow (with test editor)

**Files**:
- Create: `crates/sello/src/cli/commands/config.rs`
- Create: `crates/sello/src/cli/commands/config_test.rs`

---

#### SELLO-025: Implement `sello ethereum address` command

**Description**: Display the Ethereum address derived from the default key.

**Acceptance Criteria**:
- [ ] Loads default key
- [ ] Derives Ethereum address (keccak256 of public key)
- [ ] Displays address with 0x prefix
- [ ] EIP-55 checksummed format
- [ ] Clear error if key doesn't exist

**Dependencies**: SELLO-009, SELLO-011, SELLO-021

**Complexity**: S

**Testing Requirements**:
- Unit tests for address derivation
- Unit tests for error handling

**Files**:
- Create: `crates/sello/src/cli/commands/ethereum/address.rs`
- Create: `crates/sello/src/cli/commands/ethereum/address_test.rs`

---

#### SELLO-026: Implement signing flow orchestration

**Description**: Create the core signing flow that orchestrates parsing, policy checking, and signing.

**Acceptance Criteria**:
- [ ] `SigningService` struct coordinates components
- [ ] Takes dependencies via trait injection (Chain, PolicyEngine, Signer)
- [ ] Parses transaction using chain parser
- [ ] Checks policy
- [ ] Records transaction if allowed
- [ ] Signs transaction hash
- [ ] Returns comprehensive result or error
- [ ] Logs all operations

**Dependencies**: SELLO-009, SELLO-014, SELLO-018

**Complexity**: L

**Testing Requirements**:
- Unit tests with mock dependencies
- Unit tests for policy rejection flow
- Unit tests for signing success flow
- Integration tests with real components

**Files**:
- Create: `crates/sello-core/src/signing.rs`
- Create: `crates/sello-core/src/signing_test.rs`

---

#### SELLO-027: Implement `sello ethereum sign` command

**Description**: Parse, validate policy, and sign Ethereum transactions from the CLI.

**Acceptance Criteria**:
- [ ] Accepts raw transaction hex as argument
- [ ] Decodes hex input
- [ ] Loads configuration
- [ ] Loads default key (prompts for passphrase)
- [ ] Initializes signing service with real components
- [ ] Displays parsed transaction details
- [ ] Displays policy check results
- [ ] Displays signature on success
- [ ] Clear error messages on failure
- [ ] Exit codes: 0 (success), 1 (policy denied), 2 (other error)

**Dependencies**: SELLO-015, SELLO-018, SELLO-021, SELLO-026

**Complexity**: L

**Testing Requirements**:
- Integration tests with test fixtures
- Tests for policy rejection
- Tests for signing success
- Tests for invalid input handling

**Files**:
- Create: `crates/sello/src/cli/commands/ethereum/sign.rs`
- Create: `crates/sello/src/cli/commands/ethereum/sign_test.rs`

---

### Epic 8: Unix Socket Server

#### SELLO-028: Implement JSON-RPC protocol types

**Description**: Define request/response types for JSON-RPC protocol over Unix socket.

**Acceptance Criteria**:
- [ ] `JsonRpcRequest` struct (id, method, params)
- [ ] `JsonRpcResponse` struct (id, result/error)
- [ ] `SignRequest` and `SignResponse` types
- [ ] Error response types
- [ ] All types implement serde
- [ ] Protocol version included

**Dependencies**: SELLO-005

**Complexity**: M

**Testing Requirements**:
- Unit tests for JSON serialization
- Unit tests for deserialization
- Unit tests for error responses

**Files**:
- Create: `crates/sello/src/server/protocol.rs`
- Create: `crates/sello/src/server/protocol_test.rs`

---

#### SELLO-029: Implement Unix socket server

**Description**: Create a Unix socket server that listens for signing requests and executes the signing flow.

**Acceptance Criteria**:
- [ ] Listens on `~/.sello/sello.sock`
- [ ] Sets socket permissions to 0600
- [ ] Accepts concurrent connections (tokio async)
- [ ] Parses JSON-RPC requests
- [ ] Routes to signing service
- [ ] Returns JSON-RPC responses
- [ ] Graceful shutdown on SIGTERM/SIGINT
- [ ] Logs all requests/responses

**Dependencies**: SELLO-026, SELLO-028

**Complexity**: L

**Testing Requirements**:
- Integration tests with test client
- Tests for concurrent connections
- Tests for malformed requests
- Tests for graceful shutdown

**Files**:
- Create: `crates/sello/src/server/socket.rs`
- Create: `crates/sello/src/server/socket_test.rs`

---

#### SELLO-030: Implement `sello serve` command

**Description**: Start the Unix socket server as a long-running process.

**Acceptance Criteria**:
- [ ] Loads configuration
- [ ] Loads default key (prompts for passphrase once)
- [ ] Initializes all services (parser, policy, signer)
- [ ] Starts Unix socket server
- [ ] Displays startup message with socket path
- [ ] Handles signals for graceful shutdown
- [ ] Logs server events

**Dependencies**: SELLO-021, SELLO-029

**Complexity**: M

**Testing Requirements**:
- Integration tests with server startup/shutdown
- Tests for signal handling

**Files**:
- Create: `crates/sello/src/cli/commands/serve.rs`
- Create: `crates/sello/src/cli/commands/serve_test.rs`

---

### Epic 9: Main Binary and Integration

#### SELLO-031: Implement main binary entry point

**Description**: Create the main binary that dispatches to CLI commands.

**Acceptance Criteria**:
- [ ] Parses CLI arguments
- [ ] Dispatches to appropriate command handler
- [ ] Sets up logging
- [ ] Handles errors and exit codes
- [ ] Version and help information

**Dependencies**: SELLO-021

**Complexity**: S

**Testing Requirements**:
- Integration tests for command dispatch
- Tests for error handling

**Files**:
- Create: `crates/sello/src/main.rs`

---

#### SELLO-031.5: Implement audit logging with HMAC chain

**Description**: Create tamper-evident audit logging with HMAC chain for security-critical events.

**Security Note**: CRITICAL - Audit logs provide forensic evidence for security incidents.

**Acceptance Criteria**:
- [ ] `AuditLogger` struct for append-only logging
- [ ] JSONL format for log entries
- [ ] HMAC chain linking entries (tamper-evidence)
- [ ] Log entry includes: seq, timestamp, correlation_id, chain, tx_hash, recipient, amount, token, tx_type, policy_result, signature
- [ ] Automatic log rotation by size
- [ ] Log verification command to check HMAC chain integrity
- [ ] Compressed rotation of old logs

**Dependencies**: SELLO-021.5

**Complexity**: L

**Testing Requirements**:
- Unit tests for log entry creation
- Unit tests for HMAC chain generation
- Unit tests for chain verification
- Unit tests for log rotation
- Tests for tamper detection

**Files**:
- Create: `crates/sello/src/audit.rs`
- Create: `crates/sello/src/audit_test.rs`

---

#### SELLO-032: Create end-to-end integration tests

**Description**: Comprehensive integration tests covering the full signing flow from CLI to signature.

**Acceptance Criteria**:
- [ ] Test full `init` → `sign` flow
- [ ] Test policy enforcement end-to-end
- [ ] Test server mode signing flow
- [ ] Test with real Ethereum transaction fixtures
- [ ] Test error paths (invalid tx, policy rejection)
- [ ] Test concurrent server requests
- [ ] Test daily limit persistence across restarts
- [ ] Test all ERC-20 operations (transfer, approve, transferFrom)
- [ ] Test nonce and chain_id validation

**Dependencies**: SELLO-027, SELLO-030

**Complexity**: XL

**Testing Requirements**:
- Full end-to-end scenarios
- Performance benchmarks
- Concurrency stress tests
- Database persistence tests

**Files**:
- Create: `tests/integration/sign_flow_test.rs`
- Create: `tests/integration/policy_enforcement_test.rs`
- Create: `tests/integration/server_test.rs`
- Create: `tests/integration/persistence_test.rs`

---

### Epic 10: Documentation and Polish

#### SELLO-033: Write API documentation

**Description**: Comprehensive rustdoc documentation for all public APIs.

**Acceptance Criteria**:
- [ ] All public types have doc comments
- [ ] All public functions have doc comments
- [ ] Examples included in doc comments
- [ ] Module-level documentation
- [ ] `cargo doc` generates clean documentation
- [ ] No missing doc warnings

**Dependencies**: All implementation tasks

**Complexity**: M

**Testing Requirements**:
- Doc tests compile and pass
- `cargo doc --no-deps` succeeds

**Files**:
- Modify: All `src/**/*.rs` files

---

#### SELLO-033.5: Implement coverage enforcement in CI

**Description**: Configure CI to enforce coverage requirements and block PRs that decrease coverage on critical modules.

**Acceptance Criteria**:
- [ ] cargo-llvm-cov configured (replacing tarpaulin)
- [ ] Coverage thresholds defined per crate
- [ ] CI fails if sello-crypto < 100%
- [ ] CI fails if sello-chain < 100%
- [ ] CI fails if sello-policy < 100%
- [ ] Coverage badge in README
- [ ] Coverage trend tracking
- [ ] PR comments with coverage diff

**Dependencies**: SELLO-003

**Complexity**: M

**Testing Requirements**:
- Verify coverage reports generate correctly
- Verify CI fails on coverage decrease

**Files**:
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/coverage.yml`
- Create: `codecov.yml`

---

#### SELLO-034: Create user guide

**Description**: User-facing documentation covering installation, quickstart, and common workflows.

**Acceptance Criteria**:
- [ ] Installation instructions
- [ ] Quickstart guide (2-minute path)
- [ ] Configuration guide
- [ ] Policy examples
- [ ] Troubleshooting section
- [ ] Security best practices

**Dependencies**: SELLO-032

**Complexity**: M

**Testing Requirements**:
- Manual testing of all instructions
- Links validation

**Files**:
- Create: `docs/USER_GUIDE.md`
- Create: `docs/QUICKSTART.md`
- Create: `docs/CONFIGURATION.md`

---

#### SELLO-035: Create developer guide

**Description**: Developer documentation covering architecture, contribution guidelines, and testing.

**Acceptance Criteria**:
- [ ] Architecture overview
- [ ] Module responsibilities
- [ ] Testing guidelines
- [ ] Contribution workflow
- [ ] Code style guide
- [ ] Security review checklist

**Dependencies**: SELLO-032

**Complexity**: M

**Testing Requirements**:
- Code examples compile
- Instructions are accurate

**Files**:
- Create: `docs/DEVELOPER_GUIDE.md`
- Create: `docs/CONTRIBUTING.md`
- Create: `docs/ARCHITECTURE.md`

---

#### SELLO-036: Achieve 100% test coverage on critical modules

**Description**: Ensure 100% line and branch coverage on crypto, chain parsers, and policy engine.

**Security Note**: CRITICAL - These modules require exhaustive testing.

**Acceptance Criteria**:
- [ ] `sello-crypto` has 100% coverage
- [ ] `sello-chain` has 100% coverage
- [ ] `sello-policy` has 100% coverage
- [ ] Coverage report generated with cargo-llvm-cov
- [ ] Coverage badge in README
- [ ] CI enforces coverage requirements (SELLO-033.5)

**Dependencies**: All implementation tasks, SELLO-033.5

**Complexity**: L

**Testing Requirements**:
- Run `cargo llvm-cov --html`
- Verify coverage metrics
- Add missing tests for uncovered paths

**Files**:
- Modify: All test files
- Create: Additional test cases as needed

---

#### SELLO-037: Security audit and review

**Description**: Comprehensive security review of cryptographic code, key storage, and policy enforcement.

**Security Note**: CRITICAL - Human review required for all security-sensitive code.

**Acceptance Criteria**:
- [ ] Crypto code reviewed for side-channel vulnerabilities
- [ ] Key storage reviewed for secure defaults
- [ ] Policy engine reviewed for bypass vulnerabilities
- [ ] All unsafe code blocks justified and documented
- [ ] Dependencies audited with `cargo audit`
- [ ] Security checklist completed
- [ ] Known issues documented

**Dependencies**: SELLO-036

**Complexity**: XL

**Testing Requirements**:
- Run `cargo audit`
- Run `cargo clippy -- -D warnings`
- Manual code review
- Security-focused integration tests

**Files**:
- Create: `SECURITY.md`
- Create: `docs/SECURITY_AUDIT.md`

---

#### SELLO-038: Performance benchmarking

**Description**: Create benchmarks for critical paths (parsing, signing) and document performance characteristics.

**Acceptance Criteria**:
- [ ] Benchmarks for Ethereum transaction parsing
- [ ] Benchmarks for signing operations
- [ ] Benchmarks for policy evaluation
- [ ] Benchmarks run in CI
- [ ] Performance regression detection
- [ ] Results documented

**Dependencies**: SELLO-032

**Complexity**: M

**Testing Requirements**:
- Use criterion for benchmarks
- Establish baseline metrics

**Files**:
- Create: `benches/parsing.rs`
- Create: `benches/signing.rs`
- Create: `benches/policy.rs`

---

#### SELLO-039: Create release automation

**Description**: Set up CI/CD pipeline for automated releases with GitHub Actions.

**Acceptance Criteria**:
- [ ] GitHub Actions workflow for releases
- [ ] Automated binary builds for Linux/macOS
- [ ] Checksums generated
- [ ] Release notes automation
- [ ] Version bumping workflow
- [ ] Tag-based release triggers

**Dependencies**: SELLO-037

**Complexity**: M

**Testing Requirements**:
- Test release workflow on test repository
- Verify artifact generation

**Files**:
- Create: `.github/workflows/release.yml`
- Create: `scripts/release.sh`

---

#### SELLO-040: Prepare v0.1.0 release

**Description**: Final preparations for v0.1.0 release including changelog, version updates, and release announcement.

**Acceptance Criteria**:
- [ ] CHANGELOG.md created with all changes
- [ ] Version bumped to 0.1.0 in all Cargo.toml files
- [ ] README.md updated with installation instructions
- [ ] All CI checks passing
- [ ] Release notes drafted
- [ ] GitHub release created
- [ ] Announcement prepared

**Dependencies**: SELLO-039

**Complexity**: S

**Testing Requirements**:
- Manual testing of release artifacts
- Verify installation from release

**Files**:
- Create: `CHANGELOG.md`
- Modify: `Cargo.toml` (all)
- Modify: `README.md`

---

## Task Summary

### By Complexity
- **Small (S)**: 7 tasks (SELLO-001, 002, 004, 012, 012.5, 013.5, 040)
- **Medium (M)**: 18 tasks
- **Large (L)**: 14 tasks (including SELLO-017, 031.5)
- **Extra Large (XL)**: 7 tasks (SELLO-014, 032, 037)

**Total**: 46 tasks (40 original + 6 new critical tasks)

### By Epic
1. **Project Infrastructure**: 5 tasks (SELLO-001 to SELLO-004, SELLO-003.5)
2. **Core Types and Errors**: 2 tasks (SELLO-005 to SELLO-006)
3. **Cryptography**: 5 tasks (SELLO-007 to SELLO-011)
4. **Ethereum Chain Parser**: 6 tasks (SELLO-012 to SELLO-015, SELLO-012.5, SELLO-013.5)
5. **Policy Engine**: 3 tasks (SELLO-016 to SELLO-018)
6. **Configuration Management**: 2 tasks (SELLO-019 to SELLO-020)
7. **CLI Interface**: 8 tasks (SELLO-021 to SELLO-027, SELLO-021.5)
8. **Unix Socket Server**: 3 tasks (SELLO-028 to SELLO-030)
9. **Main Binary and Integration**: 3 tasks (SELLO-031 to SELLO-032, SELLO-031.5)
10. **Documentation and Polish**: 9 tasks (SELLO-033 to SELLO-040, SELLO-033.5)

### Critical Security Tasks
The following tasks require extra scrutiny and human review:
- **SELLO-007**: SecretKey zeroization
- **SELLO-010**: Key encryption
- **SELLO-014**: Ethereum parser
- **SELLO-015**: ERC-20 token transfer detection
- **SELLO-018**: Policy engine
- **SELLO-031.5**: Audit logging with HMAC chain
- **SELLO-036**: Test coverage
- **SELLO-037**: Security audit

### Recommended Sprint Planning

**Sprint 1 (Foundation)**:
- SELLO-001 through SELLO-006, SELLO-003.5
- Focus: Project setup, core types, and testing/fuzzing infrastructure

**Sprint 2 (Crypto)**:
- SELLO-007 through SELLO-011
- Focus: Cryptographic primitives and key management

**Sprint 3 (Parsing)**:
- SELLO-012 through SELLO-015, SELLO-012.5, SELLO-013.5
- Focus: Chain trait, registry, token registry, and Ethereum parsing

**Sprint 4 (Policy)**:
- SELLO-016 through SELLO-020
- Focus: Policy engine (with SQLite history) and configuration

**Sprint 5 (CLI)**:
- SELLO-021 through SELLO-027, SELLO-021.5
- Focus: Command-line interface and logging infrastructure

**Sprint 6 (Server)**:
- SELLO-028 through SELLO-032, SELLO-031.5
- Focus: Unix socket server, audit logging, and integration tests

**Sprint 7 (Polish)**:
- SELLO-033 through SELLO-040, SELLO-033.5
- Focus: Documentation, coverage enforcement, testing, and release

---

## Notes

1. **Test-Driven Development**: For all crypto, parsing, and policy tasks, write tests first.

2. **Security Review**: All security-sensitive tasks (marked with Security Note) require human review before merging.

3. **Coverage Enforcement**: CI must enforce coverage requirements - no PR merges with decreased coverage.

4. **Mock Implementations**: Every trait must have a mock implementation for testing. Consider using mockall for complex mocks.

5. **Documentation**: Write documentation as you implement, not after. Doc comments are part of the task acceptance criteria.

6. **Dependencies**: Strictly follow dependency order. No task can be started until its dependencies are complete.

7. **Error Handling**: Every error must have a clear, actionable message. No generic "something went wrong" errors.

8. **Versioning**: All breaking changes must be documented in CHANGELOG.md with migration guides.
