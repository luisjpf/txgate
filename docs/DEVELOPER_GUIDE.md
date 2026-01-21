# Sello Developer Guide

This guide covers everything you need to know to develop, build, and extend Sello.

## Table of Contents

1. [Setting Up Development Environment](#setting-up-development-environment)
2. [Building the Project](#building-the-project)
3. [Running Tests](#running-tests)
4. [Code Organization](#code-organization)
5. [Adding a New Chain Parser](#adding-a-new-chain-parser)
6. [Adding New CLI Commands](#adding-new-cli-commands)
7. [Debugging Tips](#debugging-tips)
8. [Performance Considerations](#performance-considerations)

---

## Setting Up Development Environment

### Prerequisites

| Requirement | Minimum Version | Recommended |
|-------------|-----------------|-------------|
| Rust | 1.75 | Latest stable |
| Cargo | 1.75 | Latest stable |
| Git | 2.0 | Latest |

Optional but recommended:
- `cargo-watch` - For auto-rebuilding during development
- `cargo-llvm-cov` - For code coverage
- `cargo-fuzz` - For fuzz testing (requires nightly)

### Initial Setup

1. **Clone the repository**:

```bash
git clone https://github.com/sello-project/sello.git
cd sello
```

2. **Install Rust** (if not already installed):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

3. **Verify the Rust version**:

```bash
rustc --version
# Should be >= 1.75
```

4. **Install development tools**:

```bash
# Auto-rebuild on file changes
cargo install cargo-watch

# Code coverage
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov

# Fuzz testing (optional, requires nightly)
rustup install nightly
cargo install cargo-fuzz
```

5. **Build the project**:

```bash
cargo build
```

6. **Run tests** to verify setup:

```bash
cargo test
```

### IDE Setup

#### VS Code

Install the following extensions:
- **rust-analyzer** - Rust language support
- **CodeLLDB** - Debugging support
- **Even Better TOML** - TOML file support

Recommended settings (`.vscode/settings.json`):

```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.checkOnSave.extraArgs": ["--", "-D", "warnings"],
    "editor.formatOnSave": true,
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer"
    }
}
```

#### IntelliJ IDEA / CLion

Install the **Rust** plugin and enable:
- External linter (Clippy)
- Format on save (rustfmt)

---

## Building the Project

### Debug Build

```bash
# Build all crates
cargo build

# Build a specific crate
cargo build -p sello-core
cargo build -p sello-crypto
cargo build -p sello-chain
cargo build -p sello-policy
cargo build -p sello
```

### Release Build

```bash
# Optimized build
cargo build --release

# The binary is at target/release/sello
```

### Build with Features

```bash
# Build with all features
cargo build --all-features

# Build sello-chain with mock feature (for testing)
cargo build -p sello-chain --features mock
```

### Check Without Building

```bash
# Fast syntax and type checking
cargo check

# Check all targets (including tests)
cargo check --all-targets
```

### Auto-Rebuild During Development

```bash
# Watch for changes and rebuild
cargo watch -x build

# Watch and run tests on change
cargo watch -x test

# Watch specific crate
cargo watch -x 'test -p sello-crypto'
```

---

## Running Tests

### Quick Reference

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test by name
cargo test test_parse_eip1559

# Run tests for a specific crate
cargo test -p sello-core
cargo test -p sello-crypto
cargo test -p sello-chain
cargo test -p sello-policy

# Run integration tests only
cargo test --test integration

# Run tests in release mode (faster execution)
cargo test --release
```

### Code Coverage

We use `cargo-llvm-cov` for code coverage:

```bash
# Generate HTML report
cargo llvm-cov --html
# Open target/llvm-cov/html/index.html

# Terminal summary
cargo llvm-cov

# Coverage for specific crate
cargo llvm-cov -p sello-crypto --html

# Generate LCOV format for CI
cargo llvm-cov --lcov --output-path lcov.info
```

**Coverage Targets**:

| Crate | Target |
|-------|--------|
| sello-crypto | 100% |
| sello-chain | 100% |
| sello-policy | 100% |
| sello-core | 90%+ |
| sello | 80%+ |

### Property Testing

We use `proptest` for property-based testing. See `tests/integration/common/mod.rs` for available test strategies:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_address_roundtrip(addr in ethereum_address()) {
        // Test your parsing logic
    }
}
```

### Fuzz Testing

See [FUZZING.md](./FUZZING.md) for detailed fuzz testing instructions.

```bash
# Run fuzz test (requires nightly)
cd fuzz
cargo +nightly fuzz run ethereum_parser -- -max_total_time=60
```

### Pre-Commit Checks

Run this before committing:

```bash
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

Or set up a git hook:

```bash
# Create .git/hooks/pre-commit
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
cargo fmt --check && cargo clippy -- -D warnings && cargo test
EOF
chmod +x .git/hooks/pre-commit
```

---

## Code Organization

### Workspace Structure

```
sello/
+-- Cargo.toml           # Workspace manifest
+-- Cargo.lock           # Dependency lock file
+-- rustfmt.toml         # Formatting configuration
+-- CLAUDE.md            # Project guidelines
+-- ARCHITECTURE.md      # Full architecture spec
+-- README.md
|
+-- crates/
|   +-- sello-core/      # Core types and errors
|   +-- sello-crypto/    # Cryptographic operations
|   +-- sello-chain/     # Chain parsers
|   +-- sello-policy/    # Policy engine
|   +-- sello/           # CLI and server
|
+-- docs/
|   +-- ARCHITECTURE.md  # Architecture overview
|   +-- DEVELOPER_GUIDE.md
|   +-- CONTRIBUTING.md
|   +-- TESTING.md
|   +-- FUZZING.md
|
+-- tests/
|   +-- integration/     # Integration tests
|   +-- fixtures/        # Test data files
|
+-- fuzz/
    +-- fuzz_targets/    # Fuzz test targets
    +-- corpus/          # Fuzz test corpus
```

### Module Conventions

Each crate follows this structure:

```
crates/sello-xxx/
+-- Cargo.toml           # Crate manifest
+-- src/
    +-- lib.rs           # Public API and re-exports
    +-- module_a.rs      # Module implementation
    +-- module_b.rs
    +-- module_b/        # Or as a directory
        +-- mod.rs
        +-- submodule.rs
```

### Import Conventions

```rust
// Standard library
use std::collections::HashMap;

// External crates
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Internal crates
use sello_core::{ParsedTx, SelloError};

// Current crate modules
use crate::module_a::TypeA;
```

---

## Adding a New Chain Parser

This section walks through adding support for a new blockchain.

### Step 1: Create the Parser Module

Create a new file in `crates/sello-chain/src/`:

```rust
// crates/sello-chain/src/solana.rs

use crate::chain::Chain;
use sello_core::{ParsedTx, TxType};
use sello_core::error::ParseError;
use sello_crypto::CurveType;

/// Parser for Solana transactions
pub struct SolanaParser;

impl SolanaParser {
    /// Create a new Solana parser
    pub fn new() -> Self {
        Self
    }
}

impl Default for SolanaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain for SolanaParser {
    fn id(&self) -> &'static str {
        "solana"
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
        // 1. Decode the transaction format
        // 2. Extract recipient, amount, token info
        // 3. Compute the transaction hash
        // 4. Return ParsedTx

        // Example placeholder:
        if raw.is_empty() {
            return Err(ParseError::empty_transaction());
        }

        // Parse the Solana transaction format...
        // This is where you implement the actual parsing logic

        Ok(ParsedTx {
            hash: [0u8; 32], // Compute actual hash
            recipient: None,
            amount: None,
            token: Some("SOL".to_string()),
            token_address: None,
            tx_type: TxType::Transfer,
            chain: "solana".to_string(),
            nonce: None,
            chain_id: None,
            metadata: std::collections::HashMap::new(),
        })
    }

    fn curve(&self) -> CurveType {
        CurveType::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_id() {
        let parser = SolanaParser::new();
        assert_eq!(parser.id(), "solana");
    }

    #[test]
    fn test_empty_transaction() {
        let parser = SolanaParser::new();
        let result = parser.parse(&[]);
        assert!(result.is_err());
    }

    // Add more tests for actual transaction parsing...
}
```

### Step 2: Export from lib.rs

Update `crates/sello-chain/src/lib.rs`:

```rust
pub mod solana;

// Re-export at crate root
pub use solana::SolanaParser;
```

### Step 3: Register in ChainRegistry

Update `crates/sello-chain/src/registry.rs`:

```rust
use crate::solana::SolanaParser;

impl ChainRegistry {
    pub fn new() -> Self {
        let mut chains: HashMap<String, Box<dyn Chain>> = HashMap::new();

        // Existing chains
        chains.insert("ethereum".to_string(), Box::new(EthereumParser::new()));

        // Add new chain
        chains.insert("solana".to_string(), Box::new(SolanaParser::new()));

        Self { chains }
    }
}
```

### Step 4: Add Test Fixtures

Create test fixtures in `tests/fixtures/solana/`:

```json
// tests/fixtures/solana/transfer.json
{
    "description": "Simple SOL transfer",
    "raw_tx": "base64-encoded-transaction-here",
    "expected": {
        "tx_type": "Transfer",
        "recipient": "recipient-pubkey",
        "amount": "1000000000",
        "token": "SOL"
    }
}
```

### Step 5: Add Integration Tests

Add integration tests in `tests/integration/`:

```rust
#[test]
fn test_solana_transfer_parsing() {
    let registry = ChainRegistry::new();
    let parser = registry.get("solana").expect("Solana parser should exist");

    let fixture = load_fixture("solana/transfer.json").unwrap();
    let raw = hex::decode(fixture["raw_tx"].as_str().unwrap()).unwrap();

    let parsed = parser.parse(&raw).expect("Should parse successfully");

    assert_eq!(parsed.chain, "solana");
    assert_eq!(parsed.tx_type, TxType::Transfer);
}
```

### Step 6: Add CLI Support (Optional)

If needed, add CLI commands in `crates/sello/src/cli/commands/`:

```rust
// crates/sello/src/cli/commands/solana/mod.rs
pub mod address;
pub mod sign;
```

---

## Adding New CLI Commands

### Step 1: Define the Command in args.rs

Update `crates/sello/src/cli/args.rs`:

```rust
#[derive(Subcommand, Debug)]
pub enum Commands {
    // Existing commands...

    /// New command description
    NewCommand {
        /// Argument description
        #[arg(long)]
        option: Option<String>,
    },
}
```

### Step 2: Create Command Handler

Create `crates/sello/src/cli/commands/new_command.rs`:

```rust
use crate::cli::args::Commands;
use sello_core::SelloError;

/// Execute the new command
pub fn run(option: Option<String>) -> Result<(), SelloError> {
    // Implementation here
    println!("Running new command with option: {:?}", option);
    Ok(())
}
```

### Step 3: Export from commands/mod.rs

Update `crates/sello/src/cli/commands/mod.rs`:

```rust
pub mod new_command;
```

### Step 4: Handle in main.rs

Update `crates/sello/src/main.rs`:

```rust
match cli.command {
    // Existing handlers...

    Commands::NewCommand { option } => {
        commands::new_command::run(option)?;
    }
}
```

---

## Debugging Tips

### Enable Debug Logging

```bash
# Set log level
RUST_LOG=debug cargo run -- status

# More granular control
RUST_LOG=sello=debug,sello_crypto=trace cargo run -- status
```

### Use cargo expand

See macro expansions:

```bash
cargo install cargo-expand
cargo expand -p sello-core types
```

### Debug with LLDB/GDB

```bash
# Build with debug symbols (default in debug mode)
cargo build

# Run under LLDB (macOS)
lldb -- ./target/debug/sello status

# Run under GDB (Linux)
gdb --args ./target/debug/sello status
```

### VS Code Debugging

Add to `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "Debug sello",
            "cargo": {
                "args": ["build", "--bin=sello", "--package=sello"],
                "filter": {
                    "name": "sello",
                    "kind": "bin"
                }
            },
            "args": ["status"],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

### Print Debugging

For quick debugging, use the `dbg!` macro:

```rust
let value = compute_something();
dbg!(&value);  // Prints [src/file.rs:10] &value = ...
```

### Inspect Memory

Use `cargo-inspect` for memory layout:

```bash
cargo install cargo-inspect
cargo inspect ParsedTx
```

---

## Performance Considerations

### Hot Path Optimization

The signing path is performance-critical. Key optimizations:

1. **Static Dispatch**: Use generics instead of trait objects for signing:

```rust
// Good: static dispatch, inlines well
pub struct SigningService<S: Signer> {
    signer: S,
}

// Avoid on hot path: dynamic dispatch
pub struct SigningService {
    signer: Box<dyn Signer>,
}
```

2. **Avoid Allocations**: Reuse buffers where possible:

```rust
// Preallocate and reuse
let mut buffer = Vec::with_capacity(1024);
for tx in transactions {
    buffer.clear();
    // Use buffer...
}
```

3. **Use Appropriate Data Structures**:
   - `HashMap` for chain registry (O(1) lookup)
   - `LruCache` for hot data (token registry)
   - `Vec` with known capacity for collections

### Benchmarking

Use Criterion for benchmarks:

```rust
// benches/signing.rs
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_signing(c: &mut Criterion) {
    c.bench_function("sign_transaction", |b| {
        b.iter(|| {
            // Benchmark code here
        })
    });
}

criterion_group!(benches, bench_signing);
criterion_main!(benches);
```

Run benchmarks:

```bash
cargo bench
```

### Profiling

Use `perf` (Linux) or Instruments (macOS):

```bash
# Linux with perf
cargo build --release
perf record -g ./target/release/sello sign ...
perf report

# macOS with Instruments
cargo build --release
instruments -t "Time Profiler" ./target/release/sello sign ...
```

### Memory Profiling

Use `valgrind` (Linux) or Instruments (macOS):

```bash
# Linux with valgrind
cargo build --release
valgrind --tool=massif ./target/release/sello status
ms_print massif.out.*
```

### Avoiding Common Performance Pitfalls

1. **Don't clone unnecessarily**: Use references where possible
2. **Avoid String for identifiers**: Use `&'static str` or enums
3. **Profile before optimizing**: Measure actual bottlenecks
4. **Consider async overhead**: Sync code may be faster for simple operations

---

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- [TESTING.md](./TESTING.md) - Detailed testing guide
- [FUZZING.md](./FUZZING.md) - Fuzz testing guide
- [../CLAUDE.md](../CLAUDE.md) - Project guidelines
