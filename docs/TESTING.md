# Testing Guide for Sello

This document describes the testing infrastructure, conventions, and procedures for the Sello project.

## Test Organization

```
tests/
├── integration/           # Integration tests
│   ├── mod.rs            # Main integration test module
│   └── common/
│       └── mod.rs        # Shared test utilities
└── fixtures/             # Test fixtures
    └── ethereum/
        ├── legacy_transfer.json    # Type 0 (legacy) transactions
        ├── eip1559_transfer.json   # Type 2 (EIP-1559) transactions
        └── erc20_transfer.json     # ERC-20 token transfers

crates/
├── sello-core/src/       # Unit tests with #[cfg(test)] modules
├── sello-crypto/src/     # Unit tests (100% coverage required)
├── sello-chain/src/      # Unit tests (100% coverage required)
├── sello-policy/src/     # Unit tests (100% coverage required)
└── sello/src/            # Unit tests

fuzz/                     # Fuzz tests (cargo-fuzz)
```

## Running Tests

### Basic Test Commands

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests for a specific crate
cargo test -p sello-core
cargo test -p sello-crypto
cargo test -p sello-chain
cargo test -p sello-policy

# Run only integration tests
cargo test --test integration

# Run tests in release mode (faster, but less debug info)
cargo test --release
```

### Test Filtering

```bash
# Run tests matching a pattern
cargo test ethereum
cargo test policy

# Run tests in a specific module
cargo test common::tests

# Exclude slow tests
cargo test -- --skip slow
```

## Code Coverage

We use `cargo-llvm-cov` for code coverage (NOT tarpaulin). This provides accurate coverage data using LLVM's instrumentation.

### Installation

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Or using rustup component (recommended)
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

### Running Coverage

```bash
# Generate HTML coverage report
cargo llvm-cov --html
# Report is at target/llvm-cov/html/index.html

# Generate coverage report in terminal
cargo llvm-cov

# Generate JSON report (for CI integration)
cargo llvm-cov --json --output-path coverage.json

# Generate LCOV format (for tools like Codecov)
cargo llvm-cov --lcov --output-path lcov.info

# Coverage for specific crate
cargo llvm-cov -p sello-crypto --html

# Coverage with all features
cargo llvm-cov --all-features --html

# Ignore specific files in coverage
cargo llvm-cov --html --ignore-filename-regex 'tests/.*'
```

### Coverage Targets

| Crate | Target Coverage |
|-------|----------------|
| sello-crypto | 100% |
| sello-chain | 100% |
| sello-policy | 100% |
| sello-core | 90%+ |
| sello (binary) | 80%+ |

## Property-Based Testing

We use `proptest` for property-based testing. This framework generates random test cases to find edge cases.

### Using Proptest

The test utilities module (`tests/integration/common/mod.rs`) provides reusable proptest strategies:

```rust
use proptest::prelude::*;
use crate::common::{ethereum_address, wei_amount, chain_id};

proptest! {
    #[test]
    fn test_address_validation(addr in ethereum_address()) {
        // addr is a randomly generated valid Ethereum address
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_amount_parsing(amount in wei_amount()) {
        // amount is a valid wei amount as a string
        let parsed: u128 = amount.parse().unwrap();
        // Test your parsing logic here
    }
}
```

### Available Strategies

| Strategy | Description | Example Output |
|----------|-------------|----------------|
| `ethereum_address()` | Valid Ethereum address | `0x742d35Cc6634C0532925a3b844Bc9e7595f5b3d2` |
| `hex_bytes(n)` | Hex string of n bytes | `0xabcd1234...` |
| `wei_amount()` | Valid wei amount (0 to 10^21) | `"1000000000000000000"` |
| `chain_id()` | Valid chain ID (1-100000) | `1`, `137`, `42161` |
| `nonce()` | Transaction nonce | `0`, `42`, `1000000` |
| `gas_limit()` | Gas limit (21000-10M) | `21000`, `100000` |
| `gas_price()` | Legacy gas price (1-1000 gwei) | `"20000000000"` |
| `erc20_transfer_data()` | ERC-20 transfer calldata | `0xa9059cbb000...` |

### Custom Strategies

Create custom strategies for your domain:

```rust
use proptest::prelude::*;

// Custom strategy for policy rules
fn policy_limit() -> impl Strategy<Value = u64> {
    (1u64..=1_000_000_000u64)
}

// Composite strategy
fn transaction_fixture() -> impl Strategy<Value = (String, String, String)> {
    (
        ethereum_address(),
        ethereum_address(),
        wei_amount(),
    )
}
```

## Fixtures

### Fixture Format

JSON fixtures follow a standard structure:

```json
{
  "description": "Human-readable description of the test case",
  "raw_tx": "0x...",
  "expected": {
    "tx_type": "Transfer|TokenTransfer",
    "recipient": "0x...",
    "amount": "...",
    "token": "ETH|USDC|...",
    "chain_id": 1,
    "nonce": 0
  },
  "metadata": {
    "source": "Where this fixture came from",
    "notes": "Any additional notes"
  }
}
```

### Loading Fixtures

```rust
use crate::common::load_fixture;

#[test]
fn test_with_fixture() {
    let fixture = load_fixture("ethereum/legacy_transfer.json")
        .expect("Fixture should exist");

    let raw_tx = fixture["raw_tx"].as_str().unwrap();
    let expected_recipient = fixture["expected"]["recipient"].as_str().unwrap();

    // Test your parsing logic
}
```

### Adding New Fixtures

1. Create a JSON file in the appropriate `tests/fixtures/` subdirectory
2. Follow the standard fixture format
3. Include realistic test data
4. Add a descriptive `description` field
5. Update fixture validation tests if needed

## Fuzz Testing

We use `cargo-fuzz` for fuzz testing critical parsers.

### Setup

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz

# Or use the nightly toolchain
rustup install nightly
```

### Running Fuzz Tests

```bash
# List fuzz targets
cargo +nightly fuzz list

# Run a fuzz target
cargo +nightly fuzz run fuzz_target_name

# Run with a timeout (in seconds)
cargo +nightly fuzz run fuzz_target_name -- -max_total_time=60

# Run with a corpus
cargo +nightly fuzz run fuzz_target_name corpus/
```

### Writing Fuzz Targets

```rust
// fuzz/fuzz_targets/fuzz_ethereum_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse the data - should not panic
    let _ = sello_chain::evm::parse_transaction(data);
});
```

## CI Integration

Tests run automatically on every PR and push to main. The CI pipeline:

1. Runs `cargo fmt --check` - Code formatting
2. Runs `cargo clippy -- -D warnings` - Linting
3. Runs `cargo test` - All tests
4. Runs `cargo llvm-cov` - Coverage report
5. Uploads coverage to Codecov (if configured)

### Local Pre-Commit Check

Run this before committing:

```bash
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

Or add a git hook:

```bash
# .git/hooks/pre-commit
#!/bin/sh
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

## Best Practices

### Unit Tests

- Place unit tests in `#[cfg(test)]` modules alongside the code
- Test both success and error cases
- Use descriptive test names: `test_<function>_<scenario>_<expected_result>`
- Keep tests focused - one assertion per test when possible

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_address_returns_ok() {
        let result = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f5b3d2");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_invalid_address_returns_error() {
        let result = parse_address("invalid");
        assert!(result.is_err());
    }
}
```

### Integration Tests

- Test component interactions, not individual units
- Use fixtures for complex test data
- Test realistic scenarios
- Clean up test data (use `temp_data_dir()`)

### Property Tests

- Test invariants that should always hold
- Generate diverse inputs to find edge cases
- Use domain-specific strategies
- Configure appropriate test case counts

```rust
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn roundtrip_serialization(addr in ethereum_address()) {
        let parsed = parse_address(&addr).unwrap();
        let serialized = parsed.to_string();
        assert_eq!(serialized.to_lowercase(), addr.to_lowercase());
    }
}
```

## Troubleshooting

### Common Issues

**Tests fail with "fixture not found"**
- Ensure you're running tests from the project root
- Check that `CARGO_MANIFEST_DIR` is set correctly
- Verify fixture files exist in `tests/fixtures/`

**Coverage report shows 0%**
- Ensure `cargo-llvm-cov` is installed correctly
- Try running `rustup component add llvm-tools-preview`
- Check that tests are actually running

**Property tests are slow**
- Reduce the number of cases: `proptest_config(ProptestConfig::with_cases(100))`
- Simplify strategies
- Mark slow tests with `#[ignore]` and run separately

**Fuzz tests crash immediately**
- Ensure you're using the nightly toolchain
- Check that the fuzz target compiles correctly
- Start with a minimal corpus
