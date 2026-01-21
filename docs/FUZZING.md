# Fuzz Testing Guide

This document describes how to run fuzz tests for the Sello project using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Overview

Fuzz testing (or fuzzing) is an automated testing technique that provides random, unexpected, or malformed data as input to a program. It's particularly valuable for security-critical code like transaction parsers and policy engines.

Sello uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html) via `cargo-fuzz` for coverage-guided fuzzing. This means the fuzzer learns from previous inputs to discover new code paths and edge cases.

## Prerequisites

### Install Rust Nightly

Fuzzing requires the nightly Rust compiler:

```bash
rustup install nightly
```

### Install cargo-fuzz

```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

| Target | Description | Location |
|--------|-------------|----------|
| `ethereum_parser` | Fuzzes Ethereum transaction parsing | `fuzz/fuzz_targets/ethereum_parser.rs` |
| `policy_rules` | Fuzzes policy engine evaluation | `fuzz/fuzz_targets/policy_rules.rs` |

## Running Fuzz Tests

### Basic Usage

To run a fuzz target:

```bash
cd fuzz
cargo +nightly fuzz run <target_name>
```

For example:

```bash
# Fuzz the Ethereum parser
cargo +nightly fuzz run ethereum_parser

# Fuzz the policy rules engine
cargo +nightly fuzz run policy_rules
```

### Time-Limited Fuzzing

Run fuzzing for a specific duration:

```bash
# Run for 1 hour (3600 seconds)
cargo +nightly fuzz run ethereum_parser -- -max_total_time=3600

# Run for 10 minutes
cargo +nightly fuzz run policy_rules -- -max_total_time=600
```

### Input Size Limits

Limit the maximum input size to focus on specific scenarios:

```bash
# Limit inputs to 1KB
cargo +nightly fuzz run ethereum_parser -- -max_len=1024

# Limit inputs to 64KB (default for Ethereum transactions)
cargo +nightly fuzz run ethereum_parser -- -max_len=65536
```

### Parallel Fuzzing

Run multiple fuzzing instances in parallel:

```bash
# Run 4 parallel fuzzing jobs
cargo +nightly fuzz run ethereum_parser -- -jobs=4 -workers=4
```

## Understanding Output

### Normal Operation

During fuzzing, you'll see output like:

```
#12345    NEW    cov: 1234 ft: 5678 corp: 100/50kb exec/s: 1000
```

- `#12345`: Number of test cases executed
- `NEW`: A new interesting input was found
- `cov`: Number of coverage points reached
- `ft`: Number of feature combinations discovered
- `corp`: Corpus size (count/total size)
- `exec/s`: Executions per second

### Crash Detection

If a crash is found, you'll see:

```
==12345==ERROR: libFuzzer: deadly signal
SUMMARY: libFuzzer: deadly signal
Test unit written to ./artifacts/ethereum_parser/crash-abc123...
```

The crashing input is saved to the `artifacts/` directory.

## Working with Crashes

### Reproducing a Crash

To reproduce a crash from a saved artifact:

```bash
cargo +nightly fuzz run ethereum_parser fuzz/artifacts/ethereum_parser/crash-abc123...
```

### Minimizing a Crash

To find the minimal input that triggers a crash:

```bash
cargo +nightly fuzz tmin ethereum_parser fuzz/artifacts/ethereum_parser/crash-abc123...
```

### Debugging a Crash

Build with debug symbols and run under a debugger:

```bash
# Build with debug info
cargo +nightly fuzz build ethereum_parser

# Run under lldb (macOS)
lldb -- ./target/x86_64-apple-darwin/release/ethereum_parser fuzz/artifacts/ethereum_parser/crash-abc123...

# Run under gdb (Linux)
gdb --args ./target/x86_64-unknown-linux-gnu/release/ethereum_parser fuzz/artifacts/ethereum_parser/crash-abc123...
```

## Managing the Corpus

### Corpus Location

The corpus (interesting inputs discovered during fuzzing) is stored in:

```
fuzz/corpus/<target_name>/
```

### Adding Seed Files

You can add initial seed files to help the fuzzer explore faster:

```bash
# Create a seed directory
mkdir -p fuzz/corpus/ethereum_parser

# Add seed files (e.g., valid transaction examples)
cp test_vectors/*.rlp fuzz/corpus/ethereum_parser/
```

### Merging Corpus Files

After extended fuzzing runs, merge corpus files to remove redundant entries:

```bash
cargo +nightly fuzz cmin ethereum_parser
```

## Adding New Fuzz Targets

### 1. Create the Target File

Create a new file in `fuzz/fuzz_targets/`:

```rust
// fuzz/fuzz_targets/new_target.rs
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Your fuzzing logic here
    let _ = your_crate::parse(data);
});
```

### 2. Register in Cargo.toml

Add the target to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "new_target"
path = "fuzz_targets/new_target.rs"
test = false
doc = false
bench = false
```

### 3. Using Structured Input

For complex inputs, use the `arbitrary` crate:

```rust
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct MyInput {
    value: u64,
    data: Vec<u8>,
    flag: bool,
}

fuzz_target!(|input: MyInput| {
    // Use structured input
    let _ = process(input.value, &input.data, input.flag);
});
```

## CI Integration

Fuzz testing runs automatically in CI:

- **Schedule**: Daily at 3 AM UTC
- **Duration**: 30 minutes per target
- **Artifacts**: Crash files are uploaded if found
- **Notifications**: Issues are created for discovered crashes

### Manual CI Trigger

You can manually trigger fuzzing from the GitHub Actions UI:

1. Go to Actions > Fuzz
2. Click "Run workflow"
3. Optionally specify duration and target
4. Click "Run workflow"

## Best Practices

### What to Fuzz

Focus fuzzing on:

- **Parsing code**: Transaction parsing, RLP decoding
- **Cryptographic operations**: Signature verification (input handling, not the crypto itself)
- **Policy evaluation**: Rule parsing and evaluation
- **Serialization**: Any code that handles untrusted input

### Writing Effective Targets

1. **Avoid assertions in production code**: Use `Result` types instead
2. **Return early on invalid input**: Don't waste cycles on clearly invalid data
3. **Keep targets focused**: One target per logical component
4. **Use structured fuzzing**: When input has known structure, use `Arbitrary`

### Corpus Maintenance

1. **Commit curated seeds**: Add known edge cases to version control
2. **Don't commit random corpus**: The auto-generated corpus is git-ignored
3. **Periodically minimize**: Run `cargo +nightly fuzz cmin` to reduce corpus size

## Troubleshooting

### "error: could not compile"

Ensure you're using nightly:

```bash
cargo +nightly fuzz run ethereum_parser
```

### "LLVM ERROR: out of memory"

Reduce input size or parallel workers:

```bash
cargo +nightly fuzz run ethereum_parser -- -max_len=1024 -jobs=1
```

### Slow Fuzzing Speed

1. Check for expensive operations in the fuzz target
2. Reduce input size with `-max_len`
3. Profile with `cargo +nightly fuzz coverage`

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [The Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [Arbitrary crate documentation](https://docs.rs/arbitrary)
