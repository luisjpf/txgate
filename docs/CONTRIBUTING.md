# Contributing to TxGate

Thank you for your interest in contributing to TxGate! This document provides guidelines and instructions for contributing.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Report Bugs](#how-to-report-bugs)
3. [How to Propose Features](#how-to-propose-features)
4. [Pull Request Process](#pull-request-process)
5. [Code Style](#code-style)
6. [Commit Message Format](#commit-message-format)
7. [Testing Requirements](#testing-requirements)
8. [Documentation Requirements](#documentation-requirements)

---

## Code of Conduct

Please read and follow `CODE_OF_CONDUCT.md` in the repository root.

---

## How to Report Bugs

### Before Submitting

1. **Search existing issues** to avoid duplicates
2. **Update to the latest version** to see if the bug is fixed
3. **Reproduce the bug** with a minimal example

### Submitting a Bug Report

Create a [new issue](https://github.com/txgate-project/txgate/issues/new) with:

**Title**: Clear, descriptive title (e.g., "Ethereum parser fails on EIP-1559 transactions with access lists")

**Body** (use this template):

```markdown
## Description
A clear description of the bug.

## Steps to Reproduce
1. Run command `txgate ...`
2. Provide input `...`
3. Observe error

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- TxGate version: (run `txgate --version`)
- OS: (e.g., macOS 14.0, Ubuntu 22.04)
- Rust version: (run `rustc --version`)

## Additional Context
- Error messages
- Log output (with `RUST_LOG=debug`)
- Relevant configuration

## Minimal Reproduction
If possible, provide a minimal example that reproduces the issue:
```bash
# Commands to reproduce
```
```

### Security Vulnerabilities

**Do not report security vulnerabilities through public issues.**

Instead, email security@txgate-project.org with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

---

## How to Propose Features

### Before Proposing

1. **Check the roadmap** in TASKS.md
2. **Search existing issues** for similar proposals
3. **Consider if it fits** the project scope

### Submitting a Feature Request

Create a [new issue](https://github.com/txgate-project/txgate/issues/new) with:

**Title**: "Feature: [Brief description]"

**Body** (use this template):

```markdown
## Summary
Brief description of the feature.

## Motivation
Why is this feature needed? What problem does it solve?

## Proposed Solution
Describe your proposed solution in detail.

## Alternatives Considered
What alternatives have you considered?

## Additional Context
- Mockups or diagrams
- Related issues or PRs
- External references

## Implementation Notes
If you have ideas about implementation:
- Which crates would be affected?
- Any breaking changes?
- Performance considerations?
```

---

## Pull Request Process

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/txgate.git
   cd txgate
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/txgate-project/txgate.git
   ```

### Development Workflow

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

3. **Make your changes**:
   - Write code following the [Code Style](#code-style) guidelines
   - Add tests for new functionality
   - Update documentation as needed

4. **Run checks locally**:
   ```bash
   # Format code
   cargo fmt

   # Run linter
   cargo clippy -- -D warnings

   # Run tests
   cargo test

   # Check coverage (for crypto, chain, policy)
   cargo llvm-cov -p txgate-crypto
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat(chain): add Solana transaction parser"
   ```

6. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

### PR Requirements

Before submitting:

- [ ] Code compiles without warnings (`cargo check`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] No Clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation is updated
- [ ] Commit messages follow the [format](#commit-message-format)
- [ ] PR description explains the changes

### PR Review Process

1. **Automated checks** run on all PRs
2. **Maintainer review** for code quality and design
3. **Address feedback** through new commits (don't force-push)
4. **Final approval** and merge by maintainer

### After Merge

- Delete your feature branch
- Sync your fork with upstream

---

## Code Style

### Rust Conventions

We follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and enforce style with `rustfmt` and `clippy`.

**Formatting**:
```bash
# Format all code
cargo fmt

# Check without modifying
cargo fmt --check
```

**Configuration** (`rustfmt.toml`):
```toml
max_width = 100
tab_spaces = 4
edition = "2021"
use_small_heuristics = "Default"
```

### Linting

We use strict Clippy rules to prevent common issues:

```bash
# Run Clippy
cargo clippy -- -D warnings

# The workspace enforces these rules:
# - unwrap_used = "deny"
# - panic = "deny"
# - indexing_slicing = "deny"
# - expect_used = "warn"
# - todo = "warn"
```

**Avoiding Common Violations**:

```rust
// BAD: Don't use .unwrap()
let value = result.unwrap();

// GOOD: Use ? operator
let value = result?;

// GOOD: Or handle the error
let value = result.unwrap_or_default();
let value = result.map_err(|e| MyError::from(e))?;
```

```rust
// BAD: Don't index directly
let item = vec[0];

// GOOD: Use .get() with handling
let item = vec.get(0).ok_or(MyError::Empty)?;
let item = vec.first().ok_or(MyError::Empty)?;
```

### Error Handling

Use `thiserror` for error types:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("parse failed: {0}")]
    Parse(String),

    #[error("invalid input: expected {expected}, got {actual}")]
    InvalidInput {
        expected: String,
        actual: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

### Documentation Comments

All public items must have doc comments:

```rust
/// Brief one-line description.
///
/// Longer description if needed, explaining the purpose
/// and any important details.
///
/// # Arguments
///
/// * `name` - The key name
/// * `passphrase` - The encryption passphrase
///
/// # Returns
///
/// Returns the decrypted secret key.
///
/// # Errors
///
/// Returns an error if:
/// * The key file does not exist
/// * The passphrase is incorrect
/// * The file is corrupted
///
/// # Examples
///
/// ```rust
/// let key = store.load("default", "passphrase")?;
/// ```
pub fn load(&self, name: &str, passphrase: &str) -> Result<SecretKey, StoreError> {
    // ...
}
```

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `chore` | Maintenance tasks |
| `ci` | CI/CD changes |

### Scopes

| Scope | Crate/Area |
|-------|------------|
| `core` | txgate-core |
| `crypto` | txgate-crypto |
| `chain` | txgate-chain |
| `policy` | txgate-policy |
| `cli` | CLI commands |
| `server` | Server code |
| `docs` | Documentation |

### Examples

```
feat(chain): add Solana transaction parser

Implement parsing for Solana versioned transactions including:
- Legacy transaction format
- V0 transaction format with address lookup tables
- SPL token transfer detection

Closes #123
```

```
fix(crypto): prevent timing attacks in key comparison

Use constant-time comparison for secret key validation
to prevent timing side-channel attacks.

Security: HIGH
```

```
docs(readme): update installation instructions

Add instructions for installing via cargo and from source.
```

---

## Testing Requirements

### Coverage Requirements

| Crate | Required Coverage |
|-------|-------------------|
| txgate-crypto | 100% |
| txgate-chain | 100% |
| txgate-policy | 100% |
| txgate-core | 90%+ |
| txgate | 80%+ |

### Test Categories

1. **Unit Tests**: Place in `#[cfg(test)]` modules alongside code
2. **Integration Tests**: Place in `tests/integration/`
3. **Property Tests**: Use `proptest` for invariant testing
4. **Fuzz Tests**: Use `cargo-fuzz` for parser robustness

### Writing Tests

**Unit Test Example**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_address_succeeds() {
        let result = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f5b3d2");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_invalid_address_fails() {
        let result = parse_address("invalid");
        assert!(result.is_err());
    }
}
```

**Property Test Example**:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn roundtrip_serialization(amount in 0u64..u64::MAX) {
        let serialized = amount.to_string();
        let parsed: u64 = serialized.parse().unwrap();
        assert_eq!(parsed, amount);
    }
}
```

### Test Naming Convention

Use descriptive names: `test_<function>_<scenario>_<expected_result>`

- `test_parse_eip1559_valid_transfer_succeeds`
- `test_parse_eip1559_empty_input_fails`
- `test_policy_blacklist_blocks_recipient`

---

## Documentation Requirements

### What to Document

1. **Public API**: All `pub` items need doc comments
2. **Modules**: Add module-level documentation in `//!` comments
3. **Examples**: Include runnable examples where helpful
4. **Architecture**: Update docs/ if making structural changes

### Documentation Checks

The CI runs documentation checks:

```bash
# Build docs with warnings as errors
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Check for broken links
cargo doc --no-deps
```

### Updating Documentation

When your changes affect:

- **Public API**: Update doc comments and examples
- **Architecture**: Update `docs/ARCHITECTURE.md`
- **Development workflow**: Update `docs/DEVELOPER_GUIDE.md`
- **Configuration**: Update README.md and examples

---

## Questions?

- **Discussion**: Open a [GitHub Discussion](https://github.com/txgate-project/txgate/discussions)
- **Chat**: Join our Discord (if available)
- **Issues**: For bugs and feature requests

Thank you for contributing to TxGate!
