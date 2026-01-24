# Sello

[![CI](https://github.com/sello-project/sello/actions/workflows/ci.yml/badge.svg)](https://github.com/sello-project/sello/actions/workflows/ci.yml)

Multi-chain transaction signing service with policy engine.

## Overview

Sello is a secure, high-performance transaction signing service designed for blockchain applications. It provides:

- **Multi-chain support**: Sign transactions for Ethereum (Solana, Bitcoin planned)
- **Policy engine**: Define and enforce signing policies (amount limits, address allowlists, etc.)
- **Key management**: Secure key storage with encrypted files (HSM and cloud KMS support planned)
- **API server**: REST/gRPC APIs for integration with your applications

## Project Structure

```
sello/
├── crates/
│   ├── sello-core/      # Core types, traits, and error definitions
│   ├── sello-crypto/    # Cryptographic operations (signing, verification)
│   ├── sello-chain/     # Multi-chain transaction parsing
│   ├── sello-policy/    # Policy engine for signing rules
│   └── sello/           # Binary crate (CLI + Server)
├── tests/
│   ├── integration/     # Integration tests
│   └── fixtures/        # Test data files
└── fuzz/                # Fuzz testing targets
```

## Installation

### From GitHub Releases (Recommended)

Download the latest pre-built binary for your platform from the [Releases](https://github.com/sello-project/sello/releases) page.

**Linux (x86_64)**
```bash
curl -LO https://github.com/sello-project/sello/releases/latest/download/sello-linux-x86_64.tar.gz
tar -xzf sello-linux-x86_64.tar.gz
sudo mv sello /usr/local/bin/
```

**macOS (Apple Silicon)**
```bash
curl -LO https://github.com/sello-project/sello/releases/latest/download/sello-macos-aarch64.tar.gz
tar -xzf sello-macos-aarch64.tar.gz
sudo mv sello /usr/local/bin/
```

**macOS (Intel)**
```bash
curl -LO https://github.com/sello-project/sello/releases/latest/download/sello-macos-x86_64.tar.gz
tar -xzf sello-macos-x86_64.tar.gz
sudo mv sello /usr/local/bin/
```

### Verify Installation

After installation, verify the binary works:
```bash
sello --version
sello --help
```

### From crates.io

```bash
cargo install sello
```

### From Source

#### Prerequisites

- Rust 1.75 or later
- Cargo

#### Building

```bash
# Clone the repository
git clone https://github.com/sello-project/sello.git
cd sello

# Build all crates
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run the CLI
cargo run -- --help
```

### Running the Server

```bash
# Start the signing server
sello serve
```

## Configuration

Configuration is done via TOML files. See `config.example.toml` and
`docs/CONFIGURATION.md` for available options.

## Documentation

- Quickstart: `docs/QUICKSTART.md`
- User guide: `docs/USER_GUIDE.md`
- Configuration reference: `docs/CONFIGURATION.md`
- Developer guide: `docs/DEVELOPER_GUIDE.md`

## Security

Sello is designed with security as a top priority:

- No unsafe code (`#![forbid(unsafe_code)]`)
- Comprehensive input validation
- Policy-based access control
- Audit logging for all signing operations
- HSM and cloud KMS backends (planned)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` for expectations and workflows.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
