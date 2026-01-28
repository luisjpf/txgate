# TxGate

[![CI](https://github.com/luisjpf/txgate/actions/workflows/ci.yml/badge.svg)](https://github.com/luisjpf/txgate/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/txgate.svg)](https://crates.io/crates/txgate)
[![Documentation](https://img.shields.io/badge/docs-user_guide-blue)](docs/USER_GUIDE.md)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Multi-chain transaction signing service with policy engine.

## Overview

TxGate is a secure, high-performance transaction signing service designed for blockchain applications. It provides:

- **Multi-chain support**: Sign transactions for Ethereum, Bitcoin, and Solana
- **Policy engine**: Define and enforce signing policies (amount limits, address allowlists, etc.)
- **Key management**: Secure key storage with encrypted files (HSM and cloud KMS support planned)
- **API server**: REST/gRPC APIs for integration with your applications

## Project Structure

```
txgate/
├── crates/
│   ├── txgate-core/      # Core types, traits, and error definitions
│   ├── txgate-crypto/    # Cryptographic operations (signing, verification)
│   ├── txgate-chain/     # Multi-chain transaction parsing
│   ├── txgate-policy/    # Policy engine for signing rules
│   └── txgate/           # Binary crate (CLI + Server)
├── tests/
│   ├── integration/     # Integration tests
│   └── fixtures/        # Test data files
└── fuzz/                # Fuzz testing targets
```

## Installation

### From GitHub Releases (Recommended)

Download the latest pre-built binary for your platform from the [Releases](https://github.com/luisjpf/txgate/releases) page.

**Linux (x86_64)**
```bash
curl -LO https://github.com/luisjpf/txgate/releases/latest/download/txgate-linux-x86_64.tar.gz
tar -xzf txgate-linux-x86_64.tar.gz
sudo mv txgate /usr/local/bin/
```

**macOS (Apple Silicon)**
```bash
curl -LO https://github.com/luisjpf/txgate/releases/latest/download/txgate-macos-aarch64.tar.gz
tar -xzf txgate-macos-aarch64.tar.gz
sudo mv txgate /usr/local/bin/
```

**macOS (Intel)**
```bash
curl -LO https://github.com/luisjpf/txgate/releases/latest/download/txgate-macos-x86_64.tar.gz
tar -xzf txgate-macos-x86_64.tar.gz
sudo mv txgate /usr/local/bin/
```

### Verify Installation

After installation, verify the binary works:
```bash
txgate --version
txgate --help
```

### From crates.io

```bash
cargo install txgate
```

### From Source

#### Prerequisites

- Rust 1.75 or later
- Cargo

#### Building

```bash
# Clone the repository
git clone https://github.com/luisjpf/txgate.git
cd txgate

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
txgate serve
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

TxGate is designed with security as a top priority:

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
