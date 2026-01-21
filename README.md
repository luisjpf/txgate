# Sello

Multi-chain transaction signing service with policy engine.

## Overview

Sello is a secure, high-performance transaction signing service designed for blockchain applications. It provides:

- **Multi-chain support**: Sign transactions for Ethereum, Solana, Bitcoin, and more
- **Policy engine**: Define and enforce signing policies (amount limits, address allowlists, etc.)
- **Key management**: Secure key storage with support for HSMs and cloud KMS
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

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Cargo

### Building

```bash
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
# Start the signing server (placeholder)
cargo run -- server --config config.yaml
```

## Configuration

Configuration is done via YAML files. See `config.example.yaml` for available options.

## Security

Sello is designed with security as a top priority:

- No unsafe code (`#![forbid(unsafe_code)]`)
- Comprehensive input validation
- Policy-based access control
- Audit logging for all signing operations
- Support for HSM and cloud KMS backends

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
