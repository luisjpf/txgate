# txgate

[![Crates.io](https://img.shields.io/crates/v/txgate.svg)](https://crates.io/crates/txgate)
[![Documentation](https://docs.rs/txgate/badge.svg)](https://docs.rs/txgate)
[![License](https://img.shields.io/crates/l/txgate.svg)](https://github.com/luisjpf/txgate#license)

Multi-chain transaction signing service with policy engine.

## Overview

TxGate is a secure, high-performance transaction signing service designed for blockchain applications. It provides:

- **Multi-chain support**: Sign transactions for Ethereum, Bitcoin, and Solana
- **Policy engine**: Define and enforce signing policies (amount limits, address allowlists, rate limits)
- **Key management**: Secure key storage with Argon2id + ChaCha20-Poly1305 encryption
- **CLI interface**: Full-featured command-line interface for key and transaction management

## Installation

### From crates.io

```bash
cargo install txgate
```

### From GitHub Releases

Download pre-built binaries from [GitHub Releases](https://github.com/luisjpf/txgate/releases):

| Platform | Download |
|----------|----------|
| Linux x86_64 | `txgate-linux-x86_64.tar.gz` |
| macOS Intel | `txgate-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `txgate-macos-aarch64.tar.gz` |

## Quick Start

```bash
# Initialize TxGate (creates ~/.txgate directory and default key)
txgate init

# View your Ethereum address
txgate ethereum address

# View your Bitcoin address
txgate bitcoin address

# View your Solana address
txgate solana address

# Sign an Ethereum transaction
txgate ethereum sign <raw-tx-hex>

# Start the signing server
txgate serve
```

## Supported Chains

| Chain | Address Format | Transaction Types |
|-------|----------------|-------------------|
| Ethereum | EIP-55 checksummed | Legacy, EIP-2930, EIP-1559, ERC-20 |
| Bitcoin | P2WPKH (bech32) | P2PKH, P2WPKH, P2TR |
| Solana | Base58 | Native SOL, SPL Token |

## Key Management

TxGate stores keys in `~/.txgate/keys/` with strong encryption:

- **Key derivation**: Argon2id (64 MiB memory, 3 iterations, 4 lanes)
- **Encryption**: ChaCha20-Poly1305 authenticated encryption
- **Memory safety**: All secrets implement `Zeroize` and `ZeroizeOnDrop`

```bash
# Import an existing private key
txgate key import --name mykey

# List all keys
txgate key list

# Export a key (displays hex, does NOT write to file)
txgate key export --name default
```

## Policy Engine

Configure transaction policies in `~/.txgate/policy.toml`:

```toml
[ethereum]
allowlist = ["0x742d35Cc6634C0532925a3b844Bc9e7595f0Ab1c"]
max_amount = "1.0"        # Max ETH per transaction
max_daily = "10.0"        # Max ETH per day
rate_limit = { max_requests = 100, window_seconds = 3600 }

[bitcoin]
denylist = ["bc1qexample..."]
max_amount = "0.1"        # Max BTC per transaction
```

## Security

- No `unsafe` code (`#![forbid(unsafe_code)]`)
- Comprehensive input validation
- Constant-time cryptographic operations
- Audit logging for all signing operations

## Architecture

TxGate is built as a Rust workspace with focused crates:

| Crate | Purpose |
|-------|---------|
| `txgate-core` | Core types, traits, errors |
| `txgate-crypto` | Key management, signing |
| `txgate-chain` | Transaction parsing |
| `txgate-policy` | Policy evaluation |
| `txgate` | CLI and server |

## Documentation

- [User Guide](https://github.com/luisjpf/txgate/blob/main/docs/USER_GUIDE.md)
- [Configuration](https://github.com/luisjpf/txgate/blob/main/docs/CONFIGURATION.md)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
