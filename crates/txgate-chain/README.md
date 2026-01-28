# txgate-chain

[![Crates.io](https://img.shields.io/crates/v/txgate-chain.svg)](https://crates.io/crates/txgate-chain)
[![Documentation](https://docs.rs/txgate-chain/badge.svg)](https://docs.rs/txgate-chain)
[![License](https://img.shields.io/crates/l/txgate-chain.svg)](https://github.com/luisjpf/txgate#license)

Multi-chain transaction parsing and construction for the [TxGate](https://crates.io/crates/txgate) transaction signing service.

## Warning

**This is an internal crate with an unstable API.**

This crate is published to crates.io only as a dependency of the `txgate` binary. The API may change without notice between versions.

**Do not depend on this crate directly.** Use the [`txgate`](https://crates.io/crates/txgate) crate instead.

## What's Inside

### Supported Chains

| Chain | Parser | Features |
|-------|--------|----------|
| Ethereum | `EthereumParser` | EIP-1559/2930/Legacy transactions, ERC-20 token detection |
| Bitcoin | `BitcoinParser` | P2PKH, P2WPKH (SegWit), P2TR (Taproot), OP_RETURN |
| Solana | `SolanaParser` | Native SOL transfers, SPL Token transfers |

### Transaction Parsing
- Parse raw transaction bytes into chain-agnostic `ParsedTransaction`
- Extract recipients, amounts, and token information
- Support for both legacy and modern transaction formats

### Chain Registry
- Dynamic chain parser registration
- Extensible architecture for adding new chains

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
