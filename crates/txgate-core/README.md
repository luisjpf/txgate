# txgate-core

[![Crates.io](https://img.shields.io/crates/v/txgate-core.svg)](https://crates.io/crates/txgate-core)
[![Documentation](https://docs.rs/txgate-core/badge.svg)](https://docs.rs/txgate-core)
[![License](https://img.shields.io/crates/l/txgate-core.svg)](https://github.com/luisjpf/txgate#license)

Core types, traits, and error definitions for the [TxGate](https://crates.io/crates/txgate) transaction signing service.

## Warning

**This is an internal crate with an unstable API.**

This crate is published to crates.io only as a dependency of the `txgate` binary. The API may change without notice between versions.

**Do not depend on this crate directly.** Use the [`txgate`](https://crates.io/crates/txgate) crate instead.

## What's Inside

- `Chain` enum - Supported blockchain identifiers (Ethereum, Bitcoin, Solana)
- `ParsedTransaction` - Chain-agnostic transaction representation
- `Recipient` - Transaction output with address and amount
- Error types for the entire TxGate ecosystem

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
