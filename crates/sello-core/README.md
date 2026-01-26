# sello-core

[![Crates.io](https://img.shields.io/crates/v/sello-core.svg)](https://crates.io/crates/sello-core)
[![Documentation](https://docs.rs/sello-core/badge.svg)](https://docs.rs/sello-core)
[![License](https://img.shields.io/crates/l/sello-core.svg)](https://github.com/luisjpf/sello#license)

Core types, traits, and error definitions for the [Sello](https://crates.io/crates/sello) transaction signing service.

## Warning

**This is an internal crate with an unstable API.**

This crate is published to crates.io only as a dependency of the `sello` binary. The API may change without notice between versions.

**Do not depend on this crate directly.** Use the [`sello`](https://crates.io/crates/sello) crate instead.

## What's Inside

- `Chain` enum - Supported blockchain identifiers (Ethereum, Bitcoin, Solana)
- `ParsedTransaction` - Chain-agnostic transaction representation
- `Recipient` - Transaction output with address and amount
- Error types for the entire Sello ecosystem

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
