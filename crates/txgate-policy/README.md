# txgate-policy

[![Crates.io](https://img.shields.io/crates/v/txgate-policy.svg)](https://crates.io/crates/txgate-policy)
[![Documentation](https://docs.rs/txgate-policy/badge.svg)](https://docs.rs/txgate-policy)
[![License](https://img.shields.io/crates/l/txgate-policy.svg)](https://github.com/luisjpf/txgate#license)

Policy engine for transaction approval rules in the [TxGate](https://crates.io/crates/txgate) transaction signing service.

## Warning

**This is an internal crate with an unstable API.**

This crate is published to crates.io only as a dependency of the `txgate` binary. The API may change without notice between versions.

**Do not depend on this crate directly.** Use the [`txgate`](https://crates.io/crates/txgate) crate instead.

## What's Inside

### Policy Rules
- **Allowlist** - Only sign transactions to approved addresses
- **Denylist** - Block transactions to specific addresses
- **Rate Limits** - Limit transaction frequency per time window
- **Amount Limits** - Maximum per-transaction spending limits

### Features
- TOML-based policy configuration
- Per-chain policy rules
- Composable rule evaluation

### Example Policy

```toml
[ethereum]
allowlist = ["0x742d35Cc6634C0532925a3b844Bc9e7595f0Ab1c"]
max_amount = "1.0"
rate_limit = { max_requests = 100, window_seconds = 3600 }
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
