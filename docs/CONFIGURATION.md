# TxGate Configuration Reference

This document provides a complete reference for all TxGate configuration options.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Configuration File Format](#configuration-file-format)
- [Server Configuration](#server-configuration)
- [Keys Configuration](#keys-configuration)
- [Policy Configuration](#policy-configuration)
- [Logging Configuration](#logging-configuration)
- [Complete Example](#complete-example)
- [Environment Variables](#environment-variables)

---

## Configuration File Location

The default configuration file is located at:

```
~/.txgate/config.toml
```

### Custom Location

Use the `-c` or `--config` flag to specify an alternative location:

```bash
txgate -c /etc/txgate/config.toml serve
```

### View Location

```bash
txgate config path
```

### Edit Configuration

```bash
txgate config edit
```

Opens the configuration file in your default editor (`$EDITOR` or `$VISUAL`).

---

## Configuration File Format

TxGate uses TOML format for configuration. The file contains three main sections:

```toml
[server]
# Server configuration

[keys]
# Key storage configuration

[policy]
# Policy rules configuration
```

---

## Server Configuration

The `[server]` section configures the signing daemon.

### socket_path

Path to the Unix domain socket for IPC communication.

| Property | Value |
|----------|-------|
| Type | String |
| Default | `~/.txgate/txgate.sock` |
| Required | No |

```toml
[server]
socket_path = "~/.txgate/txgate.sock"
```

Notes:
- Supports `~` expansion for home directory
- Directory must exist and be writable
- Socket is created with owner-only permissions

### timeout_secs

Maximum time in seconds to wait for a signing request to complete.

| Property | Value |
|----------|-------|
| Type | Integer |
| Default | `30` |
| Required | No |
| Valid Range | 1 - 3600 |

```toml
[server]
timeout_secs = 30
```

Includes time for:
- Policy evaluation
- Key loading
- Cryptographic operations

---

## Keys Configuration

The `[keys]` section configures key storage.

### directory

Directory where encrypted key files are stored.

| Property | Value |
|----------|-------|
| Type | String |
| Default | `~/.txgate/keys` |
| Required | No |

```toml
[keys]
directory = "~/.txgate/keys"
```

Notes:
- Supports `~` expansion
- Directory is created with 0700 permissions
- Key files are stored as `<name>.enc`

### default_key

Name of the default key used for signing operations.

| Property | Value |
|----------|-------|
| Type | String |
| Default | `default` |
| Required | No |

```toml
[keys]
default_key = "default"
```

The actual file will be `<directory>/<default_key>.enc`.

---

## Policy Configuration

The `[policy]` section defines transaction approval rules.

### whitelist_enabled

Enable or disable whitelist mode.

| Property | Value |
|----------|-------|
| Type | Boolean |
| Default | `false` |
| Required | No |

```toml
[policy]
whitelist_enabled = true
```

When enabled:
- Only addresses in `whitelist` are allowed as recipients
- Transactions to non-whitelisted addresses are denied

When disabled:
- All addresses are allowed (unless blacklisted)
- The `whitelist` array is ignored

### whitelist

List of addresses that are always allowed as recipients (when whitelist mode is enabled).

| Property | Value |
|----------|-------|
| Type | Array of Strings |
| Default | `[]` |
| Required | No |

```toml
[policy]
whitelist_enabled = true
whitelist = [
    "0x742d35Cc6634C0532925a3b844Bc454e4429713d",
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
]
```

Notes:
- Address comparison is case-insensitive
- Include the `0x` prefix
- Has no effect unless `whitelist_enabled = true`

### blacklist

List of addresses that are always denied as recipients.

| Property | Value |
|----------|-------|
| Type | Array of Strings |
| Default | `[]` |
| Required | No |

```toml
[policy]
blacklist = [
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dEaD"
]
```

Notes:
- Blacklist is checked before whitelist (higher priority)
- Address comparison is case-insensitive
- An address cannot be in both whitelist and blacklist

### transaction_limits

Maximum amount allowed per single transaction, specified per token.

| Property | Value |
|----------|-------|
| Type | Table (String -> String) |
| Default | `{}` |
| Required | No |

```toml
[policy.transaction_limits]
# Native ETH - 5 ETH max per transaction
ETH = "5000000000000000000"

# USDC (6 decimals) - 10,000 USDC max per transaction
"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" = "10000000000"

# USDT (6 decimals) - 10,000 USDT max per transaction
"0xdAC17F958D2ee523a2206206994597C13D831ec7" = "10000000000"
```

Notes:
- Use `ETH` for native Ether transfers
- Use token contract address for ERC-20 tokens
- Amounts are in the token's smallest unit (wei for ETH)
- Token keys are case-insensitive
- Omitting a token means no per-transaction limit for that token

### daily_limits

Maximum total amount allowed per 24-hour period, specified per token.

| Property | Value |
|----------|-------|
| Type | Table (String -> String) |
| Default | `{}` |
| Required | No |

```toml
[policy.daily_limits]
# Native ETH - 10 ETH max per day
ETH = "10000000000000000000"

# USDC (6 decimals) - 50,000 USDC max per day
"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" = "50000000000"
```

Notes:
- Daily limit tracking resets every 24 hours
- Tracked amounts persist across server restarts
- Uses rolling 24-hour window
- Token keys are case-insensitive

---

## Logging Configuration

Logging is configured via environment variables (see below). Audit logs are written to:

```
~/.txgate/logs/audit.jsonl
```

Each line is a JSON object containing:
- Timestamp
- Operation type
- Transaction details
- Result (allowed/denied)
- Policy rule that applied

---

## Complete Example

Here is a complete configuration file with all options:

```toml
# =============================================================================
# TxGate Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# Server Settings
# -----------------------------------------------------------------------------
[server]
# Path to the Unix socket for client connections
socket_path = "~/.txgate/txgate.sock"

# Request timeout in seconds
timeout_secs = 30

# -----------------------------------------------------------------------------
# Key Storage Settings
# -----------------------------------------------------------------------------
[keys]
# Directory containing encrypted key files
directory = "~/.txgate/keys"

# Name of the default signing key
default_key = "default"

# -----------------------------------------------------------------------------
# Policy Settings
# -----------------------------------------------------------------------------
[policy]
# Enable whitelist mode (only allow transactions to whitelisted addresses)
whitelist_enabled = true

# Addresses allowed as recipients (when whitelist_enabled = true)
whitelist = [
    # Uniswap V3 Router
    "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    # USDC contract
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    # Personal wallet
    "0x742d35Cc6634C0532925a3b844Bc454e4429713d"
]

# Addresses always denied (checked before whitelist)
blacklist = [
    # Null address
    "0x0000000000000000000000000000000000000000",
    # Burn address
    "0x000000000000000000000000000000000000dEaD"
]

# -----------------------------------------------------------------------------
# Transaction Limits (per single transaction)
# -----------------------------------------------------------------------------
[policy.transaction_limits]
# Maximum ETH per transaction: 5 ETH
ETH = "5000000000000000000"

# Maximum USDC per transaction: 10,000 USDC
"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" = "10000000000"

# Maximum USDT per transaction: 10,000 USDT
"0xdAC17F958D2ee523a2206206994597C13D831ec7" = "10000000000"

# -----------------------------------------------------------------------------
# Daily Limits (rolling 24-hour window)
# -----------------------------------------------------------------------------
[policy.daily_limits]
# Maximum ETH per day: 20 ETH
ETH = "20000000000000000000"

# Maximum USDC per day: 50,000 USDC
"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" = "50000000000"

# Maximum USDT per day: 50,000 USDT
"0xdAC17F958D2ee523a2206206994597C13D831ec7" = "50000000000"
```

---

## Environment Variables

### RUST_LOG

Controls log verbosity. TxGate uses the `tracing` framework.

```bash
# Show info and above
export RUST_LOG=info

# Show debug messages for txgate
export RUST_LOG=txgate=debug

# Show all trace messages
export RUST_LOG=trace

# Combination
export RUST_LOG=warn,txgate=debug,txgate_policy=trace
```

### EDITOR / VISUAL

Used by `txgate config edit` to determine the text editor.

```bash
export EDITOR=vim
# or
export VISUAL=code
```

---

## Wei Conversion Reference

When configuring limits, amounts must be in the token's smallest unit.

### ETH (18 decimals)

| Amount | Wei Value |
|--------|-----------|
| 0.001 ETH | `1000000000000000` |
| 0.01 ETH | `10000000000000000` |
| 0.1 ETH | `100000000000000000` |
| 1 ETH | `1000000000000000000` |
| 10 ETH | `10000000000000000000` |
| 100 ETH | `100000000000000000000` |

### USDC / USDT (6 decimals)

| Amount | Smallest Unit |
|--------|--------------|
| 1 | `1000000` |
| 10 | `10000000` |
| 100 | `100000000` |
| 1,000 | `1000000000` |
| 10,000 | `10000000000` |
| 100,000 | `100000000000` |

---

## Validation Rules

TxGate validates the configuration on startup. Invalid configurations will cause startup to fail.

### Validation Checks

| Check | Error Message |
|-------|---------------|
| Empty socket_path | `invalid value for 'server.socket_path': <empty>` |
| Zero timeout | `invalid value for 'server.timeout_secs': 0` |
| Empty keys directory | `invalid value for 'keys.directory': <empty>` |
| Empty default_key | `invalid value for 'keys.default_key': <empty>` |
| Address in both lists | `policy validation failed: address 'X' appears in both whitelist and blacklist` |

### Testing Configuration

Validate your configuration by running:

```bash
txgate status
```

If the configuration is valid, status information will be displayed. If invalid, an error message will indicate the problem.

---

## Default Configuration

When you run `txgate init`, the following default configuration is created:

```toml
[server]
socket_path = "~/.txgate/txgate.sock"
timeout_secs = 30

[keys]
directory = "~/.txgate/keys"
default_key = "default"

[policy]
whitelist_enabled = false
whitelist = []
blacklist = []

[policy.transaction_limits]
# ETH = "1000000000000000000"  # 1 ETH

[policy.daily_limits]
# ETH = "10000000000000000000"  # 10 ETH
```

The limits are commented out by default, meaning no amount limits are enforced until you configure them.

---

## Security Recommendations

### Minimal Whitelist

Enable whitelist mode and add only addresses you actively use:

```toml
[policy]
whitelist_enabled = true
whitelist = [
    # Only your known contracts and wallets
]
```

### Conservative Limits

Start with low limits and increase as needed:

```toml
[policy.transaction_limits]
ETH = "1000000000000000000"  # 1 ETH

[policy.daily_limits]
ETH = "5000000000000000000"  # 5 ETH
```

### Blacklist Known Bad Addresses

Always blacklist the null address and known scam addresses:

```toml
[policy]
blacklist = [
    "0x0000000000000000000000000000000000000000"
]
```

### Regular Review

Periodically review your configuration:

```bash
txgate config
```

Remove addresses you no longer need and update limits based on actual usage.
