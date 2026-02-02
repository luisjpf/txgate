# TxGate Configuration Reference

Config file: `~/.txgate/config.toml`

## Sections

### [server]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket_path` | String | `~/.txgate/txgate.sock` | Unix socket path for IPC |
| `timeout_secs` | Integer | `30` | Request timeout (1-3600) |

### [keys]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `directory` | String | `~/.txgate/keys` | Encrypted key storage dir |
| `default_key` | String | `default` | Default signing key name |

### [policy]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `whitelist_enabled` | Boolean | `false` | Enable whitelist mode |
| `whitelist` | Array\<String\> | `[]` | Allowed recipient addresses |
| `blacklist` | Array\<String\> | `[]` | Denied recipient addresses |

### [policy.transaction_limits]

Key-value pairs where key is token identifier and value is max amount in smallest unit.

| Key format | Example | Description |
|------------|---------|-------------|
| `ETH` | `"5000000000000000000"` | Native ETH (5 ETH) |
| `"0x<contract>"` | `"10000000000"` | ERC-20 token (10,000 USDC) |

## Policy Evaluation Order

1. **Blacklist** (highest priority) -- deny if recipient blacklisted
2. **Whitelist** -- deny if enabled and recipient not listed
3. **Transaction Limit** -- deny if amount exceeds per-tx limit
4. **Allow** -- approve if all checks pass

## Wei Conversion

### ETH (18 decimals)

| Amount | Wei |
|--------|-----|
| 0.01 ETH | `10000000000000000` |
| 0.1 ETH | `100000000000000000` |
| 1 ETH | `1000000000000000000` |
| 5 ETH | `5000000000000000000` |
| 10 ETH | `10000000000000000000` |

### USDC/USDT (6 decimals)

| Amount | Smallest Unit |
|--------|---------------|
| 100 | `100000000` |
| 1,000 | `1000000000` |
| 10,000 | `10000000000` |

## Environment Variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `RUST_LOG` | Logging | Verbosity filter (e.g., `txgate=debug`) |
| `EDITOR` / `VISUAL` | `txgate config edit` | Text editor selection |

## Validation Rules

- `socket_path` must not be empty
- `timeout_secs` must be 1-3600
- `keys.directory` must not be empty
- `keys.default_key` must not be empty
- An address cannot appear in both whitelist and blacklist

## Default Configuration (created by `txgate init`)

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
# ETH = "1000000000000000000"  # 1 ETH (uncomment to enable)
```
