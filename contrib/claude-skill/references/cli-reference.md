# TxGate CLI Reference

## General Commands

| Command | Description |
|---------|-------------|
| `txgate init` | Initialize configuration and generate key |
| `txgate init --force` | Reinitialize (overwrites existing) |
| `txgate status` | Display current status |
| `txgate config` | View configuration |
| `txgate config edit` | Edit configuration in default editor |
| `txgate config path` | Show configuration file path |
| `txgate serve` | Start the signing server |
| `txgate serve --foreground` | Start server in foreground |
| `txgate install-skill` | Print Claude Code skill install instructions |

## Ethereum Commands

| Command | Description |
|---------|-------------|
| `txgate ethereum address` | Display Ethereum address (EIP-55 checksummed) |
| `txgate ethereum sign <TX>` | Sign a transaction (hex output) |
| `txgate ethereum sign <TX> -f json` | Sign with JSON output (`-f` / `--format`) |

## Bitcoin Commands

| Command | Description |
|---------|-------------|
| `txgate bitcoin address` | Display Bitcoin address (P2WPKH bech32) |
| `txgate bitcoin sign <TX>` | Sign a Bitcoin transaction (hex output) |
| `txgate bitcoin sign <TX> -f json` | Sign with JSON output (`-f` / `--format`) |

## Solana Commands

| Command | Description |
|---------|-------------|
| `txgate solana address` | Display Solana address (base58 ed25519) |
| `txgate solana sign <TX>` | Sign a Solana transaction (hex output) |
| `txgate solana sign <TX> -f json` | Sign with JSON output (`-f` / `--format`) |

## Key Management Commands

| Command | Description |
|---------|-------------|
| `txgate key list` | List all stored keys |
| `txgate key list -d` | List keys with file details (`-d` / `--details`) |
| `txgate key import <HEX>` | Import a private key (secp256k1) |
| `txgate key import <HEX> --name NAME` | Import with custom name |
| `txgate key import <HEX> -C ed25519` | Import an ed25519 key (`-C` / `--curve`) |
| `txgate key export <NAME>` | Export a key as encrypted backup |
| `txgate key export <NAME> -o PATH` | Export to specific file (`-o` / `--output`) |
| `txgate key export <NAME> --force` | Overwrite existing export file |
| `txgate key delete <NAME>` | Delete a key (with confirmation) |
| `txgate key delete <NAME> --force` | Delete without confirmation |

## Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Increase verbosity (repeat: -v, -vv, -vvv) |
| `-c, --config <PATH>` | Use custom config file |
| `--help` | Show help information |
| `--version` | Show version |

## Exit Codes

| Code | Name | Description |
|------|------|-------------|
| `0` | Success | Command completed successfully |
| `1` | Policy Denied | Transaction rejected by policy rules |
| `2` | Error | General error (invalid input, I/O failure, etc.) |

## JSON Output Format

All `sign` commands support `--format json`. Success response:

```json
{
  "chain": "ethereum",
  "transaction_hash": "0x...",
  "signature": { "v": 28, "r": "0x...", "s": "0x..." },
  "signed_transaction": "0x...",
  "signer": "0x..."
}
```

Policy denied response:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied: blacklist - recipient address is blacklisted",
    "policy": "blacklist"
  }
}
```
