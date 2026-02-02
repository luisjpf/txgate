---
name: txgate
description: Guide for using the TxGate secure multi-chain transaction signing CLI. Use when working with txgate commands, transaction signing, key management, policy configuration, or the txgate daemon.
---

# TxGate CLI Skill

Self-hosted, chain-agnostic transaction signing server. Parses raw transactions, enforces configurable policies (whitelist, blacklist, per-tx limits), then signs. Supports Ethereum (secp256k1), Bitcoin (secp256k1), Solana (ed25519).

## Security Model

- Keys encrypted at rest (Argon2id + ChaCha20-Poly1305)
- Unix socket IPC only (no network exposure)
- Policy engine evaluates every signing request
- Passphrase never stored on disk
- All signing operations audit-logged to `~/.txgate/logs/audit.jsonl`

## Quick Reference

### First-time Setup

```bash
txgate init                        # Creates ~/.txgate/, prompts passphrase, generates key
txgate status                      # Verify installation
txgate ethereum address            # Show Ethereum address
```

### Signing Transactions

```bash
txgate ethereum sign <TX_HEX>                  # Sign, hex output
txgate ethereum sign <TX_HEX> --format json    # Sign, JSON output
txgate bitcoin sign <TX_HEX>
txgate solana sign <TX_HEX>
```

### Key Management

```bash
txgate key list [--details]
txgate key import <HEX> [--name NAME] [--curve ed25519]
txgate key export <NAME> [--output PATH] [--force]
txgate key delete <NAME> [--force]
```

### Server Mode (JSON-RPC daemon)

```bash
txgate serve [--foreground]        # Listens on ~/.txgate/txgate.sock
```

### Configuration

```bash
txgate config                      # Show current config
txgate config edit                 # Open in $EDITOR
txgate config path                 # Print config file path
```

### Global Options

```
-v / -vv / -vvv                    # Verbosity: info / debug / trace
-c / --config <PATH>               # Custom config file
--help                             # Help for any command
--version                          # Show version
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Policy denied (transaction rejected by rules) |
| 2 | General error |

## Policy Configuration

Policies live in `~/.txgate/config.toml` under `[policy]`:

```toml
[policy]
whitelist_enabled = true
whitelist = ["0x742d...713d"]      # Only these recipients allowed
blacklist = ["0x0000...0000"]      # Always denied (checked first)

[policy.transaction_limits]
ETH = "5000000000000000000"        # 5 ETH max per tx (in wei)
```

Evaluation order: blacklist > whitelist > tx_limit > allow.

## Key Curves

- **secp256k1** (default): Ethereum, Bitcoin
- **ed25519**: Solana. Import with `--curve ed25519`

## Common Workflows

### Sign and check result in a script

```bash
txgate ethereum sign "$TX_HEX"
case $? in
  0) echo "signed" ;;
  1) echo "policy denied" ;;
  2) echo "error" ;;
esac
```

### Debug a denied transaction

```bash
txgate -vv ethereum sign <TX_HEX>
# Exit code 1 = policy denied. Check stderr for which rule.
```

### Import an existing private key

```bash
txgate key import 0x<hex> --name my-wallet
# Prompts for passphrase. Key encrypted and stored.
```

### Import a Solana key

```bash
txgate key import <hex> --name sol-wallet --curve ed25519
```

## Gotchas

- TX_HEX accepts with or without `0x` prefix
- Passphrase prompted interactively (not from stdin by default)
- "default" key cannot be deleted without `--force`
- Solana requires ed25519 key (different from Ethereum/Bitcoin)
- Socket permissions are 0700 (owner only)
- `txgate init --force` overwrites existing keys -- use with caution

## For More Detail

- Run `txgate --help` or `txgate <command> --help` for real-time CLI docs
- See `references/cli-reference.md` for full command table
- See `references/config-reference.md` for complete config schema
