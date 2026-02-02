# TxGate User Guide

TxGate is a secure multi-chain transaction signing daemon that provides policy-based transaction approval with encrypted key storage. It supports Ethereum, Bitcoin, and Solana.

## Table of Contents

- [What is TxGate?](#what-is-txgate)
- [Why Use TxGate?](#why-use-txgate)
- [Installation](#installation)
- [Initialization](#initialization)
- [Key Management](#key-management)
- [Policy Configuration](#policy-configuration)
- [Running the Daemon](#running-the-daemon)
- [Connecting Clients](#connecting-clients)
- [JSON-RPC API](#json-rpc-api)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## What is TxGate?

TxGate is a transaction signing daemon designed for secure, automated signing of blockchain transactions. It supports Ethereum (secp256k1), Bitcoin (secp256k1), and Solana (ed25519). It separates key management from application logic, enabling:

- **Isolated key storage**: Private keys never leave the TxGate process
- **Policy enforcement**: Define rules for which transactions can be signed
- **Audit logging**: Track all signing operations
- **Unix socket communication**: Secure local IPC without network exposure

## Why Use TxGate?

| Use Case | Benefit |
|----------|---------|
| Bot automation | Sign transactions without exposing keys to your bot |
| Multi-sig preparation | Generate signatures for multi-sig wallets |
| Per-tx limits | Enforce per-transaction amount limits |
| Address restrictions | Whitelist/blacklist recipient addresses |
| Audit compliance | Maintain tamper-evident signing logs |

---

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/txgate-project/txgate.git
cd txgate

# Build and install
cargo install --path crates/txgate
```

### From crates.io

```bash
cargo install txgate
```

### Verify Installation

```bash
txgate --version
```

### System Requirements

- Rust 1.75 or later
- Unix-like operating system (Linux, macOS, WSL)
- ~50MB disk space for keys and logs

---

## Initialization

Initialize TxGate to create the configuration directory and generate your first key:

```bash
txgate init
```

### What Happens During Init

1. Creates `~/.txgate/` directory structure:
   ```
   ~/.txgate/
   ├── config.toml       (0600) - Configuration file
   ├── keys/             (0700) - Encrypted key storage
   │   └── default.enc   (0600) - Default signing key
   └── logs/             (0700) - Audit logs
   ```

2. Prompts for a passphrase (minimum 8 characters)
3. Generates a secp256k1 keypair
4. Encrypts and stores the key using Argon2id + ChaCha20-Poly1305
5. Displays your Ethereum address

### Force Reinitialization

To reset your configuration and generate a new key:

```bash
txgate init --force
```

**Warning**: This overwrites your existing key and configuration.

---

## Key Management

### View Your Address

```bash
txgate ethereum address
```

You will be prompted for your passphrase. The output is an EIP-55 checksummed Ethereum address:

```
0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
```

### Key Storage

Keys are stored encrypted at `~/.txgate/keys/default.enc` with:

- **Key derivation**: Argon2id (memory-hard, resistant to GPU attacks)
- **Encryption**: ChaCha20-Poly1305 (authenticated encryption)
- **File permissions**: 0600 (owner read/write only)

### Passphrase Requirements

- Minimum 8 characters
- Required for all operations that access the key
- Never stored on disk

### Multiple Keys

TxGate supports managing multiple keys. Each key has a unique name.

#### List Keys

```bash
txgate key list
```

Shows all stored keys:

```
Keys:
  default
  trading-wallet
  cold-storage
```

Use `--details` for additional details:

```bash
txgate key list --details
```

```
Keys:
  NAME                 FILE                      SIZE
  default              default.enc               77 B
  trading-wallet       trading-wallet.enc        77 B
```

#### Import an Existing Key

Import a private key from a hex string:

```bash
txgate key import 0xabc123... --name my-imported-key
```

You will be prompted for a passphrase to encrypt the key.

**Security notes:**
- The key hex is validated as a valid secp256k1 scalar
- Intermediate key bytes are zeroized after import
- Requires an interactive terminal (use scripts with caution)

#### Export a Key

Export a key as an encrypted backup:

```bash
txgate key export my-key --output /path/to/backup.json
```

You will be prompted for:
1. The current passphrase to decrypt the key
2. A new passphrase for the exported backup

The exported file is JSON with the encrypted key data:

```json
{
  "version": 1,
  "name": "my-key",
  "ethereum_address": "0x...",
  "encrypted_key": "base64-encoded-data"
}
```

**Security notes:**
- Output file permissions are set to 0600 (Unix)
- Requires an interactive terminal for passphrase prompts

#### Delete a Key

Delete a key permanently:

```bash
txgate key delete my-key
```

You will be prompted to confirm deletion. Use `--force` to skip confirmation:

```bash
txgate key delete my-key --force
```

**Security notes:**
- The "default" key cannot be deleted without `--force`
- Deletion is permanent and cannot be undone
- Confirmation prompts require an interactive terminal

---

## Policy Configuration

TxGate enforces policies before signing any transaction. Configure policies in `~/.txgate/config.toml`.

### Policy Types

| Policy | Description |
|--------|-------------|
| Whitelist | Only allow transactions to specified addresses |
| Blacklist | Deny transactions to specified addresses |
| Transaction Limit | Maximum amount per single transaction |

### Rule Evaluation Order

Policies are evaluated in strict priority order:

1. **Blacklist** (highest priority) - Deny if recipient is blacklisted
2. **Whitelist** - Deny if whitelist enabled and recipient not listed
3. **Transaction Limit** - Deny if amount exceeds per-tx limit
4. **Allow** - Approve if all checks pass

### Example Policy Configuration

```toml
[policy]
# Enable whitelist mode (only allow whitelisted addresses)
whitelist_enabled = true

# Addresses always allowed
whitelist = [
    "0x742d35Cc6634C0532925a3b844Bc454e4429713d",
    "0xdAC17F958D2ee523a2206206994597C13D831ec7"
]

# Addresses always denied (checked before whitelist)
blacklist = [
    "0x0000000000000000000000000000000000000000"
]

# Per-transaction limits (in wei)
[policy.transaction_limits]
ETH = "5000000000000000000"  # 5 ETH max per transaction
```

See [Configuration Reference](CONFIGURATION.md) for all options.

---

## Running the Daemon

### Start the Server

```bash
txgate serve
```

Or explicitly run in foreground:

```bash
txgate serve --foreground
```

### Server Behavior

1. Prompts for passphrase to unlock the signing key
2. Starts listening on `~/.txgate/txgate.sock`
3. Handles incoming JSON-RPC requests
4. Enforces policy rules for each signing request
5. Logs all operations to audit log

### Stopping the Server

Press `Ctrl+C` or send `SIGTERM`/`SIGINT` for graceful shutdown.

### Server Output

```
TxGate server starting...

Address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
Socket: /home/user/.txgate/txgate.sock
Audit log: /home/user/.txgate/logs/audit.jsonl

Press Ctrl+C to stop the server.
```

---

## Connecting Clients

### Unix Socket Communication

TxGate listens on a Unix domain socket at `~/.txgate/txgate.sock`. This provides:

- No network exposure
- OS-level access control via file permissions
- Fast local IPC

### Socket Permissions

The socket inherits directory permissions (0700), ensuring only the owning user can connect.

### Example Connection (Python)

```python
import socket
import json

def sign_transaction(tx_hex):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/home/user/.txgate/txgate.sock")

    request = {
        "jsonrpc": "2.0",
        "method": "eth_signTransaction",
        "params": [tx_hex],
        "id": 1
    }

    sock.send(json.dumps(request).encode())
    response = json.loads(sock.recv(4096).decode())
    sock.close()

    return response
```

### Example Connection (Rust)

```rust
use std::os::unix::net::UnixStream;
use std::io::{Read, Write};

fn sign_transaction(tx_hex: &str) -> String {
    let mut stream = UnixStream::connect("/home/user/.txgate/txgate.sock")
        .expect("Failed to connect");

    let request = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_signTransaction","params":["{}"],"id":1}}"#,
        tx_hex
    );

    stream.write_all(request.as_bytes()).unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    response
}
```

---

## JSON-RPC API

TxGate implements a JSON-RPC 2.0 API for signing operations.

### eth_signTransaction

Sign a raw Ethereum transaction.

**Request:**
```json
{
    "jsonrpc": "2.0",
    "method": "eth_signTransaction",
    "params": ["0xf86c..."],
    "id": 1
}
```

**Response (Success):**
```json
{
    "jsonrpc": "2.0",
    "result": {
        "transaction_hash": "0xabc...",
        "signature": "0xdef...",
        "signed_transaction": "0x123...",
        "signer": "0x5aAeb..."
    },
    "id": 1
}
```

**Response (Policy Denied):**
```json
{
    "jsonrpc": "2.0",
    "error": {
        "code": -32001,
        "message": "Policy denied: blacklist - recipient address is blacklisted"
    },
    "id": 1
}
```

### eth_accounts

Get the signing address.

**Request:**
```json
{
    "jsonrpc": "2.0",
    "method": "eth_accounts",
    "params": [],
    "id": 1
}
```

**Response:**
```json
{
    "jsonrpc": "2.0",
    "result": ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"],
    "id": 1
}
```

---

## Security Best Practices

### Passphrase Security

- Use a strong passphrase (12+ characters recommended)
- Never store your passphrase in scripts or environment variables
- Consider using a password manager

### File Permissions

TxGate sets secure permissions automatically:
- `~/.txgate/` - 0700 (owner only)
- `~/.txgate/config.toml` - 0600 (owner read/write)
- `~/.txgate/keys/*.enc` - 0600 (owner read/write)

Verify permissions:
```bash
ls -la ~/.txgate/
```

### Network Isolation

- TxGate uses Unix sockets, not network ports
- No remote access by default
- Never expose the socket over a network

### Policy Configuration

- Start with `whitelist_enabled = true`
- Whitelist only known, trusted addresses
- Set conservative transaction limits
- Review and update policies regularly

### Audit Logging

- Audit logs are written to `~/.txgate/logs/audit.jsonl`
- Review logs regularly for unexpected activity
- Back up logs to detect tampering

### Key Backup

- The encrypted key at `~/.txgate/keys/default.enc` can be backed up
- Store backups securely (encrypted, offline)
- Remember: backups are useless without the passphrase

---

## Troubleshooting

### Common Issues

#### "TxGate is not initialized"

Run `txgate init` to create the configuration and key.

#### "Invalid passphrase"

The passphrase you entered does not match the one used to encrypt the key. There is no recovery mechanism - ensure you remember your passphrase.

#### "Passphrase is too short"

Passphrases must be at least 8 characters.

#### "Policy denied: blacklist"

The recipient address is in your blacklist. Edit `~/.txgate/config.toml` to remove it.

#### "Policy denied: whitelist"

Whitelist mode is enabled and the recipient is not whitelisted. Either:
- Add the address to the whitelist
- Disable whitelist mode: `whitelist_enabled = false`

#### "Policy denied: tx_limit"

The transaction amount exceeds your configured per-transaction limit. Adjust `[policy.transaction_limits]` in config.

#### Socket connection refused

Ensure the server is running:
```bash
txgate serve
```

Check socket existence:
```bash
ls -la ~/.txgate/txgate.sock
```

#### Permission denied on socket

Verify you are running as the same user who started the server. The socket is only accessible by its owner.

### Getting Help

```bash
# General help
txgate --help

# Command-specific help
txgate init --help
txgate serve --help
txgate ethereum --help
```

### Verbose Output

Increase verbosity for debugging:

```bash
txgate -v status      # Info level
txgate -vv status     # Debug level
txgate -vvv status    # Trace level
```

### Checking Status

```bash
txgate status
```

Displays:
- Server status (running/stopped)
- Configured keys
- Active policies
- Recent signing activity

### Viewing Configuration

```bash
# Display current configuration
txgate config

# Show config file path
txgate config path

# Edit configuration
txgate config edit
```

---

## CLI Reference

### General Commands

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

### Ethereum Commands

| Command | Description |
|---------|-------------|
| `txgate ethereum address` | Display Ethereum address |
| `txgate ethereum sign <TX>` | Sign a transaction (hex output) |
| `txgate ethereum sign <TX> --format json` | Sign with JSON output |

### Bitcoin Commands

| Command | Description |
|---------|-------------|
| `txgate bitcoin address` | Display Bitcoin address (P2WPKH bech32) |
| `txgate bitcoin sign <TX>` | Sign a Bitcoin transaction (hex output) |
| `txgate bitcoin sign <TX> --format json` | Sign with JSON output |

### Solana Commands

| Command | Description |
|---------|-------------|
| `txgate solana address` | Display Solana address (base58 ed25519) |
| `txgate solana sign <TX>` | Sign a Solana transaction (hex output) |
| `txgate solana sign <TX> --format json` | Sign with JSON output |

### Key Management Commands

| Command | Description |
|---------|-------------|
| `txgate key list` | List all stored keys |
| `txgate key list --details` | List keys with details |
| `txgate key import <HEX>` | Import a private key |
| `txgate key import <HEX> --name NAME` | Import with custom name |
| `txgate key import <HEX> --curve ed25519` | Import an ed25519 key |
| `txgate key export <NAME>` | Export a key as encrypted backup |
| `txgate key delete <NAME>` | Delete a key |
| `txgate key delete <NAME> --force` | Delete without confirmation |

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Increase verbosity (can repeat: -vvv) |
| `-c, --config <PATH>` | Use custom config file |
| `--help` | Show help information |
| `--version` | Show version |

---

## Exit Codes

TxGate uses consistent exit codes for scripting and automation:

| Code | Name | Description |
|------|------|-------------|
| `0` | Success | Command completed successfully |
| `1` | Policy Denied | Transaction rejected by policy rules |
| `2` | Error | General error (invalid input, I/O failure, etc.) |

### Usage in Scripts

```bash
#!/bin/bash

# Sign a transaction
txgate ethereum sign "$TX_HEX"
exit_code=$?

case $exit_code in
    0)
        echo "Transaction signed successfully"
        ;;
    1)
        echo "Policy denied the transaction"
        # Handle policy violation (e.g., notify admin)
        ;;
    2)
        echo "An error occurred"
        # Handle error (e.g., retry or alert)
        ;;
esac
```

### Error Handling Examples

```bash
# Check if policy allows the transaction
if txgate ethereum sign "$TX_HEX" > /dev/null 2>&1; then
    echo "Signed!"
elif [ $? -eq 1 ]; then
    echo "Policy denied - check your limits"
else
    echo "Error occurred"
fi
```

---

## JSON Output Examples

All `sign` commands support `--format json` for machine-readable output.

### Ethereum JSON Output

```bash
txgate ethereum sign 0xf86c... --format json
```

**Success Response:**
```json
{
  "chain": "ethereum",
  "transaction_hash": "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
  "signature": {
    "v": 28,
    "r": "0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0",
    "s": "0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a"
  },
  "signed_transaction": "0xf86c...signed...",
  "signer": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
}
```

### Bitcoin JSON Output

```bash
txgate bitcoin sign 0100000001... --format json
```

**Success Response:**
```json
{
  "chain": "bitcoin",
  "transaction_hash": "abc123...txid...",
  "signature": "304402...der...",
  "signed_transaction": "0100000001...signed...",
  "signer": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
}
```

### Solana JSON Output

```bash
txgate solana sign 0100000001... --format json
```

**Success Response:**
```json
{
  "chain": "solana",
  "transaction_hash": "5WXz...base58...",
  "signature": "5aB3...base58-sig...",
  "signed_transaction": "0100...signed...",
  "signer": "9aE7...base58-pubkey..."
}
```

### Error Response (All Chains)

When a policy denies a transaction:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied: blacklist - recipient address is blacklisted",
    "policy": "blacklist",
    "details": {
      "recipient": "0x0000000000000000000000000000000000000000"
    }
  }
}
```

---

For detailed configuration options, see [Configuration Reference](CONFIGURATION.md).
