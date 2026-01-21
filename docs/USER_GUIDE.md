# Sello User Guide

Sello is a secure Ethereum transaction signing daemon that provides policy-based transaction approval with encrypted key storage.

## Table of Contents

- [What is Sello?](#what-is-sello)
- [Why Use Sello?](#why-use-sello)
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

## What is Sello?

Sello is a transaction signing daemon designed for secure, automated signing of Ethereum transactions. It separates key management from application logic, enabling:

- **Isolated key storage**: Private keys never leave the Sello process
- **Policy enforcement**: Define rules for which transactions can be signed
- **Audit logging**: Track all signing operations
- **Unix socket communication**: Secure local IPC without network exposure

## Why Use Sello?

| Use Case | Benefit |
|----------|---------|
| Bot automation | Sign transactions without exposing keys to your bot |
| Multi-sig preparation | Generate signatures for multi-sig wallets |
| Rate limiting | Enforce transaction limits per day/transaction |
| Address restrictions | Whitelist/blacklist recipient addresses |
| Audit compliance | Maintain tamper-evident signing logs |

---

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/sello-project/sello.git
cd sello

# Build and install
cargo install --path crates/sello
```

### From crates.io

```bash
cargo install sello
```

### Verify Installation

```bash
sello --version
```

### System Requirements

- Rust 1.75 or later
- Unix-like operating system (Linux, macOS, WSL)
- ~50MB disk space for keys and logs

---

## Initialization

Initialize Sello to create the configuration directory and generate your first key:

```bash
sello init
```

### What Happens During Init

1. Creates `~/.sello/` directory structure:
   ```
   ~/.sello/
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
sello init --force
```

**Warning**: This overwrites your existing key and configuration.

---

## Key Management

### View Your Address

```bash
sello ethereum address
```

You will be prompted for your passphrase. The output is an EIP-55 checksummed Ethereum address:

```
0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
```

### Key Storage

Keys are stored encrypted at `~/.sello/keys/default.enc` with:

- **Key derivation**: Argon2id (memory-hard, resistant to GPU attacks)
- **Encryption**: ChaCha20-Poly1305 (authenticated encryption)
- **File permissions**: 0600 (owner read/write only)

### Passphrase Requirements

- Minimum 8 characters
- Required for all operations that access the key
- Never stored on disk

---

## Policy Configuration

Sello enforces policies before signing any transaction. Configure policies in `~/.sello/config.toml`.

### Policy Types

| Policy | Description |
|--------|-------------|
| Whitelist | Only allow transactions to specified addresses |
| Blacklist | Deny transactions to specified addresses |
| Transaction Limit | Maximum amount per single transaction |
| Daily Limit | Maximum total amount per 24-hour period |

### Rule Evaluation Order

Policies are evaluated in strict priority order:

1. **Blacklist** (highest priority) - Deny if recipient is blacklisted
2. **Whitelist** - Deny if whitelist enabled and recipient not listed
3. **Transaction Limit** - Deny if amount exceeds per-tx limit
4. **Daily Limit** - Deny if amount would exceed daily total
5. **Allow** - Approve if all checks pass

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

# Daily spending limits (in wei)
[policy.daily_limits]
ETH = "10000000000000000000"  # 10 ETH max per day
```

See [Configuration Reference](CONFIGURATION.md) for all options.

---

## Running the Daemon

### Start the Server

```bash
sello serve
```

Or explicitly run in foreground:

```bash
sello serve --foreground
```

### Server Behavior

1. Prompts for passphrase to unlock the signing key
2. Starts listening on `~/.sello/sello.sock`
3. Handles incoming JSON-RPC requests
4. Enforces policy rules for each signing request
5. Logs all operations to audit log

### Stopping the Server

Press `Ctrl+C` or send `SIGTERM`/`SIGINT` for graceful shutdown.

### Server Output

```
Sello server starting...

Address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
Socket: /home/user/.sello/sello.sock
Audit log: /home/user/.sello/logs/audit.jsonl

Press Ctrl+C to stop the server.
```

---

## Connecting Clients

### Unix Socket Communication

Sello listens on a Unix domain socket at `~/.sello/sello.sock`. This provides:

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
    sock.connect("/home/user/.sello/sello.sock")

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
    let mut stream = UnixStream::connect("/home/user/.sello/sello.sock")
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

Sello implements a JSON-RPC 2.0 API for signing operations.

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

Sello sets secure permissions automatically:
- `~/.sello/` - 0700 (owner only)
- `~/.sello/config.toml` - 0600 (owner read/write)
- `~/.sello/keys/*.enc` - 0600 (owner read/write)

Verify permissions:
```bash
ls -la ~/.sello/
```

### Network Isolation

- Sello uses Unix sockets, not network ports
- No remote access by default
- Never expose the socket over a network

### Policy Configuration

- Start with `whitelist_enabled = true`
- Whitelist only known, trusted addresses
- Set conservative transaction and daily limits
- Review and update policies regularly

### Audit Logging

- Audit logs are written to `~/.sello/logs/audit.jsonl`
- Review logs regularly for unexpected activity
- Back up logs to detect tampering

### Key Backup

- The encrypted key at `~/.sello/keys/default.enc` can be backed up
- Store backups securely (encrypted, offline)
- Remember: backups are useless without the passphrase

---

## Troubleshooting

### Common Issues

#### "Sello is not initialized"

Run `sello init` to create the configuration and key.

#### "Invalid passphrase"

The passphrase you entered does not match the one used to encrypt the key. There is no recovery mechanism - ensure you remember your passphrase.

#### "Passphrase is too short"

Passphrases must be at least 8 characters.

#### "Policy denied: blacklist"

The recipient address is in your blacklist. Edit `~/.sello/config.toml` to remove it.

#### "Policy denied: whitelist"

Whitelist mode is enabled and the recipient is not whitelisted. Either:
- Add the address to the whitelist
- Disable whitelist mode: `whitelist_enabled = false`

#### "Policy denied: tx_limit"

The transaction amount exceeds your configured per-transaction limit. Adjust `[policy.transaction_limits]` in config.

#### "Policy denied: daily_limit"

You have exceeded your daily spending limit. Wait until the next day or adjust `[policy.daily_limits]`.

#### Socket connection refused

Ensure the server is running:
```bash
sello serve
```

Check socket existence:
```bash
ls -la ~/.sello/sello.sock
```

#### Permission denied on socket

Verify you are running as the same user who started the server. The socket is only accessible by its owner.

### Getting Help

```bash
# General help
sello --help

# Command-specific help
sello init --help
sello serve --help
sello ethereum --help
```

### Verbose Output

Increase verbosity for debugging:

```bash
sello -v status      # Info level
sello -vv status     # Debug level
sello -vvv status    # Trace level
```

### Checking Status

```bash
sello status
```

Displays:
- Server status (running/stopped)
- Configured keys
- Active policies
- Recent signing activity

### Viewing Configuration

```bash
# Display current configuration
sello config

# Show config file path
sello config path

# Edit configuration
sello config edit
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `sello init` | Initialize configuration and generate key |
| `sello init --force` | Reinitialize (overwrites existing) |
| `sello status` | Display current status |
| `sello config` | View configuration |
| `sello config edit` | Edit configuration in default editor |
| `sello config path` | Show configuration file path |
| `sello serve` | Start the signing server |
| `sello serve --foreground` | Start server in foreground |
| `sello ethereum address` | Display Ethereum address |
| `sello ethereum sign <TX>` | Sign a transaction |
| `sello ethereum sign <TX> --format json` | Sign with JSON output |

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Increase verbosity (can repeat: -vvv) |
| `-c, --config <PATH>` | Use custom config file |
| `--help` | Show help information |
| `--version` | Show version |

---

For detailed configuration options, see [Configuration Reference](CONFIGURATION.md).
