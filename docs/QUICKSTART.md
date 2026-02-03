# TxGate Quickstart

Get started with TxGate in under 2 minutes.

## Prerequisites

- Rust toolchain (1.75 or later)
- A terminal with Unix-like environment (Linux, macOS, WSL)

## Install

```bash
# Install from crates.io (when published)
cargo install txgate

# Or build from source
git clone https://github.com/luisjpf/txgate.git
cd txgate
cargo install --path crates/txgate
```

## Initialize

```bash
txgate init
```

You will be prompted to create a passphrase (minimum 8 characters). This passphrase encrypts your signing key.

Example output:
```
Enter a passphrase to encrypt your key:
Confirm your passphrase:

TxGate initialized successfully!

Your Ethereum address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed

Next steps:
  1. Edit configuration: txgate config edit
  2. View status: txgate status
  3. Start server: txgate serve
```

## Get Your Address

```bash
txgate ethereum address
```

Enter your passphrase when prompted. Your Ethereum address (EIP-55 checksummed) will be displayed.

## Sign Your First Transaction

```bash
# Sign a raw transaction (hex-encoded RLP)
txgate ethereum sign 0xf86c0a8502540be400825208944592d8f8d7b001e72cb26a73e4fa1806a51ac79d880de0b6b3a7640000801ba0...
```

The signed transaction is output in hex format, ready to broadcast.

## Start the Daemon (Optional)

For continuous signing via Unix socket:

```bash
txgate serve
```

The server listens at `~/.txgate/txgate.sock` for JSON-RPC requests.

---

## What's Next?

- Read the [User Guide](USER_GUIDE.md) for detailed usage
- See [Configuration](CONFIGURATION.md) for policy setup
- Check `txgate --help` for all commands
