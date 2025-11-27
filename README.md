# VELUM

**A post-quantum command-line encryption tool with recipient anonymity and zero-seek streaming.**

**Experimental and unaudited cryptographic software.**
**Use at your own risk.**

[![License: ](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)


```bash
# Generate a keypair
velum keygen --out-pub key.pub --out-sec key.sec

# Encrypt a file for multiple recipients
velum encrypt -i document.pdf -o document.pdf.velum \
  -r alice.pub -r bob.pub -r carol.pub

# Decrypt (automatically detects format)
velum decrypt -i document.pdf.velum -o document.pdf --secret key.sec

# Stream large files with constant memory
velum encrypt -i bigfile.tar.gz -o bigfile.tar.gz.velum \
  -r recipient.pub --stream
```

---

## What is VELUM?

VELUM is a command-line encryption tool designed for the post-quantum era. It combines the simplicity of tools like [age](https://github.com/FiloSottile/age) with post-quantum cryptography and advanced features like recipient anonymity and zero-seek streaming.

### Why VELUM?

**Post-Quantum Security**
- Post-quantum resistant encryption using NIST-standardized algorithms
- Hybrid construction: X25519 + ML-KEM-768 (Kyber)
- Hybrid signatures: Ed25519 + ML-DSA-65 (Dilithium3)

**Recipient Anonymity**
- No metadata about who can decrypt
- Recipients are unlinkable to observers
- Fast O(1) recipient discovery for decryptors

**Zero-Seek Streaming**
- Encrypt/decrypt files of any size with constant memory
- Works with pipes: `tar c bigdir | velum encrypt -r key.pub > backup.velum`
- No temporary files needed

**Simple & Secure**
- One command to encrypt, one to decrypt
- Automatic format detection
- Secure passphrase handling
- Progress bars with throughput stats

---

## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/velum-project/velum/releases):

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/velum-project/velum/releases/latest/download/velum-macos-aarch64
chmod +x velum-macos-aarch64
sudo mv velum-macos-aarch64 /usr/local/bin/velum

# macOS (Intel)
curl -LO https://github.com/velum-project/velum/releases/latest/download/velum-macos-x86_64
chmod +x velum-macos-x86_64
sudo mv velum-macos-x86_64 /usr/local/bin/velum
```

### From Source

Requires Rust 1.70 or later:

```bash
git clone https://github.com/velum-project/velum.git
cd velum
cargo build --release
sudo cp target/release/velum /usr/local/bin/
```

---

## Quick Start

### 1. Generate Your Keypair

```bash
velum keygen --out-pub ~/.velum/identity.pub --out-sec ~/.velum/identity.sec
```

You'll be prompted for a passphrase to protect your secret key. This uses Argon2id with secure defaults (96 MiB memory, 4 iterations).

**Share `identity.pub` with anyone who wants to send you encrypted files.**  
**Keep `identity.sec` secret and backed up!**

### 2. Encrypt a File

```bash
# Encrypt for one recipient
velum encrypt -i secrets.txt -o secrets.txt.velum -r alice.pub

# Encrypt for multiple recipients (anyone can decrypt)
velum encrypt -i document.pdf -o document.pdf.velum \
  -r alice.pub -r bob.pub -r carol.pub

# Encrypt from stdin to stdout
echo "secret message" | velum encrypt -r key.pub > message.velum
```

### 3. Decrypt a File

```bash
# Basic decryption
velum decrypt -i secrets.txt.velum -o secrets.txt --secret identity.sec

# Decrypt from stdin to stdout
cat message.velum | velum decrypt --secret identity.sec

# Auto-detects format (armored text or binary)
velum decrypt -i message.velum --secret identity.sec
```

### 4. Sign and Verify

```bash
# Sign while encrypting
velum encrypt -i document.pdf -o document.pdf.velum \
  -r recipient.pub \
  --signer-secret signer.sec

# Verify signature while decrypting
velum decrypt -i document.pdf.velum -o document.pdf \
  --secret recipient.sec \
  --expect-public signer.pub

# Output:
# [sig] VERIFIED
```

---

## Usage Guide

### Key Generation

```bash
# Interactive (prompts for passphrase)
velum keygen --out-pub key.pub --out-sec key.sec

# With passphrase from environment
export VELUM_PASS="my-secure-passphrase"
velum keygen --out-pub key.pub --out-sec key.sec

# Output to stdout
velum keygen > keys.txt
```

### Encryption

```bash
# Basic file encryption
velum encrypt -i file.txt -o file.txt.velum -r recipient.pub

# Multiple recipients
velum encrypt -i file.txt -o file.txt.velum \
  -r alice.pub -r bob.pub -r carol.pub

# Streaming mode (for large files)
velum encrypt -i bigfile.tar.gz -o bigfile.tar.gz.velum \
  -r recipient.pub --stream

# Custom chunk size (default: 4 MiB)
velum encrypt -i file.bin -o file.bin.velum \
  -r recipient.pub --stream --chunk-size 1048576  # 1 MiB

# ASCII-armored output (non-streaming only)
velum encrypt -i message.txt -o message.txt.velum \
  -r recipient.pub --armor

# Sign the message
velum encrypt -i file.txt -o file.txt.velum \
  -r recipient.pub \
  --signer-secret signer.sec --signer-pass "passphrase"

# Pipe usage
tar czf - /path/to/dir | velum encrypt -r backup.pub > backup.tar.gz.velum
```

### Decryption

```bash
# Basic decryption
velum decrypt -i file.velum -o file.txt --secret identity.sec

# With passphrase from environment
export VELUM_PASS="my-passphrase"
velum decrypt -i file.velum -o file.txt --secret identity.sec

# Verify signature
velum decrypt -i file.velum -o file.txt \
  --secret recipient.sec \
  --expect-public signer.pub

# Auto-detect format (default behavior)
velum decrypt -i message.velum --secret identity.sec

# Force format interpretation
velum decrypt -i message --secret identity.sec --binary-input
velum decrypt -i message --secret identity.sec --armor-input

# Pipe usage
cat backup.tar.gz.velum | velum decrypt --secret backup.sec | tar xzf -
```

### Password Management

```bash
# Change passphrase (keeps same keys)
velum rewrap --input-secret identity.sec --output identity_new.sec

# Increase security (more memory/iterations)
velum rewrap --input-secret identity.sec --output identity_new.sec \
  --m-mib 128 --t-cost 5

# Decrease security (faster, less secure - not recommended)
velum rewrap --input-secret identity.sec --output identity_new.sec \
  --m-mib 64 --t-cost 3
```

---

## Real-World Examples

### Backup to Cloud Storage

```bash
# Encrypt directory before uploading
tar czf - ~/Documents | \
  velum encrypt -r backup.pub --stream > \
  documents_$(date +%Y%m%d).tar.gz.velum

# Upload to S3/cloud storage
aws s3 cp documents_20250126.tar.gz.velum s3://my-backups/

# Restore later
aws s3 cp s3://my-backups/documents_20250126.tar.gz.velum - | \
  velum decrypt --secret backup.sec | \
  tar xzf - -C ~/Restored
```

### Secure File Sharing

```bash
# Alice encrypts for Bob and Carol
velum encrypt -i report.pdf -o report.pdf.velum \
  -r bob.pub -r carol.pub \
  --signer-secret alice.sec

# Bob decrypts and verifies Alice's signature
velum decrypt -i report.pdf.velum -o report.pdf \
  --secret bob.sec \
  --expect-public alice.pub
# Output: [sig] VERIFIED
```

### Database Backups

```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
pg_dump mydb | gzip | \
  velum encrypt -r backup.pub --stream > \
  "/backups/mydb_${DATE}.sql.gz.velum"

# Restore
velum decrypt -i mydb_20250126.sql.gz.velum --secret backup.sec | \
  gunzip | psql mydb
```

### Encrypted Git Repository

```bash
# Encrypt before committing sensitive config
velum encrypt -i config.yaml -o config.yaml.velum -r team.pub
git add config.yaml.velum
git commit -m "Add encrypted config"

# Decrypt in production
velum decrypt -i config.yaml.velum -o config.yaml --secret prod.sec
```

---

## Format Specifications

VELUM supports two wire formats that are **automatically detected**:

### ASCII-Armored (Text)

Human-readable, copy-pasteable format:

```
-----BEGIN VELUM MESSAGE-----
v:1
enc_ecdh:kH8p2vGxN...
nonce:mJ7FqR...
recipients:wK3nP...
ct:xR2vN...
signature:pQ8mL...
-----END VELUM MESSAGE-----
```

**When to use:**
- Embedding in emails or documents
- Storing in text-based systems
- Copy-paste scenarios

### Binary (VLM1)

Compact binary format for efficient storage:

```
VLM1 [version] [flags] [header_len]
[ephemeral_key] [nonce] [commitment]
[recipients] [signature]
[ciphertext+tag or chunked frames]
```

**When to use:**
- File encryption (default for `--stream`)
- Network protocols
- Space-constrained environments

---

## Performance

### Benchmarks (Apple M1 Pro)

| Operation | Time | Throughput |
|-----------|------|------------|
| Key Generation | ~230 ms | - |
| Encrypt (1 MB, 1 recipient, unsigned) | - | 214 MB/s |
| Decrypt (1 MB, 1 recipient, unsigned) | - | 202 MB/s |
| Encrypt (1 MB, 1 recipient, signed) | - | 109 MB/s |
| Decrypt (1 MB, 1 recipient, signed) | - | 118 MB/s |

*Key generation is intentionally slow due to Argon2id (memory-hard password hashing)*

### Memory Usage

```bash
# Non-streaming: 2× file size in memory
velum encrypt -i 1GB.bin -o 1GB.bin.velum -r key.pub
# Memory: ~2 GB

# Streaming: constant memory regardless of file size
velum encrypt -i 1GB.bin -o 1GB.bin.velum -r key.pub --stream
# Memory: ~6.5 MB (chunk size + 2.5 MB overhead)
```

### Recommendations

**Streaming vs. Non-Streaming:**
- Use `--stream` for files > 100 MB
- Use `--stream` when piping or working with unknown sizes
- Skip `--stream` for small files (faster, can use `--armor`)

**Chunk Size Selection:**
- **64 KiB** - Network streaming, low latency
- **1 MiB** - Balanced for most use cases
- **4 MiB** - Default, best throughput (recommended)

---

## Security

### Cryptographic Primitives

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| KEM (Classical) | X25519 | ~128-bit |
| KEM (Post-Quantum) | ML-KEM-768 (Kyber) | NIST Level 3 (~192-bit) |
| Signature (Classical) | Ed25519 | ~128-bit |
| Signature (Post-Quantum) | ML-DSA-65 (Dilithium3) | NIST Level 3 (~192-bit) |
| Content Encryption | XChaCha20-Poly1305 | 256-bit |
| Keystore Encryption | AES-256-GCM-SIV | 256-bit |
| Password Hashing | Argon2id | Configurable |

### Key Security Practices

**✅ DO:**
- Use strong passphrases (≥20 characters, high entropy)
- Keep secret keys on encrypted storage
- Back up your secret key securely
- Use `--stream` for large files
- Verify signatures with `--expect-public` when trust matters

**❌ DON'T:**
- Share your secret key (only share `.pub` files)
- Use weak passphrases
- Store passphrases in shell history (use `VELUM_PASS` or prompts)
- Encrypt to more than ~10 recipients (performance degradation)
- Lower Argon2id parameters below defaults

### Threat Model

**Protected Against:**
- Quantum computer attacks (via post-quantum algorithms)
- Passive eavesdropping
- Active message tampering
- Recipient identification by observers
- Chosen-ciphertext attacks

**Not Protected Against:**
- Endpoint compromise (malware, keyloggers)
- Weak passphrases (brute-force attacks)
- Replay attacks (add timestamps at application level)
- Side-channel attacks on the host system

**Known Trade-offs:**
- Index hints enable statistical recipient linking across multiple messages (performance vs. perfect anonymity)
- Static long-term keys (compromise breaks past message confidentiality)

See [SECURITY.md](SECURITY.md) for detailed security documentation.

---

## Comparison with Other Tools

| Feature | VELUM | age | GPG |
|---------|-------|-----|-----|
| **Post-Quantum** | ✅ | ❌ | ❌ |
| **Recipient Anonymity** | ✅ | ❌ | ❌ |
| **Multi-Recipient** | ✅ | ✅ | ✅ |
| **Streaming** | ✅ | ✅ | ❌ |
| **Signatures** | ✅ | ❌ | ✅ |
| **ASCII Armor** | ✅ | ✅ | ✅ |
| **Simplicity** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |

---

## Advanced Usage

### Environment Variables

```bash
# Skip passphrase prompts
export VELUM_PASS="my-passphrase"
velum decrypt -i file.velum --secret identity.sec

# For signing operations
export VELUM_SIGN_PASS="signer-passphrase"
velum encrypt -i file.txt -r key.pub --signer-secret signer.sec
```

### Custom Argon2id Parameters

```bash
# High security (slow, 128 MiB memory)
velum rewrap --input-secret identity.sec --output identity_strong.sec \
  --m-mib 128 --t-cost 5 --parallelism 4

# Fast unlock (less secure, 32 MiB memory)
velum rewrap --input-secret identity.sec --output identity_fast.sec \
  --m-mib 32 --t-cost 2 --parallelism 2
```

### Many Recipients

```bash
# Default limit: 512 recipients
velum encrypt -i file.txt -o file.velum -r recipient*.pub

# Override limit (not recommended - performance impact)
velum encrypt -i file.txt -o file.velum -r recipient*.pub \
  --allow-many-recipients
```

### Progress Reporting

Progress bars are shown automatically for streaming encryption/decryption.

Example output:
```
[enc] 45.2% | 452.0 MB / 1000.0 MB | 125.3 MB/s | ETA: 4s
```

Disable by redirecting stderr:
```bash
velum encrypt -i file.bin --stream 2>/dev/null
```

---

## Troubleshooting

### "Decryption failed"

**Possible causes:**
1. Wrong passphrase
2. Corrupted ciphertext
3. Not a valid recipient

**Solutions:**
```bash
# Verify your passphrase works
velum rewrap --input-secret identity.sec --output /dev/null

# Check file integrity
sha256sum message.velum

# Verify you're in the recipient list (should succeed if you are)
velum decrypt -i message.velum --secret identity.sec > /dev/null
```

### "Signature verification failed"

**Possible causes:**
1. Message was tampered with
2. Wrong public key provided

**Solutions:**
```bash
# Try without signature verification
velum decrypt -i message.velum --secret identity.sec

# Check if signature is present
grep -q "signature:" message.velum && echo "Has signature" || echo "No signature"
```

### Out of Memory

**For large files:**
```bash
# Use streaming mode
velum encrypt -i largefile.bin -o largefile.velum \
  -r key.pub --stream

# Reduce chunk size
velum encrypt -i largefile.bin -o largefile.velum \
  -r key.pub --stream --chunk-size 1048576  # 1 MiB
```

### Broken Pipe

When piping to commands that exit early (like `head`), you may see:
```
Error: Broken pipe (os error 32)
```

This is **expected behavior** and indicates the receiving process closed the pipe. The data up to that point was successfully transmitted.

---

## Integration

### Shell Scripts

```bash
#!/bin/bash
set -euo pipefail

# Configuration
RECIPIENT_KEY="/path/to/recipient.pub"
SIGNER_KEY="/path/to/signer.sec"

# Encrypt all .txt files in a directory
for file in /data/*.txt; do
    velum encrypt -i "$file" -o "${file}.velum" \
        -r "$RECIPIENT_KEY" \
        --signer-secret "$SIGNER_KEY"
done
```

### Systemd Backup Service

```ini
# /etc/systemd/system/velum-backup.service
[Unit]
Description=Daily encrypted backup with VELUM
After=network.target

[Service]
Type=oneshot
Environment=VELUM_PASS=your-passphrase
ExecStart=/usr/local/bin/backup.sh

[Install]
WantedBy=multi-user.target
```

### Library Integration

VELUM can also be used as a Rust library:

```toml
[dependencies]
velum = "0.1.0"
```

```rust
use velum::{generate_keypair, encrypt, decrypt};

let (public, secret) = generate_keypair("passphrase")?;
let ciphertext = encrypt(b"data", &public, None)?;
let (plaintext, _) = decrypt(&ciphertext, &secret, "passphrase", None)?;
```

---

## Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo
- Git

### Build

```bash
# Clone repository
git clone https://github.com/velum-project/velum.git
cd velum

# Build release binary
cargo build --release

# Install locally
cargo install --path .

# Run tests
cargo test

# Run with optimizations for your CPU
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Cross-Compilation

```bash
# Linux → Windows
cargo build --release --target x86_64-pc-windows-gnu

# Linux → macOS (requires osxcross)
cargo build --release --target x86_64-apple-darwin

# Using cross
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
```

---

## License

VELUM is licensed under the [Apache 2.0 License](LICENSE).

---

## Acknowledgments

VELUM builds on excellent cryptographic libraries:

- **[pqcrypto](https://github.com/rustpq/pqcrypto)** - Post-quantum primitives
- **[RustCrypto](https://github.com/RustCrypto)** - Pure Rust cryptography
- **[dalek-cryptography](https://github.com/dalek-cryptography)** - Curve25519 & Ed25519
- **[Argon2](https://github.com/P-H-C/phc-winner-argon2)** - Password hashing

Special thanks to:
- The NIST Post-Quantum Cryptography standardization project
- The [age](https://github.com/FiloSottile/age) project for inspiration
- All contributors and security researchers

---

## Contact

**Email:** velum-pq@protonmail.com

**PGP Fingerprint:**  
`3720 D73C 646E 1F22 923E  9014 ADC4 2172 FBA8 3645`

[PGP Public Key](./VELUM-PGP.asc)

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for reporting procedures.

---
