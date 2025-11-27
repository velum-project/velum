# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in VELUM, please report it responsibly:

### Reporting Process

1. **Email:** Send details to [velum-pq@protonmail.com](mailto:velum-pq@protonmail.com)
2. **Encryption:** Use our PGP key for sensitive reports (see below)
3. **Response Time:** We will acknowledge receipt within 48 hours

### What to Include

Please provide:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fixes (if any)
- Your contact information for follow-up

### PGP Key

The PGP key is located in the [VELUM-PGP.asc](./VELUM-PGP.asc) file in the repository.

Fingerprint: `3720 D73C 646E 1F22 923E  9014 ADC4 2172 FBA8 3645`

---

## Protocol Version Support

VELUM v1 protocol (`v:1` in armored messages) is the current and only supported protocol version. All implementations must support v1 messages for compatibility.

---

## Threat Model

### Design Goals

VELUM is designed to protect against:

**Passive Eavesdropping**
- All content is encrypted with authenticated encryption
- Ephemeral keys provide per-message forward secrecy (sender side)

**Active Tampering**
- AEAD provides integrity and authenticity
- All metadata bound via Additional Authenticated Data (AAD)
- Signature verification available for sender authentication

**Quantum Computer Attacks**
- Hybrid construction with NIST-standardized post-quantum algorithms
- Both classical and PQ components must be broken for compromise

**Recipient Identification**
- No plaintext recipient public keys in ciphertext
- Blinded entry identifiers prevent linkability
- Index hints computed with secret ECDH shares

**Chosen-Ciphertext Attacks (IND-CCA2)**
- Proper KEM construction
- AEAD with unique nonces
- Recipient commitment prevents substitution attacks

### Known Limitations

**Not Protected Against:**

**Endpoint Security**
- Malware, keyloggers, or trojan horses on the user's system
- Physical access to unlocked systems
- Memory dumps while keys are in use
- Compromise of the operating system or hardware

**Weak Passphrases**
- Brute-force attacks against weak passphrases
- Dictionary attacks if Argon2id parameters are too low
- Password reuse across multiple systems

**Replay Attacks**
- Messages can be replayed to recipients
- No built-in timestamp or sequence number validation
- Applications should implement their own replay protection if needed

**Traffic Analysis**
- Message sizes are not hidden (padding must be added at application layer)
- Timing of message sends is visible to network observers
- Communication patterns are not obfuscated

**Side-Channel Attacks**
- Cache-timing attacks (depends on underlying crypto libraries)
- Power analysis (not applicable to software-only implementation)
- Acoustic cryptanalysis

**Forward Secrecy (Recipient Side)**
- Compromise of recipient's long-term secret key allows decryption of all past messages
- This is inherent to asynchronous messaging (sender cannot know if recipient's key is compromised)
- Consider key rotation and time-limited key validity for high-security scenarios

### Intentional Design Trade-offs

**Index Hints vs. Perfect Anonymity**
- Index hints are 64-bit deterministic values enabling O(1) recipient discovery
- Same hint appears across multiple messages to the same recipient
- This allows statistical linking: "messages X, Y, Z all went to the same (unknown) recipient"
- **Trade-off:** Performance (fast decryption) vs. perfect unlinkability
- **Mitigation:** Use fresh recipient keys per sender if unlinkability is critical

**Static Long-Term Keys**
- Recipients use the same long-term key for all messages
- Compromise of this key breaks confidentiality of all past messages
- **Trade-off:** Simplicity and asynchronous messaging vs. forward secrecy
- **Mitigation:** Rotate keys periodically, use ephemeral keys for high-value communications

**No Revocation Mechanism**
- Once a public key is distributed, it cannot be revoked
- Compromised keys can still decrypt past messages
- **Trade-off:** Simplicity vs. key lifecycle management
- **Mitigation:** Manual key rotation, out-of-band revocation announcements

---

## Cryptographic Specification

### Algorithms and Parameters

#### Key Encapsulation Mechanism (KEM)

**Hybrid Construction:**
```
ss_combined = ss_x25519 || ss_mlkem768
KEK = HKDF-SHA256(salt=RC, IKM=ss_combined, info=label||entry_id)
```

| Component | Algorithm | Parameters | Security Level |
|-----------|-----------|------------|----------------|
| Classical | X25519 | Curve25519 ECDH | ~128-bit |
| Post-Quantum | ML-KEM-768 (Kyber) | NIST Level 3 | ~192-bit |
| KDF | HKDF-SHA256 | 32-byte output | 256-bit |

**Security Properties:**
- IND-CCA2 secure under hybrid assumption
- Both components must be broken for compromise
- Each recipient has independent KEK derived from shared secrets

#### Digital Signatures

**Hybrid Construction:**
```
signature = sig_mldsa65 || sig_ed25519
verify(message) = verify_mldsa65(message) AND verify_ed25519(message)
```

| Component | Algorithm | Signature Size | Security Level |
|-----------|-----------|----------------|----------------|
| Post-Quantum | ML-DSA-65 (Dilithium3) | ~3,309 bytes | NIST Level 3 (~192-bit) |
| Classical | Ed25519 | 64 bytes | ~128-bit |

**Security Properties:**
- EUF-CMA secure under hybrid assumption
- Both signatures must verify for acceptance
- Constant-time verification using `subtle` crate

#### Authenticated Encryption

**Content Encryption:**

| Usage | Algorithm | Key Size | Nonce Size | Tag Size |
|-------|-----------|----------|------------|----------|
| Message Content | XChaCha20-Poly1305 | 32 bytes | 24 bytes | 16 bytes |
| Secret Keystore | AES-256-GCM-SIV | 32 bytes | 12 bytes | 16 bytes |

**XChaCha20-Poly1305:**
- AEAD with extended nonce space
- Nonces randomly generated per message
- Additional Authenticated Data (AAD) binds metadata

**AES-256-GCM-SIV:**
- Nonce-misuse resistant AEAD
- Used for secret keystores to protect against accidental nonce reuse
- Deterministic nonce derivation safe

#### Key Derivation

**Password-Based Key Derivation:**

| Parameter | Default | Minimum (Secure) | Algorithmic Minimum |
|-----------|---------|------------------|---------------------|
| Algorithm | Argon2id v0x13 | - | - |
| Memory (m_cost) | 96 MiB | 15 MiB | 8 KiB |
| Iterations (t_cost) | 4 | 2 | 1 |
| Parallelism | 4 | 1 | 1 |
| Output Length | 32 bytes | 32 bytes | 32 bytes |

**HKDF-SHA256:**
- Extract-and-expand key derivation
- Used for KEK, wrap nonces, and streaming nonces
- Proper domain separation via info strings

### Domain Separation Labels

All cryptographic contexts use explicit labels to prevent cross-protocol attacks:

```rust
SIG_LABEL                = "VELUM-v1-SIGN"
AAD_LABEL                = "VELUM-v1-AAD"
SECRET_AAD_LABEL         = "VELUM-SECRET-v1-AAD"
RECIPIENTS_COMMIT_LABEL  = "VELUM-v1 recipients"
WRAP_INFO_LABEL          = "VELUM-v1 KEK"
WRAP_NONCE_INFO_LABEL    = "VELUM-v1 WRAP NONCE"
WRAP_AAD_LABEL           = "VELUM-v1 WRAP-AAD"
STREAM_NONCE_INFO_LABEL  = "VELUM-v1 STREAM NONCE"
```

### Recipient Commitment (RC)

The recipient commitment binds all recipients to the ciphertext:

```
entry_id[i] = SHA256(enc_pq[i])
RC = SHA256("VELUM-v1 recipients" || sort(entry_ids))
```

**Properties:**
- Order-independent (sorted before hashing)
- Used as HKDF salt for KEK derivation
- Prevents recipient substitution attacks

### Additional Authenticated Data (AAD)

**Content AEAD:**
```
AAD = "VELUM-v1-AAD\n"
    + "v:1\n"
    + "stream:N/Y\n"
    + "enc_ecdh:<base64>\n"
    + "nonce:<base64>\n"
    + "recipients:<base64>\n"
```

**Secret Keystore AEAD:**
```
AAD = "VELUM-SECRET-v1-AAD\n"
    + "v:1\n"
    + "kdf:Argon2id\n"
    + "kdf_v:0x13\n"
    + "m_cost_kib:<value>\n"
    + "t_cost:<value>\n"
    + "parallelism:<value>\n"
    + "salt:<base64>\n"
    + "nonce:<base64>"
```

**Properties:**
- Binds all public metadata to ciphertext
- Prevents header manipulation
- Tested in: `test_decrypt_rejects_recipients_grafting`

---

## Implementation Security

### Memory Safety

**Zeroization:**
- All secret key material is zeroized on drop using `zeroize` crate
- Temporary secrets wrapped in `Zeroizing<T>` containers
- Automatic cleanup even on panic paths

**No Unsafe Code:**
- Library core is 100% safe Rust (no `unsafe` blocks except FFI boundary)
- Memory safety guaranteed by Rust compiler
- Bounds checking enforced

**Constant-Time Operations:**
- Magic/version checks use `subtle::ConstantTimeEq`
- Signature verification uses `subtle::Choice`
- Prevents timing side-channels in critical paths

### Error Handling

**Fail-Safe Design:**
- All errors return `Result<T, ()>` (no panics in library)
- Invalid inputs rejected early
- No partial decryption or signature verification

**FFI Panic Safety:**
- All FFI functions wrapped in panic catcher
- Panics converted to error codes
- No undefined behavior across FFI boundary

### Input Validation

**Strict Parsing:**
- All armored formats validated with constant-time comparison
- Binary envelope magic/version checked
- Reserved fields must be zero
- Length fields bounds-checked before allocation
- No trailing data tolerated

**Cryptographic Validation:**
- X25519 public keys validated as curve points
- ML-KEM/ML-DSA keys validated by crypto library
- Signature lengths checked against expected values
- Recipient blob integrity verified (entry_id recomputation)

---

## Operational Security

### Key Management Best Practices

**Secret Key Storage:**
- Store on encrypted filesystem (FileVault, LUKS, BitLocker)
- Use restrictive file permissions: `chmod 600 identity.sec`
- Consider hardware security modules (HSM) for high-value keys
- Never email or transmit secret keys unencrypted

**Passphrase Guidelines:**
- Minimum 20 characters recommended
- Use high-entropy passphrases (diceware, password managers)
- Never reuse passphrases across systems
- Consider using hardware tokens (YubiKey) for additional protection

**Key Rotation:**
- Rotate keys annually or after suspected compromise
- Generate new keypair and re-encrypt sensitive data
- Securely destroy old keys (e.g., `shred -n 7 old_key.sec`)

**Backup Strategy:**
- Maintain encrypted backups of secret keys
- Store backups offline (air-gapped storage, safety deposit box)
- Test backup restoration procedure regularly
- Document recovery process

### Argon2id Tuning

**Recommended Configurations:**

| Environment | Memory | Iterations | Parallelism | Unlock Time (approx) |
|-------------|--------|------------|-------------|----------------------|
| **High Security** | 128 MiB | 5 | 4 | ~300 ms |
| **Default** | 96 MiB | 4 | 4 | ~270 ms |
| **Mobile** | 64 MiB | 3 | 2 | ~150 ms |
| **Minimum Secure** | 15 MiB | 2 | 1 | ~50 ms |

**Tuning Guidelines:**
- Increase memory cost if system allows (limits parallelization of attacks)
- Balance security with usability (unlock time should be acceptable)
- Never use parameters below OWASP recommendations (15 MiB, 2 iterations)
- Document parameter choices in your threat model

### Secure Usage Patterns

**DO:**
```bash
# Use environment variables to avoid shell history
export VELUM_PASS="your-passphrase"
velum decrypt -i file.velum --secret key.sec

# Pipe sensitive data (no temporary files)
tar czf - secrets/ | velum encrypt -r key.pub > backup.velum

# Verify signatures when trust matters
velum decrypt -i message.velum --secret key.sec --expect-public signer.pub

# Use streaming for large files
velum encrypt -i bigfile.bin --stream -r key.pub
```

**DON'T:**
```bash
# Never put passphrases in command line
velum keygen --pass "my-password"  # Visible in process list!

# Don't create unencrypted temporary files
tar xzf archive.tar.gz
velum encrypt -i extracted/ ...  # Files exposed!

# Don't ignore signature verification failures
velum decrypt ... 2>/dev/null  # Might miss "[sig] INVALID"

# Don't lower Argon2id below secure minimums
velum rewrap --m-mib 8 --t-cost 1  # Weak against brute-force!
```

---

## Audit History

### External Audits

*No external audits completed yet.*

**Audit Commitment:**
We are committed to obtaining third-party security audits. If you are a security auditing firm interested in reviewing VELUM, please contact us at [velum-pq@protonmail.com](mailto:velum-pq@protonmail.com).

---

## Security Update Policy

### Vulnerability Response Timeline

| Severity | Response Time | Patch Target | Disclosure |
|----------|---------------|--------------|------------|
| **Critical** | 24 hours | 7 days | After patch |
| **High** | 48 hours | 14 days | After patch |
| **Medium** | 1 week | 30 days | After patch |
| **Low** | 2 weeks | 90 days | After patch |

### Severity Ratings

**Critical:**
- Remote code execution
- Private key extraction
- Complete cryptographic break
- Bypass of all security measures

**High:**
- Authentication bypass
- Significant data disclosure
- Partial cryptographic weakness
- Privilege escalation

**Medium:**
- Information disclosure (limited impact)
- Denial of service (requires local access)
- Side-channel attacks (high complexity)

**Low:**
- Minor information leaks
- Edge-case vulnerabilities
- Theoretical attacks with no practical exploit

---

## Compliance and Standards

### Cryptographic Standards

VELUM implements algorithms from:
- **NIST FIPS 180-4** - SHA-256
- **NIST FIPS 202** - SHA-3 (for ML-KEM/ML-DSA)
- **RFC 7539** - ChaCha20 and Poly1305
- **RFC 8439** - ChaCha20-Poly1305 AEAD
- **RFC 5869** - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 9106** - Argon2 Memory-Hard Function
- **NIST SP 800-56A** - Key Establishment (ECDH)
- **NIST PQC Standards** - ML-KEM-768, ML-DSA-65 (final standards pending)

### Best Practice Adherence

- OWASP Password Storage Cheat Sheet
- NIST SP 800-38D (GCM mode)
- NIST SP 800-108 (Key derivation)
- RFC 9180 (HPKE) - similar hybrid construction patterns

---

## Known Issues and Mitigations

### 1. Index Hint Linkability

**Issue:**
Index hints allow statistical linking of messages to the same (unknown) recipient across multiple observations.

**Impact:**
An attacker observing multiple encrypted messages can determine that messages X, Y, and Z were all sent to the same recipient, without knowing who that recipient is.

**Mitigation:**
- Use fresh recipient keys per sender if unlinkability is critical
- Accept performance trade-off for perfect anonymity (requires trying all recipients)
- Document limitation clearly to users

**Status:** By design (documented trade-off)

### 2. Long-Term Key Compromise

**Issue:**
Compromise of a recipient's long-term secret key allows decryption of all past messages.

**Impact:**
No forward secrecy on the recipient side. If an attacker obtains the secret key, they can decrypt historical ciphertexts.

**Mitigation:**
- Rotate keys periodically (e.g., annually)
- Use time-limited key validity periods
- Consider ephemeral recipient keys for high-value communications
- Use secure deletion for old ciphertexts after decryption

**Status:** Inherent to asynchronous messaging without recipient key rotation

### 3. No Built-in Replay Protection

**Issue:**
VELUM does not include timestamps or sequence numbers in the protocol.

**Impact:**
Messages can be replayed to recipients. An attacker can resend old valid messages.

**Mitigation:**
- Implement replay protection at the application layer
- Include timestamps in plaintext if needed
- Use nonce tracking or sequence numbers in your protocol
- Combine with transport-layer security (TLS)

**Status:** Intentional (keeps protocol simple)

### 4. No Key Revocation Mechanism

**Issue:**
Once a public key is distributed, there is no built-in mechanism to revoke it.

**Impact:**
Compromised keys cannot be automatically invalidated. Senders must be notified out-of-band.

**Mitigation:**
- Distribute updated keys through secure channels
- Maintain a trusted key directory with version tracking
- Use short-lived keys (e.g., monthly rotation)
- Publish revocation notices via alternative channels

**Status:** Intentional (simplicity over key management complexity)

---

## Security Checklist for Deployments

### Before Production Use

- [ ] Review threat model and ensure it matches your use case
- [ ] Verify Argon2id parameters are appropriate for your environment
- [ ] Test key backup and recovery procedures
- [ ] Configure secure key storage (encrypted filesystem, restrictive permissions)
- [ ] Document your security assumptions and limitations
- [ ] Train users on secure passphrase practices
- [ ] Establish key rotation schedule
- [ ] Set up monitoring for security advisories
- [ ] Consider third-party security audit
- [ ] Implement application-layer protections (replay, timestamps) if needed

### Operational Security

- [ ] Monitor for security updates and apply promptly
- [ ] Audit key usage and access logs
- [ ] Review and test incident response procedures
- [ ] Maintain offline backups of critical keys
- [ ] Document key lifecycle (generation, rotation, retirement)
- [ ] Establish secure key distribution channels
- [ ] Train users to recognize phishing and social engineering
- [ ] Implement least-privilege access to secret keys
- [ ] Use hardware security modules (HSM) for high-value keys
- [ ] Conduct regular security training for operators

---

## Responsible Disclosure Hall of Fame

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities:

*No vulnerabilities disclosed yet.*

---

## Contact

**Email:** [velum-pq@protonmail.com](mailto:velum-pq@protonmail.com)  
**PGP Key:** See above  
**Response Time:** Within 48 hours  
**Bug Bounty:** Not currently offered  

---

*Last Updated: November 26, 2025*  
*Document Version: 1.0*
