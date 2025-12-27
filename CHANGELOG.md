# Changelog

All notable changes to VELUM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Shorter command-line flags for common operations
- `inspect` command for examining encrypted files
- Streaming mode as default for binary format
- Formal protocol specification

---

## [0.1.4] - 2025-12-27

### Fixed
- **Incomplete Fix for Heap Corruption:** Addressed a limitation in the v0.1.3 
  security patch regarding FFI memory management. The previous fix relied on 
  `Vec::shrink_to_fit()`, which is an advisory hint to the allocator and **does 
  not guarantee** that `capacity == len`. Consequently, v0.1.3 remained vulnerable 
  to Undefined Behavior on allocators that ignore the shrink request or align capacity 
  to block sizes. This release replaces the `Vec` handling with `Box<[u8]>` 
  (`into_boxed_slice()`), which enforces a strict memory layout where capacity is 
  structurally irrelevant, completely eliminating the risk of allocator mismatch.

  **Severity:** **CRITICAL**

  **Impact:** The potential for heap corruption and RCE described in v0.1.3 persists 
  in that version.

  **Affected versions:** v0.1.0, v0.1.1, v0.1.2, **v0.1.3**.

  **Recommendation:** All users, including those who updated to v0.1.3, must upgrade 
  to v0.1.4 **immediately**. Developers using the FFI bindings must rebuild their 
  binaries with this version.

---

## [0.1.3] - 2025-12-26

### Fixed
- Fixed a heap corruption vulnerability in the FFI byte-level API 
  (`velum_*_bytes`). Vectors returned to the host application (C/Swift/Kotlin) 
  did not have their capacity synchronized with their length, leading to 
  Undefined Behavior and allocator corruption when freed via `velum_free_bytes`.
  
  **Severity:** **CRITICAL**
  
  **Impact:** Could lead to application crashes (`SIGABRT`) or Remote Code 
  Execution (RCE) in host applications processing untrusted binary data via 
  the FFI byte API. The text-based FFI API (`_string`) was **not** affected.
  
  **Affected versions:** v0.1.0, v0.1.1, v0.1.2
  
  **Recommendation:** All users are strongly advised to upgrade to v0.1.3 
  **immediately**. Developers using the FFI bindings must rebuild their binaries 
  with this version.

---

## [0.1.2] - 2025-12-02

### Fixed
- Fixed signature verification in non-streaming binary mode. Signatures
  were incorrectly reported as invalid even when correct, due to incorrect 
  ciphertext data being passed to the verification function.
  
  **Severity:** Medium  

  **Impact:** Only affected non-streaming binary mode with signatures enabled. 
  Streaming mode and armored format signature verification were unaffected. 
  Encryption and decryption continued to work correctly in all modes. No 
  data compromise or key exposure occurred.
  
  **Affected versions:** v0.1.0, v0.1.1
  
  **Recommendation:** All users should upgrade to v0.1.2, especially if using 
  signature verification with the `--signer-secret` and `--expect-public` flags 
  in non-streaming binary mode.

---

## [0.1.1] - 2025-11-29

### Fixed
- Key validation now happens before encryption/decryption starts, providing 
  faster failure for invalid keys
- Improved error messages for invalid keys and incorrect passphrases

---

## [0.1.0] - 2025-11-27

### Added
- Initial release of VELUM
- Post-quantum hybrid encryption (X25519 + ML-KEM-768)
- Post-quantum hybrid signatures (Ed25519 + ML-DSA-65)
- Multi-recipient encryption with recipient anonymity
- Zero-seek streaming mode for large files
- ASCII-armored and binary (VLM1) wire formats
- Argon2id-based secret key protection
- Command-line interface with `keygen`, `encrypt`, `decrypt`, and `rewrap` commands
- Comprehensive documentation and security policy

### Security Features
- Recipient anonymity via blinded entry identifiers
- O(1) recipient discovery using index hints
- Forward secrecy for sender (ephemeral X25519 keys)
- Authenticated encryption (XChaCha20-Poly1305)
- Hybrid post-quantum construction
- Domain separation for all cryptographic contexts

### Documentation
- Complete README with usage examples
- Detailed SECURITY.md with threat model and cryptographic specification
- Real-world usage examples (backups, file sharing, database backups)
- Comparison table with age and GPG
- Encryption/decryption speed benchmark

---

## Release Notes

### Version Numbering

VELUM follows [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 0.1.2)
- **MAJOR**: Incompatible wire format changes (breaking)
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, backward-compatible

### Pre-1.0 Status

VELUM is currently in **experimental status** (v0.x.x):
- Wire format may change between minor versions
- API is not yet stable
- External security audit pending
- Use at your own risk for production workloads

Version 1.0.0 will indicate:
- Stable wire format (backward compatibility guaranteed)
- External security audit completed
- Production-ready status

---

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for 
responsible disclosure procedures.

**Security Contact:** velum-pq@protonmail.com  
**PGP Fingerprint:** `3720 D73C 646E 1F22 923E  9014 ADC4 2172 FBA8 3645`

---

[Unreleased]: https://github.com/velum-project/velum/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/velum-project/velum/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/velum-project/velum/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/velum-project/velum/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/velum-project/velum/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/velum-project/velum/releases/tag/v0.1.0
