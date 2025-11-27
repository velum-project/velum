//! src/constants.rs
//!
//! Centralized, immutable constants for the VELUM v1 protocol.
//!
//! This module is the **single source of truth** for all magic values, wire-format identifiers,
//! cryptographic labels, lengths, and bitfield flags used throughout the crate.
//!
//! Using these constants instead of hardcoded literals prevents inconsistencies and greatly
//! simplifies future protocol upgrades (e.g. bumping the version or adding new flags).
//!
//! All values are deliberately `pub(crate)` — they are internal to the crate but shared across
//! modules. They must never be changed without a major protocol version bump.

/// Current protocol and armor format version.
///
/// Appears as `v:1` in all armored blocks (PUBLIC, MESSAGE) and in binary envelope headers.
/// Changing this value constitutes a **hard fork** of the protocol.
pub(crate) const V: &str = "1";

/// Armor boundary markers for public key blocks (PEM-style).
pub(crate) const BEGIN_PUB: &str = "-----BEGIN VELUM PUBLIC KEY-----";
pub(crate) const END_PUB: &str = "-----END VELUM PUBLIC KEY-----";

/// Armor boundary markers for encrypted secret key (keystore) blocks.
pub(crate) const BEGIN_SEC: &str = "-----BEGIN VELUM SECRET KEY-----";
pub(crate) const END_SEC: &str = "-----END VELUM SECRET KEY-----";

/// Armor boundary markers for encrypted message blocks.
pub(crate) const BEGIN_MSG: &str = "-----BEGIN VELUM MESSAGE-----";
pub(crate) const END_MSG: &str = "-----END VELUM MESSAGE-----";

/// Domain separation labels used in transcripts, HKDF derivations, and AAD construction.
///
/// These labels ensure that the same key material cannot be reused across different
/// cryptographic contexts (key separation).
pub(crate) const SIG_LABEL: &[u8] = b"VELUM-v1-SIGN"; // Hybrid signature transcript
pub(crate) const AAD_LABEL: &[u8] = b"VELUM-v1-AAD"; // Content AEAD additional data
pub(crate) const SECRET_AAD_LABEL: &[u8] = b"VELUM-SECRET-v1-AAD"; // Secret keystore AAD

/// HKDF info strings used in multi-recipient key wrapping and commitments.
pub(crate) const RECIPIENTS_COMMIT_LABEL: &[u8] = b"VELUM-v1 recipients";
pub(crate) const WRAP_INFO_LABEL: &[u8] = b"VELUM-v1 KEK";
pub(crate) const WRAP_NONCE_INFO_LABEL: &[u8] = b"VELUM-v1 WRAP NONCE";
pub(crate) const WRAP_AAD_LABEL: &[u8] = b"VELUM-v1 WRAP-AAD";

/// HKDF info string for deriving per-chunk nonces in streaming mode.
pub(crate) const STREAM_NONCE_INFO_LABEL: &[u8] = b"VELUM-v1 STREAM NONCE";

/// Fixed cryptographic parameter sizes (in bytes).
///
/// These values are derived from the underlying primitives:
/// - `SALT_LEN`: Argon2id salt size
/// - `MSG_NONCE_LEN`: XChaCha20-Poly1305 nonce (24 bytes)
/// - `SECRET_NONCE_LEN`: AES-GCM-SIV nonce in secret keystore (12 bytes)
/// - `TAG_LEN`: Poly1305 / GCM authentication tag size (16 bytes)
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const MSG_NONCE_LEN: usize = 24;
pub(crate) const SECRET_NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

/// Magic identifier and version byte for the binary VLM1 envelope format.
///
/// All valid binary messages begin with the four bytes `"VLM1"` followed by version `0x01`.
pub(crate) const MSG_MAGIC: &[u8; 4] = b"VLM1";
pub(crate) const MSG_VERSION: u8 = 0x01;

/// Bitfield flags in the binary envelope preamble (1 byte).
///
/// Currently defined bits:
/// - Bit 0 (`0x01`): `MSG_FLAG_STREAM` — payload is chunked (streaming mode)
/// - Bit 1 (`0x02`): `MSG_FLAG_SIGTRAILER` — hybrid signature is appended as a trailer
///
/// All other bits are reserved and must be zero.
pub(crate) const MSG_FLAG_STREAM: u8 = 0x01;
pub(crate) const MSG_FLAG_SIGTRAILER: u8 = 0x02;

/// Sentinel length value used to mark the end of streaming payload frames.
///
/// Chosen as `0xFFFFFFFF` because it is not a valid chunk length (real chunks are limited
/// to sensible sizes). When this length is encountered, the parser knows to expect the
/// signature trailer.
pub(crate) const TRAILER_SENTINEL_LEN: u32 = 0xFFFF_FFFF;

/// Magic identifier for the streaming signature trailer.
///
/// This 32-byte sequence (padded with null bytes) immediately follows the sentinel length.
/// It unambiguously identifies the beginning of the trailer containing the hybrid signature.
pub(crate) const TRAILER_MAGIC: &[u8; 32] = b"VLM1-SIGTRAILER-STREAM-v1\0\0\0\0\0\0\0";
