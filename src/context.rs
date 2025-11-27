// context.rs
//
// Shared encryption/decryption context structures used by core, streaming
// and transcript logic. This module is intentionally small to avoid
// cyclic dependencies between higher-level modules.

use crate::constants::MSG_NONCE_LEN;
use crate::envelope::ParsedBinary;
use zeroize::Zeroize;

/// Shared state for an encryption handshake.
///
/// This struct is created by the high-level encryption core and then
/// consumed by:
///   - AEAD logic for non-streaming payloads,
///   - streaming module for chunked payloads,
///   - file-streaming helpers.
///
/// Only the CEK is considered secret here and is wiped on drop.
/// Other fields (nonce, enc_ecdh, RC, recipients_blob) are either
/// public or derivable from the final ciphertext.
pub struct EncryptHandshake {
    /// Whether this message uses streaming payload (stream:Y/N flag in envelope).
    pub(crate) stream_on: bool,

    /// Ephemeral X25519 public key used as `enc_ecdh` in the header.
    pub(crate) enc_ecdh: [u8; 32],

    /// Nonce for the main content AEAD (XChaCha20-Poly1305).
    ///
    /// For stream:N this is the single AEAD nonce over the whole payload.
    /// For stream:Y this is still bound into AAD/transcripts even though
    /// per-chunk nonces are derived from (CEK, RC, chunk_index).
    pub(crate) nonce: [u8; MSG_NONCE_LEN],

    /// Recipient commitment (RC) over all entry_ids.
    pub(crate) rc: [u8; 32],

    /// Serialized recipients blob (encode_recipients entries).
    pub(crate) recipients_blob: Vec<u8>,

    /// Content Encryption Key (CEK) – 32 bytes.
    ///
    /// This is the only secret in this struct and is zeroized on drop.
    /// Access is restricted through the cek() method to prevent accidental exposure.
    cek: [u8; 32],
}

impl EncryptHandshake {
    /// Create a new encryption handshake with the given parameters.
    pub(crate) fn new(
        stream_on: bool,
        enc_ecdh: [u8; 32],
        nonce: [u8; MSG_NONCE_LEN],
        rc: [u8; 32],
        recipients_blob: Vec<u8>,
        cek: [u8; 32],
    ) -> Self {
        Self {
            stream_on,
            enc_ecdh,
            nonce,
            rc,
            recipients_blob,
            cek,
        }
    }

    /// Controlled read-only access to the CEK.
    ///
    /// Returns a reference to prevent accidental copying.
    /// Callers should use this only when absolutely necessary
    /// and must not log, print, or persist the key material.
    pub(crate) fn cek(&self) -> &[u8; 32] {
        &self.cek
    }
}

impl Drop for EncryptHandshake {
    fn drop(&mut self) {
        // Only CEK is secret here; everything else is public metadata.
        self.cek.zeroize();
    }
}

/// Shared decryption context.
///
/// This struct is produced by the decryption core (KEM + unwrap of CEK)
/// and then passed to:
///   - AEAD content decryption (non-streaming and streaming),
///   - signature verification (transcript module),
///   - file-streaming decrypt helpers.
///
/// `ParsedBinary` contains header + payload metadata;
/// `rc` and `cek` are derived during KEM/unwrap.
pub struct DecryptContext {
    /// Fully parsed binary envelope (header + payload metadata).
    pub(crate) parsed: ParsedBinary,

    /// Recipient commitment for this ciphertext.
    pub(crate) rc: [u8; 32],

    /// Content Encryption Key (CEK) recovered from the KEM layer.
    ///
    /// This is the only secret in this struct and is zeroized on drop.
    /// Access is restricted through the cek() method to prevent accidental exposure.
    cek: [u8; 32],
}

impl DecryptContext {
    /// Create a new decryption context.
    pub(crate) fn new(parsed: ParsedBinary, rc: [u8; 32], cek: [u8; 32]) -> Self {
        Self { parsed, rc, cek }
    }

    /// Controlled read-only access to the CEK.
    ///
    /// Returns a reference to prevent accidental copying.
    /// Callers should use this only when absolutely necessary
    /// and must not log, print, or persist the key material.
    pub(crate) fn cek(&self) -> &[u8; 32] {
        &self.cek
    }
}

impl Drop for DecryptContext {
    fn drop(&mut self) {
        self.cek.zeroize();
    }
}
