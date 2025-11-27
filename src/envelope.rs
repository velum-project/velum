//! src/envelope.rs
//!
//! Binary VELUM v1 envelope format (VLM1) — on-wire representation.
//!
//! This module defines the complete binary message format used in both non-streaming
//! and zero-seek streaming modes. It is deliberately low-level and focused solely on
//! serialization and strict parsing — all cryptographic logic (KEM, CEK derivation,
//! signatures, streaming frames) lives in higher-level modules (`core`, `streaming`, etc.).
//!
//! ### VLM1 Envelope Layout (zero-seek, pipe-friendly)
//!
//! ```text
//! preamble (12 bytes, fixed):
//!   [4]  magic: "VLM1"
//!   [1]  version: 0x01
//!   [1]  flags: bitfield
//!        bit 0 → MSG_FLAG_STREAM     (payload is chunked)
//!        bit 1 → MSG_FLAG_SIGTRAILER (hybrid signature in trailer)
//!   [2]  reserved: 0x0000
//!   [4]  len_hdr: u32 BE length of header-part
//!
//! header-part (variable, len_hdr bytes):
//!   [32] enc_ecdh: ephemeral X25519 public key
//!   [24] nonce: main XChaCha20-Poly1305 nonce
//!   [32] rc: recipient commitment (SHA256 over sorted entry_ids)
//!   [4]  recipients_len: u32 BE
//!   [..] recipients_blob
//!   [4]  sig_len: u32 BE (0 if no header signature)
//!   [..] signature (optional, only in non-streaming or legacy mode)
//!
//! payload:
//!   ct_and_tag: ciphertext || tag (non-streaming: single AEAD)
//!               or chunked frames + optional trailer (streaming)
//! ```
//!
//! The streaming trailer (sentinel + magic + signature) is **not** parsed here —
//! it is handled by the `streaming` and `core` modules.

use crate::constants::{
    MSG_FLAG_SIGTRAILER, MSG_FLAG_STREAM, MSG_MAGIC, MSG_NONCE_LEN, MSG_VERSION, TAG_LEN,
};
use crate::recipients::decode_recipients;

use pqcrypto_mldsa::mldsa65;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey as XPublic;

/// Streaming mode indicator extracted from the `flags` bitfield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamFlag {
    /// Non-streaming: single AEAD over the entire payload.
    No,
    /// Streaming: payload is split into independently encrypted chunks.
    Yes,
}

/// Fully parsed binary VLM1 envelope.
///
/// All fields are validated during parsing (lengths, cryptographic primitives,
/// recipient list integrity, etc.). The payload (`ct_and_tag`) is returned as an
/// opaque blob — decryption and streaming frame handling occur at higher levels.
#[derive(Clone, Debug)]
pub(crate) struct ParsedBinary {
    /// Ephemeral X25519 public key used in the hybrid KEM (32 bytes).
    pub(crate) enc_ecdh: [u8; 32],

    /// Main content nonce for XChaCha20-Poly1305 (24 bytes).
    /// In streaming mode this is bound into AAD but not used directly per chunk.
    pub(crate) nonce: [u8; MSG_NONCE_LEN],

    /// Serialized recipients blob (encoded per-recipient KEM capsules + wrapped CEKs).
    pub(crate) recipients_blob: Vec<u8>,

    /// Ciphertext + authentication tag(s). Layout depends on `stream` flag.
    pub(crate) ct_and_tag: Vec<u8>,

    /// Optional hybrid signature stored in the header.
    /// Usually `None` in streaming mode (signature is in trailer instead).
    pub(crate) signature: Option<Vec<u8>>,

    /// Whether the payload is chunked (streaming mode).
    pub(crate) stream: StreamFlag,

    /// Recipient commitment as stored in the header (used for integrity and binding).
    pub(crate) rc: [u8; 32],

    /// Whether a signature trailer is expected after the payload (streaming mode).
    pub(crate) has_trailer: bool,
}

/// Serializes a complete binary VLM1 envelope.
///
/// Low-level function — assumes all inputs have already been validated and derived
/// by higher-level code (`core`). The `flags` byte must be constructed by the caller
/// (e.g., `MSG_FLAG_STREAM | MSG_FLAG_SIGTRAILER` when appropriate).
///
/// All secret buffers passed by ownership are zeroized before return.
///
/// # Panics
///
/// Panics only if header or field lengths exceed `u32::MAX` (impossible in practice).
pub(crate) fn encode_envelope_binary(
    enc_ecdh: [u8; 32],
    nonce: [u8; MSG_NONCE_LEN],
    mut recipients_blob: Vec<u8>,
    mut ct_and_tag: Vec<u8>,
    mut signature: Option<Vec<u8>>,
    flags: u8,
    rc: [u8; 32],
) -> Vec<u8> {
    use zeroize::Zeroize;

    let sig_len = signature.as_ref().map(|s| s.len()).unwrap_or(0);

    let mut header =
        Vec::with_capacity(32 + MSG_NONCE_LEN + 32 + 4 + recipients_blob.len() + 4 + sig_len);

    header.extend_from_slice(&enc_ecdh);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&rc);

    let recip_len_u32 = u32::try_from(recipients_blob.len()).unwrap_or(u32::MAX);
    header.extend_from_slice(&recip_len_u32.to_be_bytes());
    header.extend_from_slice(&recipients_blob);

    let sig_len_u32 = u32::try_from(sig_len).unwrap_or(u32::MAX);
    header.extend_from_slice(&sig_len_u32.to_be_bytes());
    if let Some(sig) = signature.as_ref() {
        header.extend_from_slice(sig);
    }

    let header_len_u32 = u32::try_from(header.len()).expect("header too large");

    let mut out = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + header.len() + ct_and_tag.len());

    out.extend_from_slice(MSG_MAGIC);
    out.push(MSG_VERSION);
    out.push(flags);
    out.extend_from_slice(&[0u8, 0u8]); // reserved
    out.extend_from_slice(&header_len_u32.to_be_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct_and_tag);

    // Zeroize owned secret material
    recipients_blob.zeroize();
    ct_and_tag.zeroize();
    if let Some(ref mut sig) = signature {
        sig.zeroize();
    }

    out
}

/// Parses and rigorously validates a binary VLM1 envelope.
///
/// Enforces all protocol invariants including:
/// - Constant-time magic and version checks
/// - Reserved field zero
/// - Exact header/payload boundary
/// - Valid X25519 ephemeral key
/// - Well-formed recipients blob
/// - Reasonable signature length (upper bounded)
/// - No trailing garbage in header
///
/// Returns a fully validated [`ParsedBinary`] or `Err(())` on any violation.
///
/// The streaming trailer (if present) is **not** parsed here — only the `has_trailer`
/// flag is set based on the header `flags` field.
pub(crate) fn parse_envelope_binary(bytes: &[u8]) -> Result<ParsedBinary, ()> {
    if bytes.len() < 4 + 1 + 1 + 2 + 4 {
        return Err(());
    }

    let mut off = 0usize;

    // Magic + version (constant-time)
    if !bool::from(bytes[off..off + 4].ct_eq(MSG_MAGIC)) || bytes[off + 4] != MSG_VERSION {
        return Err(());
    }
    off += 5;

    let flags = bytes[off];
    off += 1;

    // Reserved must be zero
    if bytes[off] != 0 || bytes[off + 1] != 0 {
        return Err(());
    }
    off += 2;

    // Header length
    if off + 4 > bytes.len() {
        return Err(());
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&bytes[off..off + 4]);
    off += 4;
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len == 0 || off + header_len > bytes.len() {
        return Err(());
    }

    let header = &bytes[off..off + header_len];
    off += header_len;

    let ct_and_tag = bytes[off..].to_vec();
    if ct_and_tag.len() < TAG_LEN {
        return Err(());
    }

    // Parse header fields
    let mut h_off = 0usize;

    // enc_ecdh
    let mut enc_ecdh = [0u8; 32];
    enc_ecdh.copy_from_slice(&header[h_off..h_off + 32]);
    h_off += 32;

    // nonce
    let mut nonce = [0u8; MSG_NONCE_LEN];
    nonce.copy_from_slice(&header[h_off..h_off + MSG_NONCE_LEN]);
    h_off += MSG_NONCE_LEN;

    // rc
    let mut rc = [0u8; 32];
    rc.copy_from_slice(&header[h_off..h_off + 32]);
    h_off += 32;

    // recipients blob
    let recip_len = u32::from_be_bytes(header[h_off..h_off + 4].try_into().unwrap()) as usize;
    h_off += 4;
    if recip_len == 0 || h_off + recip_len > header.len() {
        return Err(());
    }
    let recipients_blob = header[h_off..h_off + recip_len].to_vec();
    h_off += recip_len;

    // signature (optional)
    let sig_len = u32::from_be_bytes(header[h_off..h_off + 4].try_into().unwrap()) as usize;
    h_off += 4;

    let max_sig_len = mldsa65::signature_bytes() + 64;
    if sig_len as u64 > max_sig_len as u64 {
        return Err(());
    }

    let signature = if sig_len == 0 {
        None
    } else {
        if h_off + sig_len > header.len() {
            return Err(());
        }
        let sig = header[h_off..h_off + sig_len].to_vec();
        h_off += sig_len;
        Some(sig)
    };

    if h_off != header.len() {
        return Err(());
    }

    let stream = if (flags & MSG_FLAG_STREAM) != 0 {
        StreamFlag::Yes
    } else {
        StreamFlag::No
    };
    let has_trailer = (flags & MSG_FLAG_SIGTRAILER) != 0;

    // Cryptographic validation
    let _ = XPublic::from(enc_ecdh);
    decode_recipients(&recipients_blob).map_err(|_| ())?;

    Ok(ParsedBinary {
        enc_ecdh,
        nonce,
        recipients_blob,
        ct_and_tag,
        signature,
        stream,
        rc,
        has_trailer,
    })
}

// ============================================================
// Unit tests for src/envelope.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `envelope.rs`
    //!
    //! These tests exercise the low-level VLM1 binary envelope:
    //! - `encode_envelope_binary`: header + payload construction
    //! - `parse_envelope_binary`: strict validation and field parsing
    //! - flag handling for `stream` and `has_trailer`
    //! - rejection of malformed headers, bad magic/version, and invalid recipients
    //!
    //! Cryptographic operations are not executed here; we only validate structural
    //! and length constraints, plus X25519/recipient-list sanity.

    use super::*;
    use crate::constants::{MSG_FLAG_SIGTRAILER, MSG_FLAG_STREAM, TAG_LEN};
    use crate::recipients::{compute_entry_id, encode_recipients, RecipientEntry};

    // ------------------------------------------------------------
    // Helper generators (deterministic)
    // ------------------------------------------------------------

    fn fixed_arr<const N: usize>() -> [u8; N] {
        let mut arr = [0u8; N];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        arr
    }

    fn dummy_recipients_blob() -> Vec<u8> {
        use pqcrypto_mlkem::mlkem768;

        let enc_pq = vec![0xAA; mlkem768::ciphertext_bytes()];
        let wrap = vec![0xBB; 32 + TAG_LEN];
        let entry_id = compute_entry_id(&enc_pq);
        let entry = RecipientEntry {
            enc_pq,
            wrap,
            entry_id,
            index_hint: 42,
        };
        encode_recipients(&[entry]).unwrap()
    }

    // ------------------------------------------------------------
    // Round-trip tests
    // ------------------------------------------------------------

    #[test]
    fn test_encode_and_parse_roundtrip_non_streaming_no_signature() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0xCC; 64 + TAG_LEN];

        let bin = encode_envelope_binary(
            enc_ecdh,
            nonce,
            recipients_blob.clone(),
            ct_and_tag.clone(),
            None,
            0,
            rc,
        );

        let parsed = parse_envelope_binary(&bin).expect("parse ok");
        assert_eq!(parsed.enc_ecdh, enc_ecdh);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.recipients_blob, recipients_blob);
        assert_eq!(parsed.ct_and_tag, ct_and_tag);
        assert!(parsed.signature.is_none());
        assert_eq!(parsed.stream, StreamFlag::No);
        assert!(!parsed.has_trailer);
    }

    #[test]
    fn test_encode_and_parse_roundtrip_streaming_with_trailer_flag() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0xDD; 128 + TAG_LEN];

        let flags = MSG_FLAG_STREAM | MSG_FLAG_SIGTRAILER;

        let bin = encode_envelope_binary(
            enc_ecdh,
            nonce,
            recipients_blob.clone(),
            ct_and_tag.clone(),
            None,
            flags,
            rc,
        );

        let parsed = parse_envelope_binary(&bin).expect("parse ok");
        assert_eq!(parsed.stream, StreamFlag::Yes);
        assert!(parsed.has_trailer);
        assert_eq!(parsed.ct_and_tag, ct_and_tag);
    }

    // ------------------------------------------------------------
    // Header / magic / structural validation
    // ------------------------------------------------------------

    #[test]
    fn test_parse_rejects_bad_magic() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0xEE; 32 + TAG_LEN];

        let mut bin =
            encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);

        // Corrupt first magic byte
        bin[0] ^= 0xFF;
        assert!(parse_envelope_binary(&bin).is_err());
    }

    #[test]
    fn test_parse_rejects_reserved_nonzero() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0xEF; 32 + TAG_LEN];

        let mut bin =
            encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);

        // reserved is bytes[6..8]; offset: 4 magic + 1 version + 1 flags = index 6
        // MSG layout: [0..3]='VLM1', [4]=version, [5]=flags, [6..8]=reserved
        bin[6] = 1;
        assert!(parse_envelope_binary(&bin).is_err());
    }

    #[test]
    fn test_parse_rejects_header_len_zero_or_truncated() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0xAA; 32 + TAG_LEN];

        let mut bin =
            encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);

        // header_len is at bytes[8..12]
        bin[8] = 0;
        bin[9] = 0;
        bin[10] = 0;
        bin[11] = 0;
        assert!(parse_envelope_binary(&bin).is_err());

        // Truncate buffer so header_len goes past end
        let truncated = &bin[..12];
        assert!(parse_envelope_binary(truncated).is_err());
    }

    #[test]
    fn test_parse_rejects_too_short_ct() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0x01; TAG_LEN - 1]; // shorter than TAG_LEN

        let bin = encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);

        assert!(parse_envelope_binary(&bin).is_err());
    }

    #[test]
    fn test_parse_rejects_invalid_recipients_blob() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();

        // Intentionally invalid blob (will fail decode_recipients)
        let recipients_blob = vec![0x00, 0x01, 0x02];
        let ct_and_tag = vec![0x33; 32 + TAG_LEN];

        let bin = encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);

        assert!(parse_envelope_binary(&bin).is_err());
    }

    #[test]
    fn test_parse_rejects_oversized_signature() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipients_blob();
        let ct_and_tag = vec![0x44; 32 + TAG_LEN];
        let mut bin =
            encode_envelope_binary(enc_ecdh, nonce, recipients_blob, ct_and_tag, None, 0, rc);
        
        // header starts at offset 4+1+1+2+4 = 12
        // We will overwrite sig_len to be absurdly large
        let header_len = {
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&bin[8..12]);
            u32::from_be_bytes(len_buf) as usize
        };
        let header_start = 12;
        let header = &mut bin[header_start..header_start + header_len];

        // walk header: ecdh(32) + nonce + rc(32) + recip_len(4) + recip + sig_len(4) + sig
        let mut h_off = 0usize;
        h_off += 32; // enc_ecdh
        h_off += MSG_NONCE_LEN; // nonce
        h_off += 32; // rc
        let recip_len = u32::from_be_bytes(header[h_off..h_off + 4].try_into().unwrap()) as usize;
        h_off += 4 + recip_len; // recipients
                                // Now at sig_len
        header[h_off] = 0xFF;
        header[h_off + 1] = 0xFF;
        header[h_off + 2] = 0xFF;
        header[h_off + 3] = 0xFF;

        assert!(parse_envelope_binary(&bin).is_err());
    }
}
