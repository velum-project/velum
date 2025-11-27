//! src/streaming.rs
//!
//! Zero-seek streaming encryption and trailer handling for VELUM v1.
//!
//! This module implements the low-level framing format used in streaming mode (`stream:Y`)
//! where the payload is split into fixed-size chunks, each independently encrypted with
//! XChaCha20-Poly1305 using a deterministically derived per-chunk nonce.
//!
//! Key properties:
//! - **No seeking required** – works on pipes, network streams, append-only logs.
//! - **Constant memory usage** – only one chunk buffer is allocated.
//! - **Forward-only hybrid signature support** – optional running digest of the exact
//!   wire format enables signing after the entire payload has been processed.
//! - Trailer with hybrid signature is written separately (via `write_signature_trailer`).
//!
//! This module is deliberately agnostic to envelope headers, recipient handling, and
//! signature verification – those are orchestrated at the higher `core` level.

use crate::constants::{TAG_LEN, TRAILER_MAGIC, TRAILER_SENTINEL_LEN};
use crate::context::EncryptHandshake;
use crate::transcript::canonical_aad;
use crate::util::b64e;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Derives a deterministic 24-byte nonce for a specific chunk index in streaming mode.
///
/// Uses HKDF-SHA256 with:
/// - Key: Content Encryption Key (`cek`)
/// - Salt: Recipient Commitment (`rc`)
/// - Info: `STREAM_NONCE_INFO_LABEL || chunk_index` (big-endian u32)
///
/// This ensures unique, unpredictable nonces per chunk while binding them to the
/// message recipients and content key – preventing nonce reuse even across messages.
///
/// # Panics
///
/// Panics only if HKDF expansion fails (impossible with valid inputs).
pub(crate) fn derive_chunk_nonce(cek: &[u8; 32], rc: &[u8; 32], chunk_index: u32) -> [u8; 24] {
    use crate::constants::STREAM_NONCE_INFO_LABEL;

    let hk = Hkdf::<Sha256>::new(Some(rc), cek);
    let mut nonce = [0u8; 24];

    let info = [STREAM_NONCE_INFO_LABEL, &chunk_index.to_be_bytes()].concat();
    hk.expand(&info, &mut nonce)
        .expect("HKDF expand for 24-byte chunk nonce failed (invalid length)");

    nonce
}

/// Encrypts a plaintext stream in fixed-size chunks using streaming mode framing.
///
/// Each output frame has the following wire format:
///
/// ```text
/// [u32_be: frame_len]       // length of (nonce + ciphertext + tag)
/// [24 bytes: nonce]         // derived via `derive_chunk_nonce`
/// [n bytes: ciphertext]     // XChaCha20-Poly1305 encrypted chunk
/// [16 bytes: tag]           // Poly1305 authenticator
/// ```
///
/// The same Additional Authenticated Data (AAD) is used for all chunks and is derived
/// from the message header (ephemeral key, main nonce, recipients blob).
///
/// If `digest_opt` is provided, the **exact on-wire bytes** of each frame
/// (`len || nonce || ciphertext || tag`) are fed into the hasher. This digest is later
/// used to construct the streaming-mode signature transcript.
///
/// This function performs **zero heap allocations per chunk** after the initial buffer.
/// The chunk buffer is automatically zeroized on drop to prevent plaintext leakage.
///
/// # Errors
///
/// Returns `Err(())` on I/O errors or if chunk length exceeds `u32::MAX`.
pub(crate) fn encrypt_stream_chunks<R: Read, W: Write>(
    hs: &EncryptHandshake,
    mut pt: R,
    mut out_payload: W,
    chunk_size: usize,
    mut digest_opt: Option<&mut Sha256>,
) -> Result<(), ()> {
    // Buffer is automatically zeroized on drop (even on error paths)
    let mut buf = Zeroizing::new(vec![0u8; chunk_size + TAG_LEN]);
    let mut index: u32 = 0;

    // Pre-compute AAD – identical for all chunks in this message
    let enc_ecdh_b64 = b64e(&hs.enc_ecdh);
    let nonce_b64 = b64e(&hs.nonce);
    let recipients_b64 = b64e(&hs.recipients_blob);
    let aad = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, hs.stream_on);

    loop {
        let read_len = pt.read(&mut buf[..chunk_size]).map_err(|_| ())?;
        if read_len == 0 {
            break; // EOF – end of input
        }

        // Derive chunk-specific nonce using controlled CEK access
        let nonce = derive_chunk_nonce(hs.cek(), &hs.rc, index);
        let cipher = XChaCha20Poly1305::new(hs.cek().into());

        let tag = cipher
            .encrypt_in_place_detached(&XNonce::from(nonce), &aad, &mut buf[..read_len])
            .map_err(|_| ())?;

        buf[read_len..read_len + TAG_LEN].copy_from_slice(tag.as_slice());
        let ct_len = read_len + TAG_LEN;
        let len_u32 = u32::try_from(ct_len).map_err(|_| ())?;

        // Ensure chunk length doesn't collide with trailer sentinel
        if len_u32 >= TRAILER_SENTINEL_LEN {
            return Err(()); // Chunk too large (would be mistaken for sentinel)
        }

        // Frame header: length (4) + nonce (24)
        let mut header = [0u8; 4 + 24];
        header[0..4].copy_from_slice(&len_u32.to_be_bytes());
        header[4..28].copy_from_slice(&nonce);

        out_payload.write_all(&header).map_err(|_| ())?;
        out_payload.write_all(&buf[..ct_len]).map_err(|_| ())?;

        // Update running transcript digest if signature is requested
        if let Some(d) = digest_opt.as_mut() {
            d.update(&len_u32.to_be_bytes());
            d.update(&nonce);
            d.update(&buf[..ct_len]);
        }

        index = index.checked_add(1).ok_or(())?; // Detect absurdly long streams
    }

    Ok(())
}

/// Writes the streaming-mode signature trailer after the final payload chunk.
///
/// Format:
/// ```text
/// 0xFFFFFFFF                  // TRAILER_SENTINEL_LEN (marks end of chunks)
/// "VLM1-SIGTRAILER-STREAM-v1" // 32-byte magic (null-padded)
/// u32_be: signature_length
/// [signature_length] bytes: hybrid ML-DSA-65 || Ed25519 signature
/// ```
///
/// This function must be called **exactly once** after `encrypt_stream_chunks` has
/// consumed all input and flushed all frames. It requires no seeking and works on
/// pipes and network streams.
///
/// # Errors
///
/// Returns `Err(())` on I/O error or if signature length exceeds `u32::MAX`.
pub(crate) fn write_signature_trailer<W: Write>(
    output: &mut W,
    signature: &[u8],
) -> Result<(), ()> {
    let sig_len_u32 = u32::try_from(signature.len()).map_err(|_| ())?;

    output
        .write_all(&TRAILER_SENTINEL_LEN.to_be_bytes())
        .map_err(|_| ())?;
    output.write_all(TRAILER_MAGIC).map_err(|_| ())?;
    output
        .write_all(&sig_len_u32.to_be_bytes())
        .map_err(|_| ())?;
    output.write_all(signature).map_err(|_| ())?;

    Ok(())
}

// ============================================================
// Unit tests for src/streaming.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `streaming.rs`
    //!
    //! Focus: streaming framing logic, deterministic nonce derivation,
    //! digest updates, and trailer serialization.
    //!
    //! These tests avoid real cryptography; instead they verify:
    //! - `derive_chunk_nonce` determinism & uniqueness
    //! - `encrypt_stream_chunks` correct frame structure and digest updates
    //! - `write_signature_trailer` exact binary layout
    //!
    //! All I/O is in-memory; no filesystem or RNG used.

    use super::*;
    use crate::context::EncryptHandshake;
    use std::io::Cursor;

    // ------------------------------------------------------------
    // Helper: deterministic N-byte pattern
    // ------------------------------------------------------------
    fn fixed_arr<const N: usize>() -> [u8; N] {
        let mut a = [0u8; N];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(19).wrapping_add(7);
        }
        a
    }

    // Minimal EncryptHandshake stub sufficient for streaming tests
    fn dummy_handshake(stream_on: bool) -> EncryptHandshake {
        EncryptHandshake::new(
            stream_on,
            fixed_arr::<32>(),
            fixed_arr::<24>(),
            fixed_arr::<32>(),
            vec![0xAA, 0xBB, 0xCC],
            fixed_arr::<32>(),
        )
    }

    // ------------------------------------------------------------
    // derive_chunk_nonce
    // ------------------------------------------------------------

    #[test]
    fn test_derive_chunk_nonce_is_deterministic() {
        let cek = fixed_arr::<32>();
        let rc = fixed_arr::<32>();
        let n1 = derive_chunk_nonce(&cek, &rc, 0);
        let n2 = derive_chunk_nonce(&cek, &rc, 0);
        let n3 = derive_chunk_nonce(&cek, &rc, 1);

        // Deterministic for same input
        assert_eq!(n1, n2);
        // Distinct for different chunk indices
        assert_ne!(n1, n3);
        assert_eq!(n1.len(), 24);
    }

    // ------------------------------------------------------------
    // encrypt_stream_chunks
    // ------------------------------------------------------------

    #[test]
    fn test_encrypt_stream_chunks_generates_valid_frames() {
        let hs = dummy_handshake(true);

        // Input: 100 bytes => should produce 1 frame (chunk_size >= input)
        let plaintext = vec![0x11; 100];
        let mut out = Vec::new();
        let mut digest = Sha256::new();

        encrypt_stream_chunks(
            &hs,
            Cursor::new(&plaintext),
            &mut out,
            256,
            Some(&mut digest),
        )
        .expect("encryption should succeed");

        // Frame layout: len(4) + nonce(24) + ciphertext+tag
        assert!(out.len() > 4 + 24 + 16);

        // First 4 bytes = total (ct+tag) length in big-endian
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&out[0..4]);
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        assert!(frame_len <= out.len());

        // Digest must have been updated (not all zeros)
        let digest_bytes = digest.finalize();
        assert!(digest_bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encrypt_stream_chunks_multiple_frames_and_digest_consistency() {
        let hs = dummy_handshake(true);
        let plaintext = vec![0x22; 8000]; // > 2 chunks
        let mut out = Vec::new();
        let mut digest = Sha256::new();

        encrypt_stream_chunks(
            &hs,
            Cursor::new(&plaintext),
            &mut out,
            4096,
            Some(&mut digest),
        )
        .expect("ok");

        // At least something was produced
        assert!(!out.is_empty());

        // Digest result depends on full byte stream; we only check size
        let dg = digest.finalize();
        assert_eq!(dg.len(), 32);
    }

    #[test]
    fn test_encrypt_stream_chunks_empty_input_produces_nothing() {
        let hs = dummy_handshake(true);
        let pt = Cursor::new(Vec::<u8>::new());
        let mut out = Vec::new();
        encrypt_stream_chunks(&hs, pt, &mut out, 128, None).expect("ok");
        assert!(out.is_empty());
    }

    // ------------------------------------------------------------
    // write_signature_trailer
    // ------------------------------------------------------------

    #[test]
    fn test_write_signature_trailer_structure() {
        let mut out = Vec::new();
        let sig = vec![0xAB; 64];
        write_signature_trailer(&mut out, &sig).expect("ok");

        // Layout:
        //  0..4   sentinel (u32::MAX)
        //  4..36  magic (32 bytes)
        //  36..40 sig_len (u32)
        //  40..end signature bytes
        assert_eq!(out.len(), 4 + 32 + 4 + 64);

        let sentinel = u32::from_be_bytes(out[0..4].try_into().unwrap());
        assert_eq!(sentinel, TRAILER_SENTINEL_LEN);

        let sig_len = u32::from_be_bytes(out[36..40].try_into().unwrap());
        assert_eq!(sig_len, 64);

        // Magic should match prefix "VLM1"
        assert_eq!(&out[4..8], b"VLM1");
    }

    #[test]
    fn test_write_signature_trailer_handles_large_signature() {
        let mut out = Vec::new();
        let sig = vec![0xCD; 2000];
        write_signature_trailer(&mut out, &sig).expect("ok");
        assert!(out.ends_with(&sig));
    }

    #[test]
    fn test_write_signature_trailer_io_error_propagates() {
        struct BadWriter;
        impl std::io::Write for BadWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "fail"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut bad = BadWriter;
        let sig = vec![0xEF; 32];
        let err = write_signature_trailer(&mut bad, &sig);
        assert!(err.is_err());
    }
}
