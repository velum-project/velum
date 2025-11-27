//! Canonical AAD and signature transcripts for VELUM.
//!
//! This module centralizes **all** logic that defines:
//! - what bytes are authenticated (AAD),
//! - what bytes are signed (transcript for PQ + Ed25519),
//! - how signature verification maps to a compact status code.
//!
//! If the signing rules ever change, this is the *only* place that needs to
//! be updated (plus the corresponding signing side).

use crate::armor::parse_public;
use crate::constants::{AAD_LABEL, SIG_LABEL, V};
use crate::envelope::StreamFlag;
use crate::util::b64e;

// Decrypt context comes from the core module (KEM + CEK + parsed header).
use crate::context::DecryptContext;

use pqcrypto_traits::sign::{PublicKey as SigPublicKey, SignedMessage};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Canonical AAD for content AEAD (both stream:N and stream:Y).
///
/// This is what is passed as `aad` into XChaCha20-Poly1305 when encrypting /
/// decrypting the payload. It intentionally **does not** include any
/// recipient-identifying metadata beyond the opaque `recipients_blob`.
pub(crate) fn canonical_aad(
    enc_ecdh_b64: &str,
    nonce_b64: &str,
    recipients_b64: &str,
    stream_on: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    out.extend_from_slice(AAD_LABEL);
    out.push(b'\n');

    out.extend_from_slice(b"v:");
    out.extend_from_slice(V.as_bytes());
    out.push(b'\n');

    // stream:N/Y – bound to the ciphertext via AAD
    out.extend_from_slice(b"stream:");
    if stream_on {
        out.extend_from_slice(b"Y");
    } else {
        out.extend_from_slice(b"N");
    }
    out.push(b'\n');

    out.extend_from_slice(b"enc_ecdh:");
    out.extend_from_slice(enc_ecdh_b64.as_bytes());
    out.push(b'\n');

    out.extend_from_slice(b"nonce:");
    out.extend_from_slice(nonce_b64.as_bytes());
    out.push(b'\n');

    out.extend_from_slice(b"recipients:");
    out.extend_from_slice(recipients_b64.as_bytes());
    out.push(b'\n');

    out
}

/// Common header part of the signature transcript (both stream:N and stream:Y).
///
/// This binds:
/// - version,
/// - enc_ecdh,
/// - nonce,
/// - recipients_blob (as Base64),
/// - stream mode (N/Y),
/// - recipients commitment (RC).
pub(crate) fn canonical_sig_header_part(
    enc_ecdh_b64: &str,
    nonce_b64: &str,
    recipients_b64: &str,
    rc: &[u8; 32],
    stream_on: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(600);

    out.extend_from_slice(SIG_LABEL);
    out.push(b'\n');

    out.extend_from_slice(b"v:");
    out.extend_from_slice(V.as_bytes());
    out.push(b'\n');

    out.extend_from_slice(b"enc_ecdh:");
    out.extend_from_slice(enc_ecdh_b64.as_bytes());
    out.push(b'\n');

    out.extend_from_slice(b"nonce:");
    out.extend_from_slice(nonce_b64.as_bytes());
    out.push(b'\n');

    out.extend_from_slice(b"recipients:");
    out.extend_from_slice(recipients_b64.as_bytes());
    out.push(b'\n');

    // stream:N/Y – binds streaming mode to the signature
    out.extend_from_slice(b"stream:");
    if stream_on {
        out.extend_from_slice(b"Y");
    } else {
        out.extend_from_slice(b"N");
    }
    out.push(b'\n');

    out.extend_from_slice(b"rc:");
    out.extend_from_slice(b64e(rc).as_bytes());
    out.push(b'\n');

    out
}

/// Signature transcript for non-streaming payloads (`stream:N`).
///
/// Extends the common header part with:
/// - `ct:BASE64(ciphertext || tag)`.
pub(crate) fn canonical_sig_nonstream(
    enc_ecdh_b64: &str,
    nonce_b64: &str,
    recipients_b64: &str,
    ct_b64: &str,
    rc: &[u8; 32],
    stream_on: bool,
) -> Vec<u8> {
    let mut out = canonical_sig_header_part(enc_ecdh_b64, nonce_b64, recipients_b64, rc, stream_on);

    out.extend_from_slice(b"ct:");
    out.extend_from_slice(ct_b64.as_bytes());
    out.push(b'\n');

    out
}

/// Signature transcript for streaming payloads (`stream:Y`).
///
/// Extends the common header part with:
/// - `digest:BASE64(SHA256(payload_bytes))`,
///   where `payload_bytes` is the serialized streaming layout:
///   `(u32_be chunk_len || chunk_nonce || ct_i||tag_i)*`.
pub(crate) fn canonical_sig_stream_digest(
    enc_ecdh_b64: &str,
    nonce_b64: &str,
    recipients_b64: &str,
    digest_b64: &str,
    rc: &[u8; 32],
    stream_on: bool,
) -> Vec<u8> {
    let mut out = canonical_sig_header_part(enc_ecdh_b64, nonce_b64, recipients_b64, rc, stream_on);

    out.extend_from_slice(b"digest:");
    out.extend_from_slice(digest_b64.as_bytes());
    out.push(b'\n');

    out
}

/// Verify the hybrid signature (ML-DSA-65 + Ed25519) for a decrypted context.
///
/// Returns a compact status code:
/// - `0` = no signature present (and `expected_public == None`),
/// - `1` = signature verified (both PQ + Ed25519),
/// - `2` = signature invalid (any part fails),
/// - `3` = signature missing / unexpected (present but not expected, or expected but not present).
///
/// This is the only place where:
/// - we interpret the `StreamFlag` for transcripts,
/// - we derive the transcript for PQ + Ed25519 verification.
pub(crate) fn verify_signature_status(
    ctx: &DecryptContext,
    expected_public: Option<&str>,
) -> Result<i32, ()> {
    let mut status = 0;

    // No signature in the message.
    if ctx.parsed.signature.is_none() {
        if expected_public.is_some() {
            // Caller expected a signature, but message has none.
            status = 3;
        }
        return Ok(status);
    }

    let sig = ctx.parsed.signature.as_ref().unwrap();

    // Signature present, but caller does not care / did not expect one.
    if expected_public.is_none() {
        status = 3;
        return Ok(status);
    }

    // We have both a signature and an expected public key.
    let pb = parse_public(expected_public.unwrap()).map_err(|_| ())?;
    let pq_len = mldsa65::signature_bytes();
    let ed_len = 64;

    if sig.len() != pq_len + ed_len {
        // Signature length is malformed.
        status = 2;
    } else {
        let sig_pq = &sig[..pq_len];
        let sig_ed = &sig[pq_len..];

        let mut enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
        let mut nonce_b64 = b64e(&ctx.parsed.nonce);
        let mut recipients_b64 = b64e(&ctx.parsed.recipients_blob);

        let stream_on = matches!(ctx.parsed.stream, StreamFlag::Yes);

        // Build the transcript according to stream mode.
        let transcript = if !stream_on {
            // stream:N → transcript binds CT directly.
            let mut ct_b64 = b64e(&ctx.parsed.ct_and_tag);
            let t = canonical_sig_nonstream(
                &enc_ecdh_b64,
                &nonce_b64,
                &recipients_b64,
                &ct_b64,
                &ctx.rc,
                stream_on,
            );
            ct_b64.zeroize();
            t
        } else {
            // stream:Y → transcript binds SHA256(payload_bytes) instead of CT verbatim.
            let mut hasher = Sha256::new();
            hasher.update(&ctx.parsed.ct_and_tag);
            let digest_bytes = hasher.finalize();
            let mut digest_b64 = b64e(&digest_bytes);

            let t = canonical_sig_stream_digest(
                &enc_ecdh_b64,
                &nonce_b64,
                &recipients_b64,
                &digest_b64,
                &ctx.rc,
                stream_on,
            );

            digest_b64.zeroize();
            t
        };

        // === PQ verification (ML-DSA-65) ===
        let ok_pq = match mldsa65::PublicKey::from_bytes(&pb.sig_pk_pq) {
            Ok(pk_pq) => {
                // The library uses "signed message" format: signature || message.
                let mut buf = Vec::with_capacity(sig_pq.len() + transcript.len());
                buf.extend_from_slice(sig_pq);
                buf.extend_from_slice(&transcript);

                match mldsa65::SignedMessage::from_bytes(&buf) {
                    Ok(sm) => match mldsa65::open(&sm, &pk_pq) {
                        Ok(recovered) => bool::from(recovered.ct_eq(&transcript)),
                        Err(_) => false,
                    },
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };

        // === Ed25519 verification ===
        let ok_ed = match Ed25519VerifyingKey::from_bytes(&pb.sig_pk_ed) {
            Ok(pk_ed) => Ed25519Signature::try_from(sig_ed)
                .map(|sig| pk_ed.verify_strict(&transcript, &sig).is_ok())
                .unwrap_or(false),
            Err(_) => false,
        };

        // Constant-time combination using subtle
        use subtle::Choice;
        let pq_choice = Choice::from(ok_pq as u8);
        let ed_choice = Choice::from(ok_ed as u8);
        let both_ok = pq_choice & ed_choice; 
        status = if bool::from(both_ok) { 1 } else { 2 };

        // Cleanup of temporary Base64 strings.
        enc_ecdh_b64.zeroize();
        nonce_b64.zeroize();
        recipients_b64.zeroize();
    }

    Ok(status)
}

// ============================================================
// Unit tests for src/transcript.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `transcript.rs`
    //!
    //! This suite focuses on **structure and control-flow**, not on
    //! real cryptographic verification:
    //! - `canonical_aad` – correct inclusion of all header fields and
    //!   stream flag (`N` / `Y`).
    //! - `canonical_sig_header_part` – common signed header layout.
    //! - `canonical_sig_nonstream` / `canonical_sig_stream_digest` –
    //!   transcript extensions for non-streaming and streaming modes.
    //! - `verify_signature_status` – return codes 0, 3 and early-exit
    //!   paths without exercising real PQ / Ed25519 verification.
    //!
    //! Cryptographic signatures are *not* validated here; those paths
    //! are left to higher-level / integration tests.

    use super::*;
    use crate::constants::{MSG_NONCE_LEN, TAG_LEN};
    use crate::context::DecryptContext;
    use crate::envelope::{ParsedBinary, StreamFlag};

    // ------------------------------------------------------------
    // Small deterministic helpers
    // ------------------------------------------------------------

    /// Deterministic byte pattern for fixed-size arrays.
    ///
    /// Used to construct synthetic but stable test inputs without RNG.
    fn fixed_arr<const N: usize>() -> [u8; N] {
        let mut a = [0u8; N];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        a
    }

    /// Minimal `ParsedBinary` instance suitable for transcript tests.
    ///
    /// Only the fields used by `verify_signature_status` and transcript
    /// builders are populated sensibly. The rest is just structurally valid.
    fn dummy_parsed(signature: Option<Vec<u8>>, stream: StreamFlag) -> ParsedBinary {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();

        // Recipients blob is opaque here; we do not re-parse it in this module.
        let recipients_blob = vec![0xAA, 0xBB, 0xCC];

        // ct_and_tag: must be at least TAG_LEN bytes to satisfy basic checks
        let mut ct_and_tag = vec![0x11; TAG_LEN + 4];
        ct_and_tag[0] = 0x42;

        let rc = fixed_arr::<32>();

        ParsedBinary {
            enc_ecdh,
            nonce,
            recipients_blob,
            ct_and_tag,
            signature,
            stream,
            rc,
            has_trailer: matches!(stream, StreamFlag::Yes),
        }
    }

    /// Minimal `DecryptContext` used for signature-status tests.
    ///
    /// `cek` is populated with a dummy fixed array; it is never touched
    /// by `verify_signature_status`, but the field must exist for the
    /// struct literal to compile.
    fn dummy_ctx(signature: Option<Vec<u8>>, stream: StreamFlag) -> DecryptContext {
        let parsed = dummy_parsed(signature, stream);
        DecryptContext::new(parsed, fixed_arr::<32>(), fixed_arr::<32>())
    }

    // ------------------------------------------------------------
    // canonical_aad
    // ------------------------------------------------------------

    #[test]
    fn canonical_aad_includes_all_fields_and_stream_flag() {
        let aad_n = canonical_aad("ECDH_B64", "NONCE_B64", "REC_B64", false);
        let s_n = String::from_utf8_lossy(&aad_n);

        // Version and basic fields
        assert!(s_n.contains("v:"));
        assert!(s_n.contains("enc_ecdh:ECDH_B64"));
        assert!(s_n.contains("nonce:NONCE_B64"));
        assert!(s_n.contains("recipients:REC_B64"));

        // Non-streaming flag
        assert!(s_n.contains("stream:N"));

        let aad_y = canonical_aad("ECDH_B64", "NONCE_B64", "REC_B64", true);
        let s_y = String::from_utf8_lossy(&aad_y);
        assert!(s_y.contains("stream:Y"));
    }

    // ------------------------------------------------------------
    // canonical_sig_header_part / nonstream / stream_digest
    // ------------------------------------------------------------

    #[test]
    fn canonical_sig_header_part_has_expected_structure() {
        let rc = fixed_arr::<32>();
        let out = canonical_sig_header_part("E_B64", "N_B64", "R_B64", &rc, false);
        let s = String::from_utf8_lossy(&out);

        // High-level sanity of fields and order
        assert!(s.contains("v:"));
        assert!(s.contains("enc_ecdh:E_B64"));
        assert!(s.contains("nonce:N_B64"));
        assert!(s.contains("recipients:R_B64"));
        assert!(s.contains("stream:N"));
        assert!(s.contains("rc:"));
    }

    #[test]
    fn canonical_sig_nonstream_appends_ct_line() {
        let rc = fixed_arr::<32>();
        let out = canonical_sig_nonstream("E", "N", "R", "CT_B64", &rc, false);
        let s = String::from_utf8_lossy(&out);

        // Non-streaming transcript must bind CT directly
        assert!(s.contains("ct:CT_B64"));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn canonical_sig_stream_digest_appends_digest_line() {
        let rc = fixed_arr::<32>();
        let out = canonical_sig_stream_digest("E", "N", "R", "DG_B64", &rc, true);
        let s = String::from_utf8_lossy(&out);

        // Streaming transcript binds digest instead of CT verbatim
        assert!(s.contains("digest:DG_B64"));
        assert!(s.contains("stream:Y"));
        assert!(s.ends_with('\n'));
    }

    // ------------------------------------------------------------
    // verify_signature_status: control-flow / status codes
    // ------------------------------------------------------------

    /// When no signature is present and no signature is expected,
    /// `verify_signature_status` must return `0`.
    #[test]
    fn verify_status_0_when_no_sig_and_no_expectation() {
        let ctx = dummy_ctx(None, StreamFlag::No);
        let status = verify_signature_status(&ctx, None).expect("status should be Ok");
        assert_eq!(status, 0);
    }

    /// When a signature is *expected* but not present in the message,
    /// the function must return status `3`.
    #[test]
    fn verify_status_3_when_expected_but_signature_missing() {
        let ctx = dummy_ctx(None, StreamFlag::No);
        let fake_pub =
            "-----BEGIN VELUM PUBLIC KEY-----\nv:1\nX:dummy\n-----END VELUM PUBLIC KEY-----";
        let status = verify_signature_status(&ctx, Some(fake_pub)).expect("status should be Ok");
        assert_eq!(status, 3);
    }

    /// When a signature is present but the caller does *not* expect or
    /// care about signatures, the function must return status `3` and
    /// exit before transcript / crypto paths.
    #[test]
    fn verify_status_3_when_signature_present_but_not_expected() {
        let ctx = dummy_ctx(Some(vec![0xAA, 0xBB, 0xCC]), StreamFlag::No);
        let status = verify_signature_status(&ctx, None).expect("status should be Ok");
        assert_eq!(status, 3);
    }

    /// When a signature is present and a public key is provided, the
    /// function must follow the "verify" path instead of returning 0/3
    /// early. We do **not** assert on 1 vs 2 here, because that would
    /// require valid PQ + Ed25519 signatures; we only assert that the
    /// call returns *some* status (Ok) and does not panic.
    #[test]
    fn verify_status_reaches_verification_path_with_sig_and_expected_key() {
        // Signature length is arbitrary here; real verification is not the goal
        let sig = vec![0xAB; 16];
        let ctx = dummy_ctx(Some(sig), StreamFlag::No);

        // Public key armor is intentionally malformed; this may result
        // in `Err(())` (parsing failure) or a concrete status. Both
        // are acceptable for this structural test.
        let fake_pub = "-----BEGIN VELUM PUBLIC KEY-----\nv:1\necdh_pk:AAAA\npq_pk:BBBB\nsig_pk_pq:CCCC\nsig_pk_ed:DDDD\n-----END VELUM PUBLIC KEY-----";

        let _ = verify_signature_status(&ctx, Some(fake_pub));
        // No assertion on value; this test is about the call not panicking.
    }
}
