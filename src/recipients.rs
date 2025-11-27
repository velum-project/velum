//! Multi-recipient helper types and functions for VELUM.
//!
//! This module is responsible **only** for the recipient list logic:
//! - per-recipient entries (PQ capsule + wrapped CEK + identifiers),
//! - entry identifiers (`entry_id`),
//! - deterministic index hints for O(1) recipient discovery,
//! - recipients-set commitment (RC),
//! - compact binary serialization of the recipients blob.
//!
//! It does **not** know anything about:
//! - content AAD,
//! - streaming,
//! - full envelope layout.

use crate::constants::{RECIPIENTS_COMMIT_LABEL, TAG_LEN};

use pqcrypto_mlkem::mlkem768;
use sha2::{Digest, Sha256};

/// One entry of the multi-recipient recipient list.
///
/// A VELUM ciphertext embeds *one such entry per recipient*.
/// Each entry independently wraps the CEK (content-encryption key) so that:
/// - any intended recipient can recover the CEK,
/// - non-recipients gain no information,
/// - recipient anonymity is preserved,
/// - all entries are unlinkable.
///
/// The entry also carries a deterministic 64-bit hint that allows O(1) recipient
/// discovery without leaking the recipient’s identity globally.
#[derive(Clone)]
pub(crate) struct RecipientEntry {
    /// ML-KEM-768 ciphertext ("capsule").
    /// This is the PQ half of the hybrid KEM and has fixed length.
    pub(crate) enc_pq: Vec<u8>,

    /// The wrapped CEK:
    /// `wrap = XChaCha20-Poly1305(KEK_i, nonce_i, aad_i ; CEK)`.
    ///
    /// Contains `CEK || TAG`.
    pub(crate) wrap: Vec<u8>,

    /// `entry_id = SHA256(enc_pq)`.
    /// Used for recipient-set commitments and deterministic KEK derivation.
    pub(crate) entry_id: [u8; 32],

    /// Deterministic 64-bit index hint (big-endian).
    ///
    /// Allows a legitimate recipient to identify their own entry in O(1)
    /// without revealing anything to an observer.
    pub(crate) index_hint: u64,
}

/// Computes the recipient entry identifier: `entry_id = SHA256(enc_pq)`.
pub(crate) fn compute_entry_id(enc_pq: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(enc_pq);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// Computes a deterministic 64-bit recipient hint used for rapid matching
/// during decryption.
///
/// Inputs:
/// - `entry_id`  – 32-byte identifier of the recipient entry,
/// - `enc_ecdh`  – ephemeral X25519 public key (32 bytes),
/// - `rc`        – 32-byte recipients commitment,
/// - `ss_ecdh`   – recipient's ECDH shared secret (32 bytes).
///
/// The only secret input is `ss_ecdh`; all other values are public.
pub(crate) fn compute_index_hint(
    entry_id: &[u8; 32],
    enc_ecdh: &[u8; 32],
    rc: &[u8; 32],
    ss_ecdh: &[u8; 32],
) -> u64 {
    let mut h = Sha256::new();
    h.update(entry_id);
    h.update(enc_ecdh);
    h.update(rc);
    h.update(ss_ecdh); // the only secret input
    let out = h.finalize();
    u64::from_be_bytes(out[0..8].try_into().unwrap())
}

/// Computes the *recipient commitment* (RC) for a multi-recipient message.
///
/// RC is a deterministic, order-independent hash of all `entry_id`s:
/// ```text
/// RC = SHA256( "VELUM-v1 recipients" || sort(entry_ids) )
/// ```
pub(crate) fn recipients_commitment(entry_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut v = entry_ids.to_vec();
    v.sort(); // lexicographically sort the entry_id list

    let mut h = Sha256::new();
    h.update(RECIPIENTS_COMMIT_LABEL);
    for id in v.iter() {
        h.update(id);
    }

    let out = h.finalize();
    let mut rc = [0u8; 32];
    rc.copy_from_slice(&out);
    rc
}

/// Serializes a list of `RecipientEntry` structures into a compact binary blob.
///
/// Layout (repeated for each entry):
///
/// ```text
///   u16_be lpq        // length of enc_pq
///   [lpq]  enc_pq
///
///   u16_be lw         // length of wrap (must be 32 + TAG_LEN)
///   [lw]  wrap
///
///   u16_be lid = 32
///   [32]  entry_id
///
///   u16_be lhint = 8
///   [8]   index_hint (big-endian u64)
/// ```
///
/// Returns `Err(())` if:
/// - `entries` is empty,
/// - any length does not fit into `u16`.
pub(crate) fn encode_recipients(entries: &[RecipientEntry]) -> Result<Vec<u8>, ()> {
    if entries.is_empty() {
        return Err(());
    }

    let mut out = Vec::with_capacity(entries.len() * 1500);

    for e in entries {
        // enc_pq
        let lpq = e.enc_pq.len();
        if lpq > u16::MAX as usize {
            return Err(());
        }
        out.push(((lpq >> 8) & 0xff) as u8);
        out.push((lpq & 0xff) as u8);
        out.extend_from_slice(&e.enc_pq);

        // wrap (CEK encrypted under KEK_i)
        let lw = e.wrap.len();
        if lw > u16::MAX as usize {
            return Err(());
        }
        out.push(((lw >> 8) & 0xff) as u8);
        out.push((lw & 0xff) as u8);
        out.extend_from_slice(&e.wrap);

        // entry_id (32 bytes)
        let lid: usize = 32;
        out.push(((lid >> 8) & 0xff) as u8);
        out.push((lid & 0xff) as u8);
        out.extend_from_slice(&e.entry_id);

        // index_hint (8 bytes, BE)
        let lhint: usize = 8;
        out.push(((lhint >> 8) & 0xff) as u8);
        out.push((lhint & 0xff) as u8);
        out.extend_from_slice(&e.index_hint.to_be_bytes());
    }

    Ok(out)
}

/// Decodes a binary recipients-blob produced by [`encode_recipients`].
///
/// Performs the following checks:
/// - blob is non-empty,
/// - each field fits inside the buffer,
/// - `enc_pq` has exactly `mlkem768::ciphertext_bytes()` bytes,
/// - `wrap` length is exactly `32 + TAG_LEN`,
/// - `entry_id` has length 32,
/// - `index_hint` has length 8,
/// - recomputed `entry_id = SHA256(enc_pq)` matches the stored one,
/// - at least one entry is present.
///
/// On success returns a `Vec<RecipientEntry>`. Otherwise returns `Err(())`.
pub(crate) fn decode_recipients(blob: &[u8]) -> Result<Vec<RecipientEntry>, ()> {
    if blob.is_empty() {
        return Err(());
    }

    let mut i = 0usize;
    let mut out = Vec::new();

    while i < blob.len() {
        // enc_pq
        if i + 2 > blob.len() {
            return Err(());
        }
        let lpq = ((blob[i] as usize) << 8) | (blob[i + 1] as usize);
        i += 2;
        if i + lpq > blob.len() {
            return Err(());
        }
        let enc_pq = blob[i..i + lpq].to_vec();
        i += lpq;

        // validate ML-KEM-768 CT size
        if enc_pq.len() != mlkem768::ciphertext_bytes() {
            return Err(());
        }

        // wrap
        if i + 2 > blob.len() {
            return Err(());
        }
        let lw = ((blob[i] as usize) << 8) | (blob[i + 1] as usize);
        i += 2;
        if i + lw > blob.len() {
            return Err(());
        }
        let wrap = blob[i..i + lw].to_vec();
        i += lw;

        // wrap must be CEK (32) + TAG (16)
        if wrap.len() != 32 + TAG_LEN {
            return Err(());
        }

        // entry_id (32 bytes)
        if i + 2 > blob.len() {
            return Err(());
        }
        let lid = ((blob[i] as usize) << 8) | (blob[i + 1] as usize);
        i += 2;
        if lid != 32 {
            return Err(());
        }
        if i + 32 > blob.len() {
            return Err(());
        }
        let mut entry_id = [0u8; 32];
        entry_id.copy_from_slice(&blob[i..i + 32]);
        i += 32;

        // index_hint — 8-byte big-endian u64
        if i + 2 > blob.len() {
            return Err(());
        }
        let lhint = ((blob[i] as usize) << 8) | (blob[i + 1] as usize);
        i += 2;
        if lhint != 8 {
            return Err(());
        }
        if i + 8 > blob.len() {
            return Err(());
        }
        let mut hint_bytes = [0u8; 8];
        hint_bytes.copy_from_slice(&blob[i..i + 8]);
        let index_hint = u64::from_be_bytes(hint_bytes);
        i += 8;

        // recompute entry_id integrity
        let expected_id = compute_entry_id(&enc_pq);
        if expected_id != entry_id {
            return Err(()); // corrupted or manipulated recipients_blob
        }

        out.push(RecipientEntry {
            enc_pq,
            wrap,
            entry_id,
            index_hint,
        });
    }

    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

// ============================================================
// Unit tests for src/recipients.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `recipients.rs`
    //!
    //! Scope:
    //! - Deterministic calculation of `entry_id` and `index_hint`
    //! - Stability and ordering in `recipients_commitment`
    //! - Correctness of serialization (`encode_recipients`) and deserialization (`decode_recipients`)
    //! - Validation of error cases (empty data, incorrect lengths, corrupted entry_id)
    //!
    //! All tests run **locally**, with no dependency on post-quantum cryptography
    //! beyond requiring knowledge of `mlkem768::ciphertext_bytes()` size.

    use super::*;
    use rand::Rng;

    /// Helper constructor for a random (but valid) `RecipientEntry`.
    fn fake_entry() -> RecipientEntry {
        let mut rng = rand::thread_rng();
        let enc_pq_len = mlkem768::ciphertext_bytes();
        let enc_pq: Vec<u8> = (0..enc_pq_len).map(|_| rng.gen()).collect();
        let entry_id = compute_entry_id(&enc_pq);
        let wrap: Vec<u8> = (0..(32 + TAG_LEN)).map(|_| rng.gen()).collect();
        let index_hint = rng.gen::<u64>();
        RecipientEntry {
            enc_pq,
            wrap,
            entry_id,
            index_hint,
        }
    }

    // ------------------------------------------------------------
    // compute_entry_id
    // ------------------------------------------------------------

    /// `compute_entry_id` should be deterministic and sensitive to data changes.
    #[test]
    fn test_compute_entry_id_deterministic_and_unique() {
        let data = b"example capsule data";
        let id1 = compute_entry_id(data);
        let id2 = compute_entry_id(data);
        assert_eq!(id1, id2, "Hash should be deterministic");

        let mut data_mut = data.to_vec();
        data_mut[0] ^= 0x01;
        let id3 = compute_entry_id(&data_mut);
        assert_ne!(id1, id3, "Even 1-bit change should alter hash");
    }

    // ------------------------------------------------------------
    // compute_index_hint
    // ------------------------------------------------------------

    /// `compute_index_hint` should return a deterministic result,
    /// but different results with different `ss_ecdh` secrets.
    #[test]
    fn test_compute_index_hint_determinism_and_variation() {
        let entry_id = [1u8; 32];
        let enc_ecdh = [2u8; 32];
        let rc = [3u8; 32];
        let ss1 = [4u8; 32];
        let ss2 = [5u8; 32];

        let hint1 = compute_index_hint(&entry_id, &enc_ecdh, &rc, &ss1);
        let hint2 = compute_index_hint(&entry_id, &enc_ecdh, &rc, &ss1);
        assert_eq!(hint1, hint2, "Same inputs -> same output");

        let hint3 = compute_index_hint(&entry_id, &enc_ecdh, &rc, &ss2);
        assert_ne!(hint1, hint3, "Different secret should yield different hint");
    }

    // ------------------------------------------------------------
    // recipients_commitment
    // ------------------------------------------------------------

    /// `recipients_commitment` should give the same result regardless of `entry_id` order.
    #[test]
    fn test_recipients_commitment_order_independent() {
        let ids_a = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let ids_b = [[3u8; 32], [1u8; 32], [2u8; 32]]; // permutation

        let rc1 = recipients_commitment(&ids_a);
        let rc2 = recipients_commitment(&ids_b);

        assert_eq!(rc1, rc2, "Commitment must be order-independent");
    }

    /// `recipients_commitment` with an empty list should not panic and has a deterministic result.
    #[test]
    fn test_recipients_commitment_empty() {
        let ids: [[u8; 32]; 0] = [];
        let rc1 = recipients_commitment(&ids);
        let rc2 = recipients_commitment(&ids);
        assert_eq!(rc1, rc2);
    }

    // ------------------------------------------------------------
    // encode_recipients / decode_recipients
    // ------------------------------------------------------------

    /// Round-trip test: encode → decode → compare fields.
    #[test]
    fn test_encode_decode_roundtrip() {
        let entries: Vec<RecipientEntry> = (0..3).map(|_| fake_entry()).collect();
        let blob = encode_recipients(&entries).expect("encode ok");
        let decoded = decode_recipients(&blob).expect("decode ok");
        assert_eq!(decoded.len(), entries.len());

        for (a, b) in entries.iter().zip(decoded.iter()) {
            assert_eq!(a.enc_pq, b.enc_pq);
            assert_eq!(a.wrap, b.wrap);
            assert_eq!(a.entry_id, b.entry_id);
            assert_eq!(a.index_hint, b.index_hint);
        }
    }

    /// `encode_recipients` should return an error on an empty list.
    #[test]
    fn test_encode_empty() {
        let res = encode_recipients(&[]);
        assert!(res.is_err(), "Empty recipients list must be rejected");
    }

    /// `decode_recipients` should reject an empty blob.
    #[test]
    fn test_decode_empty_blob() {
        let blob: Vec<u8> = vec![];
        assert!(decode_recipients(&blob).is_err());
    }

    /// `decode_recipients` should detect corrupted entry_id.
    #[test]
    fn test_decode_corrupted_entry_id() {
        let entries: Vec<RecipientEntry> = vec![fake_entry()];
        let mut blob = encode_recipients(&entries).unwrap();
        
        // Find the entry_id fragment (last 32 bytes before the final 10 bytes)
        // and corrupt one byte
        let len = blob.len();
        if len >= 10 {
            blob[len - 10] ^= 0xFF;
        }
        
        assert!(decode_recipients(&blob).is_err(), "Tampered entry_id must fail validation");
    }

    /// `decode_recipients` should reject a blob with incorrect field lengths (e.g., wrap != 32 + TAG_LEN).
    #[test]
    fn test_decode_invalid_wrap_length() {
        let mut e = fake_entry();
        e.wrap = vec![0u8; 10]; // incorrect length
        let blob = encode_recipients(&[e]).unwrap();
        assert!(decode_recipients(&blob).is_err());
    }

    /// `decode_recipients` should reject a blob when `enc_pq` doesn't have ML-KEM-768 ciphertext length.
    #[test]
    fn test_decode_invalid_encpq_length() {
        let mut e = fake_entry();
        e.enc_pq = vec![0u8; 10]; // too short
        e.entry_id = compute_entry_id(&e.enc_pq);
        let blob = encode_recipients(&[e]).unwrap();
        assert!(decode_recipients(&blob).is_err());
    }

    /// Round-trip with multiple entries with different `index_hint` values to confirm consistency.
    #[test]
    fn test_roundtrip_multiple_different_hints() {
        let mut e1 = fake_entry();
        let mut e2 = fake_entry();
        e1.index_hint = 42;
        e2.index_hint = 1337;

        let blob = encode_recipients(&[e1.clone(), e2.clone()]).unwrap();
        let decoded = decode_recipients(&blob).unwrap();

        assert_eq!(decoded[0].index_hint, e1.index_hint);
        assert_eq!(decoded[1].index_hint, e2.index_hint);
    }
}
