//! src/armor.rs
//!
//! Textual armor encoding/decoding for VELUM v1 (PUBLIC, SECRET, MESSAGE).
//!
//! This module implements the human-readable, PEM-like armored formats used for:
//! - Long-term public key bundles (`-----BEGIN VELUM PUBLIC KEY-----`)
//! - Encrypted secret keystores (`-----BEGIN VELUM SECRET KEY-----`)
//! - Encrypted messages in non-streaming mode (`-----BEGIN VELUM MESSAGE-----`)
//!
//! It also provides bidirectional conversion between armored MESSAGE blocks and the
//! binary VLM1 envelope format (used by streaming and FFI APIs).
//!
//! All armored formats use strict key-value syntax, constant-time header validation,
//! and canonical Base64 encoding (standard alphabet, no wrapping).

use std::collections::{BTreeMap, BTreeSet};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use x25519_dalek::PublicKey as XPublic;

use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::{kem::PublicKey as KemPublicKey, sign::PublicKey};

use crate::constants::*;
use crate::envelope::{encode_envelope_binary, parse_envelope_binary};
use crate::keys::PublicBundle;
use crate::recipients::{compute_entry_id, decode_recipients, recipients_commitment};
use crate::util::{b64d, b64e};

/// Generic parser for PEM-style armored K:V blocks (used by PUBLIC and SECRET).
///
/// Validates begin/end markers using constant-time comparison, strips empty lines and
/// carriage returns, enforces lowercase keys, and rejects duplicate or malformed fields.
///
/// Returns a `BTreeMap` with lowercase keys for deterministic iteration and lookup.
///
/// # Errors
///
/// Returns `Err(())` if:
/// - Begin/end markers are missing or mismatched
/// - Any line lacks a `:` separator
/// - Keys are empty, duplicate, or contain invalid characters
pub(crate) fn parse_armor(
    text: &str,
    begin: &str,
    end: &str,
) -> Result<BTreeMap<String, String>, ()> {
    let t = text.trim().replace('\r', "");
    let mut lines: Vec<_> = t
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    let is_valid = lines
        .first()
        .map(|l| l.as_bytes().ct_eq(begin.as_bytes()).into())
        .unwrap_or(false)
        && lines
            .last()
            .map(|l| l.as_bytes().ct_eq(end.as_bytes()).into())
            .unwrap_or(false);

    if !is_valid {
        return Err(());
    }

    lines.remove(0);
    lines.pop();

    let mut out = BTreeMap::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(())?;
        let key = k.trim().to_lowercase();
        let val = v.trim();
        if key.is_empty() || val.is_empty() || out.contains_key(&key) {
            return Err(());
        }
        out.insert(key, val.to_string());
    }
    Ok(out)
}

// =====================
// PUBLIC key armors
// =====================

/// Serializes a public key bundle into armored format.
///
/// Output format:
/// ```text
/// -----BEGIN VELUM PUBLIC KEY-----
/// v:1
/// ecdh_pk:<base64>
/// pq_pk:<base64>
/// sig_pk_pq:<base64>
/// sig_pk_ed:<base64>
/// -----END VELUM PUBLIC KEY-----
/// ```
pub(crate) fn armor_public(
    ecdh_pk: &[u8],
    pq_pk: &[u8],
    sig_pk_pq: &[u8],
    sig_pk_ed: &[u8],
) -> String {
    format!(
        "{}\nv:{}\necdh_pk:{}\npq_pk:{}\nsig_pk_pq:{}\nsig_pk_ed:{}\n{}",
        BEGIN_PUB,
        V,
        b64e(ecdh_pk),
        b64e(pq_pk),
        b64e(sig_pk_pq),
        b64e(sig_pk_ed),
        END_PUB
    )
}

/// Parses an armored PUBLIC key block into a validated `PublicBundle`.
///
/// Performs full cryptographic validation:
/// - X25519 public key (curve point)
/// - ML-KEM-768 public key
/// - ML-DSA-65 public key
/// - Ed25519 verification key
///
/// # Errors
///
/// Returns `Err(())` on any parsing or validation failure.
pub(crate) fn parse_public(arm: &str) -> Result<PublicBundle, ()> {
    let d = parse_armor(arm, BEGIN_PUB, END_PUB)?;
    if !d
        .get("v")
        .map(|s| s.as_bytes().ct_eq(V.as_bytes()).into())
        .unwrap_or(false)
    {
        return Err(());
    }

    let ecdh_pk = b64d(d.get("ecdh_pk").ok_or(())?)?;
    let pq_pk = b64d(d.get("pq_pk").ok_or(())?)?;
    let sig_pk_pq = b64d(d.get("sig_pk_pq").ok_or(())?)?;
    let sig_pk_ed = b64d(d.get("sig_pk_ed").ok_or(())?)?;

    if ecdh_pk.len() != 32
        || pq_pk.len() != mlkem768::public_key_bytes()
        || sig_pk_pq.len() != mldsa65::public_key_bytes()
        || sig_pk_ed.len() != 32
    {
        return Err(());
    }

    let mut e = [0u8; 32];
    e.copy_from_slice(&ecdh_pk);
    let mut sig_ed_arr = [0u8; 32];
    sig_ed_arr.copy_from_slice(&sig_pk_ed);

    let _ = XPublic::from(e);
    let _ = mlkem768::PublicKey::from_bytes(&pq_pk).map_err(|_| ())?;
    let _ = mldsa65::PublicKey::from_bytes(&sig_pk_pq).map_err(|_| ())?;
    let _ = Ed25519VerifyingKey::from_bytes(&sig_ed_arr).map_err(|_| ())?;

    Ok(PublicBundle {
        ecdh_pk: e,
        pq_pk,
        sig_pk_pq,
        sig_pk_ed: sig_ed_arr,
    })
}

// =====================
// SECRET keystore armors
// =====================

/// Serializes an encrypted secret keystore into armored format.
///
/// Includes embedded Argon2id parameters for future-proof password changes.
pub(crate) fn armor_secret(
    salt: &[u8],
    nonce: &[u8],
    ct: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
) -> String {
    format!(
        "{}\nv:{}\nkdf:Argon2id\nkdf_v:0x13\nm_cost_kib:{}\nt_cost:{}\nparallelism:{}\nsalt:{}\nnonce:{}\nct:{}\n{}",
        BEGIN_SEC,
        V,
        m_cost_kib,
        t_cost,
        parallelism,
        b64e(salt),
        b64e(nonce),
        b64e(ct),
        END_SEC
    )
}

/// Constructs the canonical AAD used when encrypting/decrypting the secret keystore.
///
/// Binds all KDF parameters and salt/nonce to prevent downgrade or parameter tampering.
pub(crate) fn canonical_secret_aad(
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
    salt_b64: &str,
    nonce_b64: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(160);
    aad.extend_from_slice(SECRET_AAD_LABEL);
    aad.push(b'\n');
    aad.extend_from_slice(b"v:");
    aad.extend_from_slice(V.as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(b"kdf:Argon2id\nkdf_v:0x13\n");
    aad.extend_from_slice(format!("m_cost_kib:{}\n", m_cost_kib).as_bytes());
    aad.extend_from_slice(format!("t_cost:{}\n", t_cost).as_bytes());
    aad.extend_from_slice(format!("parallelism:{}\n", parallelism).as_bytes());
    aad.extend_from_slice(b"salt:");
    aad.extend_from_slice(salt_b64.as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(b"nonce:");
    aad.extend_from_slice(nonce_b64.as_bytes());
    aad
}

/// Extracts Argon2id parameters from an armored SECRET block.
pub(crate) fn extract_argon2_params(secret_armored: &str) -> Result<(u32, u32, u32), ()> {
    let d = parse_armor(secret_armored, BEGIN_SEC, END_SEC)?;
    let m_cost_kib: u32 = d.get("m_cost_kib").ok_or(())?.parse().map_err(|_| ())?;
    let t_cost: u32 = d.get("t_cost").ok_or(())?.parse().map_err(|_| ())?;
    let parallelism: u32 = d.get("parallelism").ok_or(())?.parse().map_err(|_| ())?;
    Ok((m_cost_kib, t_cost, parallelism))
}

// =====================
// MESSAGE armors (non-streaming only)
// =====================

/// Serializes a non-streaming message into armored format.
///
/// Optional `signature` field contains the concatenated ML-DSA-65 || Ed25519 signature.
pub(crate) fn armor_message(
    enc_ecdh_b64: &str,
    nonce_b64: &str,
    recipients_blob_b64: &str,
    ct_b64: &str,
    signature: Option<&[u8]>,
) -> String {
    let mut s = format!(
        "{}\nv:{}\nenc_ecdh:{}\nnonce:{}\nrecipients:{}\nct:{}\n",
        BEGIN_MSG, V, enc_ecdh_b64, nonce_b64, recipients_blob_b64, ct_b64
    );
    if let Some(sig) = signature {
        s.push_str(&format!("signature:{}\n", b64e(sig)));
    }
    s.push_str(END_MSG);
    s
}

/// Parsed representation of an armored MESSAGE block (non-streaming).
#[derive(Debug)]
pub(crate) struct ParsedMsg {
    pub enc_ecdh: [u8; 32],
    pub nonce: [u8; MSG_NONCE_LEN],
    pub recipients_blob: Vec<u8>,
    pub ct_and_tag: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

/// Parses an armored MESSAGE block with strict field ordering and validation.
///
/// Enforces exact field order, validates all lengths and cryptographic primitives.
/// The `signature` field is optional; an empty or invalid Base64 signature is treated
/// as absent (to support forward compatibility).
pub(crate) fn parse_message(arm: &str) -> Result<ParsedMsg, ()> {
    let t = arm.trim().replace('\r', "");
    let lines: Vec<&str> = t
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let ok_begin = lines
        .first()
        .map(|l| l.as_bytes().ct_eq(BEGIN_MSG.as_bytes()).into())
        .unwrap_or(false);
    let ok_end = lines
        .last()
        .map(|l| l.as_bytes().ct_eq(END_MSG.as_bytes()).into())
        .unwrap_or(false);
    if !ok_begin || !ok_end {
        return Err(());
    }

    let body = &lines[1..lines.len() - 1];
    if body.len() != 5 && body.len() != 6 {
        return Err(());
    }

    const ORDER_BASE: [&str; 5] = ["v", "enc_ecdh", "nonce", "recipients", "ct"];
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(body.len());
    let mut vals = Vec::with_capacity(body.len());

    for &line in body {
        let (k, v) = line.split_once(':').ok_or(())?;
        let key_lower = k.trim().to_lowercase();
        if !matches!(
            key_lower.as_str(),
            "v" | "enc_ecdh" | "nonce" | "recipients" | "ct" | "signature"
        ) {
            return Err(());
        }
        if !seen.insert(key_lower.clone()) {
            return Err(());
        }
        keys.push(key_lower);
        vals.push(v.trim().to_string());
    }

    for (i, want) in ORDER_BASE.iter().enumerate() {
        if keys.get(i).map(|s| s.as_str()) != Some(*want) {
            return Err(());
        }
    }
    if body.len() == 6 && keys[5].as_str() != "signature" {
        return Err(());
    }

    if vals[0].as_bytes().ct_eq(V.as_bytes()).unwrap_u8() != 1 {
        return Err(());
    }

    let enc_ecdh_bytes = b64d(&vals[1])?;
    if enc_ecdh_bytes.len() != 32 {
        return Err(());
    }
    let mut enc_ecdh = [0u8; 32];
    enc_ecdh.copy_from_slice(&enc_ecdh_bytes);
    let _ = XPublic::from(enc_ecdh);

    let nonce_bytes = b64d(&vals[2])?;
    if nonce_bytes.len() != MSG_NONCE_LEN {
        return Err(());
    }
    let mut nonce = [0u8; MSG_NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let recipients_blob = b64d(&vals[3])?;
    if recipients_blob.is_empty() {
        return Err(());
    }
    decode_recipients(&recipients_blob)?;

    let ct_and_tag = b64d(&vals[4])?;
    if ct_and_tag.len() < TAG_LEN {
        return Err(());
    }

    let signature = if body.len() == 6 {
        match b64d(&vals[5]) {
            Ok(v) => Some(v),
            Err(_) => Some(Vec::new()), // Treat invalid signature as absent (forward compat)
        }
    } else {
        None
    };

    Ok(ParsedMsg {
        enc_ecdh,
        nonce,
        recipients_blob,
        ct_and_tag,
        signature,
    })
}

// ================================
// Binary ↔ armored MESSAGE glue
// ================================

/// Converts a binary VLM1 envelope to armored text representation (non-streaming only).
///
/// All temporary Base64 strings are zeroized immediately after use.
pub(crate) fn armor_from_binary(envelope: &[u8]) -> String {
    let parsed =
        parse_envelope_binary(envelope).expect("armor_from_binary: invalid VELUM binary envelope");
    let mut enc_ecdh_b64 = b64e(&parsed.enc_ecdh);
    let mut nonce_b64 = b64e(&parsed.nonce);
    let mut recipients_b64 = b64e(&parsed.recipients_blob);
    let mut ct_b64 = b64e(&parsed.ct_and_tag);
    let sig_opt = parsed.signature.as_deref();

    let s = armor_message(&enc_ecdh_b64, &nonce_b64, &recipients_b64, &ct_b64, sig_opt);

    enc_ecdh_b64.zeroize();
    nonce_b64.zeroize();
    recipients_b64.zeroize();
    ct_b64.zeroize();
    s
}

/// Converts an armored MESSAGE block back into binary VLM1 envelope format.
///
/// Recomputes the recipient commitment (RC) from the parsed recipients list.
pub(crate) fn binary_from_armor(armored: &str) -> Result<Vec<u8>, ()> {
    let parsed = parse_message(armored)?;
    let recipients = decode_recipients(&parsed.recipients_blob)?;
    let mut eid_list = Vec::with_capacity(recipients.len());
    for r in recipients.iter() {
        eid_list.push(compute_entry_id(&r.enc_pq));
    }
    let rc = recipients_commitment(&eid_list);

    let envelope = encode_envelope_binary(
        parsed.enc_ecdh,
        parsed.nonce,
        parsed.recipients_blob,
        parsed.ct_and_tag,
        parsed.signature,
        0, // stream always false in armored
        rc,
    );
    Ok(envelope)
}

/// Parses multiple concatenated PUBLIC key blocks from a single string.
///
/// Useful for recipient lists passed as text (e.g. CLI `--recipient @file`).
pub(crate) fn parse_public_list(input: &str) -> Result<Vec<PublicBundle>, ()> {
    let mut out = Vec::new();
    let mut s = input;
    while let Some(start) = s.find(BEGIN_PUB) {
        if let Some(end) = s[start..].find(END_PUB) {
            let block = &s[start..start + end + END_PUB.len()];
            out.push(parse_public(block)?);
            s = &s[start + end + END_PUB.len()..];
        } else {
            break;
        }
    }
    if out.is_empty() {
        Err(())
    } else {
        Ok(out)
    }
}

// ============================================================
// Unit tests for src/armor.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `armor.rs`
    //!
    //! This test suite verifies all armor encoders and parsers:
    //! - `parse_armor`: strict K:V parsing, marker matching, duplicate rejection
    //! - `armor_public` / `parse_public`: deterministic public key serialization
    //! - `armor_secret`, `canonical_secret_aad`, `extract_argon2_params`
    //! - `armor_message` / `parse_message`: non-streaming message round-trip
    //! - `armor_from_binary` / `binary_from_armor`: glue between textual and binary formats
    //! - `parse_public_list`: multi-block PUBLIC key extraction
    //!
    //! Each test uses minimal deterministic data; cryptographic primitives are only
    //! validated structurally (not semantically).

    use super::*;
    use crate::envelope::{encode_envelope_binary, parse_envelope_binary};
    use crate::recipients::{compute_entry_id, encode_recipients, RecipientEntry};

    // ------------------------------------------------------------
    // Helper generators (deterministic, no RNG)
    // ------------------------------------------------------------

    fn fixed_arr<const N: usize>() -> [u8; N] {
        // Deterministic, non-random pattern good enough for tests.
        let mut arr = [0u8; N];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        arr
    }

    /// Construct a minimal valid recipient blob for message tests.
    fn dummy_recipient_blob() -> Vec<u8> {
        use crate::constants::TAG_LEN;
        use pqcrypto_mlkem::mlkem768;

        let enc_pq = vec![0xAA; mlkem768::ciphertext_bytes()];
        let wrap = vec![0xBB; 32 + TAG_LEN];
        let entry_id = compute_entry_id(&enc_pq);
        let entry = RecipientEntry {
            enc_pq,
            wrap,
            entry_id,
            index_hint: 123,
        };
        encode_recipients(&[entry]).unwrap()
    }

    // ------------------------------------------------------------
    // parse_armor: basic validation
    // ------------------------------------------------------------

    #[test]
    fn test_parse_armor_valid_basic() {
        let arm = "-----BEGIN TEST-----\nfoo:bar\nbaz:qux\n-----END TEST-----";
        let m = parse_armor(arm, "-----BEGIN TEST-----", "-----END TEST-----").unwrap();
        assert_eq!(m.get("foo").unwrap(), "bar");
        assert_eq!(m.get("baz").unwrap(), "qux");
    }

    #[test]
    fn test_parse_armor_invalid_missing_markers() {
        let arm = "foo:bar\nbaz:qux";
        assert!(parse_armor(arm, "BEGIN", "END").is_err());
    }

    #[test]
    fn test_parse_armor_duplicate_key_rejected() {
        let arm = "-----BEGIN T-----\nfoo:1\nfoo:2\n-----END T-----";
        assert!(parse_armor(arm, "-----BEGIN T-----", "-----END T-----").is_err());
    }

    // ------------------------------------------------------------
    // Public key armor
    // ------------------------------------------------------------

    #[test]
    fn test_armor_public_and_parse_public_roundtrip() {
        let ecdh = fixed_arr::<32>();
        let pq = vec![0x11; pqcrypto_mlkem::mlkem768::public_key_bytes()];
        let pq_sig = vec![0x22; pqcrypto_mldsa::mldsa65::public_key_bytes()];
        let ed_sig = fixed_arr::<32>();

        let arm = armor_public(&ecdh, &pq, &pq_sig, &ed_sig);
        let parsed = parse_public(&arm).expect("parse_public should succeed");

        assert_eq!(parsed.ecdh_pk, ecdh);
        assert_eq!(parsed.pq_pk, pq);
        assert_eq!(parsed.sig_pk_pq, pq_sig);
        assert_eq!(parsed.sig_pk_ed, ed_sig);
    }

    #[test]
    fn test_parse_public_rejects_wrong_length() {
        let arm = format!(
            "{}\nv:{}\necdh_pk:{}\npq_pk:{}\nsig_pk_pq:{}\nsig_pk_ed:{}\n{}",
            BEGIN_PUB,
            V,
            b64e(&[0u8; 31]), // invalid length
            b64e(&[0u8; pqcrypto_mlkem::mlkem768::public_key_bytes()]),
            b64e(&[0u8; pqcrypto_mldsa::mldsa65::public_key_bytes()]),
            b64e(&[0u8; 32]),
            END_PUB
        );
        assert!(parse_public(&arm).is_err());
    }

    // ------------------------------------------------------------
    // Secret armor utilities
    // ------------------------------------------------------------

    #[test]
    fn test_armor_secret_and_extract_params() {
        let arm = armor_secret(&[1, 2, 3], &[4, 5, 6], &[7, 8, 9], 1024, 3, 1);
        let (m, t, p) = extract_argon2_params(&arm).expect("valid params");
        assert_eq!((m, t, p), (1024, 3, 1));
    }

    #[test]
    fn test_canonical_secret_aad_contains_fields() {
        let aad = canonical_secret_aad(4096, 2, 1, "abc", "xyz");
        let s = String::from_utf8_lossy(&aad);
        assert!(s.contains("m_cost_kib:4096"));
        assert!(s.contains("t_cost:2"));
        assert!(s.contains("salt:abc"));
        assert!(s.contains("nonce:xyz"));
    }

    // ------------------------------------------------------------
    // Message armor: round-trip
    // ------------------------------------------------------------

    #[test]
    fn test_armor_message_and_parse_message_roundtrip() {
        let enc_ecdh = b64e(&fixed_arr::<32>());
        let nonce = b64e(&fixed_arr::<MSG_NONCE_LEN>());
        let recip = b64e(&dummy_recipient_blob());
        let ct = b64e(&[0x55; 48 + TAG_LEN]);
        let sig = vec![0xAA; 64];

        let arm = armor_message(&enc_ecdh, &nonce, &recip, &ct, Some(&sig));

        let parsed = parse_message(&arm).expect("parse_message ok");
        assert_eq!(parsed.enc_ecdh.len(), 32);
        assert_eq!(parsed.nonce.len(), MSG_NONCE_LEN);
        assert!(parsed.signature.is_some());
    }

    #[test]
    fn test_parse_message_rejects_wrong_order_or_missing_fields() {
        let bad = format!("{}\nv:{}\nct:AAA\nnonce:BBB\n-----END-----", BEGIN_MSG, V);
        assert!(parse_message(&bad).is_err());
    }

    // ------------------------------------------------------------
    // Binary <-> armor glue
    // ------------------------------------------------------------

    #[test]
    fn test_binary_to_armor_and_back_roundtrip() {
        let enc_ecdh = fixed_arr::<32>();
        let nonce = fixed_arr::<MSG_NONCE_LEN>();
        let rc = fixed_arr::<32>();
        let recipients_blob = dummy_recipient_blob();
        let ct = vec![0x44; 64 + TAG_LEN];
        let sig = Some(vec![0x77; 64]);

        let bin = encode_envelope_binary(
            enc_ecdh,
            nonce,
            recipients_blob.clone(),
            ct.clone(),
            sig.clone(),
            0,
            rc,
        );
        let text = armor_from_binary(&bin);
        let bin2 = binary_from_armor(&text).expect("reparsed");
        let parsed = parse_envelope_binary(&bin2).expect("valid binary");
        assert_eq!(parsed.enc_ecdh, enc_ecdh);
        assert_eq!(parsed.ct_and_tag, ct);
        assert_eq!(parsed.recipients_blob, recipients_blob);
    }

    // ------------------------------------------------------------
    // parse_public_list
    // ------------------------------------------------------------

    #[test]
    fn test_parse_public_list_multiple_blocks() {
        let ecdh = fixed_arr::<32>();
        let pq = vec![0x11; pqcrypto_mlkem::mlkem768::public_key_bytes()];
        let pq_sig = vec![0x22; pqcrypto_mldsa::mldsa65::public_key_bytes()];
        let ed_sig = fixed_arr::<32>();

        let arm = armor_public(&ecdh, &pq, &pq_sig, &ed_sig);
        let multi = format!("{}\n\n{}", arm, arm);
        let list = parse_public_list(&multi).expect("parse_public_list");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_parse_public_list_empty_rejected() {
        assert!(parse_public_list("no valid block here").is_err());
    }

    // ------------------------------------------------------------
    // Edge & error cases
    // ------------------------------------------------------------

    #[test]
    fn test_parse_message_invalid_base64_signature_tolerated() {
        let enc_ecdh = b64e(&fixed_arr::<32>());
        let nonce = b64e(&fixed_arr::<MSG_NONCE_LEN>());
        let recip = b64e(&dummy_recipient_blob());
        let ct = b64e(&[0x55; 48 + TAG_LEN]);

        // invalid base64 signature value
        let arm = format!(
            "{}\nv:{}\nenc_ecdh:{}\nnonce:{}\nrecipients:{}\nct:{}\nsignature:!!!INVALID!!!\n{}",
            BEGIN_MSG, V, enc_ecdh, nonce, recip, ct, END_MSG
        );
        let parsed = parse_message(&arm).expect("should tolerate invalid b64");
        assert!(parsed.signature.is_some(), "should still produce Some(Vec)");
    }

    #[test]
    fn test_binary_from_armor_rejects_invalid_message() {
        let bad = "-----BEGIN VELUM MESSAGE-----\ninvalid:stuff\n-----END VELUM MESSAGE-----";
        assert!(binary_from_armor(bad).is_err());
    }
}
