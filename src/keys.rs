// src/keys.rs
//
// Long-term key bundling and keystore logic.
//
// This module owns:
// - PublicBundle: all public crypto material for a recipient,
// - SecretBundle: all long-term private keys (unlocked SECRET),
// - Argon2idParams: KDF configuration,
// - SECRET keystore encoding/decoding + Argon2id + AES-GCM,
// - rewrap_secret: change passphrase / KDF parameters,
// - generate_keypair: create a fresh PUBLIC/SECRET pair.
//
// It does *not* know about recipients-blob, streaming, or the
// binary VLM1 envelope.

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::KeyInit;
use aes_gcm_siv::{aead::Payload as AesPayload, Aes256GcmSiv, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SigPublicKey, SecretKey as SigSecretKey};
use rand::RngCore;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::armor::{armor_secret, canonical_secret_aad, parse_armor};
use crate::constants::{BEGIN_SEC, END_SEC, SALT_LEN, SECRET_NONCE_LEN, TAG_LEN, V};
use crate::util::{b64d, b64e, be_u32, random_bytes, read_be_u32};

/// A parsed VELUM public-key bundle.
///
/// This struct contains **all public cryptographic material** needed to:
/// - perform recipient key-encapsulation (X25519 + ML-KEM-768),
/// - verify hybrid signatures (ML-DSA-65 + Ed25519),
/// - identify a recipient uniquely.
///
/// It corresponds to the data stored inside an armored
/// `-----BEGIN VELUM PUBLIC KEY-----` block.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub(crate) struct PublicBundle {
    /// X25519 static public key (32 bytes).
    /// Used for the ephemeral–static ECDH component of the hybrid KEM.
    pub(crate) ecdh_pk: [u8; 32],

    /// ML-KEM-768 public key (post-quantum KEM).
    pub(crate) pq_pk: Vec<u8>,

    /// ML-DSA-65 public key (~1952 bytes).
    /// Used to verify the PQ signature of the ciphertext transcript.
    pub(crate) sig_pk_pq: Vec<u8>,

    /// Ed25519 public key (32 bytes).
    /// Used to verify the classical signature of the ciphertext transcript.
    pub(crate) sig_pk_ed: [u8; 32],
}

/// A fully unlocked VELUM secret-key bundle.
///
/// This struct contains **all long-term private cryptographic keys** required for:
/// - performing decapsulation (X25519 + ML-KEM-768),
/// - producing hybrid signatures (ML-DSA-65 + Ed25519),
/// - decrypting messages addressed to this user.
///
/// It is obtained only after correctly unlocking the armored SECRET using Argon2id.
/// All fields are wiped from memory on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub(crate) struct SecretBundle {
    /// X25519 static secret key (32 bytes).
    /// Part of the hybrid KEM (ECDH).
    pub(crate) ecdh_sk: [u8; 32],

    /// ML-KEM-768 secret key (PQ decapsulation).
    pub(crate) pq_sk: Vec<u8>,

    /// ML-DSA-65 secret key (~4032 bytes).
    /// Used to generate PQ signatures that bind ciphertext metadata.
    pub(crate) sig_sk_pq: Vec<u8>,

    /// Ed25519 secret key seed (32 bytes).
    /// Used to generate classical signatures in the hybrid signing scheme.
    pub(crate) sig_sk_ed: [u8; 32],
}

/// Public configuration for Argon2id.
///
/// These are *algorithmic minimums*, not a security policy. Concrete
/// policies (e.g. “at least 96 MiB, 4 iterations”) live at call sites.
#[derive(Clone, Copy)]
pub struct Argon2idParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub parallelism: u32,
}

/// Default Argon2id parameters used by VELUM when creating new secrets.
///
/// - m_cost_kib = 96 MiB
/// - t_cost = 4
/// - parallelism = 4
impl Default for Argon2idParams {
    #[inline(always)]
    fn default() -> Self {
        Self {
            m_cost_kib: 96 * 1024, // 96 MiB
            t_cost: 4,
            parallelism: 4,
        }
    }
}

// ==========================
// SECRET blob (single-CT TLV)
// ==========================

/// Encodes four long-term secret keys into a TLV-like blob:
///
///   len(ecdh)||ecdh ||
///   len(pq)||pq ||
///   len(sig_pq)||sig_pq ||
///   len(sig_ed)||sig_ed
pub(crate) fn encode_secret_blob(
    ecdh_sk: &[u8],
    pq_sk: &[u8],
    sig_sk_pq: &[u8],
    sig_sk_ed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + ecdh_sk.len() + 4 + pq_sk.len() + 4 + sig_sk_pq.len() + 4 + sig_sk_ed.len(),
    );

    out.extend_from_slice(&be_u32(ecdh_sk.len()));
    out.extend_from_slice(ecdh_sk);

    out.extend_from_slice(&be_u32(pq_sk.len()));
    out.extend_from_slice(pq_sk);

    out.extend_from_slice(&be_u32(sig_sk_pq.len()));
    out.extend_from_slice(sig_sk_pq);

    out.extend_from_slice(&be_u32(sig_sk_ed.len()));
    out.extend_from_slice(sig_sk_ed);

    out
}

/// Decodes the TLV blob produced by `encode_secret_blob` and enforces
/// the expected sizes for each secret.
///
/// Returns the four raw key components on success.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_secret_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), ()> {
    let mut off = 0usize;

    let le = read_be_u32(blob, &mut off)?;
    if off + le > blob.len() {
        return Err(());
    }
    let e = blob[off..off + le].to_vec();
    off += le;

    let lp = read_be_u32(blob, &mut off)?;
    if off + lp > blob.len() {
        return Err(());
    }
    let p = blob[off..off + lp].to_vec();
    off += lp;

    let lspq = read_be_u32(blob, &mut off)?;
    if off + lspq > blob.len() {
        return Err(());
    }
    let s_pq = blob[off..off + lspq].to_vec();
    off += lspq;

    let lsed = read_be_u32(blob, &mut off)?;
    if off + lsed > blob.len() {
        return Err(());
    }
    let s_ed = blob[off..off + lsed].to_vec();
    off += lsed;

    // Nothing should remain.
    if off != blob.len() {
        return Err(());
    }

    // Enforce expected sizes.
    if e.len() != 32 {
        return Err(());
    }
    if p.len() != mlkem768::secret_key_bytes() {
        return Err(());
    }
    if s_pq.len() != mldsa65::secret_key_bytes() {
        return Err(());
    }
    if s_ed.len() != 32 {
        return Err(());
    }

    Ok((e, p, s_pq, s_ed))
}

// ==========================
// Argon2id + KDF utilities
// ==========================

/// Derives a 32-byte key from `pass` and `salt` using Argon2id.
pub(crate) fn pbkdf(
    pass: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
) -> Result<[u8; 32], ()> {
    let mut out = [0u8; 32];

    let params = Params::new(
        m_cost_kib,  // memory (KiB)
        t_cost,      // iterations
        parallelism, // parallelism
        Some(32),    // output length
    )
    .map_err(|_| ())?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| ())?;

    Ok(out)
}

/// Minimal algorithmic constraints for Argon2id parameters.
///
/// These are not *policy* constraints, only the minimum required for
/// correct operation of Argon2id.
pub(crate) fn validate_argon2_params(p: &Argon2idParams) -> Result<(), ()> {
    // Argon2id becomes unstable below ~8 KiB.
    if p.m_cost_kib < 8 {
        return Err(());
    }
    if p.t_cost < 1 {
        return Err(());
    }
    if p.parallelism < 1 {
        return Err(());
    }
    Ok(())
}

// ==========================
// SECRET keystore unlock
// ==========================

/// Unlocks an armored VELUM SECRET key using Argon2id + AES-256-GCM.
///
/// Steps:
/// - parse armor and validate version,
/// - parse and validate KDF parameters,
/// - derive 32-byte AES key using Argon2id,
/// - decrypt single AEAD ciphertext with canonical AAD,
/// - decode TLV blob into four long-term keys,
/// - validate key sizes and encodings (X25519, ML-KEM, Ed25519),
/// - return `SecretBundle` (zeroized on drop).
pub(crate) fn unlock_secret(arm: &str, pass: &str) -> Result<SecretBundle, ()> {
    if pass.trim().is_empty() {
        return Err(());
    }

    let d = parse_armor(arm, BEGIN_SEC, END_SEC)?;

    // Strict version check (constant-time).
    if !d
        .get("v")
        .map(|s| s.as_bytes().ct_eq(V.as_bytes()).into())
        .unwrap_or(false)
    {
        return Err(());
    }

    // Required KDF headers.
    let kdf = d.get("kdf").ok_or(())?;
    if kdf != "Argon2id" {
        return Err(());
    }

    let kdf_v = d.get("kdf_v").ok_or(())?;
    if kdf_v != "0x13" {
        return Err(());
    }

    let m_cost_kib: u32 = d.get("m_cost_kib").ok_or(())?.parse().map_err(|_| ())?;
    let t_cost: u32 = d.get("t_cost").ok_or(())?.parse().map_err(|_| ())?;
    let parallelism: u32 = d.get("parallelism").ok_or(())?.parse().map_err(|_| ())?;

    // Cryptographic fields.
    let salt = b64d(d.get("salt").ok_or(())?)?;
    let nonce_v = b64d(d.get("nonce").ok_or(())?)?;
    let ct = b64d(d.get("ct").ok_or(())?)?;

    if nonce_v.len() != SECRET_NONCE_LEN || ct.len() < TAG_LEN {
        return Err(());
    }

    // Derive AES-256 key via Argon2id.
    let mut key = pbkdf(pass, &salt, m_cost_kib, t_cost, parallelism).map_err(|_| ())?;
    let aes = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(aes) => aes,
        Err(_) => {
            key.zeroize();
            return Err(());
        }
    };

    // Canonical AAD binds all KDF headers + salt + nonce.
    let salt_b64_s = d.get("salt").ok_or(())?;
    let nonce_b64_s = d.get("nonce").ok_or(())?;

    let mut aad = canonical_secret_aad(m_cost_kib, t_cost, parallelism, salt_b64_s, nonce_b64_s);

    // Decrypt into Zeroizing buffer.
    let plain = match aes.decrypt(
        AesNonce::from_slice(&nonce_v),
        AesPayload {
            msg: &ct,
            aad: &aad,
        },
    ) {
        Ok(p) => {
            aad.zeroize();
            Zeroizing::new(p.to_vec())
        }
        Err(_) => {
            aad.zeroize();
            key.zeroize();
            return Err(());
        }
    };

    // Decode TLV blob into four keys.
    let (ecdh_sk_v, pq_sk_v, sig_sk_pq_v, sig_sk_ed_v) = match decode_secret_blob(&plain) {
        Ok(quads) => quads,
        Err(_) => {
            key.zeroize();
            return Err(());
        }
    };

    // Enforce expected sizes again (defensive).
    if ecdh_sk_v.len() != 32
        || pq_sk_v.len() != mlkem768::secret_key_bytes()
        || sig_sk_pq_v.len() != mldsa65::secret_key_bytes()
        || sig_sk_ed_v.len() != 32
    {
        key.zeroize();
        return Err(());
    }

    // Validate encodings and copy into fixed-size buffers.
    let mut e = [0u8; 32];
    e.copy_from_slice(&ecdh_sk_v);
    let _ = XSecret::from(e);
    let _ = mlkem768::SecretKey::from_bytes(&pq_sk_v).map_err(|_| ())?;

    let mut sig_ed = [0u8; 32];
    sig_ed.copy_from_slice(&sig_sk_ed_v);
    let _ = Ed25519SigningKey::from_bytes(&sig_ed);

    // Drop KDF key material.
    key.zeroize();

    Ok(SecretBundle {
        ecdh_sk: e,
        pq_sk: pq_sk_v,
        sig_sk_pq: sig_sk_pq_v,
        sig_sk_ed: sig_ed,
    })
}

// ==========================
// SECRET rewrap (change pass)
// ==========================

/// Rewraps a SECRET keystore under a new passphrase and (optionally)
/// new Argon2id parameters.
///
/// If `params_opt` is:
/// - `Some(custom)` – uses the provided parameters (validated),
/// - `None`         – reuses parameters from the old SECRET.
///
/// Returns a new armored SECRET block on success.
pub(crate) fn rewrap_secret(
    old_armored: &str,
    old_pass: &str,
    new_pass: &str,
    params_opt: Option<Argon2idParams>,
) -> Result<String, ()> {
    if old_pass.trim().is_empty() || new_pass.trim().is_empty() {
        return Err(());
    }

    // 1) Unlock the old SECRET.
    let sb = unlock_secret(old_armored, old_pass)?;

    // 2) Decide on Argon2id parameters.
    let Argon2idParams {
        m_cost_kib,
        t_cost,
        parallelism,
    } = match params_opt {
        Some(custom) => {
            validate_argon2_params(&custom)?;
            custom
        }
        None => {
            let (m_cost_kib, t_cost, parallelism) =
                crate::armor::extract_argon2_params(old_armored)?;            
            let old = Argon2idParams {
                m_cost_kib,
                t_cost,
                parallelism,
            };
            validate_argon2_params(&old)?;
            old
        }
    };

    // 3) Fresh salt + nonce for the new SECRET.
    let salt = random_bytes(SALT_LEN);
    let nonce_v = random_bytes(SECRET_NONCE_LEN);

    // 4) Derive new AES key with Argon2id.
    let mut key = pbkdf(new_pass, &salt, m_cost_kib, t_cost, parallelism).map_err(|_| ())?;

    let aes = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(aes) => aes,
        Err(_) => {
            key.zeroize();
            return Err(());
        }
    };

    // 5) Build canonical AAD for the new SECRET.
    let salt_b64 = b64e(&salt);
    let nonce_b64 = b64e(&nonce_v);
    let mut aad = canonical_secret_aad(m_cost_kib, t_cost, parallelism, &salt_b64, &nonce_b64);

    // 6) Build TLV blob from the unlocked SecretBundle.
    let mut blob = encode_secret_blob(&sb.ecdh_sk, &sb.pq_sk, &sb.sig_sk_pq, &sb.sig_sk_ed);

    // 7) Encrypt blob in-place, zeroizing on all paths.
    let ct = match aes.encrypt(
        AesNonce::from_slice(&nonce_v),
        AesPayload {
            msg: &blob,
            aad: &aad,
        },
    ) {
        Ok(c) => {
            blob.zeroize();
            c
        }
        Err(_) => {
            blob.zeroize();
            aad.zeroize();
            key.zeroize();
            return Err(());
        }
    };

    // 8) Build new armored SECRET.
    let out = armor_secret(&salt, &nonce_v, &ct, m_cost_kib, t_cost, parallelism);

    // 9) Cleanup.
    aad.zeroize();
    key.zeroize();

    Ok(out)
}

// ==========================
// Key generation
// ==========================

/// Internal helper: generate a fresh (PUBLIC, SECRET) pair for VELUM.
///
/// - X25519 static keypair,
/// - ML-KEM-768 keypair,
/// - ML-DSA-65 keypair,
/// - Ed25519 seed + verifying key,
/// - SECRET keystore sealed using default Argon2id parameters.
pub(crate) fn generate_keypair_core(pass: &str) -> Result<(String, String), ()> {
    if pass.trim().is_empty() {
        return Err(()); // empty passphrase is rejected
    }

    // X25519
    let x_sk = XSecret::random_from_rng(rand::rngs::OsRng);
    let x_pk = XPublic::from(&x_sk);

    // ML-KEM-768
    let (pq_pk, pq_sk) = mlkem768::keypair();

    // ML-DSA-65
    let (sig_pk_dil, sig_sk_dil) = mldsa65::keypair();

    // Ed25519 (32-byte seed)
    let mut ed_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ed_seed);

    let ed_signing = Ed25519SigningKey::from_bytes(&ed_seed);
    let ed_verify = Ed25519VerifyingKey::from(&ed_signing);
    drop(ed_signing);

    // PUBLIC armor.
    let pub_arm = crate::armor::armor_public(
        x_pk.as_bytes(),
        pq_pk.as_bytes(),
        sig_pk_dil.as_bytes(),
        ed_verify.as_bytes(),
    );

    // SECRET: AES-GCM + Argon2id + AAD (single-CT keystore).
    let Argon2idParams {
        m_cost_kib,
        t_cost,
        parallelism,
    } = Argon2idParams::default();

    let salt = random_bytes(SALT_LEN);
    let mut key = pbkdf(pass, &salt, m_cost_kib, t_cost, parallelism)?;

    let aes = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(a) => a,
        Err(_) => {
            key.zeroize();
            return Err(());
        }
    };

    // Build blob with all four secrets (TLV).
    let mut sig_sk_pq_bytes = sig_sk_dil.as_bytes().to_vec();
    let mut sig_sk_ed_bytes = ed_seed;
    ed_seed.zeroize();

    let mut blob = encode_secret_blob(
        &x_sk.to_bytes(),
        pq_sk.as_bytes(),
        &sig_sk_pq_bytes,
        &sig_sk_ed_bytes,
    );

    sig_sk_pq_bytes.zeroize();
    sig_sk_ed_bytes.zeroize();

    // Single nonce for the SECRET keystore.
    let nonce_v = random_bytes(SECRET_NONCE_LEN);

    // Canonical AAD tying KDF + salt + nonce.
    let salt_b64 = b64e(&salt);
    let nonce_b64 = b64e(&nonce_v);
    let mut secret_aad =
        canonical_secret_aad(m_cost_kib, t_cost, parallelism, &salt_b64, &nonce_b64);

    let ct = match aes.encrypt(
        AesNonce::from_slice(&nonce_v),
        AesPayload {
            msg: &blob,
            aad: &secret_aad,
        },
    ) {
        Ok(c) => c,
        Err(_) => {
            blob.zeroize();
            secret_aad.zeroize();
            key.zeroize();
            return Err(());
        }
    };

    // Build armored SECRET with embedded KDF parameters.
    let sec_arm = armor_secret(&salt, &nonce_v, &ct, m_cost_kib, t_cost, parallelism);

    // Cleanup.
    blob.zeroize();
    secret_aad.zeroize();
    key.zeroize();

    Ok((pub_arm, sec_arm))
}

/// Public Rust API: generate a fresh (PUBLIC, SECRET) pair as armors.
///
/// This is the main key-generation entry point for library users.
pub fn generate_keypair(pass: &str) -> Result<(String, String), ()> {
    generate_keypair_core(pass)
}

pub fn validate_public(arm: &str) -> Result<(), ()> {
    crate::armor::parse_public(arm).map(|_| ())
}

pub fn validate_secret(arm: &str, pass: &str) -> Result<(), ()> {
    unlock_secret(arm, pass).map(|_| ())
    // SecretBundle is immediately dropped here and zeroized
}

pub fn rewrap_secret_with_params(
    old_secret: &str,
    old_pass: &str,
    new_pass: &str,
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
) -> Result<String, ()> {
    let params = Argon2idParams {
        m_cost_kib,
        t_cost,
        parallelism,
    };
    rewrap_secret(old_secret, old_pass, new_pass, Some(params))
}

// ============================================================
// Unit tests for src/keys.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `keys.rs`
    //!
    //! Focused on deterministic, structural correctness of:
    //! - `encode_secret_blob` / `decode_secret_blob`
    //! - `pbkdf` (Argon2id derivation)
    //! - `validate_argon2_params`
    //! - `Argon2idParams::default()`
    //!
    //! The heavy crypto (KEM, PQ sigs, AES) and keypair generation are
    //! intentionally *not* tested here — they are validated in higher
    //! integration tests. This suite only ensures that low-level helpers
    //! behave predictably and reject malformed input.

    use super::*;
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_mlkem::mlkem768;

    // ------------------------------------------------------------
    // Deterministic helpers
    // ------------------------------------------------------------

    fn fixed_vec(len: usize, base: u8) -> Vec<u8> {
        (0..len).map(|i| base.wrapping_add(i as u8)).collect()
    }

    /// Generate a test SECRET armor suitable for KDF / Argon2id tests.
    ///
    /// Returns:
    /// - `secret_armor` – armored VELUM SECRET key protected by "test-pass".
    fn test_keypair_secret() -> String {
        let (_pub, sec) =
            generate_keypair("test-pass").expect("test keypair generation must succeed");
        sec
    }

    // ------------------------------------------------------------
    // encode_secret_blob / decode_secret_blob
    // ------------------------------------------------------------

    #[test]
    fn encode_and_decode_secret_blob_roundtrip() {
        let ecdh = fixed_vec(32, 1);
        let pq = fixed_vec(mlkem768::secret_key_bytes(), 2);
        let spq = fixed_vec(mldsa65::secret_key_bytes(), 3);
        let sed = fixed_vec(32, 4);

        let blob = encode_secret_blob(&ecdh, &pq, &spq, &sed);
        assert!(blob.len() > ecdh.len() + pq.len());

        let (d_ecdh, d_pq, d_spq, d_sed) = decode_secret_blob(&blob).expect("decode ok");

        assert_eq!(d_ecdh, ecdh);
        assert_eq!(d_pq, pq);
        assert_eq!(d_spq, spq);
        assert_eq!(d_sed, sed);
    }

    #[test]
    fn decode_secret_blob_rejects_truncated_data() {
        let ecdh = fixed_vec(32, 1);
        let pq = fixed_vec(mlkem768::secret_key_bytes(), 2);
        let spq = fixed_vec(mldsa65::secret_key_bytes(), 3);
        let sed = fixed_vec(32, 4);

        let mut blob = encode_secret_blob(&ecdh, &pq, &spq, &sed);
        blob.truncate(blob.len() - 10); // break alignment

        assert!(decode_secret_blob(&blob).is_err());
    }

    #[test]
    fn decode_secret_blob_rejects_wrong_sizes() {
        // smaller PQ key than expected
        let blob = encode_secret_blob(&[0u8; 32], &[1u8; 8], &[2u8; 8], &[3u8; 32]);
        assert!(decode_secret_blob(&blob).is_err());
    }

    // ------------------------------------------------------------
    // Argon2id KDF
    // ------------------------------------------------------------

    #[test]
    fn pbkdf_produces_32_bytes_and_is_deterministic() {
        let salt = [7u8; 16];
        let key1 = pbkdf("pass123", &salt, 8 * 1024, 2, 2).expect("ok");
        let key2 = pbkdf("pass123", &salt, 8 * 1024, 2, 2).expect("ok");
        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2);
    }

    #[test]
    fn pbkdf_fails_on_invalid_params() {
        // ridiculous parameters: 0 memory
        let salt = [1u8; 8];
        let r = pbkdf("x", &salt, 0, 1, 1);
        assert!(r.is_err());
    }

    // ------------------------------------------------------------
    // Argon2idParams validation
    // ------------------------------------------------------------

    #[test]
    fn validate_argon2_params_rejects_too_small_values() {
        let p1 = Argon2idParams {
            m_cost_kib: 1,
            t_cost: 1,
            parallelism: 1,
        };
        assert!(validate_argon2_params(&p1).is_err());

        let p2 = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 0,
            parallelism: 1,
        };
        assert!(validate_argon2_params(&p2).is_err());

        let p3 = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            parallelism: 0,
        };
        assert!(validate_argon2_params(&p3).is_err());
    }

    #[test]
    fn validate_argon2_params_accepts_minimum_valid() {
        let p = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            parallelism: 1,
        };
        assert!(validate_argon2_params(&p).is_ok());
    }

    // ------------------------------------------------------------
    // Argon2idParams::default
    // ------------------------------------------------------------

    #[test]
    fn argon2idparams_default_values_are_expected() {
        let d = Argon2idParams::default();
        assert!(d.m_cost_kib >= 96 * 1024);
        assert_eq!(d.t_cost, 4);
        assert_eq!(d.parallelism, 4);
    }

    // ============================================================
    // Secret armor tampering (KDF headers / salt)
    // ============================================================

    /// Tamper with the `salt:` header in SECRET armor and ensure
    /// that `rewrap_secret` rejects it.
    ///
    /// Rationale:
    /// - salt is part of the Argon2id KDF input.
    /// - changing it in the header without changing the ciphertext
    ///   must make decryption / rewrap fail.
    #[test]
    fn test_rewrap_secret_fails_if_salt_tampered() {
        let sec = test_keypair_secret();

        let mut lines: Vec<String> = sec.lines().map(|s| s.to_string()).collect();
        let mut tampered_any = false;

        for line in lines.iter_mut() {
            if let Some(rest) = line.strip_prefix("salt:") {
                let mut b = rest.trim().as_bytes().to_vec();
                if !b.is_empty() {
                    // Flip first char in Base64 alphabet (A ↔ B) to keep it syntactically valid.
                    b[0] = if b[0] == b'A' { b'B' } else { b'A' };
                    *line = format!("salt:{}", String::from_utf8(b).unwrap());
                    tampered_any = true;
                    break;
                }
            }
        }

        assert!(tampered_any, "SECRET armor must contain a salt: header");

        let tampered = lines.join("\n");
        let res = rewrap_secret(&tampered, "test-pass", "new-pass", None);

        assert!(
            res.is_err(),
            "tampering salt in SECRET armor must cause rewrap_secret to fail"
        );
    }

    /// Tamper with the `kdf_v:` header in SECRET armor and ensure
    /// that `rewrap_secret` rejects it.
    ///
    /// Rationale:
    /// - KDF version controls how the blob is interpreted.
    /// - Mismatch between `kdf_v` and the actual encoding must be fatal.
    #[test]
    fn test_rewrap_secret_fails_if_kdf_version_tampered() {
        let sec = test_keypair_secret();

        let mut lines: Vec<String> = sec.lines().map(|s| s.to_string()).collect();
        let mut tampered_any = false;

        for line in lines.iter_mut() {
            if let Some(rest) = line.strip_prefix("kdf_v:") {
                let v = rest.trim();
                // Simple toggle between two values: 0x13 <-> 0x14.
                let new_v = if v == "0x13" { "0x14" } else { "0x13" };
                *line = format!("kdf_v:{}", new_v);
                tampered_any = true;
                break;
            }
        }

        assert!(tampered_any, "SECRET armor must contain a kdf_v: header");

        let tampered = lines.join("\n");
        let res = rewrap_secret(&tampered, "test-pass", "new-pass", None);

        assert!(
            res.is_err(),
            "tampering kdf_v in SECRET armor must cause rewrap_secret to fail"
        );
    }

    /// Tamper with the `t_cost:` header in SECRET armor by adding 1
    /// and verify that `rewrap_secret` fails.
    ///
    /// Rationale:
    /// - t_cost is part of KDF parameters; changing it in the header
    ///   but not regenerating the blob must desynchronize KDF settings
    ///   from the actual ciphertext and lead to failure.
    #[test]
    fn test_rewrap_secret_fails_if_t_cost_tampered() {
        let sec = test_keypair_secret();

        let mut lines: Vec<String> = sec.lines().map(|s| s.to_string()).collect();
        let mut tampered_any = false;

        for line in lines.iter_mut() {
            if let Some(rest) = line.strip_prefix("t_cost:") {
                if let Ok(mut n) = rest.trim().parse::<u32>() {
                    n = n.saturating_add(1);
                    *line = format!("t_cost:{}", n);
                    tampered_any = true;
                    break;
                }
            }
        }

        assert!(tampered_any, "SECRET armor must contain a t_cost: header");

        let tampered = lines.join("\n");
        let res = rewrap_secret(&tampered, "test-pass", "new-pass", None);

        assert!(
            res.is_err(),
            "tampering t_cost in SECRET armor must cause rewrap_secret to fail"
        );
    }

    /// Remove the KDF version header (`kdf_v:`) from SECRET armor
    /// and verify that `rewrap_secret` rejects such input.
    ///
    /// Rationale:
    /// - SECRET armor without KDF metadata is structurally incomplete
    ///   and must never be accepted as a valid input for rewrapping.
    #[test]
    fn test_rewrap_secret_rejects_missing_kdf_header() {
        let sec = test_keypair_secret();

        let without_kdf = sec
            .lines()
            .filter(|l| !l.trim_start().starts_with("kdf_v:"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            without_kdf != sec,
            "original SECRET armor must contain a kdf_v: line"
        );

        let res = rewrap_secret(&without_kdf, "test-pass", "new-pass", None);

        assert!(
            res.is_err(),
            "rewrap_secret must fail if required KDF header is missing"
        );
    }
}
