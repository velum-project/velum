// core.rs
//
// High-level VELUM v1 encryption/decryption logic (zero-seek version).
// - PUBLIC/SECRET/MESSAGE armoring (armor.rs),
// - key bundles & keystore (keys.rs),
// - multi-recipient KEM (recipients.rs),
// - binary envelope (envelope.rs),
// - transcripts/AAD/signatures (transcript.rs),
// - streaming payloads and I/O (streaming.rs; NO Seek anywhere),
// - shared contexts (context.rs).

#![allow(clippy::result_unit_err)]

use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};
use std::str;

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, Payload as ChaChaPayload},
    Key as ChaChaKey, KeyInit, Tag as ChaChaTag, XChaCha20Poly1305, XNonce as ChaChaNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;

use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SigDetachedSignature, PublicKey as SigPublicKey,
    SecretKey as SigSecretKey, SignedMessage as SigSignedMessage,
};

use crate::armor::{armor_from_binary, binary_from_armor, parse_message, parse_public_list};
use crate::constants::{
    MSG_FLAG_SIGTRAILER, MSG_FLAG_STREAM, MSG_MAGIC, MSG_NONCE_LEN, MSG_VERSION, TAG_LEN,
    TRAILER_MAGIC, TRAILER_SENTINEL_LEN, V, WRAP_AAD_LABEL, WRAP_INFO_LABEL, WRAP_NONCE_INFO_LABEL,
};
use crate::context::{DecryptContext, EncryptHandshake};
use crate::envelope::{encode_envelope_binary, parse_envelope_binary, StreamFlag};
use crate::keys::unlock_secret;
use crate::recipients::{
    compute_entry_id, compute_index_hint, decode_recipients, encode_recipients,
    recipients_commitment, RecipientEntry,
};
use crate::streaming::encrypt_stream_chunks;
use crate::transcript::{
    canonical_aad, canonical_sig_nonstream, canonical_sig_stream_digest, verify_signature_status,
};
use crate::util::b64e;

// ======================================================================
// 0. Internal stream switch for in-RAM APIs.
// ======================================================================

#[allow(dead_code)]
pub(crate) enum StreamMode {
    Off,
    On { chunk_size: usize },
}

// ======================================================================
// 1. Handshake construction (encrypt/decrypt)
// ======================================================================

/// Build an encryption handshake:
/// - parses recipients,
/// - generates ephemeral X25519,
/// - samples CEK,
/// - runs hybrid KEM for each recipient (X25519 + ML-KEM-768),
/// - derives per-recipient KEKs and wraps CEK,
/// - computes RC and recipients_blob,
/// - samples content nonce.
pub(crate) fn build_encrypt_handshake(
    recipients_armored: &str,
    stream_on: bool,
) -> Result<EncryptHandshake, ()> {
    // 1) Parse PUBLIC-key blocks and deduplicate.
    let mut recips = parse_public_list(recipients_armored).map_err(|_| ())?;
    recips.sort_by(|a, b| a.ecdh_pk.cmp(&b.ecdh_pk).then(a.pq_pk.cmp(&b.pq_pk)));
    recips.dedup_by(|a, b| a.ecdh_pk == b.ecdh_pk && a.pq_pk == b.pq_pk);
    if recips.is_empty() {
        return Err(());
    }

    // 2) Ephemeral X25519.
    let eph_sk = XSecret::random_from_rng(OsRng);
    let eph_pk = XPublic::from(&eph_sk);
    let enc_ecdh_raw = *eph_pk.as_bytes();
    let mut enc_ecdh_b64 = b64e(&enc_ecdh_raw);

    // 3) CEK (32 bytes).
    let mut cek = [0u8; 32];
    OsRng.fill_bytes(&mut cek);

    // --- Phase 1: temporary per-recipient secrets ---
    struct TempRecipient {
        ss_ecdh: Zeroizing<Vec<u8>>,
        ss_kyber: Zeroizing<Vec<u8>>,
        enc_pq: Vec<u8>,
    }

    let mut temp: Vec<TempRecipient> = Vec::with_capacity(recips.len());
    for pb in recips.iter() {
        // ECDH.
        let recip_x = XPublic::from(pb.ecdh_pk);
        let ss_ecdh = eph_sk.diffie_hellman(&recip_x);
        let ss_ecdh_bytes = ss_ecdh.as_bytes().to_vec();

        // ML-KEM.
        let pq_pub = mlkem768::PublicKey::from_bytes(&pb.pq_pk).map_err(|_| ())?;
        let (ss_kyber, ct_pq) = mlkem768::encapsulate(&pq_pub);
        if ct_pq.as_bytes().len() != mlkem768::ciphertext_bytes() {
            cek.zeroize();
            enc_ecdh_b64.zeroize();
            // temp will be automatically zeroized on drop (Zeroizing wrappers)
            return Err(());
        }

        temp.push(TempRecipient {
            ss_ecdh: Zeroizing::new(ss_ecdh_bytes),
            ss_kyber: Zeroizing::new(ss_kyber.as_bytes().to_vec()),
            enc_pq: ct_pq.as_bytes().to_vec(),
        });
    }

    // --- Phase 2: entry_ids + RC ---
    let mut entry_ids: Vec<[u8; 32]> = Vec::with_capacity(temp.len());
    for te in temp.iter() {
        entry_ids.push(compute_entry_id(&te.enc_pq));
    }
    let rc = recipients_commitment(&entry_ids);

    // --- Phase 3: final RecipientEntry with wrap + index_hint ---
    let mut final_entries: Vec<RecipientEntry> = Vec::with_capacity(temp.len());

    for (idx, te) in temp.into_iter().enumerate() {
        // HKDF: salt = RC, IKM = ss_ecdh || ss_kyber.
        let mut ikm = Vec::with_capacity(te.ss_ecdh.len() + te.ss_kyber.len());
        ikm.extend_from_slice(&te.ss_ecdh);
        ikm.extend_from_slice(&te.ss_kyber);
        let hk = Hkdf::<Sha256>::new(Some(&rc), &ikm);
        ikm.zeroize();

        // KEK_i
        let mut kek_bytes = [0u8; 32];
        let mut info = Vec::with_capacity(WRAP_INFO_LABEL.len() + 32);
        info.extend_from_slice(WRAP_INFO_LABEL);
        info.extend_from_slice(&entry_ids[idx]);
        hk.expand(&info, &mut kek_bytes).map_err(|_| ())?;
        info.zeroize();

        let mut kek = ChaChaKey::from_slice(&kek_bytes).to_owned();
        kek_bytes.zeroize();

        // nonce_wrap_i
        let mut nonce_wrap = [0u8; MSG_NONCE_LEN];
        let mut ninfo = Vec::with_capacity(WRAP_NONCE_INFO_LABEL.len() + 32);
        ninfo.extend_from_slice(WRAP_NONCE_INFO_LABEL);
        ninfo.extend_from_slice(&entry_ids[idx]);
        hk.expand(&ninfo, &mut nonce_wrap).map_err(|_| ())?;
        ninfo.zeroize();
        let nonce_w = ChaChaNonce::from_slice(&nonce_wrap);

        // index_hint: deterministic, uses secret ss_ecdh.
        let mut ss_arr = [0u8; 32];
        ss_arr.copy_from_slice(&te.ss_ecdh);
        let index_hint = compute_index_hint(&entry_ids[idx], &enc_ecdh_raw, &rc, &ss_arr);
        ss_arr.zeroize();

        // AAD for wrap.
        let id_b64 = b64e(&entry_ids[idx]);
        let hint_b64 = b64e(&index_hint.to_be_bytes());
        let mut aad_wrap = Vec::with_capacity(224);
        aad_wrap.extend_from_slice(WRAP_AAD_LABEL);
        aad_wrap.push(b'\n');
        aad_wrap.extend_from_slice(b"v:");
        aad_wrap.extend_from_slice(V.as_bytes());
        aad_wrap.push(b'\n');
        aad_wrap.extend_from_slice(b"enc_ecdh:");
        aad_wrap.extend_from_slice(enc_ecdh_b64.as_bytes());
        aad_wrap.push(b'\n');
        aad_wrap.extend_from_slice(b"id:");
        aad_wrap.extend_from_slice(id_b64.as_bytes());
        aad_wrap.push(b'\n');
        aad_wrap.extend_from_slice(b"hint:");
        aad_wrap.extend_from_slice(hint_b64.as_bytes());
        aad_wrap.push(b'\n');
        aad_wrap.extend_from_slice(b"rc:");
        aad_wrap.extend_from_slice(b64e(&rc).as_bytes());

        let aead = XChaCha20Poly1305::new(&kek);
        let wrap = aead
            .encrypt(
                nonce_w,
                ChaChaPayload {
                    msg: &cek,
                    aad: &aad_wrap,
                },
            )
            .map_err(|_| ())?;

        aad_wrap.zeroize();
        nonce_wrap.zeroize();
        kek.zeroize();

        final_entries.push(RecipientEntry {
            enc_pq: te.enc_pq.clone(),
            wrap,
            entry_id: entry_ids[idx],
            index_hint,
        });
    }

    let recipients_blob = encode_recipients(&final_entries).map_err(|_| ())?;

    // Content AEAD nonce (also bound into AAD / transcripts).
    let mut nonce = [0u8; MSG_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    enc_ecdh_b64.zeroize();

    Ok(EncryptHandshake::new(
        stream_on,
        enc_ecdh_raw,
        nonce,
        rc,
        recipients_blob,
        cek,
    ))
}

/// Build decryption context:
/// - parses binary envelope,
/// - unlocks SECRET,
/// - parses recipients blob,
/// - recomputes RC and checks,
/// - derives CEK via KEM and unwraps it from recipients list.
pub(crate) fn build_decrypt_context(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
) -> Result<DecryptContext, ()> {
    use crate::util::b64e;

    if passphrase.trim().is_empty() {
        return Err(());
    }
    if my_secret_armored.trim().is_empty() {
        return Err(());
    }

    // 1) parse envelope
    let parsed = parse_envelope_binary(bytes).map_err(|_| ())?;

    // 2) unlock secret bundle
    let sb = unlock_secret(my_secret_armored, passphrase).map_err(|_| ())?;

    // 3) recipients + RC
    let recipients = decode_recipients(&parsed.recipients_blob).map_err(|_| ())?;

    let mut eid_list = Vec::with_capacity(recipients.len());
    for r in recipients.iter() {
        eid_list.push(compute_entry_id(&r.enc_pq));
    }

    let rc_calc = recipients_commitment(&eid_list);
    if rc_calc.ct_eq(&parsed.rc).unwrap_u8() != 1 {
        return Err(());
    }
    let rc = rc_calc;

    // no duplicate entry_ids
    let mut sorted = eid_list.clone();
    sorted.sort();
    let mut tmp = sorted.clone();
    tmp.dedup();
    if tmp.len() != sorted.len() {
        return Err(());
    }

    // 4) KEM: find CEK for this recipient
    let my_ecdh = XSecret::from(sb.ecdh_sk);
    let their_eph_pub = XPublic::from(parsed.enc_ecdh);
    let my_pq = mlkem768::SecretKey::from_bytes(&sb.pq_sk).map_err(|_| ())?;

    let my_ss_ecdh = my_ecdh.diffie_hellman(&their_eph_pub);
    let my_ss_arr: [u8; 32] = *my_ss_ecdh.as_bytes();

    let mut found_cek: Option<[u8; 32]> = None;

    for r in recipients.iter() {
        // Skip expensive operations if we already found the CEK
        if found_cek.is_some() {
            continue;
        }

        // O(1) hint check
        let expected_hint = compute_index_hint(&r.entry_id, &parsed.enc_ecdh, &rc, &my_ss_arr);
        if r.index_hint != expected_hint {
            continue;
        }

        let ct_pq = match mlkem768::Ciphertext::from_bytes(&r.enc_pq) {
            Ok(ct) => ct,
            Err(_) => continue,
        };
        let ss_kyber = mlkem768::decapsulate(&ct_pq, &my_pq);

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(my_ss_ecdh.as_bytes());
        ikm.extend_from_slice(ss_kyber.as_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&rc), &ikm);
        ikm.zeroize();

        // KEK_i
        let mut kek_bytes = [0u8; 32];
        {
            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(WRAP_INFO_LABEL);
            info.extend_from_slice(&r.entry_id);
            if hk.expand(&info, &mut kek_bytes).is_err() {
                continue;
            }
        }
        let mut kek = ChaChaKey::from_slice(&kek_bytes).to_owned();
        kek_bytes.zeroize();

        // nonce_wrap_i
        let mut nonce_wrap = [0u8; MSG_NONCE_LEN];
        {
            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(WRAP_NONCE_INFO_LABEL);
            info.extend_from_slice(&r.entry_id);
            if hk.expand(&info, &mut nonce_wrap).is_err() {
                nonce_wrap.zeroize();
                kek.zeroize();
                continue;
            }
        }
        let nonce_w = ChaChaNonce::from_slice(&nonce_wrap);

        // AAD for wrap
        let id_b64 = b64e(&r.entry_id);
        let hint_b64 = b64e(&r.index_hint.to_be_bytes());
        let mut aad = Vec::new();
        aad.extend_from_slice(WRAP_AAD_LABEL);
        aad.push(b'\n');
        aad.extend_from_slice(b"v:");
        aad.extend_from_slice(V.as_bytes());
        aad.push(b'\n');
        aad.extend_from_slice(b"enc_ecdh:");
        aad.extend_from_slice(b64e(&parsed.enc_ecdh).as_bytes());
        aad.push(b'\n');
        aad.extend_from_slice(b"id:");
        aad.extend_from_slice(id_b64.as_bytes());
        aad.push(b'\n');
        aad.extend_from_slice(b"hint:");
        aad.extend_from_slice(hint_b64.as_bytes());
        aad.push(b'\n');
        aad.extend_from_slice(b"rc:");
        aad.extend_from_slice(b64e(&rc).as_bytes());

        let aead = XChaCha20Poly1305::new(&kek);
        if let Ok(cek_bytes) = aead.decrypt(
            nonce_w,
            ChaChaPayload {
                msg: &r.wrap,
                aad: &aad,
            },
        ) {
            if cek_bytes.len() == 32 {
                let mut cek_arr = [0u8; 32];
                cek_arr.copy_from_slice(&cek_bytes);
                found_cek = Some(cek_arr);
            }
        }

        nonce_wrap.zeroize();
        aad.zeroize();
        kek.zeroize();
    }

    let cek = found_cek.ok_or(())?;

    Ok(DecryptContext::new(parsed, rc, cek))
}

// ======================================================================
// 2. Content AEAD (non-stream / in-RAM stream) – zero-seek aware
// ======================================================================

/// Decrypt content in one shot (no chunk callbacks).
///
/// NOTE: For stream:Y this version understands the *sentinel* at the end of
/// frames and ignores the optional trailer (signature is handled elsewhere).
fn decrypt_content(ctx: &DecryptContext) -> Result<Vec<u8>, ()> {
    match ctx.parsed.stream {
        StreamFlag::No => {
            // Single AEAD over whole payload.
            let mut enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
            let mut nonce_b64 = b64e(&ctx.parsed.nonce);
            let mut recipients_b64 = b64e(&ctx.parsed.recipients_blob);

            let aad_ct = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, false);

            let mut cek_key = ChaChaKey::from_slice(ctx.cek()).to_owned();
            let aead_ct = XChaCha20Poly1305::new(&cek_key);

            let pt_raw = aead_ct
                .decrypt(
                    ChaChaNonce::from_slice(&ctx.parsed.nonce),
                    ChaChaPayload {
                        msg: &ctx.parsed.ct_and_tag,
                        aad: &aad_ct,
                    },
                )
                .map_err(|_| ())?;

            cek_key.zeroize();
            enc_ecdh_b64.zeroize();
            nonce_b64.zeroize();
            recipients_b64.zeroize();

            Ok(pt_raw)
        }
        StreamFlag::Yes => {
            // Stream:Y – in-RAM, parse frames until sentinel, ignore trailer.
            let mut out = Vec::new();

            let enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
            let nonce_b64 = b64e(&ctx.parsed.nonce);
            let recipients_b64 = b64e(&ctx.parsed.recipients_blob);
            let aad = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, true);

            let cipher = XChaCha20Poly1305::new(ctx.cek().into());

            let mut r = Cursor::new(&ctx.parsed.ct_and_tag);

            let mut len_buf = [0u8; 4];
            let mut nonce = [0u8; 24];
            let mut buf = Vec::new();

            loop {
                if r.read_exact(&mut len_buf).is_err() {
                    return Err(()); // unexpected EOF (no sentinel)
                }
                let u = u32::from_be_bytes(len_buf);
                if u == TRAILER_SENTINEL_LEN {
                    break;
                }
                let chunk_len = u as usize;
                if chunk_len < TAG_LEN {
                    return Err(());
                }

                r.read_exact(&mut nonce).map_err(|_| ())?;
                if buf.len() < chunk_len {
                    buf.resize(chunk_len, 0);
                }
                r.read_exact(&mut buf[..chunk_len]).map_err(|_| ())?;

                let pt_len = chunk_len - TAG_LEN;
                let (pt, tag_bytes) = buf[..chunk_len].split_at_mut(pt_len);
                cipher
                    .decrypt_in_place_detached(
                        ChaChaNonce::from_slice(&nonce),
                        &aad,
                        pt,
                        ChaChaTag::from_slice(tag_bytes),
                    )
                    .map_err(|_| ())?;

                out.extend_from_slice(pt);
            }

            // If trailer is present, skip it silently (decrypt_raw doesn't verify).
            Ok(out)
        }
    }
}

// ======================================================================
// 3. Core encryption logic (bytes-first)
// ======================================================================

fn encrypt_core(
    bytes: &[u8],
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
    stream_mode: StreamMode,
) -> Result<Vec<u8>, ()> {
    use zeroize::Zeroize;

    let stream_on = matches!(stream_mode, StreamMode::On { .. });

    // 1) Handshake
    let hs = build_encrypt_handshake(recipients_armored, stream_on)?;

    // 2) Payload AEAD (ct_and_tag) + optional digest for stream:Y
    let digest_b64_opt: Option<String> = None;

    let ct_and_tag = match stream_mode {
        StreamMode::Off => {
            let mut enc_ecdh_b64 = b64e(&hs.enc_ecdh);
            let mut nonce_b64 = b64e(&hs.nonce);
            let mut recipients_b64 = b64e(&hs.recipients_blob);

            let aad_ct = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, false);

            let mut cek_key = ChaChaKey::from_slice(hs.cek()).to_owned();
            let aead_ct = XChaCha20Poly1305::new(&cek_key);

            let pt_raw = aead_ct
                .encrypt(
                    ChaChaNonce::from_slice(&hs.nonce),
                    ChaChaPayload {
                        msg: bytes,
                        aad: &aad_ct,
                    },
                )
                .map_err(|_| ())?;

            cek_key.zeroize();
            enc_ecdh_b64.zeroize();
            nonce_b64.zeroize();
            recipients_b64.zeroize();

            pt_raw
        }
        StreamMode::On { chunk_size } => {
            if chunk_size == 0 {
                return Err(());
            }

            // This branch is superseded by encrypt_streaming_binary (4a).
            // Keep minimal compatibility by delegating:
            return encrypt_streaming_binary(bytes, recipients_armored, signer, chunk_size);
        }
    };

    // 3) Optional signature (non-stream: header signature)
    let mut enc_ecdh_b64 = b64e(&hs.enc_ecdh);
    let mut nonce_b64 = b64e(&hs.nonce);
    let mut recipients_b64 = b64e(&hs.recipients_blob);
    let mut ct_b64 = b64e(&ct_and_tag);

    let signature = if let Some((sec_arm, pwd)) = signer {
        if pwd.trim().is_empty() {
            enc_ecdh_b64.zeroize();
            nonce_b64.zeroize();
            recipients_b64.zeroize();
            ct_b64.zeroize();
            return Err(());
        }

        let sb = unlock_secret(sec_arm, pwd).map_err(|_| ())?;

        let transcript = if !stream_on {
            canonical_sig_nonstream(
                &enc_ecdh_b64,
                &nonce_b64,
                &recipients_b64,
                &ct_b64,
                &hs.rc,
                false,
            )
        } else {
            // unreachable in this code path (streaming handled in encrypt_streaming_*).
            let digest_b64 = digest_b64_opt.as_ref().ok_or(())?;
            canonical_sig_stream_digest(
                &enc_ecdh_b64,
                &nonce_b64,
                &recipients_b64,
                digest_b64,
                &hs.rc,
                true,
            )
        };

        let sk_pq = mldsa65::SecretKey::from_bytes(&sb.sig_sk_pq).map_err(|_| ())?;
        let sig_pq = mldsa65::detached_sign(&transcript, &sk_pq);

        use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
        let ed = Ed25519SigningKey::from_bytes(&sb.sig_sk_ed);
        let sig_ed = ed.sign(&transcript);

        let mut out = Vec::with_capacity(sig_pq.as_bytes().len() + sig_ed.to_bytes().len());
        out.extend_from_slice(sig_pq.as_bytes());
        out.extend_from_slice(&sig_ed.to_bytes());
        Some(out)
    } else {
        None
    };

    // 4) Binary envelope VLM1...
    let envelope = encode_envelope_binary(
        hs.enc_ecdh,
        hs.nonce,
        hs.recipients_blob.clone(),
        ct_and_tag,
        signature,
        0, // flags: non-stream
        hs.rc,
    );

    enc_ecdh_b64.zeroize();
    nonce_b64.zeroize();
    recipients_b64.zeroize();
    ct_b64.zeroize();
    // hs.cek zeroized on Drop

    Ok(envelope)
}

// ======================================================================
// 4a) Stream:Y, RAM — trailing in encrypt_streaming_binary / encrypt_streaming
// ======================================================================

pub fn encrypt_streaming_binary(
    bytes: &[u8],
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
    chunk_size: usize,
) -> Result<Vec<u8>, ()> {
    use crate::streaming::write_signature_trailer;
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use pqcrypto_mldsa::mldsa65;

    if chunk_size == 0 {
        return Err(());
    }

    // 1) Handshake
    let hs = build_encrypt_handshake(recipients_armored, true)?;

    // 2) Encrypt payload frames into buffer + compute digest of frames
    let mut out_payload = Vec::new();
    let mut hasher = signer.is_some().then(Sha256::new);
    encrypt_stream_chunks(
        &hs,
        Cursor::new(bytes),
        &mut out_payload,
        chunk_size,
        hasher.as_mut(),
    )?;

    // 3) Assemble ct_and_tag = payload_frames || sentinel (and optional trailer)
    let mut ct_and_tag = out_payload;

    // 4) Header flags
    let mut flags: u8 = MSG_FLAG_STREAM;
    if signer.is_some() {
        flags |= MSG_FLAG_SIGTRAILER;
    }

    // 5) If signer → compute signature and append trailer; else append only sentinel
    if let Some((sec_arm, pwd)) = signer {
        let digest_bytes = hasher.unwrap().finalize();
        let digest_b64 = b64e(&digest_bytes);

        let enc_ecdh_b64 = b64e(&hs.enc_ecdh);
        let nonce_b64 = b64e(&hs.nonce);
        let recipients_b64 = b64e(&hs.recipients_blob);

        let transcript = canonical_sig_stream_digest(
            &enc_ecdh_b64,
            &nonce_b64,
            &recipients_b64,
            &digest_b64,
            &hs.rc,
            true,
        );

        let sb = crate::keys::unlock_secret(sec_arm, pwd).map_err(|_| ())?;
        let sk_pq = mldsa65::SecretKey::from_bytes(&sb.sig_sk_pq).map_err(|_| ())?;
        let sig_pq = mldsa65::detached_sign(&transcript, &sk_pq);
        let ed = Ed25519SigningKey::from_bytes(&sb.sig_sk_ed);
        let sig_ed = ed.sign(&transcript);

        let mut signature = Vec::with_capacity(sig_pq.as_bytes().len() + sig_ed.to_bytes().len());
        signature.extend_from_slice(sig_pq.as_bytes());
        signature.extend_from_slice(&sig_ed.to_bytes());

        // Append sentinel + trailer to the END of payload
        let mut trailer_buf = Vec::with_capacity(4 + 32 + 4 + signature.len());
        write_signature_trailer(&mut trailer_buf, &signature)?;
        ct_and_tag.extend_from_slice(&trailer_buf);
        signature.zeroize();
    } else {
        ct_and_tag.extend_from_slice(&TRAILER_SENTINEL_LEN.to_be_bytes());
    }

    // 6) Build VLM1 (header signature always empty for stream:Y)
    let envelope = encode_envelope_binary(
        hs.enc_ecdh,
        hs.nonce,
        hs.recipients_blob.clone(),
        ct_and_tag,
        None,
        flags,
        hs.rc,
    );

    Ok(envelope)
}

pub fn encrypt_streaming(
    bytes: &[u8],
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
    chunk_size: usize,
) -> Result<Vec<u8>, ()> {
    let bin = encrypt_streaming_binary(bytes, recipients_armored, signer, chunk_size)?;
    Ok(armor_from_binary(&bin).into_bytes())
}

// ======================================================================
// 4b) Stream:Y, RAM — trailing on decrypt side (decrypt_streaming_raw)
// ======================================================================

pub fn decrypt_streaming_raw<F>(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
    mut on_chunk: F,
) -> Result<i32, ()>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    use crate::armor::parse_public;
    use pqcrypto_mldsa::mldsa65;

    let ctx = build_decrypt_context(bytes, my_secret_armored, passphrase)?;

    // Non-streaming → old one-shot path
    if !matches!(ctx.parsed.stream, StreamFlag::Yes) {
        let pt = decrypt_content(&ctx)?;
        on_chunk(&pt)?;
        return verify_signature_status(&ctx, expected_public);
    }

    // Prepare AAD and cipher
    let enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
    let nonce_b64 = b64e(&ctx.parsed.nonce);
    let recipients_b64 = b64e(&ctx.parsed.recipients_blob);
    let aad = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, true);

    let cipher = XChaCha20Poly1305::new(ctx.cek().into());

    let mut r = Cursor::new(&ctx.parsed.ct_and_tag);
    let mut hasher = ctx.parsed.has_trailer.then(Sha256::new);

    let mut len_buf = [0u8; 4];
    let mut nonce = [0u8; 24];
    let mut buf = Vec::new();

    // === chunks loop until sentinel ===
    loop {
        if r.read_exact(&mut len_buf).is_err() {
            return Err(());
        }
        let u = u32::from_be_bytes(len_buf);
        if u == TRAILER_SENTINEL_LEN {
            break;
        }
        let chunk_len = u as usize;
        if chunk_len < TAG_LEN {
            return Err(());
        }

        r.read_exact(&mut nonce).map_err(|_| ())?;
        if buf.len() < chunk_len {
            buf.resize(chunk_len, 0);
        }
        r.read_exact(&mut buf[..chunk_len]).map_err(|_| ())?;

        if let Some(h) = hasher.as_mut() {
            h.update(len_buf);
            h.update(nonce);
            h.update(&buf[..chunk_len]);
        }

        let pt_len = chunk_len - TAG_LEN;
        let (pt, tag_bytes) = buf[..chunk_len].split_at_mut(pt_len);
        cipher
            .decrypt_in_place_detached(
                ChaChaNonce::from_slice(&nonce),
                &aad,
                pt,
                ChaChaTag::from_slice(tag_bytes),
            )
            .map_err(|_| ())?;
        on_chunk(pt)?;
    }

    // === trailer / status
    let sig_status: i32;
    if ctx.parsed.has_trailer {
        let mut magic = [0u8; 32];
        r.read_exact(&mut magic).map_err(|_| ())?;
        if magic.ct_eq(TRAILER_MAGIC).unwrap_u8() != 1 {
            return Err(());
        }

        let mut lbuf = [0u8; 4];
        r.read_exact(&mut lbuf).map_err(|_| ())?;
        let sig_len = u32::from_be_bytes(lbuf) as usize;
        let mut sig = vec![0u8; sig_len];
        r.read_exact(&mut sig).map_err(|_| ())?;

        if expected_public.is_none() {
            sig_status = 3;
        } else {
            let pb = parse_public(expected_public.unwrap()).map_err(|_| ())?;
            let pq_len = mldsa65::signature_bytes();
            let ed_len = 64;
            if sig.len() != pq_len + ed_len {
                sig_status = 2;
            } else {
                let sig_pq = &sig[..pq_len];
                let sig_ed = &sig[pq_len..];

                let digest_b64 = {
                    let d = hasher.unwrap().finalize();
                    b64e(&d)
                };
                let transcript = canonical_sig_stream_digest(
                    &enc_ecdh_b64,
                    &nonce_b64,
                    &recipients_b64,
                    &digest_b64,
                    &ctx.rc,
                    true,
                );

                let ok_pq = if let Ok(pk_pq) = mldsa65::PublicKey::from_bytes(&pb.sig_pk_pq) {
                    let mut buf2 = Vec::with_capacity(sig_pq.len() + transcript.len());
                    buf2.extend_from_slice(sig_pq);
                    buf2.extend_from_slice(&transcript);
                    if let Ok(sm) = mldsa65::SignedMessage::from_bytes(&buf2) {
                        if let Ok(rec) = mldsa65::open(&sm, &pk_pq) {
                            rec.ct_eq(&transcript).into()
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                let ok_ed =
                    if let Ok(pk_ed) = ed25519_dalek::VerifyingKey::from_bytes(&pb.sig_pk_ed) {
                        ed25519_dalek::Signature::try_from(sig_ed)
                            .ok()
                            .map(|s| pk_ed.verify_strict(&transcript, &s).is_ok())
                            .unwrap_or(false)
                    } else {
                        false
                    };

                sig_status = if ok_pq && ok_ed { 1 } else { 2 };
            }
        }
    } else {
        sig_status = if expected_public.is_some() { 3 } else { 0 };
    }

    Ok(sig_status)
}

pub fn decrypt_streaming<F>(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
    on_chunk: F,
) -> Result<i32, ()>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    let s = str::from_utf8(bytes).map_err(|_| ())?;
    let bin = binary_from_armor(s)?;
    decrypt_streaming_raw(
        &bin,
        my_secret_armored,
        passphrase,
        expected_public,
        on_chunk,
    )
}

// ======================================================================
// 4c) Stream:Y, FILES — drop Seek-variants → pipe-friendly replacements
// ======================================================================

pub fn encrypt_file_stream<R, W>(
    input: &mut R,
    output: &mut W,
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
    chunk_size: usize,
) -> Result<(), ()>
where
    R: Read,
    W: Write,
{
    use crate::streaming::write_signature_trailer;
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use pqcrypto_mldsa::mldsa65;

    if chunk_size == 0 {
        return Err(());
    }

    let hs = build_encrypt_handshake(recipients_armored, true)?;

    let mut flags: u8 = MSG_FLAG_STREAM;
    if signer.is_some() {
        flags |= MSG_FLAG_SIGTRAILER;
    }

    // Header (sig_len = 0)
    let recipients_len_u32 = u32::try_from(hs.recipients_blob.len()).map_err(|_| ())?;
    let sig_len_u32: u32 = 0;
    let header_len = 32 + MSG_NONCE_LEN + 32 + 4 + hs.recipients_blob.len() + 4;
    let header_len_u32 = u32::try_from(header_len).map_err(|_| ())?;

    // preamble
    output.write_all(MSG_MAGIC).map_err(|_| ())?;
    output.write_all(&[MSG_VERSION]).map_err(|_| ())?;
    output.write_all(&[flags]).map_err(|_| ())?;
    output.write_all(&[0u8, 0u8]).map_err(|_| ())?;
    output
        .write_all(&header_len_u32.to_be_bytes())
        .map_err(|_| ())?;
    // header-part
    output.write_all(&hs.enc_ecdh).map_err(|_| ())?;
    output.write_all(&hs.nonce).map_err(|_| ())?;
    output.write_all(&hs.rc).map_err(|_| ())?;
    output
        .write_all(&recipients_len_u32.to_be_bytes())
        .map_err(|_| ())?;
    output.write_all(&hs.recipients_blob).map_err(|_| ())?;
    output
        .write_all(&sig_len_u32.to_be_bytes())
        .map_err(|_| ())?;

    // payload + digest (frames only)
    let mut hasher = signer.is_some().then(Sha256::new);
    encrypt_stream_chunks(&hs, input, &mut *output, chunk_size, hasher.as_mut())?;

    // sentinel (+ trailer when signer)
    if let Some((sec_arm, pwd)) = signer {
        let digest_bytes = hasher.unwrap().finalize();
        let digest_b64 = b64e(&digest_bytes);

        let enc_ecdh_b64 = b64e(&hs.enc_ecdh);
        let nonce_b64 = b64e(&hs.nonce);
        let recipients_b64 = b64e(&hs.recipients_blob);

        let transcript = canonical_sig_stream_digest(
            &enc_ecdh_b64,
            &nonce_b64,
            &recipients_b64,
            &digest_b64,
            &hs.rc,
            true,
        );

        let sb = crate::keys::unlock_secret(sec_arm, pwd).map_err(|_| ())?;
        let sk_pq = mldsa65::SecretKey::from_bytes(&sb.sig_sk_pq).map_err(|_| ())?;
        let sig_pq = mldsa65::detached_sign(&transcript, &sk_pq);
        let ed = Ed25519SigningKey::from_bytes(&sb.sig_sk_ed);
        let sig_ed = ed.sign(&transcript);

        let mut signature = Vec::with_capacity(sig_pq.as_bytes().len() + sig_ed.to_bytes().len());
        signature.extend_from_slice(sig_pq.as_bytes());
        signature.extend_from_slice(&sig_ed.to_bytes());

        write_signature_trailer(&mut *output, &signature)?;
    } else {
        output
            .write_all(&TRAILER_SENTINEL_LEN.to_be_bytes())
            .map_err(|_| ())?;
    }

    output.flush().map_err(|_| ())?;
    Ok(())
}

pub fn decrypt_file_stream<R, F>(
    input: &mut R,
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
    mut on_chunk: F,
) -> Result<i32, ()>
where
    R: Read,
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    use crate::armor::parse_public;
    use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
    use pqcrypto_mldsa::mldsa65;

    if passphrase.trim().is_empty() || my_secret_armored.trim().is_empty() {
        return Err(());
    }

    // === pre-header ===
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic).map_err(|_| ())?;
    if magic.ct_eq(MSG_MAGIC.as_slice()).unwrap_u8() != 1 {
        return Err(());
    }

    let mut b1 = [0u8; 1];
    input.read_exact(&mut b1).map_err(|_| ())?;
    let ver = b1[0];
    if ver != MSG_VERSION {
        return Err(());
    }

    input.read_exact(&mut b1).map_err(|_| ())?;
    let flags = b1[0];

    // reserved
    let mut reserved = [0u8; 2];
    input.read_exact(&mut reserved).map_err(|_| ())?;
    if reserved != [0u8, 0u8] {
        return Err(());
    }

    // len_hdr
    let mut len_buf4 = [0u8; 4];
    input.read_exact(&mut len_buf4).map_err(|_| ())?;
    let header_len = u32::from_be_bytes(len_buf4) as usize;
    if header_len == 0 {
        return Err(());
    }

    // header-part
    let mut header = vec![0u8; header_len];
    input.read_exact(&mut header).map_err(|_| ())?;

    // Construct minimal dummy envelope in memory for KEM/CEK/RC:
    let mut dummy = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + header.len() + TAG_LEN);
    dummy.extend_from_slice(MSG_MAGIC);
    dummy.push(MSG_VERSION);
    dummy.push(flags);
    dummy.extend_from_slice(&[0u8, 0u8]);
    dummy.extend_from_slice(&len_buf4);
    dummy.extend_from_slice(&header);
    dummy.extend_from_slice(&[0u8; TAG_LEN]);

    let ctx = build_decrypt_context(&dummy, my_secret_armored, passphrase)?;

    // Stream:Y is required here
    let stream_on = (flags & MSG_FLAG_STREAM) != 0;
    if !stream_on {
        // For non-stream small messages, read remaining into RAM and decrypt once.
        let mut ct_and_tag = Vec::new();
        input.read_to_end(&mut ct_and_tag).map_err(|_| ())?;

        // Decrypt
        let mut enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
        let mut nonce_b64 = b64e(&ctx.parsed.nonce);
        let mut recipients_b64 = b64e(&ctx.parsed.recipients_blob);

        let aad_ct = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, false);

        let mut cek_key = ChaChaKey::from_slice(ctx.cek()).to_owned();
        let aead_ct = XChaCha20Poly1305::new(&cek_key);

        let pt_raw = aead_ct
            .decrypt(
                ChaChaNonce::from_slice(&ctx.parsed.nonce),
                ChaChaPayload {
                    msg: &ct_and_tag,
                    aad: &aad_ct,
                },
            )
            .map_err(|_| ())?;

        cek_key.zeroize();
        enc_ecdh_b64.zeroize();
        nonce_b64.zeroize();
        recipients_b64.zeroize();

        on_chunk(&pt_raw)?;
        
        // Replace dummy ct_and_tag with actual ciphertext for signature verification
        let mut ctx = ctx;
        ctx.parsed.ct_and_tag = ct_and_tag;
        return verify_signature_status(&ctx, expected_public);
    }

    // === streaming path: decrypt frames up to sentinel
    let mut hasher = ((flags & MSG_FLAG_SIGTRAILER) != 0).then(Sha256::new);

    // Prepare AAD/cipher
    let enc_ecdh_b64 = b64e(&ctx.parsed.enc_ecdh);
    let nonce_b64 = b64e(&ctx.parsed.nonce);
    let recipients_b64 = b64e(&ctx.parsed.recipients_blob);
    let aad = canonical_aad(&enc_ecdh_b64, &nonce_b64, &recipients_b64, true);

    let cipher = XChaCha20Poly1305::new(ctx.cek().into());

    let mut len_buf = [0u8; 4];
    let mut nonce = [0u8; 24];
    let mut buf = Vec::new();

    loop {
        if input.read_exact(&mut len_buf).is_err() {
            return Err(());
        }
        let u = u32::from_be_bytes(len_buf);
        if u == TRAILER_SENTINEL_LEN {
            break;
        }
        let chunk_len = u as usize;
        if chunk_len < TAG_LEN {
            return Err(());
        }

        input.read_exact(&mut nonce).map_err(|_| ())?;
        if buf.len() < chunk_len {
            buf.resize(chunk_len, 0);
        }
        input.read_exact(&mut buf[..chunk_len]).map_err(|_| ())?;

        if let Some(h) = hasher.as_mut() {
            h.update(len_buf);
            h.update(nonce);
            h.update(&buf[..chunk_len]);
        }

        let pt_len = chunk_len - TAG_LEN;
        let (pt, tag_bytes) = buf[..chunk_len].split_at_mut(pt_len);

        cipher
            .decrypt_in_place_detached(
                ChaChaNonce::from_slice(&nonce),
                &aad,
                pt,
                ChaChaTag::from_slice(tag_bytes),
            )
            .map_err(|_| ())?;

        on_chunk(pt)?;
    }

    // === trailer / status
    let sig_status: i32;
    if (flags & MSG_FLAG_SIGTRAILER) != 0 {
        let mut magic = [0u8; 32];
        input.read_exact(&mut magic).map_err(|_| ())?;
        if magic.ct_eq(TRAILER_MAGIC).unwrap_u8() != 1 {
            return Err(());
        }

        let mut lbuf = [0u8; 4];
        input.read_exact(&mut lbuf).map_err(|_| ())?;
        let sig_len = u32::from_be_bytes(lbuf) as usize;
        let mut sig = vec![0u8; sig_len];
        input.read_exact(&mut sig).map_err(|_| ())?;

        if expected_public.is_none() {
            sig_status = 3;
        } else {
            let pb = parse_public(expected_public.unwrap()).map_err(|_| ())?;
            let pq_len = mldsa65::signature_bytes();
            let ed_len = 64;
            if sig.len() != pq_len + ed_len {
                sig_status = 2;
            } else {
                let sig_pq = &sig[..pq_len];
                let sig_ed = &sig[pq_len..];

                let digest_b64 = {
                    let d = hasher.unwrap().finalize();
                    b64e(&d)
                };
                let transcript = canonical_sig_stream_digest(
                    &enc_ecdh_b64,
                    &nonce_b64,
                    &recipients_b64,
                    &digest_b64,
                    &ctx.rc,
                    true,
                );

                let ok_pq = if let Ok(pk_pq) = mldsa65::PublicKey::from_bytes(&pb.sig_pk_pq) {
                    let mut buf2 = Vec::with_capacity(sig_pq.len() + transcript.len());
                    buf2.extend_from_slice(sig_pq);
                    buf2.extend_from_slice(&transcript);
                    if let Ok(sm) = mldsa65::SignedMessage::from_bytes(&buf2) {
                        if let Ok(rec) = mldsa65::open(&sm, &pk_pq) {
                            rec.ct_eq(&transcript).into()
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                let ok_ed = if let Ok(pk_ed) = Ed25519VerifyingKey::from_bytes(&pb.sig_pk_ed) {
                    Ed25519Signature::try_from(sig_ed)
                        .ok()
                        .map(|s| pk_ed.verify_strict(&transcript, &s).is_ok())
                        .unwrap_or(false)
                } else {
                    false
                };

                sig_status = if ok_pq && ok_ed { 1 } else { 2 };
            }
        }
    } else {
        sig_status = if expected_public.is_some() { 3 } else { 0 };
    }

    Ok(sig_status)
}

// ======================================================================
// 5. Public Rust API: encrypt (non-stream) and convenience helpers
// ======================================================================

/// Low-level binary encrypt (VLM1..., non-stream).
pub fn encrypt_binary(
    bytes: &[u8],
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
) -> Result<Vec<u8>, ()> {
    encrypt_core(bytes, recipients_armored, signer, StreamMode::Off)
}

/// High-level armored encrypt (UTF-8 armored VELUM MESSAGE, non-stream).
pub fn encrypt(
    bytes: &[u8],
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
) -> Result<Vec<u8>, ()> {
    let bin = encrypt_binary(bytes, recipients_armored, signer)?;
    Ok(armor_from_binary(&bin).into_bytes())
}

/// Helper: string → armored bytes (non-stream).
pub fn encrypt_str(
    s: &str,
    recipients_armored: &str,
    signer: Option<(&str, &str)>,
) -> Result<Vec<u8>, ()> {
    encrypt(s.as_bytes(), recipients_armored, signer)
}

// ======================================================================
// 6. Public Rust API: decrypt (in-RAM, non-stream or stream)
// ======================================================================

/// Low-level binary decrypt: VLM1... → (plaintext, sig_status).
///
/// sig_status:
///   0 = no signature (and expected_public == None),
///   1 = signature verified,
///   2 = signature invalid,
///   3 = signature expected but missing/unexpected.
///
/// NOTE: For stream:Y, this function produces plaintext (by parsing frames and
/// ignoring trailer). For correct signature status of stream:Y prefer
/// `decrypt_streaming_raw`, which verifies the trailer.
pub fn decrypt_raw(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
) -> Result<(Vec<u8>, i32), ()> {
    let ctx = build_decrypt_context(bytes, my_secret_armored, passphrase)?;
    let pt = decrypt_content(&ctx)?;
    // For stream:Y this status may not match trailer semantics. Use streaming API to verify.
    let status = verify_signature_status(&ctx, expected_public)?;
    Ok((pt, status))
}

/// Alias for low-level binary decrypt.
pub fn decrypt_binary(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
) -> Result<(Vec<u8>, i32), ()> {
    decrypt_raw(bytes, my_secret_armored, passphrase, expected_public)
}

/// High-level armored decrypt: armored UTF-8 → (plaintext, sig_status).
pub fn decrypt(
    bytes: &[u8],
    my_secret_armored: &str,
    passphrase: &str,
    expected_public: Option<&str>,
) -> Result<(Vec<u8>, i32), ()> {
    let s = str::from_utf8(bytes).map_err(|_| ())?;

    // Detect invalid Base64 in signature field to force status=2 when expected_public is Some.
    let mut sig_b64_invalid = false;
    if let Ok(parsed) = parse_message(s) {
        if let Some(sig_bytes) = parsed.signature.as_ref() {
            if sig_bytes.is_empty() {
                sig_b64_invalid = true;
            }
        }
    }

    let bin = binary_from_armor(s)?;
    let (pt, mut status) = decrypt_raw(&bin, my_secret_armored, passphrase, expected_public)?;

    if sig_b64_invalid && expected_public.is_some() {
        status = 2;
    }

    Ok((pt, status))
}

// ======================================================================
// 7. Public Rust API: status enum
// ======================================================================

/// Hybrid signature verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    NoSignature = 0,
    Verified = 1,
    Invalid = 2,
    Unexpected = 3,
}

impl From<i32> for SigStatus {
    fn from(v: i32) -> Self {
        match v {
            0 => SigStatus::NoSignature,
            1 => SigStatus::Verified,
            2 => SigStatus::Invalid,
            _ => SigStatus::Unexpected,
        }
    }
}

// ============================================================
// Unit tests for src/core.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `core.rs`
    //!
    //! These tests focus on:
    //! - sanity checks for handshake construction,
    //! - error behavior of internal decrypt helpers,
    //! - full encrypt → decrypt round-trips for non-streaming and streaming paths.
    //!
    //! They use real key generation (Argon2id + PQ) for end-to-end coverage,
    //! so they are heavier but exercise the actual protocol wiring.

    use super::*;
    use crate::constants::MSG_NONCE_LEN;
    use crate::context::DecryptContext;
    use crate::envelope::{ParsedBinary, StreamFlag};
    use crate::keys::generate_keypair;

    // ============================================================
    // Shared helpers for core tests (ASCII + binary)
    // ============================================================

    /// Generate a test PUBLIC/SECRET keypair using the high-level key API.
    ///
    /// Returns:
    /// - `(public_armor, secret_armor)` – both in ASCII armor format
    ///   understood by `encrypt` / `decrypt` and `encrypt_binary` / `decrypt_binary`.
    fn core_test_keypair() -> (String, String) {
        crate::keys::generate_keypair("test-pass").expect("test keypair generation must succeed")
    }

    /// Build a minimal non-streaming `DecryptContext` with an empty payload,
    /// so that `decrypt_content` is forced to fail at AEAD decryption.
    fn dummy_decrypt_context_nonstream() -> DecryptContext {
        DecryptContext::new(
            ParsedBinary {
                enc_ecdh: [1u8; 32],
                nonce: [2u8; MSG_NONCE_LEN],
                recipients_blob: vec![0xAA],
                ct_and_tag: Vec::new(), // invalid: no tag, AEAD must fail
                signature: None,
                stream: StreamFlag::No,
                rc: [3u8; 32],
                has_trailer: false,
            },
            [3u8; 32],
            [4u8; 32],
        )
    }

    // ------------------------------------------------------------
    // Handshake logic
    // ------------------------------------------------------------

    /// Ensure that an empty recipient list is rejected at handshake level.
    #[test]
    fn test_build_encrypt_handshake_rejects_empty_recipient_list() {
        let empty = "";
        let res = build_encrypt_handshake(empty, false);
        assert!(res.is_err());
    }

    /// Streaming encryption must reject zero chunk size to avoid undefined behavior.
    #[test]
    fn test_encrypt_streaming_binary_refuses_zero_chunk_size() {
        let dummy_recipients =
            "-----BEGIN VELUM PUBLIC KEY-----\nAABBCC\n-----END VELUM PUBLIC KEY-----";
        let err = encrypt_streaming_binary(b"payload", dummy_recipients, None, 0);
        assert!(err.is_err());
    }

    // ------------------------------------------------------------
    // Internal decrypt helper behavior
    // ------------------------------------------------------------

    /// Non-streaming `decrypt_content` with an empty ciphertext must return `Err(())`.
    #[test]
    fn test_decrypt_content_nonstream_empty_payload_returns_err() {
        let ctx = dummy_decrypt_context_nonstream();
        let out = super::decrypt_content(&ctx);
        assert!(
            out.is_err(),
            "Empty ciphertext must cause decryption failure"
        );
    }

    /// `decrypt` must reject non-UTF8 armored input before any cryptographic processing.
    #[test]
    fn test_decrypt_rejects_non_utf8_bytes() {
        let bad = [0xFF, 0xFE, 0xFD];
        let sec = "-----BEGIN VELUM SECRET KEY-----\nAAA\n-----END VELUM SECRET KEY-----";
        let res = decrypt(&bad, sec, "pass", None);
        assert!(res.is_err(), "Invalid UTF-8 must result in Err(())");
    }

    // ------------------------------------------------------------
    // SigStatus enum mapping
    // ------------------------------------------------------------

    /// Verify that `SigStatus::from(i32)` covers all documented codes.
    #[test]
    fn test_sigstatus_enum_from_int() {
        assert_eq!(SigStatus::from(0), SigStatus::NoSignature);
        assert_eq!(SigStatus::from(1), SigStatus::Verified);
        assert_eq!(SigStatus::from(2), SigStatus::Invalid);
        assert_eq!(SigStatus::from(3), SigStatus::Unexpected);
        assert_eq!(SigStatus::from(99), SigStatus::Unexpected);
    }

    // ------------------------------------------------------------
    // End-to-end round-trips (non-streaming + streaming)
    // ------------------------------------------------------------

    /// Full non-streaming round-trip:
    /// - generate PUBLIC/SECRET pair,
    /// - encrypt plaintext,
    /// - decrypt,
    /// - verify plaintext and signature status.
    #[test]
    fn test_encrypt_decrypt_nonstream_roundtrip_no_signer() {
        let (pub_arm, sec_arm) = generate_keypair("test-pass").expect("key generation failed");

        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let ct = encrypt(plaintext, &pub_arm, None).expect("encrypt (non-stream) failed");
        let (dec, status) = decrypt(&ct, &sec_arm, "test-pass", None).expect("decrypt failed");

        assert_eq!(dec, plaintext);
        assert_eq!(SigStatus::from(status), SigStatus::NoSignature);
    }

    /// Full streaming round-trip (binary):
    /// - generate keys,
    /// - encrypt with `stream:Y` and sentinel-only trailer (no signer),
    /// - decrypt via `decrypt_streaming_raw`,
    /// - reassemble plaintext from callback chunks.
    #[test]
    fn test_encrypt_decrypt_streaming_roundtrip_no_signer() {
        let (pub_arm, sec_arm) = generate_keypair("stream-pass").expect("key generation failed");

        let plaintext = b"hello streaming world - VELUM";
        let env_bin = encrypt_streaming_binary(plaintext, &pub_arm, None, 1024)
            .expect("streaming encrypt failed");

        let mut collected = Vec::new();
        let status = decrypt_streaming_raw(&env_bin, &sec_arm, "stream-pass", None, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .expect("streaming decrypt failed");

        assert_eq!(SigStatus::from(status), SigStatus::NoSignature);
        assert_eq!(&collected, plaintext);
    }

    // ============================================================
    // AAD / RC / recipients tampering (core-level, ASCII path)
    // ============================================================

    /// Grafting attack test on the armored message format:
    ///
    /// 1. Encrypt two different messages to two different recipients.
    /// 2. Parse both armored messages using `armor::parse_message`.
    /// 3. Construct a “hybrid” message:
    ///    - `enc_ecdh`, `nonce`, `ct_and_tag` from message 1,
    ///    - `recipients_blob` from message 2.
    /// 4. Attempt to decrypt using the secret key for recipient of message 1.
    ///
    /// Expected:
    /// - `decrypt` MUST fail, because the recipients blob no longer matches
    ///   the AAD / recipients-commitment (`rc`) of the original message.
    #[test]
    fn test_decrypt_rejects_recipients_grafting() {
        use crate::armor::{armor_message, parse_message};
        use crate::util::b64e;

        let (pub1, sec1) = core_test_keypair();
        let (pub2, _sec2) = core_test_keypair();

        // Encrypt two different messages to two different recipients.
        let msg1 = encrypt(b"message-one", &pub1, None).expect("encrypt(message-one) must succeed");
        let msg2 = encrypt(b"message-two", &pub2, None).expect("encrypt(message-two) must succeed");

        // `encrypt` returns ASCII-armored bytes -> convert to &str for the parser.
        let s1 = std::str::from_utf8(&msg1).expect("msg1 must be valid UTF-8 armor");
        let s2 = std::str::from_utf8(&msg2).expect("msg2 must be valid UTF-8 armor");

        // Parse both armored messages.
        let parsed1 = parse_message(s1).expect("parse_message(msg1) must succeed");
        let parsed2 = parse_message(s2).expect("parse_message(msg2) must succeed");

        // Build a hybrid message:
        // - enc_ecdh, nonce, ct_and_tag from msg1
        // - recipients_blob from msg2
        let hybrid = armor_message(
            &b64e(&parsed1.enc_ecdh),
            &b64e(&parsed1.nonce),
            &b64e(&parsed2.recipients_blob),
            &b64e(&parsed1.ct_and_tag),
            parsed1.signature.as_deref(),
        );

        // Decrypt as the first recipient: this MUST fail due to RC / AAD mismatch.
        let res = decrypt(hybrid.as_bytes(), &sec1, "test-pass", Some(&pub1));

        assert!(
            res.is_err(),
            "grafting recipients_blob from another message must make decrypt() fail",
        );
    }

    // ============================================================
    // Simple “ct tampering → TAG mismatch” (core-level, binary path)
    // ============================================================

    /// Basic AEAD integrity test on the binary VLM1 format:
    ///
    /// 1. Encrypt a binary payload using `encrypt_binary`.
    /// 2. Flip the last byte of the resulting ciphertext.
    /// 3. Call `decrypt_binary`.
    ///
    /// Expected:
    /// - `decrypt_binary` MUST return an error (authentication failure),
    ///   even for a 1-byte modification at the very end of the ciphertext.
    #[test]
    fn test_decrypt_binary_fails_on_ciphertext_tampering() {
        let (pub_arm, sec_arm) = core_test_keypair();

        let ct = encrypt_binary(b"tag-test", &pub_arm, None).expect("encrypt_binary must succeed");

        assert!(
            !ct.is_empty(),
            "encrypt_binary must produce non-empty ciphertext"
        );

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1; // minimal bit flip

        let res = decrypt_binary(&tampered, &sec_arm, "test-pass", Some(&pub_arm));

        assert!(
            res.is_err(),
            "any ciphertext tampering (even last byte) must cause decrypt_binary to fail"
        );
    }

    // ============================================================
    // Encryption randomization (same input → different ciphertexts)
    // ============================================================

    /// Randomization test for `encrypt_binary`:
    ///
    /// 1. Encrypt the SAME plaintext to the SAME recipient twice.
    /// 2. Compare resulting ciphertexts.
    /// 3. Decrypt both and compare plaintext + signature status.
    ///
    /// Expected:
    /// - `ct1 != ct2` (fresh nonce and/or ephemeral keys are used),
    /// - both decryptions return the original plaintext,
    /// - both signature status codes are `0` (no signature), because we do NOT
    ///   provide `expected_public` to the decryptor.
    #[test]
    fn test_encrypt_binary_is_randomized_for_same_input() {
        let (pub_arm, sec_arm) = core_test_keypair();
        let pt: &[u8] = b"same-plaintext-for-randomization-test";

        let ct1 = encrypt_binary(pt, &pub_arm, None).expect("first encrypt_binary must succeed");
        let ct2 = encrypt_binary(pt, &pub_arm, None).expect("second encrypt_binary must succeed");

        // Under a sane design, ciphertexts for the same input must not be identical.
        assert_ne!(
            ct1, ct2,
            "encrypt_binary must be randomized: two ciphertexts for the same input should differ"
        );

        // We pass `expected_public = None` → no signature is expected,
        // so the status code MUST be 0 ("no signature").
        let (out1, sig1) = decrypt_binary(&ct1, &sec_arm, "test-pass", None)
            .expect("decrypt_binary(ct1) must succeed");
        let (out2, sig2) = decrypt_binary(&ct2, &sec_arm, "test-pass", None)
            .expect("decrypt_binary(ct2) must succeed");

        assert_eq!(out1, pt);
        assert_eq!(out2, pt);

        assert_eq!(sig1, 0, "expected 'no signature' status for ct1");
        assert_eq!(sig2, 0, "expected 'no signature' status for ct2");
    }
}
