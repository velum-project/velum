// ffi.rs
//
// C API for VELUM core.
// Thin wrappers around Rust functions: keygen, encrypt/decrypt,
// key rewrapping, validation, and file streaming.

use crate::core;
use crate::keys;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;

// ===============================
// Helpers
// ===============================

fn c_str_to_str<'a>(ptr: *const c_char) -> Result<&'a str, ()> {
    if ptr.is_null() {
        return Err(());
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| ())
}

unsafe fn set_null_string(out: *mut *mut c_char) {
    if !out.is_null() {
        *out = ptr::null_mut();
    }
}

unsafe fn set_null_bytes(out_ptr: *mut *mut c_uchar, out_len: *mut usize) {
    if !out_ptr.is_null() {
        *out_ptr = ptr::null_mut();
    }
    if !out_len.is_null() {
        *out_len = 0;
    }
}

fn ffi_guard<F, T>(f: F) -> T
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
    T: Default,
{
    std::panic::catch_unwind(f).unwrap_or_else(|_| T::default())
}

// ===============================
// Memory management
// ===============================

/// Free a string returned by VELUM C API (char*).
///
/// # Safety
///
/// - `s` must be a pointer previously returned by a VELUM function (or NULL)
/// - `s` must not be used after calling this function (double-free protection)
/// - Passing an invalid pointer results in undefined behavior
#[no_mangle]
pub unsafe extern "C" fn velum_free_string(s: *mut c_char) {
    ffi_guard(|| {
        if s.is_null() {
            return;
        }
        unsafe {
            // Take ownership and drop.
            let _ = CString::from_raw(s);
        }
    })
}

/// Free a byte buffer returned by VELUM C API (uint8_t* + len).
///
/// # Safety
///
/// - `p` must be a pointer previously returned by a VELUM function (or NULL)
/// - `len` must match the length returned alongside `p`
/// - `p` must not be used after calling this function
/// - Passing an invalid pointer or mismatched length results in undefined behavior
#[no_mangle]
pub unsafe extern "C" fn velum_free_bytes(p: *mut c_uchar, len: usize) {
    ffi_guard(|| {
        if p.is_null() {
            return;
        }
        unsafe {
            // Rebuild Vec and drop.
            let _ = Vec::from_raw_parts(p, len, len);
        }
    })
}

// ===============================
// Key generation / validation / rewrap
// ===============================

/// Generate (PUBLIC, SECRET) keypair protected by passphrase.
/// On success:
///   - *out_public -> newly allocated null-terminated PUBLIC armor
///   - *out_secret -> newly allocated null-terminated SECRET armor
/// # Safety
///
/// - `passphrase` must point to a valid null-terminated C string
/// - `out_public` and `out_secret` must point to valid memory locations for output pointers
/// - On success, the caller must free returned strings with `velum_free_string`
#[no_mangle]
pub unsafe extern "C" fn velum_generate_keypair(
    passphrase: *const c_char,
    out_public: *mut *mut c_char,
    out_secret: *mut *mut c_char,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_string(out_public);
            set_null_string(out_secret);
        }

        let pass = match c_str_to_str(passphrase) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        // Adjust to your actual keys.rs API name:
        // e.g. keys::generate_keypair(pass) or keys::generate_and_wrap_keypair(pass)
        let (pub_arm, sec_arm) = match keys::generate_keypair(pass) {
            Ok(pair) => pair,
            Err(_) => return -1,
        };

        let c_pub = match CString::new(pub_arm) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let c_sec = match CString::new(sec_arm) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        unsafe {
            if !out_public.is_null() {
                *out_public = c_pub.into_raw();
            }
            if !out_secret.is_null() {
                *out_secret = c_sec.into_raw();
            }
        }

        0
    })
}

/// Validate a PUBLIC armor block.
/// Returns 0 if valid, -1 if invalid.
///
/// # Safety
///
/// - `public_armor` must point to a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn velum_validate_public(public_armor: *const c_char) -> c_int {
    ffi_guard(|| {
        let s = match c_str_to_str(public_armor) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        match keys::validate_public(s) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    })
}

/// Rewrap SECRET with a new passphrase (default KDF params).
/// On success:
///   - *out_secret -> new SECRET armor (null-terminated)
///
/// # Safety
///
/// - `old_secret`, `old_pass`, and `new_pass` must point to valid null-terminated C strings
/// - `out_secret` must point to a valid memory location for the output pointer
/// - On success, the caller must free the returned string with `velum_free_string`
#[no_mangle]
pub unsafe extern "C" fn velum_rewrap_secret(
    old_secret: *const c_char,
    old_pass: *const c_char,
    new_pass: *const c_char,
    out_secret: *mut *mut c_char,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_string(out_secret);
        }

        let old_secret_s = match c_str_to_str(old_secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let old_pass_s = match c_str_to_str(old_pass) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let new_pass_s = match c_str_to_str(new_pass) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let new_sec = match keys::rewrap_secret(old_secret_s, old_pass_s, new_pass_s, None) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let c_new = match CString::new(new_sec) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        unsafe {
            if !out_secret.is_null() {
                *out_secret = c_new.into_raw();
            }
        }

        0
    })
}

/// Re-wrap (change passphrase and/or Argon2id parameters) of a VELUM SECRET key.
///
/// # Safety
///
/// - `old_arm_c`, `old_pass_c`, and `new_pass_c` must point to valid null-terminated C strings
/// - `out_new_arm` must point to a valid memory location for the output pointer
/// - On success, the caller must free the returned string with `velum_free_string`
#[no_mangle]
pub unsafe extern "C" fn velum_rewrap_secret_with_params(
    old_arm_c: *const c_char,
    old_pass_c: *const c_char,
    new_pass_c: *const c_char,
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
    out_new_arm: *mut *mut c_char,
) -> c_int {
    ffi_guard(|| {
        if old_arm_c.is_null()
            || old_pass_c.is_null()
            || new_pass_c.is_null()
            || out_new_arm.is_null()
        {
            return -1;
        }

        let old_arm = match unsafe { CStr::from_ptr(old_arm_c) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let old_pass = match unsafe { CStr::from_ptr(old_pass_c) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let new_pass = match unsafe { CStr::from_ptr(new_pass_c) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };

        if old_pass.trim().is_empty() || new_pass.trim().is_empty() {
            return -4;
        }

        let result = keys::rewrap_secret_with_params(
            old_arm,
            old_pass,
            new_pass,
            m_cost_kib,
            t_cost,
            parallelism,
        );

        match result {
            Ok(new_arm) => unsafe {
                match CString::new(new_arm) {
                    Ok(cs) => {
                        *out_new_arm = cs.into_raw();
                        0
                    }
                    Err(_) => -3,
                }
            },
            Err(_) => -12,
        }
    })
}

// ===============================
// Encrypt: string / bytes / binary
// ===============================

/// Encrypt UTF-8 string, return armored ciphertext (null-terminated).
/// signer_secret/pass may be NULL for unsigned messages.
///
/// # Safety
///
/// - `plaintext` and `recipients` must point to valid null-terminated C strings
/// - `signer_secret` and `signer_pass` may be NULL (for unsigned messages)
/// - `out_ciphertext` must point to a valid memory location for the output pointer
/// - On success, the caller must free the returned string with `velum_free_string`
#[no_mangle]
pub unsafe extern "C" fn velum_encrypt_string(
    plaintext: *const c_char,
    recipients: *const c_char,
    signer_secret: *const c_char,
    signer_pass: *const c_char,
    out_ciphertext: *mut *mut c_char,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_string(out_ciphertext);
        }

        let pt = match c_str_to_str(plaintext) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let recips = match c_str_to_str(recipients) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signer_opt = if signer_secret.is_null() {
            None
        } else {
            let sec = match c_str_to_str(signer_secret) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            let pass = if signer_pass.is_null() {
                return -1;
            } else {
                match c_str_to_str(signer_pass) {
                    Ok(s) => s,
                    Err(_) => return -1,
                }
            };
            Some((sec, pass))
        };

        let ct = match core::encrypt(pt.as_bytes(), recips, signer_opt) {
            Ok(v) => v,
            Err(_) => return -1,
        };

        let c_ct = match CString::new(ct) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        unsafe {
            if !out_ciphertext.is_null() {
                *out_ciphertext = c_ct.into_raw();
            }
        }

        0
    })
}

/// Encrypt arbitrary bytes, return armored bytes (uint8_t* + len).
///
/// # Safety
///
/// - `plaintext` must be a valid pointer to `plaintext_len` bytes (or NULL if len is 0)
/// - `recipients` must point to a valid null-terminated C string
/// - `signer_secret` and `signer_pass` may be NULL (for unsigned messages)
/// - `out_ciphertext` and `out_ciphertext_len` must point to valid memory locations
/// - On success, the caller must free returned bytes with `velum_free_bytes`
#[no_mangle]
pub unsafe extern "C" fn velum_encrypt_bytes(
    plaintext: *const c_uchar,
    plaintext_len: usize,
    recipients: *const c_char,
    signer_secret: *const c_char,
    signer_pass: *const c_char,
    out_ciphertext: *mut *mut c_uchar,
    out_ciphertext_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_bytes(out_ciphertext, out_ciphertext_len);
        }

        if plaintext.is_null() && plaintext_len > 0 {
            return -1;
        }

        let recips = match c_str_to_str(recipients) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signer_opt = if signer_secret.is_null() {
            None
        } else {
            let sec = match c_str_to_str(signer_secret) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            let pass = if signer_pass.is_null() {
                return -1;
            } else {
                match c_str_to_str(signer_pass) {
                    Ok(s) => s,
                    Err(_) => return -1,
                }
            };
            Some((sec, pass))
        };

        let pt_slice = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

        let ct = match core::encrypt(pt_slice, recips, signer_opt) {
            Ok(v) => v,
            Err(_) => return -1,
        };

        let len = ct.len();
        let mut v = ct;
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);

        unsafe {
            if !out_ciphertext.is_null() {
                *out_ciphertext = ptr;
            }
            if !out_ciphertext_len.is_null() {
                *out_ciphertext_len = len;
            }
        }

        0
    })
}

/// Encrypt arbitrary bytes to *binary* VLM1 (uint8_t* + len).
///
/// # Safety
///
/// - `plaintext` must be a valid pointer to `plaintext_len` bytes (or NULL if len is 0)
/// - `recipients` must point to a valid null-terminated C string
/// - `signer_secret` and `signer_pass` may be NULL (for unsigned messages)
/// - `out_ciphertext` and `out_ciphertext_len` must point to valid memory locations
/// - On success, the caller must free returned bytes with `velum_free_bytes`
#[no_mangle]
pub unsafe extern "C" fn velum_encrypt_binary(
    plaintext: *const c_uchar,
    plaintext_len: usize,
    recipients: *const c_char,
    signer_secret: *const c_char,
    signer_pass: *const c_char,
    out_ciphertext: *mut *mut c_uchar,
    out_ciphertext_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_bytes(out_ciphertext, out_ciphertext_len);
        }

        if plaintext.is_null() && plaintext_len > 0 {
            return -1;
        }

        let recips = match c_str_to_str(recipients) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signer_opt = if signer_secret.is_null() {
            None
        } else {
            let sec = match c_str_to_str(signer_secret) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            let pass = if signer_pass.is_null() {
                return -1;
            } else {
                match c_str_to_str(signer_pass) {
                    Ok(s) => s,
                    Err(_) => return -1,
                }
            };
            Some((sec, pass))
        };

        let pt_slice = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

        let ct = match core::encrypt_binary(pt_slice, recips, signer_opt) {
            Ok(v) => v,
            Err(_) => return -1,
        };

        let len = ct.len();
        let mut v = ct;
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);

        unsafe {
            if !out_ciphertext.is_null() {
                *out_ciphertext = ptr;
            }
            if !out_ciphertext_len.is_null() {
                *out_ciphertext_len = len;
            }
        }

        0
    })
}

// ===============================
// Decrypt: string / bytes / binary
// ===============================

/// Decrypt armored UTF-8 ciphertext into UTF-8 string.
/// expected_public may be NULL → only "has signature?" info (3/no sig).
/// On success:
///   - *out_plain -> newly allocated null-terminated string
///   - *out_sig_status -> 0/1/2/3 as per core::verify_signature_status.
///
/// # Safety
///
/// - `ciphertext`, `secret`, and `passphrase` must point to valid null-terminated C strings
/// - `expected_signer` may be NULL (to skip signature verification)
/// - `out_plaintext` and `out_sig_status` must point to valid memory locations
/// - On success, the caller must free the returned string with `velum_free_string`
#[no_mangle]
pub unsafe extern "C" fn velum_decrypt_string(
    ciphertext: *const c_char,
    secret: *const c_char,
    passphrase: *const c_char,
    expected_public: *const c_char,
    out_plain: *mut *mut c_char,
    out_sig_status: *mut c_int,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_string(out_plain);
            if !out_sig_status.is_null() {
                *out_sig_status = 0;
            }
        }

        let ct = match c_str_to_str(ciphertext) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let sec = match c_str_to_str(secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pass = match c_str_to_str(passphrase) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let expected_opt = if expected_public.is_null() {
            None
        } else {
            match c_str_to_str(expected_public) {
                Ok(s) => Some(s),
                Err(_) => return -1,
            }
        };

        let (pt_bytes, sig_status) = match core::decrypt(ct.as_bytes(), sec, pass, expected_opt) {
            Ok(t) => t,
            Err(_) => return -1,
        };

        let s = match String::from_utf8(pt_bytes) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let c_s = match CString::new(s) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        unsafe {
            if !out_plain.is_null() {
                *out_plain = c_s.into_raw();
            }
            if !out_sig_status.is_null() {
                *out_sig_status = sig_status as c_int;
            }
        }

        0
    })
}

/// Decrypt *armored* ciphertext (bytes) to raw bytes.
/// On success:
///   - *out_plain, *out_plain_len set
///   - *out_sig_status set (0/1/2/3)
///
/// # Safety
///
/// - `ciphertext` must be a valid pointer to `ciphertext_len` bytes
/// - `secret` and `passphrase` must point to valid null-terminated C strings
/// - `expected_signer` may be NULL (to skip signature verification)
/// - `out_plaintext`, `out_plaintext_len`, and `out_sig_status` must point to valid memory
/// - On success, the caller must free returned bytes with `velum_free_bytes`
#[no_mangle]
pub unsafe extern "C" fn velum_decrypt_bytes(
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
    secret: *const c_char,
    passphrase: *const c_char,
    expected_public: *const c_char,
    out_plain: *mut *mut c_uchar,
    out_plain_len: *mut usize,
    out_sig_status: *mut c_int,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_bytes(out_plain, out_plain_len);
            if !out_sig_status.is_null() {
                *out_sig_status = 0;
            }
        }

        if ciphertext.is_null() && ciphertext_len > 0 {
            return -1;
        }

        let sec = match c_str_to_str(secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pass = match c_str_to_str(passphrase) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let expected_opt = if expected_public.is_null() {
            None
        } else {
            match c_str_to_str(expected_public) {
                Ok(s) => Some(s),
                Err(_) => return -1,
            }
        };

        let ct_slice = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };

        let (pt, sig_status) = match core::decrypt(ct_slice, sec, pass, expected_opt) {
            Ok(t) => t,
            Err(_) => return -1,
        };

        let len = pt.len();
        let mut v = pt;
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);

        unsafe {
            if !out_plain.is_null() {
                *out_plain = ptr;
            }
            if !out_plain_len.is_null() {
                *out_plain_len = len;
            }
            if !out_sig_status.is_null() {
                *out_sig_status = sig_status as c_int;
            }
        }

        0
    })
}

/// Decrypt *binary* VLM1 ciphertext to raw bytes.
///
/// # Safety
///
/// - `ciphertext` must be a valid pointer to `ciphertext_len` bytes
/// - `secret` and `passphrase` must point to valid null-terminated C strings
/// - `expected_signer` may be NULL (to skip signature verification)
/// - `out_plaintext`, `out_plaintext_len`, and `out_sig_status` must point to valid memory
/// - On success, the caller must free returned bytes with `velum_free_bytes`
#[no_mangle]
pub unsafe extern "C" fn velum_decrypt_binary(
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
    secret: *const c_char,
    passphrase: *const c_char,
    expected_public: *const c_char,
    out_plain: *mut *mut c_uchar,
    out_plain_len: *mut usize,
    out_sig_status: *mut c_int,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            set_null_bytes(out_plain, out_plain_len);
            if !out_sig_status.is_null() {
                *out_sig_status = 0;
            }
        }

        if ciphertext.is_null() && ciphertext_len > 0 {
            return -1;
        }

        let sec = match c_str_to_str(secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pass = match c_str_to_str(passphrase) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let expected_opt = if expected_public.is_null() {
            None
        } else {
            match c_str_to_str(expected_public) {
                Ok(s) => Some(s),
                Err(_) => return -1,
            }
        };

        let ct_slice = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };

        let (pt, sig_status) = match core::decrypt_binary(ct_slice, sec, pass, expected_opt) {
            Ok(t) => t,
            Err(_) => return -1,
        };

        let len = pt.len();
        let mut v = pt;
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);

        unsafe {
            if !out_plain.is_null() {
                *out_plain = ptr;
            }
            if !out_plain_len.is_null() {
                *out_plain_len = len;
            }
            if !out_sig_status.is_null() {
                *out_sig_status = sig_status as c_int;
            }
        }

        0
    })
}

// ===============================
// File streaming: binary VLM1
// ===============================

use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Encrypt file -> file (binary VLM1, streaming).
/// signer_secret/pass may be NULL → unsigned ciphertext.
///
/// # Safety
///
/// - `input_path`, `output_path`, and `recipients` must point to valid null-terminated C strings
/// - `signer_secret` and `signer_pass` may be NULL (for unsigned messages)
/// - Paths must be valid UTF-8
#[no_mangle]
pub unsafe extern "C" fn velum_encrypt_file_stream(
    input_path: *const c_char,
    output_path: *const c_char,
    recipients: *const c_char,
    signer_secret: *const c_char,
    signer_pass: *const c_char,
    chunk_size: usize,
) -> c_int {
    ffi_guard(|| {
        let in_path_s = match c_str_to_str(input_path) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let out_path_s = match c_str_to_str(output_path) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let recips = match c_str_to_str(recipients) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let signer_opt = if signer_secret.is_null() {
            None
        } else {
            let sec = match c_str_to_str(signer_secret) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            let pass = if signer_pass.is_null() {
                return -1;
            } else {
                match c_str_to_str(signer_pass) {
                    Ok(s) => s,
                    Err(_) => return -1,
                }
            };
            Some((sec, pass))
        };

        let in_path = Path::new(in_path_s);
        let out_path = Path::new(out_path_s);

        let mut input = match File::open(in_path) {
            Ok(f) => f,
            Err(_) => return -1,
        };
        let mut output = match File::create(out_path) {
            Ok(f) => f,
            Err(_) => return -1,
        };

        match core::encrypt_file_stream(&mut input, &mut output, recips, signer_opt, chunk_size) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    })
}

/// Decrypt file -> file (binary VLM1, streaming).
/// expected_public may be NULL.
/// On success:
///   - *out_sig_status = 0/1/2/3
///
/// # Safety
///
/// - `input_path`, `output_path`, `secret`, and `passphrase` must point to valid null-terminated C strings
/// - `expected_signer` may be NULL (to skip signature verification)
/// - `out_sig_status` must point to a valid memory location
/// - Paths must be valid UTF-8
#[no_mangle]
pub unsafe extern "C" fn velum_decrypt_file_stream(
    input_path: *const c_char,
    output_path: *const c_char,
    secret: *const c_char,
    passphrase: *const c_char,
    expected_public: *const c_char,
    out_sig_status: *mut c_int,
) -> c_int {
    ffi_guard(|| {
        unsafe {
            if !out_sig_status.is_null() {
                *out_sig_status = 0;
            }
        }

        let in_path_s = match c_str_to_str(input_path) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let out_path_s = match c_str_to_str(output_path) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let sec = match c_str_to_str(secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let pass = match c_str_to_str(passphrase) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let expected_opt = if expected_public.is_null() {
            None
        } else {
            match c_str_to_str(expected_public) {
                Ok(s) => Some(s),
                Err(_) => return -1,
            }
        };

        let in_path = Path::new(in_path_s);
        let out_path = Path::new(out_path_s);

        let mut input = match File::open(in_path) {
            Ok(f) => f,
            Err(_) => return -1,
        };
        let mut output = match File::create(out_path) {
            Ok(f) => f,
            Err(_) => return -1,
        };

        let status = match core::decrypt_file_stream(
            &mut input,
            sec,
            pass,
            expected_opt,
            |chunk: &[u8]| {
                output.write_all(chunk).map_err(|_| ())?;
                Ok(())
            },
        ) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        unsafe {
            if !out_sig_status.is_null() {
                *out_sig_status = status as c_int;
            }
        }

        0
    })
}

// ============================================================
// Unit tests for ffi.rs
// ============================================================

#[cfg(test)]
mod tests {
    //! # Tests for `ffi.rs` C API
    //!
    //! These tests exercise the FFI surface:
    //! - key generation and validation,
    //! - secret rewrapping (default and custom params),
    //! - encrypt/decrypt for string, bytes and binary APIs,
    //! - streaming file encryption/decryption wrappers.
    //!
    //! The goal is to ensure that:
    //! - pointers are initialized/reset correctly,
    //! - returned buffers are valid and freed via `velum_free_*`,
    //! - error codes are consistent with documented behavior.

    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::io::Write;
    use std::os::raw::{c_char, c_int, c_uchar};
    use std::path::PathBuf;
    use std::ptr;

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------

    /// Helper: convert `*mut c_char` produced by FFI into `String`
    /// without taking ownership, then free using `velum_free_string`.
    unsafe fn take_c_string(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        let s = CStr::from_ptr(ptr).to_str().unwrap().to_string();
        velum_free_string(ptr);
        s
    }

    /// Helper: convert `*mut c_uchar` + len into `Vec<u8>` and free
    /// using `velum_free_bytes`.
    unsafe fn take_c_bytes(ptr: *mut c_uchar, len: usize) -> Vec<u8> {
        assert!(!ptr.is_null());
        let slice = std::slice::from_raw_parts(ptr, len);
        let v = slice.to_vec();
        velum_free_bytes(ptr, len);
        v
    }

    /// Helper: build a temporary file path in the system temp directory.
    fn temp_file_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(name);
        p
    }

    // ------------------------------------------------------------
    // Key generation / validation / rewrap
    // ------------------------------------------------------------

    /// Ensure `velum_generate_keypair` returns valid PUBLIC/SECRET armors
    /// and that they can be freed using `velum_free_string`.
    #[test]
    fn test_velum_generate_keypair_and_validate_public() {
        let pass = CString::new("ffi-test-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();

        let rc = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc, 0);
        assert!(!out_pub.is_null());
        assert!(!out_sec.is_null());

        unsafe {
            let pub_arm = CStr::from_ptr(out_pub).to_str().unwrap().to_string();
            let sec_arm = CStr::from_ptr(out_sec).to_str().unwrap().to_string();

            // Validate PUBLIC armor via FFI.
            let c_pub = CString::new(pub_arm.clone()).unwrap();
            let v_rc = velum_validate_public(c_pub.as_ptr());
            assert_eq!(v_rc, 0);

            // Free FFI strings.
            velum_free_string(out_pub);
            velum_free_string(out_sec);

            // Sanity check: armors contain BEGIN/END markers.
            assert!(pub_arm.contains("BEGIN VELUM PUBLIC KEY"));
            assert!(sec_arm.contains("BEGIN VELUM SECRET KEY"));
        }
    }

    /// `velum_validate_public` must reject malformed PUBLIC armor.
    #[test]
    fn test_velum_validate_public_rejects_garbage() {
        let bad = CString::new("not a valid armor").unwrap();
        let rc = unsafe { velum_validate_public(bad.as_ptr()) };
        assert_eq!(rc, -1);
    }

    /// `velum_rewrap_secret` should produce a different SECRET armor
    /// while keeping it structurally valid.
    #[test]
    fn test_velum_rewrap_secret_basic() {
        // Generate a fresh keypair first.
        let pass = CString::new("old-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();

        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);
        assert!(!out_sec.is_null());

        let old_secret = unsafe { take_c_string(out_sec) };
        unsafe {
            velum_free_string(out_pub);
        }

        let old_secret_c = CString::new(old_secret.clone()).unwrap();
        let old_pass_c = CString::new("old-pass").unwrap();
        let new_pass_c = CString::new("new-pass").unwrap();
        let mut out_new: *mut c_char = ptr::null_mut();

        let rc = unsafe {
            velum_rewrap_secret(
                old_secret_c.as_ptr(),
                old_pass_c.as_ptr(),
                new_pass_c.as_ptr(),
                &mut out_new,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_new.is_null());

        let new_secret = unsafe { take_c_string(out_new) };
        assert_ne!(old_secret, new_secret);
        assert!(new_secret.contains("BEGIN VELUM SECRET KEY"));
    }

    /// `velum_rewrap_secret_with_params` should succeed with custom Argon2id
    /// parameters and return a new armored SECRET key.
    #[test]
    fn test_velum_rewrap_secret_with_params_ok() {
        // Generate base keypair.
        let pass = CString::new("base-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();
        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);
        assert!(!out_sec.is_null());

        let base_secret = unsafe { take_c_string(out_sec) };
        unsafe {
            velum_free_string(out_pub);
        }

        let old_arm_c = CString::new(base_secret.clone()).unwrap();
        let old_pass_c = CString::new("base-pass").unwrap();
        let new_pass_c = CString::new("stronger-pass").unwrap();
        let mut out_new: *mut c_char = ptr::null_mut();

        let rc = unsafe {
            velum_rewrap_secret_with_params(
                old_arm_c.as_ptr(),
                old_pass_c.as_ptr(),
                new_pass_c.as_ptr(),
                96 * 1024,
                4,
                4,
                &mut out_new,
            )
        };

        assert_eq!(rc, 0);
        assert!(!out_new.is_null());

        let new_secret = unsafe { take_c_string(out_new) };
        assert!(new_secret.contains("BEGIN VELUM SECRET KEY"));
    }

    // ------------------------------------------------------------
    // Encrypt / decrypt: string API
    // ------------------------------------------------------------

    /// Full round-trip using `velum_encrypt_string` / `velum_decrypt_string`
    /// without a signer, checking plaintext and signature status.
    #[test]
    fn test_encrypt_decrypt_string_roundtrip() {
        // Generate keypair.
        let pass = CString::new("ffi-roundtrip-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();
        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);

        let pub_arm = unsafe { take_c_string(out_pub) };
        let sec_arm = unsafe { take_c_string(out_sec) };

        let plaintext = CString::new("Hello from FFI string API").unwrap();
        let recips = CString::new(pub_arm.clone()).unwrap();
        let mut out_ct: *mut c_char = ptr::null_mut();

        let rc_enc = unsafe {
            velum_encrypt_string(
                plaintext.as_ptr(),
                recips.as_ptr(),
                ptr::null(),
                ptr::null(),
                &mut out_ct,
            )
        };
        assert_eq!(rc_enc, 0);
        assert!(!out_ct.is_null());

        let ct_arm = unsafe { take_c_string(out_ct) };

        let c_ct = CString::new(ct_arm).unwrap();
        let c_sec = CString::new(sec_arm).unwrap();
        let c_pass = CString::new("ffi-roundtrip-pass").unwrap();
        let mut out_plain: *mut c_char = ptr::null_mut();
        let mut sig_status: c_int = -42;

        let rc_dec = unsafe {
            velum_decrypt_string(
                c_ct.as_ptr(),
                c_sec.as_ptr(),
                c_pass.as_ptr(),
                ptr::null(),
                &mut out_plain,
                &mut sig_status,
            )
        };
        assert_eq!(rc_dec, 0);
        assert_eq!(sig_status, 0); // no signature

        let dec_plain = unsafe { take_c_string(out_plain) };
        assert_eq!(dec_plain, "Hello from FFI string API");
    }

    // ------------------------------------------------------------
    // Encrypt / decrypt: bytes API (armored)
    // ------------------------------------------------------------

    /// Round-trip for `velum_encrypt_bytes` / `velum_decrypt_bytes`
    /// using armored MESSAGE format.
    #[test]
    fn test_encrypt_decrypt_bytes_roundtrip() {
        // Generate keypair.
        let pass = CString::new("ffi-bytes-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();
        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);

        let pub_arm = unsafe { take_c_string(out_pub) };
        let sec_arm = unsafe { take_c_string(out_sec) };

        let plaintext = b"\x01\x02binary\xFFpayload";
        let recips = CString::new(pub_arm.clone()).unwrap();
        let mut out_ct: *mut c_uchar = ptr::null_mut();
        let mut out_ct_len: usize = 0;

        let rc_enc = unsafe {
            velum_encrypt_bytes(
                plaintext.as_ptr(),
                plaintext.len(),
                recips.as_ptr(),
                ptr::null(),
                ptr::null(),
                &mut out_ct,
                &mut out_ct_len,
            )
        };
        assert_eq!(rc_enc, 0);
        assert!(!out_ct.is_null());
        assert!(out_ct_len > 0);

        let ct_bytes = unsafe { take_c_bytes(out_ct, out_ct_len) };

        let c_sec = CString::new(sec_arm).unwrap();
        let c_pass = CString::new("ffi-bytes-pass").unwrap();
        let mut out_plain: *mut c_uchar = ptr::null_mut();
        let mut out_plain_len: usize = 0;
        let mut sig_status: c_int = -99;

        let rc_dec = unsafe {
            velum_decrypt_bytes(
                ct_bytes.as_ptr(),
                ct_bytes.len(),
                c_sec.as_ptr(),
                c_pass.as_ptr(),
                ptr::null(),
                &mut out_plain,
                &mut out_plain_len,
                &mut sig_status,
            )
        };
        assert_eq!(rc_dec, 0);
        assert_eq!(sig_status, 0);

        let dec_plain = unsafe { take_c_bytes(out_plain, out_plain_len) };
        assert_eq!(dec_plain, plaintext);
    }

    // ------------------------------------------------------------
    // Encrypt / decrypt: binary VLM1 API
    // ------------------------------------------------------------

    /// Round-trip for `velum_encrypt_binary` / `velum_decrypt_binary`
    /// using raw VLM1 binary envelopes.
    #[test]
    fn test_encrypt_decrypt_binary_roundtrip() {
        // Generate keypair.
        let pass = CString::new("ffi-binary-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();
        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);

        let pub_arm = unsafe { take_c_string(out_pub) };
        let sec_arm = unsafe { take_c_string(out_sec) };

        let plaintext = b"VLM1 binary ffi test";
        let recips = CString::new(pub_arm.clone()).unwrap();
        let mut out_ct: *mut c_uchar = ptr::null_mut();
        let mut out_ct_len: usize = 0;

        let rc_enc = unsafe {
            velum_encrypt_binary(
                plaintext.as_ptr(),
                plaintext.len(),
                recips.as_ptr(),
                ptr::null(),
                ptr::null(),
                &mut out_ct,
                &mut out_ct_len,
            )
        };
        assert_eq!(rc_enc, 0);
        assert!(!out_ct.is_null());

        let ct_bin = unsafe { take_c_bytes(out_ct, out_ct_len) };

        let c_sec = CString::new(sec_arm).unwrap();
        let c_pass = CString::new("ffi-binary-pass").unwrap();
        let mut out_plain: *mut c_uchar = ptr::null_mut();
        let mut out_plain_len: usize = 0;
        let mut sig_status: c_int = -7;

        let rc_dec = unsafe {
            velum_decrypt_binary(
                ct_bin.as_ptr(),
                ct_bin.len(),
                c_sec.as_ptr(),
                c_pass.as_ptr(),
                ptr::null(),
                &mut out_plain,
                &mut out_plain_len,
                &mut sig_status,
            )
        };
        assert_eq!(rc_dec, 0);
        assert_eq!(sig_status, 0);

        let dec_plain = unsafe { take_c_bytes(out_plain, out_plain_len) };
        assert_eq!(dec_plain, plaintext);
    }

    // ------------------------------------------------------------
    // File streaming API
    // ------------------------------------------------------------

    /// End-to-end file-streaming round-trip:
    /// - write plaintext to temp file,
    /// - encrypt with `velum_encrypt_file_stream` (stream:Y),
    /// - decrypt with `velum_decrypt_file_stream`,
    /// - compare recovered file contents.
    #[test]
    fn test_encrypt_decrypt_file_stream_roundtrip() {
        // Generate keypair.
        let pass = CString::new("ffi-file-pass").unwrap();
        let mut out_pub: *mut c_char = ptr::null_mut();
        let mut out_sec: *mut c_char = ptr::null_mut();
        let rc_kp = unsafe { velum_generate_keypair(pass.as_ptr(), &mut out_pub, &mut out_sec) };
        assert_eq!(rc_kp, 0);

        let pub_arm = unsafe { take_c_string(out_pub) };
        let sec_arm = unsafe { take_c_string(out_sec) };

        // Prepare temp files.
        let in_plain = temp_file_path("velum_ffi_plain.txt");
        let out_enc = temp_file_path("velum_ffi_enc.vlm1");
        let out_dec = temp_file_path("velum_ffi_dec.txt");

        // Write plaintext.
        let mut f_plain = fs::File::create(&in_plain).unwrap();
        let content = b"streaming file test payload via FFI";
        f_plain.write_all(content).unwrap();
        drop(f_plain);

        let c_in = CString::new(in_plain.to_string_lossy().into_owned()).unwrap();
        let c_enc = CString::new(out_enc.to_string_lossy().into_owned()).unwrap();
        let c_dec = CString::new(out_dec.to_string_lossy().into_owned()).unwrap();
        let c_pub = CString::new(pub_arm.clone()).unwrap();
        let c_sec = CString::new(sec_arm).unwrap();
        let c_pass = CString::new("ffi-file-pass").unwrap();
        let mut sig_status: c_int = -11;

        // Encrypt file → file (unsigned, stream:Y).
        let rc_enc = unsafe {
            velum_encrypt_file_stream(
                c_in.as_ptr(),
                c_enc.as_ptr(),
                c_pub.as_ptr(),
                ptr::null(),
                ptr::null(),
                1024,
            )
        };
        assert_eq!(rc_enc, 0);

        // Decrypt file → file.
        let rc_dec = unsafe {
            velum_decrypt_file_stream(
                c_enc.as_ptr(),
                c_dec.as_ptr(),
                c_sec.as_ptr(),
                c_pass.as_ptr(),
                ptr::null(),
                &mut sig_status,
            )
        };
        assert_eq!(rc_dec, 0);
        assert_eq!(sig_status, 0);

        // Compare contents.
        let dec_bytes = fs::read(&out_dec).unwrap();
        assert_eq!(dec_bytes, content);

        // Cleanup (best-effort).
        let _ = fs::remove_file(in_plain);
        let _ = fs::remove_file(out_enc);
        let _ = fs::remove_file(out_dec);
    }
}