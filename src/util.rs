//! src/util.rs
//!
//! Collection of small, protocol-agnostic utility functions used throughout the VELUM core.
//!
//! This module intentionally contains **no cryptographic protocol logic** — only pure,
//! reusable helpers for common operations such as Base64 encoding/decoding, secure random
//! byte generation, and big-endian integer handling.
//!
//! All functions are deliberately simple, well-tested in practice, and designed for
//! constant-time or cryptographically safe behavior where applicable.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};

/// Encodes a byte slice into a Base64 string using the standard alphabet (RFC 4648 §4).
///
/// This function uses the URL-safe, padding-inclusive standard Base64 encoding (`A-Z`, `a-z`,
/// `0-9`, `+`, `/`, `=`). It is the canonical encoding used in all VELUM armored formats
/// (PUBLIC, SECRET, MESSAGE).
///
/// # Examples
///
/// ```ignore
/// let bytes = b"hello velum";
/// // In real code, call: velum_core::util::b64e(bytes)
/// // assert_eq!(velum_core::util::b64e(bytes), "aGVsbG8gdmVsdW0=");
/// ```
pub(crate) fn b64e(x: &[u8]) -> String {
    STANDARD.encode(x)
}

/// Decodes a Base64-encoded string into its original byte representation.
///
/// Accepts the same standard Base64 alphabet as [`b64e`]. Whitespace is not tolerated — the
/// input must be a valid, contiguous Base64 string. On any decoding error (invalid characters,
/// wrong padding, etc.), returns `Err(())`.
///
/// This function is used extensively when parsing armored blocks and message headers.
///
/// # Errors
///
/// Returns `Err(())` if the input is not valid Base64.
///
/// # Examples
///
/// ```ignore
/// // In real code, call:
/// // use velum_core::util::b64d;
/// // assert_eq!(b64d("aGVsbG8=").unwrap(), b"hello");
/// // assert!(b64d("!!!").is_err());
/// ```
pub(crate) fn b64d(s: &str) -> Result<Vec<u8>, ()> {
    STANDARD.decode(s).map_err(|_| ())
}

/// Generates a vector of cryptographically secure random bytes of the requested length.
///
/// Uses the operating system’s cryptographically secure pseudorandom number generator
/// (`getrandom` → `OsRng`) to fill a freshly allocated buffer. This function must be used
/// for all security-critical randomness (nonces, salts, keys, etc.).
///
/// # Panics
///
/// This function will not panic under normal operation. It only fails if the underlying OS
/// RNG fails (extremely rare).
///
/// # Examples
///
/// ```ignore
/// // In real code:
/// // use velum_core::util::random_bytes;
/// // let salt = random_bytes(16);
/// // assert_eq!(salt.len(), 16);
/// ```
pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Converts a `usize` value into a 4-byte big-endian (network-order) representation.
///
/// The value is truncated to 32 bits (i.e., only the lower 32 bits are preserved). This is
/// intentional and safe for all lengths used in VELUM wire formats (header lengths, field
/// sizes, etc.), which are far below 4 GiB.
///
/// # Examples
///
/// ```ignore
/// // use velum_core::util::be_u32;
/// // assert_eq!(be_u32(0x01020304), [1, 2, 3, 4]);
/// // assert_eq!(be_u32(256), [0, 0, 1, 0]);
/// ```
pub(crate) fn be_u32(x: usize) -> [u8; 4] {
    (x as u32).to_be_bytes()
}

/// Reads a big-endian `u32` from a byte buffer at the current offset and advances the offset.
///
/// The value is returned as `usize` for convenience in length calculations. If fewer than 4
/// bytes remain in the buffer, returns `Err(())` without modifying the offset.
///
/// This function is heavily used during binary envelope and recipients-blob parsing.
///
/// # Errors
///
/// Returns `Err(())` if the buffer has fewer than 4 bytes remaining from `*off`.
///
/// # Examples
///
/// ```ignore
/// // use velum_core::util::read_be_u32;
/// // let data = [0x00, 0x01, 0x00, 0x00, 0xFF];
/// // let mut off = 1;
/// // assert_eq!(read_be_u32(&data, &mut off).unwrap(), 0x010000);
/// // assert_eq!(off, 5);
/// ```
pub(crate) fn read_be_u32(buf: &[u8], off: &mut usize) -> Result<usize, ()> {
    if *off + 4 > buf.len() {
        return Err(());
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[*off..*off + 4]);
    *off += 4;
    Ok(u32::from_be_bytes(a) as usize)
}
