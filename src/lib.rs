//! velum — VELUM v1 post-quantum hybrid cryptographic engine
//!
//! This crate implements the complete **VELUM v1** protocol — a modern, post-quantum,
//! recipient-anonymous, streaming-capable end-to-end encryption system.
//!
//! ### Key Features
//! - **Hybrid KEM**: X25519 + ML-KEM-768 (Kyber) with proper shared secret composition
//! - **Recipient anonymity & unlinkability** via per-recipient blinded capsules and index hints
//! - **Hybrid signatures**: ML-DSA-65 (Dilithium3) + Ed25519 (concatenated, not nested)
//! - **Zero-seek streaming** encryption/decryption with forward-only trailer signatures
//! - **Binary (VLM1) and ASCII-armored formats** (PEM-style, strict parsing)
//! - **Secure secret keystore**: Argon2id + AES-GCM-SIV with embedded KDF parameters
//! - **Full C FFI** for integration with iOS, Android, CLI, and embedded systems
//!
//! ### Design Principles
//! - **No unsafe code** outside of FFI boundary
//! - **Constant-time** where required (parsing, comparison)
//! - **Zeroize** on drop for all secret material
//! - **Single source of truth** for protocol constants, transcripts, and AAD
//! - **Explicit error handling** (`Result<..., ()>`) — no panics in library code
//!
//! ### Intended Users
//! - The `velum` CLI (in the workspace)
//! - Mobile apps (via C FFI)
//! - Embedded systems
//! - Other Rust projects needing PQ-secure, anonymous multi-recipient encryption
//!
//! ### Public API
//! The primary entry points for Rust consumers are:
//! - [`core`] — high-level encrypt/decrypt (in-memory and streaming)
//! - [`keys`] — key generation, validation, and passphrase rewrapping
//! - [`armor`] — armored text format handling (PUBLIC/SECRET/MESSAGE)
//! - [`ffi`] — C-compatible API (`velum_*` functions)

/// Public API modules — intended for external consumers.
pub mod armor;
pub mod constants;
pub mod core;
pub mod keys;

/// Internal implementation modules — not part of the public API.
mod context;
mod envelope;
mod recipients;
mod streaming;
mod transcript;
mod util;

/// C foreign function interface (FFI).
///
/// Exports `velum_*` functions with C calling convention and manual memory management.
/// Safe to use from C, C++, Swift (via bridging), Kotlin (JNI), etc.
pub mod ffi;

/// High-level encryption/decryption API.
///
/// These are the primary functions used by applications:
/// - `encrypt` / `encrypt_binary` — in-memory encryption
/// - `encrypt_file_stream` — zero-seek streaming encryption
/// - `decrypt` / `decrypt_binary` — in-memory decryption
/// - `decrypt_file_stream` — zero-seek streaming decryption
///
/// Returns signature verification status via [`SigStatus`].
pub use crate::core::{
    decrypt, decrypt_binary, decrypt_file_stream, encrypt, encrypt_binary, encrypt_file_stream,
    SigStatus,
};

/// Key management operations.
///
/// - `generate_keypair` — create a new (PUBLIC, SECRET) pair protected by passphrase
/// - `rewrap_secret_with_params` — change passphrase or Argon2id parameters
/// - `validate_public` — strict validation of armored PUBLIC keys
pub use crate::keys::{generate_keypair, rewrap_secret_with_params, validate_public};
