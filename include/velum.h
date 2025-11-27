// include/velum/velum.h
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
   VELUM — Post-quantum hybrid encryption library
   C Foreign Function Interface (FFI)
   ======================================================================== */


/* ============ Memory management ============ */
// All functions that return allocated memory (strings or byte buffers)
// transfer ownership to the caller. You MUST free them using these functions.

/// Free a null-terminated string returned by any velum_* API.
void velum_free_string(char *s);

/// Free a byte buffer returned by any velum_* API.
/// You must pass the exact length that was returned alongside the pointer.
void velum_free_bytes(uint8_t *data, size_t len);


/* ============ Version ============ */
/// Returns library version as a null-terminated string, e.g. "0.1.0".
/// The returned pointer is valid for the lifetime of the library.
const char* velum_version(void);


/* ============ Key management ============ */
/// Generate a new keypair protected by a passphrase.
/// On success returns 0 and fills *out_public_armor / *out_secret_armor with
/// newly allocated armored blocks (PEM-style). Caller must free them.
int32_t velum_generate_keypair(const char *passphrase,
                               char **out_public_armor,
                               char **out_secret_armor);

/// Change passphrase (and optionally KDF parameters) of an existing secret key.
/// Input and output are armored SECRET blocks.
int32_t velum_rewrap_secret(const char *old_secret_armor,
                            const char *old_passphrase,
                            const char *new_passphrase,
                            char **out_new_secret_armor);

/// Validate a public-key armored block. Returns 1 if valid, 0 otherwise.
int32_t velum_validate_public(const char *public_armor);


/* ============ In-memory encryption (armored) ============ */
/// Encrypt arbitrary UTF-8 text to an armored VELUM message.
/// signer_secret_armor and signer_passphrase may be NULL (const char*)NULL.
int32_t velum_encrypt_string(const char *plaintext_utf8,
                             const char *recipient_pub_armor,
                             const char *signer_secret_armor_or_null,
                             const char *signer_pass_or_null,
                             char **out_armored_message);

/// Decrypt an armored VELUM message that may contain UTF-8 text.
/// expected_pub_armor may be NULL (no signature verification).
/// out_sig_status values:
///   0 = no signature present
///   1 = signature present and valid
///   2 = signature present but invalid
///   3 = signature expected (expected_pub_armor != NULL) but missing
int32_t velum_decrypt_string(const char *armored_message,
                             const char *my_secret_armor,
                             const char *my_passphrase,
                             const char *expected_pub_armor_or_null,
                             char **out_plaintext_utf8,
                             int32_t *out_sig_status);


/* ============ In-memory encryption (binary interface) ============ */
/// Encrypt arbitrary bytes (can contain null bytes) → returns armored message as bytes.
int32_t velum_encrypt_bytes(const uint8_t *plaintext,
                            size_t plaintext_len,
                            const char *recipient_pub_armor,
                            const char *signer_secret_armor_or_null,
                            const char *signer_pass_or_null,
                            uint8_t **out_armored_bytes,
                            size_t *out_len);

/// Decrypt armored message given as raw bytes.
int32_t velum_decrypt_bytes(const uint8_t *armored_bytes,
                            size_t armored_len,
                            const char *my_secret_armor,
                            const char *my_passphrase,
                            const char *expected_pub_armor_or_null,
                            uint8_t **out_plaintext,
                            size_t *out_plaintext_len,
                            int32_t *out_sig_status);


/* ============ Zero-seek streaming file API ============ */
/// Encrypt a file with constant memory usage (streaming mode).
/// chunk_size should be between 64 KiB and 64 MiB; recommended 4–16 MiB.
int32_t velum_encrypt_file_stream(const char *input_path_utf8,
                                  const char *output_path_utf8,
                                  const char *recipient_pub_armor,
                                  const char *signer_secret_armor_or_null,
                                  const char *signer_pass_or_null,
                                  size_t chunk_size);

/// Decrypt a streaming-mode VELUM file with constant memory.
int32_t velum_decrypt_file_stream(const char *input_path_utf8,
                                  const char *output_path_utf8,
                                  const char *my_secret_armor,
                                  const char *my_passphrase,
                                  const char *expected_pub_armor_or_null,
                                  int32_t *out_sig_status);


#ifdef __cplusplus
}
#endif
