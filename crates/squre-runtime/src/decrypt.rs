//! Runtime string decryption.
//!
//! This module provides the decryption function called by code generated
//! by the `encrypt_string!()` macro. The decryption is inlined to avoid
//! creating a single identifiable decryption callsite.

/// Decrypt a ciphertext encrypted with the SQURE multi-round XOR cipher.
///
/// This MUST be kept in sync with `squre_core::crypto::xor_cipher::decrypt_inline`.
#[inline(always)]
pub fn decrypt_xor(ciphertext: &[u8], key: &[u8]) -> String {
    let bytes = decrypt_xor_bytes(ciphertext, key);
    // SAFETY: The original plaintext was valid UTF-8 (a Rust string literal).
    // If corruption occurs (e.g., anti-debug poison), this will produce garbage
    // rather than panic, which is the desired behavior.
    String::from_utf8(bytes).unwrap_or_default()
}

/// Decrypt to raw bytes (for non-UTF8 data).
#[inline(always)]
pub fn decrypt_xor_bytes(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    if ciphertext.is_empty() || key.is_empty() {
        return Vec::new();
    }

    let len = ciphertext.len();
    let mut buf = ciphertext.to_vec();

    // Reverse Round 3: XOR with shifted key
    for i in 0..len {
        buf[i] ^= key[(i.wrapping_add(key[0] as usize)) % len];
    }

    // Reverse Round 2: Rotate right by key-derived amount
    for i in 0..len {
        let rot = key[(i + 1) % len] % 8;
        buf[i] = buf[i].rotate_right(rot as u32);
    }

    // Reverse Round 1: XOR with key
    for i in 0..len {
        buf[i] ^= key[i];
    }

    buf
}
