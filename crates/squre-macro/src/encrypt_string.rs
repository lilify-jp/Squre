//! Implementation of the `encrypt_string!()` proc macro.

use proc_macro2::TokenStream;
use quote::quote;
use rand::SeedableRng;
use rand::rngs::StdRng;

use squre_core::crypto::xor_cipher;
use squre_core::mba::constant::synthesize_constant_u8;
use crate::codegen::expr_to_tokens;

/// Generate code that decrypts an encrypted string at runtime.
///
/// The string is encrypted at compile time. The encryption key is stored
/// as MBA expressions (never as plain constants in the binary).
pub fn generate(input: &str) -> TokenStream {
    let plaintext = input.as_bytes();

    if plaintext.is_empty() {
        return quote! { String::new() };
    }

    // Generate a seed from the string content + random entropy
    let seed = {
        let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
        for &b in plaintext {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3); // FNV prime
        }
        // Mix in some compile-time entropy
        h ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        h
    };

    let mut rng = StdRng::seed_from_u64(seed);

    // Encrypt the string
    let (ciphertext, key) = xor_cipher::encrypt(plaintext, &mut rng);

    // Verify roundtrip correctness at compile time
    let verify = xor_cipher::decrypt(&ciphertext, &key);
    assert_eq!(verify, plaintext, "BUG: encrypt/decrypt roundtrip failed");

    // Generate MBA expressions for each key byte
    let key_len = key.len();
    let key_exprs: Vec<TokenStream> = key
        .iter()
        .map(|&b| {
            let mba = synthesize_constant_u8(b, 2, &mut rng);
            let tokens = expr_to_tokens(&mba);
            quote! { (#tokens) as u8 }
        })
        .collect();

    // Emit the ciphertext as a static byte array
    let cipher_bytes = &ciphertext;
    let cipher_len = ciphertext.len();

    quote! {
        {
            static __SQURE_CIPHER: [u8; #cipher_len] = [#(#cipher_bytes),*];
            let __squre_key: [u8; #key_len] = [#(#key_exprs),*];
            ::squre_runtime::decrypt::decrypt_xor(&__SQURE_CIPHER, &__squre_key)
        }
    }
}
