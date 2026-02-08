//! Multi-round XOR cipher for string encryption.
//!
//! This is NOT a cryptographically secure cipher. Its purpose is to make
//! string literals invisible to static analysis tools (strings, hex editors).
//! The real protection comes from MBA-obfuscated key storage.

use rand::Rng;

/// Encrypt plaintext using a multi-round XOR cipher.
///
/// Returns `(ciphertext, key)`. The key must be stored using MBA
/// obfuscation to prevent trivial extraction.
pub fn encrypt(plaintext: &[u8], rng: &mut impl Rng) -> (Vec<u8>, Vec<u8>) {
    if plaintext.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let len = plaintext.len();
    let key: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    let mut buf = plaintext.to_vec();

    // Round 1: XOR with key
    for i in 0..len {
        buf[i] ^= key[i];
    }

    // Round 2: Rotate left by key-derived amount
    for i in 0..len {
        let rot = key[(i + 1) % len] % 8;
        buf[i] = buf[i].rotate_left(rot as u32);
    }

    // Round 3: XOR with shifted key
    for i in 0..len {
        buf[i] ^= key[(i.wrapping_add(key[0] as usize)) % len];
    }

    (buf, key)
}

/// Decrypt ciphertext using the multi-round XOR cipher (reverse order).
///
/// This function is duplicated in `squre-runtime` for use at runtime.
/// Both implementations MUST stay in sync.
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt_inline(ciphertext, key)
}

/// Core decryption logic, shared between compile-time verification and runtime.
#[inline(always)]
pub fn decrypt_inline(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_roundtrip_ascii() {
        let mut rng = StdRng::seed_from_u64(42);
        let plain = b"Hello, World!";
        let (cipher, key) = encrypt(plain, &mut rng);
        assert_ne!(&cipher, plain);
        let decrypted = decrypt(&cipher, &key);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_roundtrip_utf8() {
        let mut rng = StdRng::seed_from_u64(99);
        let plain = "日本語テスト🎉".as_bytes();
        let (cipher, key) = encrypt(plain, &mut rng);
        let decrypted = decrypt(&cipher, &key);
        assert_eq!(decrypted, plain);
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "日本語テスト🎉");
    }

    #[test]
    fn test_roundtrip_empty() {
        let mut rng = StdRng::seed_from_u64(0);
        let (cipher, key) = encrypt(b"", &mut rng);
        assert!(cipher.is_empty());
        let decrypted = decrypt(&cipher, &key);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let mut rng = StdRng::seed_from_u64(1);
        for b in 0..=255u8 {
            let plain = [b];
            let (cipher, key) = encrypt(&plain, &mut rng);
            let decrypted = decrypt(&cipher, &key);
            assert_eq!(decrypted, plain);
        }
    }

    #[test]
    fn test_roundtrip_random_bulk() {
        let mut rng = StdRng::seed_from_u64(777);
        for _ in 0..1000 {
            let len = rng.gen_range(1..256);
            let plain: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let (cipher, key) = encrypt(&plain, &mut rng);
            let decrypted = decrypt(&cipher, &key);
            assert_eq!(decrypted, plain);
        }
    }

    #[test]
    fn test_different_seeds_different_ciphertext() {
        let plain = b"same input";
        let mut rng1 = StdRng::seed_from_u64(100);
        let mut rng2 = StdRng::seed_from_u64(200);
        let (c1, _) = encrypt(plain, &mut rng1);
        let (c2, _) = encrypt(plain, &mut rng2);
        assert_ne!(c1, c2, "Different seeds should produce different ciphertext");
    }

    #[test]
    fn test_ciphertext_not_contains_plaintext_substring() {
        let mut rng = StdRng::seed_from_u64(42);
        let plain = b"SECRET_LICENSE_KEY_12345";
        let (cipher, _) = encrypt(plain, &mut rng);
        // No 4+ byte substring of plaintext should appear in ciphertext
        for window in plain.windows(4) {
            for cwindow in cipher.windows(4) {
                assert_ne!(window, cwindow,
                    "Ciphertext contains plaintext substring");
            }
        }
    }
}
