/// XTEA block cipher (64-bit block, 128-bit key, 32 Feistel cycles).
///
/// Compact and fast — suitable for both compile-time key derivation
/// and runtime page encryption (Phase 2B: Tidal XTEA-CTR).

const DELTA: u32 = 0x9E37_79B9;
const ROUNDS: u32 = 32;

/// Encrypt a 64-bit block with a 128-bit key (4 × u32).
pub fn xtea_encrypt_block(pt: u64, key: &[u32; 4]) -> u64 {
    let mut v0 = pt as u32;
    let mut v1 = (pt >> 32) as u32;
    let mut sum: u32 = 0;

    for _ in 0..ROUNDS {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ (sum.wrapping_add(key[(sum & 3) as usize])),
        );
        sum = sum.wrapping_add(DELTA);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ (sum.wrapping_add(key[((sum >> 11) & 3) as usize])),
        );
    }

    (v0 as u64) | ((v1 as u64) << 32)
}

/// Decrypt a 64-bit block with a 128-bit key (4 × u32).
pub fn xtea_decrypt_block(ct: u64, key: &[u32; 4]) -> u64 {
    let mut v0 = ct as u32;
    let mut v1 = (ct >> 32) as u32;
    let mut sum: u32 = DELTA.wrapping_mul(ROUNDS);

    for _ in 0..ROUNDS {
        v1 = v1.wrapping_sub(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ (sum.wrapping_add(key[((sum >> 11) & 3) as usize])),
        );
        sum = sum.wrapping_sub(DELTA);
        v0 = v0.wrapping_sub(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ (sum.wrapping_add(key[(sum & 3) as usize])),
        );
    }

    (v0 as u64) | ((v1 as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210];
        for pt in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let ct = xtea_encrypt_block(pt, &key);
            assert_ne!(ct, pt, "ciphertext should differ from plaintext");
            let recovered = xtea_decrypt_block(ct, &key);
            assert_eq!(recovered, pt, "decrypt(encrypt(pt)) != pt");
        }
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let k1 = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let k2 = [0x11111111, 0x22222222, 0x33333333, 0x44444445];
        let pt = 0xCAFEBABE_DEADBEEF;
        assert_ne!(xtea_encrypt_block(pt, &k1), xtea_encrypt_block(pt, &k2));
    }

    #[test]
    fn avalanche() {
        let key = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
        let ct0 = xtea_encrypt_block(0, &key);
        let ct1 = xtea_encrypt_block(1, &key);
        let diff = (ct0 ^ ct1).count_ones();
        assert!(diff >= 20, "only {} bits differ (poor avalanche)", diff);
    }
}
