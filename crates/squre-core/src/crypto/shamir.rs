//! Shamir's Secret Sharing over GF(2^64).
//!
//! Implements a (k=3, n=3) threshold scheme: the secret is split into
//! 3 shares, and all 3 are required to reconstruct. Uses arithmetic in
//! GF(2^64) with irreducible polynomial x^64 + x^4 + x^3 + x + 1.

/// A single share: (x-coordinate, y-coordinate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    pub x: u64,
    pub y: u64,
}

// ─── GF(2^64) Arithmetic ─────────────────────────────────────

/// Irreducible polynomial for GF(2^64): x^64 + x^4 + x^3 + x + 1 = 0x1B (low bits).
const IRREDUCIBLE: u64 = 0x1B;

/// Multiplication in GF(2^64) — carry-less multiplication with reduction.
fn gf_mul(mut a: u64, mut b: u64) -> u64 {
    let mut result: u64 = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & (1u64 << 63);
        a <<= 1;
        if high_bit != 0 {
            a ^= IRREDUCIBLE;
        }
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(2^64) using iterated squaring.
/// For GF(2^n), a^(-1) = a^(2^n - 2).
fn gf_inv(a: u64) -> u64 {
    if a == 0 {
        return 0; // No inverse for zero; caller must avoid
    }
    // Compute a^(2^64 - 2) = a^(0xFFFFFFFFFFFFFFFE)
    let mut result: u64 = 1;
    let mut base = a;
    let exp: u64 = 0xFFFF_FFFF_FFFF_FFFE;
    let mut e = exp;
    while e != 0 {
        if e & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

// ─── Shamir SSS ──────────────────────────────────────────────

/// Split a secret into 3 shares (k=3, n=3 threshold).
///
/// Uses a degree-2 polynomial: f(x) = secret + a1*x + a2*x^2
/// where a1, a2 are random coefficients.
///
/// The x-coordinates are fixed at 1, 2, 3 (non-zero in GF(2^64)).
///
/// # Arguments
/// - `secret`: The value to split.
/// - `rand1`, `rand2`: Random coefficients for the polynomial.
///   These MUST be cryptographically random for security.
pub fn split(secret: u64, rand1: u64, rand2: u64) -> [Share; 3] {
    let a0 = secret;
    let a1 = rand1;
    let a2 = rand2;

    // Evaluate f(x) = a0 + a1*x + a2*x^2 at x = 1, 2, 3
    let mut shares = [Share { x: 0, y: 0 }; 3];
    let xs: [u64; 3] = [1, 2, 3];

    for i in 0..3 {
        let x = xs[i];
        let x2 = gf_mul(x, x);
        let y = a0 ^ gf_mul(a1, x) ^ gf_mul(a2, x2);
        shares[i] = Share { x, y };
    }

    shares
}

/// Reconstruct the secret from exactly 3 shares using Lagrange interpolation.
///
/// Returns the secret (the polynomial evaluated at x=0).
pub fn reconstruct(shares: &[Share; 3]) -> u64 {
    // Lagrange interpolation at x = 0:
    // secret = Σ_i y_i * Π_{j≠i} (0 - x_j) / (x_i - x_j)
    //        = Σ_i y_i * Π_{j≠i} x_j / (x_i ⊕ x_j)
    //
    // In GF(2^n): subtraction = addition = XOR, and 0 - x_j = x_j.

    let mut secret: u64 = 0;

    for i in 0..3 {
        let mut numerator: u64 = 1;
        let mut denominator: u64 = 1;

        for j in 0..3 {
            if i == j {
                continue;
            }
            // numerator *= x_j (since we evaluate at x=0, factor is (0 ⊕ x_j) = x_j)
            numerator = gf_mul(numerator, shares[j].x);
            // denominator *= (x_i ⊕ x_j)
            denominator = gf_mul(denominator, shares[i].x ^ shares[j].x);
        }

        let lagrange_coeff = gf_mul(numerator, gf_inv(denominator));
        secret ^= gf_mul(shares[i].y, lagrange_coeff);
    }

    secret
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_identity() {
        // a * 1 = a
        assert_eq!(gf_mul(0xDEADBEEF, 1), 0xDEADBEEF);
        assert_eq!(gf_mul(1, 0xCAFEBABE), 0xCAFEBABE);
    }

    #[test]
    fn test_gf_mul_zero() {
        assert_eq!(gf_mul(0, 0xDEADBEEF), 0);
        assert_eq!(gf_mul(0xDEADBEEF, 0), 0);
    }

    #[test]
    fn test_gf_mul_commutative() {
        let a = 0x1234_5678_9ABC_DEF0;
        let b = 0xFEDC_BA98_7654_3210;
        assert_eq!(gf_mul(a, b), gf_mul(b, a));
    }

    #[test]
    fn test_gf_inv_roundtrip() {
        let a = 0xDEAD_BEEF_CAFE_F00D;
        let inv = gf_inv(a);
        assert_ne!(inv, 0);
        assert_eq!(gf_mul(a, inv), 1);
    }

    #[test]
    fn test_gf_inv_multiple_values() {
        let values = [1u64, 2, 3, 0xFF, 0x1234_5678_9ABC_DEF0, 0xFFFF_FFFF_FFFF_FFFF];
        for v in values {
            let inv = gf_inv(v);
            assert_eq!(gf_mul(v, inv), 1, "gf_inv failed for 0x{:016X}", v);
        }
    }

    #[test]
    fn test_split_reconstruct_roundtrip() {
        let secret = 0xDEAD_BEEF_CAFE_F00D;
        let shares = split(secret, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222);
        let recovered = reconstruct(&shares);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_split_reconstruct_zero_secret() {
        let shares = split(0, 0xAAAA, 0xBBBB);
        assert_eq!(reconstruct(&shares), 0);
    }

    #[test]
    fn test_split_reconstruct_max_secret() {
        let secret = u64::MAX;
        let shares = split(secret, 0x9999_8888_7777_6666, 0x5555_4444_3333_2222);
        assert_eq!(reconstruct(&shares), secret);
    }

    #[test]
    fn test_different_coefficients_different_shares() {
        let secret = 0xCAFE;
        let shares1 = split(secret, 0x1111, 0x2222);
        let shares2 = split(secret, 0x3333, 0x4444);
        // Shares differ but both reconstruct to the same secret
        assert_ne!(shares1[0].y, shares2[0].y);
        assert_eq!(reconstruct(&shares1), secret);
        assert_eq!(reconstruct(&shares2), secret);
    }

    #[test]
    fn test_shares_are_all_different() {
        let shares = split(0xABCD, 0x1234, 0x5678);
        assert_ne!(shares[0].y, shares[1].y);
        assert_ne!(shares[1].y, shares[2].y);
        assert_ne!(shares[0].y, shares[2].y);
    }

    #[test]
    fn test_random_secrets() {
        // Test with various pseudo-random values
        let test_cases: [(u64, u64, u64); 5] = [
            (0x0000_0000_0000_0001, 0xAAAA_BBBB_CCCC_DDDD, 0x1111_2222_3333_4444),
            (0x8000_0000_0000_0000, 0x5555_5555_5555_5555, 0x7777_7777_7777_7777),
            (0xFFFF_FFFF_FFFF_FFFF, 0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
            (0x1234_5678_9ABC_DEF0, 0xDEAD_BEEF_DEAD_BEEF, 0xCAFE_BABE_CAFE_BABE),
            (0x0000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0001),
        ];
        for (secret, r1, r2) in test_cases {
            let shares = split(secret, r1, r2);
            let recovered = reconstruct(&shares);
            assert_eq!(recovered, secret,
                "Failed for secret=0x{:016X}, r1=0x{:016X}, r2=0x{:016X}", secret, r1, r2);
        }
    }
}
