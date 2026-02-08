//! Runtime opaque predicate evaluator.
//!
//! Evaluates quadratic residuosity predicates at runtime using Euler's criterion.
//! These functions are `#[inline(never)]` to prevent the compiler from
//! constant-folding the result (which would defeat the purpose).

/// Modular multiplication using u128 to avoid overflow.
#[inline(always)]
fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Modular exponentiation: base^exp mod modulus.
#[inline(always)]
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 { return 0; }
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        exp >>= 1;
        base = mod_mul(base, base, modulus);
    }
    result
}

/// Evaluate a quadratic residuosity opaque predicate.
///
/// Returns `true` if `witness` is a quadratic residue mod `prime`
/// (i.e., `witness^((prime-1)/2) ≡ 1 (mod prime)`).
///
/// For always-true predicates, the caller passes `witness = x² mod p`.
/// For always-false predicates, the caller passes a known QNR.
///
/// This function MUST NOT be inlined — the compiler must not see through
/// the modular exponentiation to constant-fold the result.
#[inline(never)]
pub fn check_qr(witness: u64, prime: u64) -> bool {
    if prime < 3 { return true; }
    let exp = (prime - 1) / 2;
    mod_pow(witness, exp, prime) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_qr() {
        // 4 = 2² is always a QR mod any odd prime > 2
        assert!(check_qr(4, 7));   // 4^3 mod 7 = 64 mod 7 = 1
        assert!(check_qr(4, 11));  // 4^5 mod 11 = 1024 mod 11 = 1
        assert!(check_qr(4, 13));  // 4^6 mod 13 = 4096 mod 13 = 1
    }

    #[test]
    fn test_known_qnr() {
        // 3 is a QNR mod 7 (3^3 mod 7 = 27 mod 7 = 6 = -1)
        assert!(!check_qr(3, 7));
    }

    #[test]
    fn test_trivial_cases() {
        assert!(check_qr(1, 5));  // 1 is always a QR
        assert!(check_qr(0, 2));  // prime < 3
    }
}
