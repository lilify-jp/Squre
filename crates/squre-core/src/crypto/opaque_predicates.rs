//! Cryptographic Opaque Predicates based on Quadratic Residuosity.
//!
//! Generates branch conditions whose outcome is determined by number-theoretic
//! properties that static analysis tools cannot resolve:
//!
//! - **Always-true**: `x² mod p` is always a quadratic residue
//! - **Always-false**: a known QNR mod p is never a quadratic residue
//!
//! The primes and witness values are generated at build time from a seed,
//! making each build unique.

use rand::Rng;

/// Parameters for an opaque predicate.
#[derive(Debug, Clone, Copy)]
pub struct OpaquePredicate {
    /// A prime modulus (fits in u64).
    pub prime: u64,
    /// The witness value to test (x² mod p for true, QNR mod p for false).
    pub witness: u64,
    /// Whether this predicate always evaluates to true.
    pub always_true: bool,
}

/// Generate a random prime of approximately `bits` bits from a seed.
fn generate_prime(rng: &mut impl Rng, bits: u32) -> u64 {
    loop {
        let mut candidate: u64 = rng.gen();
        // Mask to desired bit range and ensure odd + high bit set
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        candidate &= mask;
        candidate |= 1; // odd
        if bits > 1 {
            candidate |= 1u64 << (bits - 1); // ensure high bit
        }
        // Ensure > 2
        if candidate < 3 {
            continue;
        }
        if is_probably_prime(candidate) {
            return candidate;
        }
    }
}

/// Miller-Rabin primality test with fixed witnesses.
fn is_probably_prime(n: u64) -> bool {
    if n < 2 { return false; }
    if n == 2 || n == 3 { return true; }
    if n % 2 == 0 { return false; }

    // Write n-1 = 2^r * d
    let mut d = n - 1;
    let mut r = 0u32;
    while d % 2 == 0 {
        d /= 2;
        r += 1;
    }

    // Test with several witnesses
    let witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    'outer: for &a in &witnesses {
        if a >= n { continue; }
        let mut x = mod_pow(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Modular exponentiation: base^exp mod modulus.
pub fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
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

/// Modular multiplication avoiding overflow using u128.
fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Find a quadratic non-residue modulo p.
fn find_qnr(p: u64, rng: &mut impl Rng) -> u64 {
    // Euler's criterion: a is QNR iff a^((p-1)/2) ≡ p-1 (mod p)
    let exp = (p - 1) / 2;
    loop {
        let a = (rng.gen::<u64>() % (p - 2)) + 2; // range [2, p-1]
        if mod_pow(a, exp, p) == p - 1 {
            return a;
        }
    }
}

/// Generate an always-true opaque predicate.
/// Returns `(x² mod p, p)` where x² mod p is guaranteed to be a QR.
pub fn generate_true_predicate(rng: &mut impl Rng) -> OpaquePredicate {
    let prime = generate_prime(rng, 32);
    // Pick random x, compute x² mod p → always a QR
    let x = (rng.gen::<u64>() % (prime - 2)) + 2;
    let witness = mod_pow(x, 2, prime);
    // Ensure witness != 0 (0 is trivially a QR but not useful)
    let witness = if witness == 0 { 1 } else { witness };
    OpaquePredicate { prime, witness, always_true: true }
}

/// Generate an always-false opaque predicate.
/// Returns `(QNR, p)` where QNR is guaranteed to NOT be a quadratic residue.
pub fn generate_false_predicate(rng: &mut impl Rng) -> OpaquePredicate {
    let prime = generate_prime(rng, 32);
    let witness = find_qnr(prime, rng);
    OpaquePredicate { prime, witness, always_true: false }
}

/// Generate a batch of opaque predicates (mix of true and false).
pub fn generate_predicates(count: usize, rng: &mut impl Rng) -> Vec<OpaquePredicate> {
    let mut preds = Vec::with_capacity(count);
    for i in 0..count {
        if i % 2 == 0 {
            preds.push(generate_true_predicate(rng));
        } else {
            preds.push(generate_false_predicate(rng));
        }
    }
    preds
}

/// Evaluate an opaque predicate (Euler's criterion).
/// Returns true if `witness` is a quadratic residue mod `prime`.
///
/// This is the runtime evaluation function that must NOT be inlined
/// to prevent the compiler from constant-folding it away.
#[inline(never)]
pub fn eval_predicate(witness: u64, prime: u64) -> bool {
    if prime < 3 { return true; }
    let exp = (prime - 1) / 2;
    mod_pow(witness, exp, prime) == 1
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_is_probably_prime() {
        assert!(is_probably_prime(2));
        assert!(is_probably_prime(3));
        assert!(is_probably_prime(5));
        assert!(is_probably_prime(7));
        assert!(is_probably_prime(104729));
        assert!(!is_probably_prime(4));
        assert!(!is_probably_prime(100));
        assert!(!is_probably_prime(104730));
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 10, 1024), 0); // 2^10 = 1024 mod 1024 = 0
        assert_eq!(mod_pow(2, 10, 1000), 24);
        assert_eq!(mod_pow(3, 4, 17), 13); // 81 mod 17 = 13
    }

    #[test]
    fn test_generate_prime() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..20 {
            let p = generate_prime(&mut rng, 32);
            assert!(is_probably_prime(p), "Generated non-prime: {}", p);
            assert!(p >= (1 << 31), "Prime too small: {}", p);
        }
    }

    #[test]
    fn test_true_predicate_always_true() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..50 {
            let pred = generate_true_predicate(&mut rng);
            assert!(pred.always_true);
            assert!(eval_predicate(pred.witness, pred.prime),
                "True predicate evaluated to false: witness={}, prime={}", pred.witness, pred.prime);
        }
    }

    #[test]
    fn test_false_predicate_always_false() {
        let mut rng = StdRng::seed_from_u64(456);
        for _ in 0..50 {
            let pred = generate_false_predicate(&mut rng);
            assert!(!pred.always_true);
            assert!(!eval_predicate(pred.witness, pred.prime),
                "False predicate evaluated to true: witness={}, prime={}", pred.witness, pred.prime);
        }
    }

    #[test]
    fn test_mixed_predicates() {
        let mut rng = StdRng::seed_from_u64(789);
        let preds = generate_predicates(20, &mut rng);
        for pred in &preds {
            let result = eval_predicate(pred.witness, pred.prime);
            assert_eq!(result, pred.always_true,
                "Predicate mismatch: witness={}, prime={}, expected={}, got={}",
                pred.witness, pred.prime, pred.always_true, result);
        }
    }

    #[test]
    fn test_different_seeds_different_predicates() {
        let mut rng1 = StdRng::seed_from_u64(111);
        let mut rng2 = StdRng::seed_from_u64(222);
        let pred1 = generate_true_predicate(&mut rng1);
        let pred2 = generate_true_predicate(&mut rng2);
        // Different seeds should produce different primes
        assert_ne!(pred1.prime, pred2.prime);
    }
}
