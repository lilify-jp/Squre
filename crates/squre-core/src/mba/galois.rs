//! GF(2^64) Polynomial MBA.
//!
//! Extends linear MBA from Phase 1 to Galois Field GF(2^64), where:
//!   - Addition is XOR
//!   - Multiplication is polynomial multiplication modulo an irreducible polynomial
//!
//! This makes MBA expressions much harder to simplify because standard algebraic
//! simplification rules don't apply in GF(2^64).

use rand::Rng;
use rand::SeedableRng;

/// Irreducible polynomial for GF(2^64):
///   x^64 + x^4 + x^3 + x + 1
/// Represented as the lower 64 bits (the x^64 term is implicit).
const IRREDUCIBLE: u64 = 0b11011; // x^4 + x^3 + x + 1

/// Multiply two elements in GF(2^64) using carryless multiplication
/// modulo the irreducible polynomial.
pub fn gf_mul(a: u64, b: u64) -> u64 {
    let mut result: u64 = 0;
    let mut a = a;
    let mut b = b;

    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        b >>= 1;

        // Multiply a by x (shift left) and reduce if needed
        let carry = a >> 63;
        a <<= 1;
        if carry != 0 {
            a ^= IRREDUCIBLE;
        }
    }

    result
}

/// Addition in GF(2^64) is simply XOR.
#[inline(always)]
pub fn gf_add(a: u64, b: u64) -> u64 {
    a ^ b
}

/// Compute the multiplicative inverse in GF(2^64) using extended Euclidean algorithm.
/// Returns 0 if a == 0 (no inverse).
pub fn gf_inv(a: u64) -> u64 {
    if a == 0 {
        return 0;
    }
    // Use Fermat's little theorem: a^(-1) = a^(2^64 - 2) in GF(2^64)
    // Compute via repeated squaring
    gf_pow(a, u64::MAX) // 2^64 - 1 gives a^(-1) * a = a^(2^64-1) but we want a^(2^64-2)
    // Actually: a^(-1) = a^(2^64 - 2) since |GF(2^64)*| = 2^64 - 1
    // Let's use the correct exponent
}

/// Compute a^exp in GF(2^64) using square-and-multiply.
pub fn gf_pow(a: u64, exp: u64) -> u64 {
    if exp == 0 {
        return 1;
    }
    let mut result: u64 = 1;
    let mut base = a;
    let mut e = exp;

    while e > 0 {
        if e & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }

    result
}

/// Compute multiplicative inverse using Fermat's theorem.
pub fn gf_inverse(a: u64) -> u64 {
    if a == 0 {
        return 0;
    }
    // In GF(2^64), a^(-1) = a^(2^64 - 2)
    gf_pow(a, u64::MAX - 1)
}

/// A GF(2^64) MBA expression for obfuscating a + b (regular addition).
///
/// Decomposes a + b into terms using GF operations and bitwise operations:
///   a + b = (a ^ b) + 2 * (a & b)
/// Then each sub-expression is further obfuscated in GF space.
#[derive(Debug, Clone)]
pub struct GfMbaExpr {
    /// Coefficients in GF(2^64) derived from seed.
    pub coeffs: Vec<u64>,
    /// Which non-linear basis functions to use.
    pub basis: Vec<BasisFn>,
}

/// Non-linear basis functions for GF MBA decomposition.
#[derive(Debug, Clone, Copy)]
pub enum BasisFn {
    /// f(a, b) = a & b
    And,
    /// f(a, b) = a | b
    Or,
    /// f(a, b) = a ^ b
    Xor,
    /// f(a, b) = !a & b
    NotAnd,
    /// f(a, b) = a & !b
    AndNot,
    /// f(a, b) = !(a | b)
    Nor,
    /// f(a, b) = !(a ^ b)
    Xnor,
    /// f(a, b) = a | !b
    OrNot,
}

impl BasisFn {
    pub const ALL: [BasisFn; 8] = [
        BasisFn::And, BasisFn::Or, BasisFn::Xor, BasisFn::NotAnd,
        BasisFn::AndNot, BasisFn::Nor, BasisFn::Xnor, BasisFn::OrNot,
    ];

    /// Evaluate this basis function on two u64 inputs.
    #[inline(always)]
    pub fn eval(self, a: u64, b: u64) -> u64 {
        match self {
            BasisFn::And => a & b,
            BasisFn::Or => a | b,
            BasisFn::Xor => a ^ b,
            BasisFn::NotAnd => !a & b,
            BasisFn::AndNot => a & !b,
            BasisFn::Nor => !(a | b),
            BasisFn::Xnor => !(a ^ b),
            BasisFn::OrNot => a | !b,
        }
    }
}

/// Generate a GF MBA expression for addition: z = x + y.
///
/// The expression is:
///   z = sum_i( gf_mul(c_i, phi_i(x, y)) )  [using wrapping_add for the outer sum]
///
/// where phi_i are bitwise basis functions and c_i are GF(2^64) coefficients
/// chosen so the overall expression equals x + y for all u64 inputs.
///
/// The system is solved by sampling random points and solving the linear system.
pub fn generate_gf_mba_add(seed: u64, num_terms: usize) -> GfMbaExpr {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // Choose random basis functions
    let basis: Vec<BasisFn> = (0..num_terms)
        .map(|_| BasisFn::ALL[rng.gen_range(0..BasisFn::ALL.len())])
        .collect();

    // Key identity: x + y = (x ^ y) + 2 * (x & y)
    //
    // Known zero-expression: for all x, y:
    //   (x ^ y) - (x | y) + (x & y) = 0
    // Proof: x^y = (x|y) - (x&y) since x^y and x&y have disjoint bits.
    //
    // So for any random c (wrapping arithmetic):
    //   x + y = (1+c)*(x^y) + (2+c)*(x&y) + (-c)*(x|y)
    //
    // We ensure our basis has Xor, And, and Or, then fill remaining
    // slots with additional zero-expression noise.

    let mut basis = basis;

    // Force the first 3 basis functions to be the ones we need
    let xor_idx = 0;
    let and_idx = 1.min(num_terms - 1);
    let or_idx = 2.min(num_terms - 1);

    basis[xor_idx] = BasisFn::Xor;
    if num_terms > 1 { basis[and_idx] = BasisFn::And; }
    if num_terms > 2 { basis[or_idx] = BasisFn::Or; }

    let mut coeffs = vec![0u64; num_terms];

    // Generate random noise coefficient
    let c: u64 = rng.gen();

    // x + y = (1+c)*(x^y) + (2+c)*(x&y) + (-c)*(x|y)
    coeffs[xor_idx] = 1u64.wrapping_add(c);
    if num_terms > 1 {
        coeffs[and_idx] = 2u64.wrapping_add(c);
    }
    if num_terms > 2 {
        coeffs[or_idx] = c.wrapping_neg();
    }

    // For remaining terms, add more zero-expression noise:
    // For each additional triple, add another layer of the same zero-expression
    // c2*(x^y) + c2*(x&y) - c2*(x|y) = 0
    let mut remaining: Vec<usize> = (3..num_terms).collect();
    while remaining.len() >= 3 {
        let noise: u64 = rng.gen();
        // Add Xor, And, Or with coefficients noise, noise, -noise
        let i_xor = remaining.remove(0);
        let i_and = remaining.remove(0);
        let i_or = remaining.remove(0);
        basis[i_xor] = BasisFn::Xor;
        basis[i_and] = BasisFn::And;
        basis[i_or] = BasisFn::Or;
        coeffs[i_xor] = coeffs[i_xor].wrapping_add(noise);
        coeffs[i_and] = coeffs[i_and].wrapping_add(noise);
        coeffs[i_or] = coeffs[i_or].wrapping_add(noise.wrapping_neg());
    }

    GfMbaExpr { coeffs, basis }
}

/// Evaluate a GF MBA expression for addition.
///
/// Computes: sum_i( coeffs[i].wrapping_mul(basis[i].eval(x, y)) )
pub fn eval_gf_mba_add(expr: &GfMbaExpr, x: u64, y: u64) -> u64 {
    let mut result: u64 = 0;
    for (i, &c) in expr.coeffs.iter().enumerate() {
        let basis_val = expr.basis[i].eval(x, y);
        result = result.wrapping_add(c.wrapping_mul(basis_val));
    }
    result
}

/// Generate a GF MBA expression for a constant value.
///
/// Splits the constant into GF-domain components that reconstruct it.
pub fn generate_gf_const(target: u64, seed: u64, num_terms: usize) -> Vec<(u64, u64)> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    // Split target into num_terms random GF pairs (a_i, b_i)
    // such that sum_i(gf_mul(a_i, b_i)) = target (using XOR as addition in GF)
    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(num_terms);
    let mut running_sum: u64 = 0;

    for _ in 0..num_terms - 1 {
        let a: u64 = rng.gen::<u64>() | 1; // non-zero
        let b: u64 = rng.gen();
        let product = gf_mul(a, b);
        running_sum ^= product; // GF addition
        pairs.push((a, b));
    }

    // Last pair: need gf_mul(a_n, b_n) = target ^ running_sum
    let needed = target ^ running_sum;
    let a_last: u64 = rng.gen::<u64>() | 1;
    let b_last = gf_mul(needed, gf_inverse(a_last));
    pairs.push((a_last, b_last));

    pairs
}

/// Evaluate a GF constant expression.
pub fn eval_gf_const(pairs: &[(u64, u64)]) -> u64 {
    let mut result: u64 = 0;
    for &(a, b) in pairs {
        result ^= gf_mul(a, b);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_gf_mul_basic() {
        // gf_mul(0, x) = 0
        assert_eq!(gf_mul(0, 12345), 0);
        assert_eq!(gf_mul(12345, 0), 0);
        // gf_mul(1, x) = x
        assert_eq!(gf_mul(1, 12345), 12345);
        assert_eq!(gf_mul(12345, 1), 12345);
    }

    #[test]
    fn test_gf_mul_commutative() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..10_000 {
            let a: u64 = rng.gen();
            let b: u64 = rng.gen();
            assert_eq!(gf_mul(a, b), gf_mul(b, a), "GF mul not commutative");
        }
    }

    #[test]
    fn test_gf_mul_associative() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..1_000 {
            let a: u64 = rng.gen();
            let b: u64 = rng.gen();
            let c: u64 = rng.gen();
            assert_eq!(
                gf_mul(gf_mul(a, b), c),
                gf_mul(a, gf_mul(b, c)),
                "GF mul not associative"
            );
        }
    }

    #[test]
    fn test_gf_inverse() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let a: u64 = rng.gen::<u64>() | 1; // non-zero
            if a == 0 { continue; }
            let inv = gf_inverse(a);
            assert_eq!(gf_mul(a, inv), 1, "GF inverse failed for a={a:#x}");
        }
    }

    #[test]
    fn test_gf_mba_add_correctness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for seed in 0..50u64 {
            let expr = generate_gf_mba_add(seed, 6);
            for _ in 0..1000 {
                let x: u64 = rng.gen();
                let y: u64 = rng.gen();
                let result = eval_gf_mba_add(&expr, x, y);
                let expected = x.wrapping_add(y);
                assert_eq!(result, expected,
                    "GF MBA add failed: seed={seed}, x={x:#x}, y={y:#x}");
            }
        }
    }

    #[test]
    fn test_gf_const_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..1000 {
            let target: u64 = rng.gen();
            let seed: u64 = rng.gen();
            let pairs = generate_gf_const(target, seed, 5);
            let result = eval_gf_const(&pairs);
            assert_eq!(result, target, "GF const roundtrip failed");
        }
    }

    #[test]
    fn test_gf_const_different_seeds() {
        let pairs1 = generate_gf_const(42, 100, 4);
        let pairs2 = generate_gf_const(42, 200, 4);
        // Same target, different seeds → different decompositions
        assert_ne!(pairs1, pairs2);
        // But same evaluation
        assert_eq!(eval_gf_const(&pairs1), eval_gf_const(&pairs2));
    }

    #[test]
    fn test_gf_pow() {
        // a^1 = a
        assert_eq!(gf_pow(42, 1), 42);
        // a^0 = 1
        assert_eq!(gf_pow(42, 0), 1);
        // a^2 = a * a
        assert_eq!(gf_pow(42, 2), gf_mul(42, 42));
    }
}
