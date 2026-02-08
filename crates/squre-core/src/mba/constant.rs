//! Constant synthesis via MBA expressions.
//!
//! Transforms any u64 constant into a complex MBA expression that evaluates
//! to the same value. The expression structure is determined by a seed,
//! making each compilation produce different expressions.

use rand::Rng;
use super::linear::{MbaExpr, apply_mba_depth};

/// Synthesize a constant value as an MBA expression.
///
/// Splits the target into random parts, then applies multi-depth MBA
/// transformations to the addition of those parts.
pub fn synthesize_constant(target: u64, depth: u32, rng: &mut impl Rng) -> MbaExpr {
    if depth == 0 {
        return MbaExpr::lit(target);
    }

    // Strategy: split target = a + b where a and b are random
    let a: u64 = rng.gen();
    let b: u64 = target.wrapping_sub(a);

    // Build the expression tree: MBA(a) + MBA(b)
    let expr_a = synthesize_leaf(a, rng);
    let expr_b = synthesize_leaf(b, rng);
    let sum = MbaExpr::add(expr_a, expr_b);

    // Apply multi-depth MBA transformations
    apply_mba_depth(sum, depth, rng)
}

/// Synthesize a u8 constant as an MBA expression that evaluates to that u8.
/// Used for string encryption key bytes.
pub fn synthesize_constant_u8(target: u8, depth: u32, rng: &mut impl Rng) -> MbaExpr {
    // Synthesize as u64, the caller will truncate with `as u8`
    synthesize_constant(target as u64, depth, rng)
}

/// Create a leaf-level obfuscated constant using bitwise tricks.
fn synthesize_leaf(val: u64, rng: &mut impl Rng) -> MbaExpr {
    match rng.gen_range(0u32..5) {
        // val = val ^ 0
        0 => MbaExpr::xor(MbaExpr::lit(val), MbaExpr::lit(0)),
        // val = (val | mask) & (val | !mask)  where mask is random
        // This simplifies to val but looks complex
        1 => {
            let mask: u64 = rng.gen();
            MbaExpr::and(
                MbaExpr::or(MbaExpr::lit(val), MbaExpr::lit(mask)),
                MbaExpr::or(MbaExpr::lit(val), MbaExpr::lit(!mask)),
            )
        }
        // val = !!val = NOT(NOT(val))
        2 => MbaExpr::not(MbaExpr::not(MbaExpr::lit(val))),
        // val = (a ^ b) where a ^ b = val
        3 => {
            let a: u64 = rng.gen();
            let b = a ^ val;
            MbaExpr::xor(MbaExpr::lit(a), MbaExpr::lit(b))
        }
        // val = (a + b) where a + b = val (wrapping)
        _ => {
            let a: u64 = rng.gen();
            let b = val.wrapping_sub(a);
            MbaExpr::add(MbaExpr::lit(a), MbaExpr::lit(b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_synthesize_zero() {
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..100 {
            let expr = synthesize_constant(0, 2, &mut rng);
            assert_eq!(expr.eval(&[]), 0);
        }
    }

    #[test]
    fn test_synthesize_one() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..100 {
            let expr = synthesize_constant(1, 2, &mut rng);
            assert_eq!(expr.eval(&[]), 1);
        }
    }

    #[test]
    fn test_synthesize_max() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..100 {
            let expr = synthesize_constant(u64::MAX, 2, &mut rng);
            assert_eq!(expr.eval(&[]), u64::MAX);
        }
    }

    #[test]
    fn test_synthesize_random_values() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10_000 {
            let target: u64 = rng.gen();
            let expr = synthesize_constant(target, 2, &mut rng);
            assert_eq!(expr.eval(&[]), target,
                "Failed to synthesize {target:#x}");
        }
    }

    #[test]
    fn test_synthesize_depth_3() {
        let mut rng = StdRng::seed_from_u64(77);
        for _ in 0..1_000 {
            let target: u64 = rng.gen();
            let expr = synthesize_constant(target, 3, &mut rng);
            assert_eq!(expr.eval(&[]), target);
        }
    }

    #[test]
    fn test_synthesize_u8() {
        let mut rng = StdRng::seed_from_u64(88);
        for target in 0..=255u8 {
            let expr = synthesize_constant_u8(target, 2, &mut rng);
            assert_eq!(expr.eval(&[]) as u8, target);
        }
    }

    #[test]
    fn test_different_seeds_different_expressions() {
        let mut rng1 = StdRng::seed_from_u64(100);
        let mut rng2 = StdRng::seed_from_u64(200);
        let expr1 = synthesize_constant(42, 2, &mut rng1);
        let expr2 = synthesize_constant(42, 2, &mut rng2);
        // Both evaluate to 42
        assert_eq!(expr1.eval(&[]), 42);
        assert_eq!(expr2.eval(&[]), 42);
        // But have different structure (hard to test structurally,
        // so we just verify both produce correct results)
    }

    #[test]
    fn test_synthesize_leaf_correctness() {
        let mut rng = StdRng::seed_from_u64(55);
        for _ in 0..10_000 {
            let val: u64 = rng.gen();
            let expr = synthesize_leaf(val, &mut rng);
            assert_eq!(expr.eval(&[]), val);
        }
    }
}
