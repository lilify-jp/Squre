//! Linear MBA (Mixed Boolean-Arithmetic) transformation engine.
//!
//! Provides mathematically equivalent transformations for basic arithmetic
//! operations. Each identity is provable for all u64 inputs.

use rand::Rng;

/// Represents an MBA expression tree that can be evaluated or converted to tokens.
#[derive(Debug, Clone)]
pub enum MbaExpr {
    /// A literal value
    Lit(u64),
    /// A named variable reference
    Var(String),
    /// Bitwise XOR
    Xor(Box<MbaExpr>, Box<MbaExpr>),
    /// Bitwise AND
    And(Box<MbaExpr>, Box<MbaExpr>),
    /// Bitwise OR
    Or(Box<MbaExpr>, Box<MbaExpr>),
    /// Bitwise NOT
    Not(Box<MbaExpr>),
    /// Wrapping addition
    Add(Box<MbaExpr>, Box<MbaExpr>),
    /// Wrapping subtraction
    Sub(Box<MbaExpr>, Box<MbaExpr>),
    /// Wrapping multiplication
    Mul(Box<MbaExpr>, Box<MbaExpr>),
    /// Left shift
    Shl(Box<MbaExpr>, u32),
    /// Wrapping negation (-x)
    Neg(Box<MbaExpr>),
}

impl MbaExpr {
    /// Evaluate the expression with variable bindings.
    pub fn eval(&self, vars: &[(&str, u64)]) -> u64 {
        match self {
            MbaExpr::Lit(v) => *v,
            MbaExpr::Var(name) => {
                vars.iter()
                    .find(|(n, _)| *n == name.as_str())
                    .map(|(_, v)| *v)
                    .unwrap_or(0)
            }
            MbaExpr::Xor(a, b) => a.eval(vars) ^ b.eval(vars),
            MbaExpr::And(a, b) => a.eval(vars) & b.eval(vars),
            MbaExpr::Or(a, b) => a.eval(vars) | b.eval(vars),
            MbaExpr::Not(a) => !a.eval(vars),
            MbaExpr::Add(a, b) => a.eval(vars).wrapping_add(b.eval(vars)),
            MbaExpr::Sub(a, b) => a.eval(vars).wrapping_sub(b.eval(vars)),
            MbaExpr::Mul(a, b) => a.eval(vars).wrapping_mul(b.eval(vars)),
            MbaExpr::Shl(a, n) => a.eval(vars).wrapping_shl(*n),
            MbaExpr::Neg(a) => a.eval(vars).wrapping_neg(),
        }
    }

    pub fn var(name: &str) -> Self {
        MbaExpr::Var(name.to_string())
    }

    pub fn lit(v: u64) -> Self {
        MbaExpr::Lit(v)
    }

    pub fn xor(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::Xor(Box::new(a), Box::new(b))
    }

    pub fn and(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::And(Box::new(a), Box::new(b))
    }

    pub fn or(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::Or(Box::new(a), Box::new(b))
    }

    pub fn not(a: MbaExpr) -> Self {
        MbaExpr::Not(Box::new(a))
    }

    pub fn add(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::Add(Box::new(a), Box::new(b))
    }

    pub fn sub(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::Sub(Box::new(a), Box::new(b))
    }

    pub fn mul(a: MbaExpr, b: MbaExpr) -> Self {
        MbaExpr::Mul(Box::new(a), Box::new(b))
    }

    pub fn shl(a: MbaExpr, n: u32) -> Self {
        MbaExpr::Shl(Box::new(a), n)
    }

    pub fn neg(a: MbaExpr) -> Self {
        MbaExpr::Neg(Box::new(a))
    }
}

// ─── Transformation Rules ───────────────────────────────────────────

/// Transform `x + y` using MBA identity: (x ^ y) + 2 * (x & y)
pub fn transform_add_v1(x: MbaExpr, y: MbaExpr) -> MbaExpr {
    MbaExpr::add(
        MbaExpr::xor(x.clone(), y.clone()),
        MbaExpr::shl(MbaExpr::and(x, y), 1),
    )
}

/// Transform `x + y` using MBA identity: (x | y) + (x & y)
pub fn transform_add_v2(x: MbaExpr, y: MbaExpr) -> MbaExpr {
    MbaExpr::add(
        MbaExpr::or(x.clone(), y.clone()),
        MbaExpr::and(x, y),
    )
}

/// Transform `x - y` using MBA identity: (x ^ y) - 2 * (!x & y)
pub fn transform_sub_v1(x: MbaExpr, y: MbaExpr) -> MbaExpr {
    MbaExpr::sub(
        MbaExpr::xor(x.clone(), y.clone()),
        MbaExpr::shl(MbaExpr::and(MbaExpr::not(x), y), 1),
    )
}

/// Transform `x ^ y` using MBA identity: (x | y) - (x & y)
pub fn transform_xor_v1(x: MbaExpr, y: MbaExpr) -> MbaExpr {
    MbaExpr::sub(
        MbaExpr::or(x.clone(), y.clone()),
        MbaExpr::and(x, y),
    )
}

/// Transform `-x` using MBA identity: !x + 1
pub fn transform_neg(x: MbaExpr) -> MbaExpr {
    MbaExpr::add(MbaExpr::not(x), MbaExpr::lit(1))
}

/// Transform `x + 1` using MBA identity: -(!x)
pub fn transform_inc(x: MbaExpr) -> MbaExpr {
    MbaExpr::neg(MbaExpr::not(x))
}

// ─── Multi-depth recursive MBA ─────────────────────────────────────

/// Apply MBA transformations recursively to the given depth.
/// Each application expands sub-expressions using randomly chosen rules.
pub fn apply_mba_depth(expr: MbaExpr, depth: u32, rng: &mut impl Rng) -> MbaExpr {
    if depth == 0 {
        return expr;
    }

    let transformed = match expr {
        MbaExpr::Add(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            if rng.gen_bool(0.5) {
                transform_add_v1(a, b)
            } else {
                transform_add_v2(a, b)
            }
        }
        MbaExpr::Sub(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            transform_sub_v1(a, b)
        }
        MbaExpr::Xor(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            if rng.gen_bool(0.5) {
                transform_xor_v1(a, b)
            } else {
                MbaExpr::xor(a, b)
            }
        }
        MbaExpr::Neg(a) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            transform_neg(a)
        }
        MbaExpr::And(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            MbaExpr::and(a, b)
        }
        MbaExpr::Or(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            MbaExpr::or(a, b)
        }
        MbaExpr::Not(a) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            MbaExpr::not(a)
        }
        MbaExpr::Mul(a, b) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            let b = apply_mba_depth(*b, depth - 1, rng);
            MbaExpr::mul(a, b)
        }
        MbaExpr::Shl(a, n) => {
            let a = apply_mba_depth(*a, depth - 1, rng);
            MbaExpr::shl(a, n)
        }
        other => other,
    };

    // Randomly insert identity transformations to add noise
    if depth > 1 && rng.gen_bool(0.3) {
        insert_identity_noise(transformed, rng)
    } else {
        transformed
    }
}

/// Insert identity-preserving noise: x → expr that still equals x.
fn insert_identity_noise(expr: MbaExpr, rng: &mut impl Rng) -> MbaExpr {
    match rng.gen_range(0u32..4) {
        // x + (a ^ a) = x + 0 = x
        0 => {
            let a = MbaExpr::lit(rng.gen::<u64>());
            MbaExpr::add(expr, MbaExpr::xor(a.clone(), a))
        }
        // x ^ (a & !a) = x ^ 0 = x
        1 => {
            let a = MbaExpr::lit(rng.gen::<u64>());
            MbaExpr::xor(expr, MbaExpr::and(a.clone(), MbaExpr::not(a)))
        }
        // (x | x) = x
        2 => MbaExpr::or(expr.clone(), expr),
        // (x & x) = x
        _ => MbaExpr::and(expr.clone(), expr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_add_v1_identity() {
        for (x, y) in [(0u64, 0u64), (1, 1), (0xFF, 0x01), (u64::MAX, 1),
                        (u64::MAX, u64::MAX), (0xDEADBEEF, 0xCAFEBABE)] {
            let expr = transform_add_v1(MbaExpr::var("x"), MbaExpr::var("y"));
            let result = expr.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x.wrapping_add(y), "v1 failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_add_v2_identity() {
        for (x, y) in [(0u64, 0u64), (1, 1), (0xFF, 0x01), (u64::MAX, 1),
                        (u64::MAX, u64::MAX), (0xDEADBEEF, 0xCAFEBABE)] {
            let expr = transform_add_v2(MbaExpr::var("x"), MbaExpr::var("y"));
            let result = expr.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x.wrapping_add(y), "v2 failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_sub_identity() {
        for (x, y) in [(0u64, 0u64), (5, 3), (3, 5), (u64::MAX, 0),
                        (0, u64::MAX), (0xDEADBEEF, 0xCAFEBABE)] {
            let expr = transform_sub_v1(MbaExpr::var("x"), MbaExpr::var("y"));
            let result = expr.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x.wrapping_sub(y), "sub failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_xor_identity() {
        for (x, y) in [(0u64, 0u64), (0xFF, 0xFF), (0xFF, 0x0F),
                        (u64::MAX, 0), (0xDEADBEEF, 0xCAFEBABE)] {
            let expr = transform_xor_v1(MbaExpr::var("x"), MbaExpr::var("y"));
            let result = expr.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x ^ y, "xor failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_neg_identity() {
        for x in [0u64, 1, u64::MAX, 0x8000000000000000, 42, 0xDEADBEEF] {
            let expr = transform_neg(MbaExpr::var("x"));
            let result = expr.eval(&[("x", x)]);
            assert_eq!(result, x.wrapping_neg(), "neg failed: x={x:#x}");
        }
    }

    #[test]
    fn test_inc_identity() {
        for x in [0u64, 1, u64::MAX, 0x8000000000000000, 42] {
            let expr = transform_inc(MbaExpr::var("x"));
            let result = expr.eval(&[("x", x)]);
            assert_eq!(result, x.wrapping_add(1), "inc failed: x={x:#x}");
        }
    }

    #[test]
    fn test_depth_3_add_random() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10_000 {
            let x: u64 = rng.gen();
            let y: u64 = rng.gen();
            let base = MbaExpr::add(MbaExpr::var("x"), MbaExpr::var("y"));
            let transformed = apply_mba_depth(base, 3, &mut rng);
            let result = transformed.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x.wrapping_add(y));
        }
    }

    #[test]
    fn test_depth_2_sub_random() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..10_000 {
            let x: u64 = rng.gen();
            let y: u64 = rng.gen();
            let base = MbaExpr::sub(MbaExpr::var("x"), MbaExpr::var("y"));
            let transformed = apply_mba_depth(base, 2, &mut rng);
            let result = transformed.eval(&[("x", x), ("y", y)]);
            assert_eq!(result, x.wrapping_sub(y));
        }
    }

    #[test]
    fn test_identity_noise_preserves_value() {
        let mut rng = StdRng::seed_from_u64(999);
        for _ in 0..10_000 {
            let x: u64 = rng.gen();
            let base = MbaExpr::var("x");
            let noisy = insert_identity_noise(base, &mut rng);
            let result = noisy.eval(&[("x", x)]);
            assert_eq!(result, x);
        }
    }
}
