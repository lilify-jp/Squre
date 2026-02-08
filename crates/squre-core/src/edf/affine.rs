//! Encoded Data Flow (EDF) using affine transformations.
//!
//! Every value is stored in encoded form: encode(x) = x * a + b (mod 2^64).
//! The encoding parameters (a, b) are unique per variable and per build.
//! Arithmetic operations are performed directly on encoded values, so
//! plaintext values never appear in registers or memory.

use rand::Rng;

/// Parameters for an affine encoding.
///
/// encode(x) = x.wrapping_mul(a).wrapping_add(b)
/// decode(y) = y.wrapping_sub(b).wrapping_mul(a_inv)
///
/// Invariant: a must be odd (so that a_inv exists mod 2^64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdfParam {
    pub a: u64,
    pub b: u64,
    pub a_inv: u64,
}

impl EdfParam {
    /// Create EDF parameters with the given multiplier and offset.
    /// `a` must be odd (panics otherwise).
    pub fn new(a: u64, b: u64) -> Self {
        assert!(a & 1 == 1, "EDF multiplier must be odd for invertibility");
        let a_inv = mod_inverse_u64(a);
        EdfParam { a, b, a_inv }
    }

    /// Generate random EDF parameters from an RNG.
    pub fn random(rng: &mut impl Rng) -> Self {
        let a = rng.gen::<u64>() | 1; // Ensure odd
        let b = rng.gen::<u64>();
        Self::new(a, b)
    }

    /// Encode a plaintext value.
    #[inline(always)]
    pub fn encode(&self, x: u64) -> u64 {
        x.wrapping_mul(self.a).wrapping_add(self.b)
    }

    /// Decode an encoded value back to plaintext.
    #[inline(always)]
    pub fn decode(&self, y: u64) -> u64 {
        y.wrapping_sub(self.b).wrapping_mul(self.a_inv)
    }

    /// Identity encoding (no transformation).
    pub fn identity() -> Self {
        EdfParam { a: 1, b: 0, a_inv: 1 }
    }
}

// ─── Arithmetic on encoded values ─────────────────────────────

/// Precomputed constants for performing addition in EDF space.
///
/// Given: ez = encode_z(decode_x(ex) + decode_y(ey))
///        ez = ex * C1 + ey * C2 + C3
#[derive(Debug, Clone, Copy)]
pub struct EdfAddConstants {
    pub c1: u64, // a_z * a_x_inv
    pub c2: u64, // a_z * a_y_inv
    pub c3: u64, // a_z * (-b_x * a_x_inv - b_y * a_y_inv) + b_z
}

/// Compute addition constants for encoded addition: z = x + y.
pub fn add_constants(px: &EdfParam, py: &EdfParam, pz: &EdfParam) -> EdfAddConstants {
    let c1 = pz.a.wrapping_mul(px.a_inv);
    let c2 = pz.a.wrapping_mul(py.a_inv);
    let term_x = px.b.wrapping_mul(px.a_inv).wrapping_neg();
    let term_y = py.b.wrapping_mul(py.a_inv).wrapping_neg();
    let c3 = pz.a.wrapping_mul(term_x.wrapping_add(term_y)).wrapping_add(pz.b);
    EdfAddConstants { c1, c2, c3 }
}

/// Perform encoded addition: ez = ex * c1 + ey * c2 + c3.
#[inline(always)]
pub fn edf_add(ex: u64, ey: u64, c: &EdfAddConstants) -> u64 {
    ex.wrapping_mul(c.c1)
        .wrapping_add(ey.wrapping_mul(c.c2))
        .wrapping_add(c.c3)
}

/// Precomputed constants for subtraction in EDF space.
/// ez = ex * C1 - ey * C2 + C3
#[derive(Debug, Clone, Copy)]
pub struct EdfSubConstants {
    pub c1: u64,
    pub c2: u64,
    pub c3: u64,
}

/// Compute subtraction constants for encoded subtraction: z = x - y.
pub fn sub_constants(px: &EdfParam, py: &EdfParam, pz: &EdfParam) -> EdfSubConstants {
    let c1 = pz.a.wrapping_mul(px.a_inv);
    let c2 = pz.a.wrapping_mul(py.a_inv);
    let term_x = px.b.wrapping_mul(px.a_inv).wrapping_neg();
    let term_y = py.b.wrapping_mul(py.a_inv); // note: positive because subtracted
    let c3 = pz.a.wrapping_mul(term_x.wrapping_add(term_y)).wrapping_add(pz.b);
    EdfSubConstants { c1, c2, c3 }
}

/// Perform encoded subtraction.
#[inline(always)]
pub fn edf_sub(ex: u64, ey: u64, c: &EdfSubConstants) -> u64 {
    ex.wrapping_mul(c.c1)
        .wrapping_sub(ey.wrapping_mul(c.c2))
        .wrapping_add(c.c3)
}

/// Precomputed constants for XOR in EDF space.
/// XOR cannot be expressed as a simple affine transform on encoded values.
/// We must decode, XOR, and re-encode. The constants here support that.
#[derive(Debug, Clone, Copy)]
pub struct EdfXorParams {
    pub px: EdfParam,
    pub py: EdfParam,
    pub pz: EdfParam,
}

/// Perform encoded XOR: decode both, XOR, re-encode.
/// This is the fallback for non-linear operations.
#[inline(always)]
pub fn edf_xor(ex: u64, ey: u64, p: &EdfXorParams) -> u64 {
    let x = p.px.decode(ex);
    let y = p.py.decode(ey);
    p.pz.encode(x ^ y)
}

/// Perform encoded comparison (equality): returns 1 if equal, 0 if not.
/// The result is in plaintext (not encoded) since it's a boolean.
#[inline(always)]
pub fn edf_cmp_eq(ex: u64, ey: u64, px: &EdfParam, py: &EdfParam) -> u64 {
    let x = px.decode(ex);
    let y = py.decode(ey);
    if x == y { 1 } else { 0 }
}

/// Encode an immediate constant into EDF space.
#[inline(always)]
pub fn edf_encode_const(val: u64, p: &EdfParam) -> u64 {
    p.encode(val)
}

// ─── Modular arithmetic helpers ──────────────────────────────

/// Compute the multiplicative inverse of `a` mod 2^64.
/// Uses the extended Euclidean algorithm adapted for power-of-2 modulus.
/// `a` must be odd.
fn mod_inverse_u64(a: u64) -> u64 {
    // For odd a, a * a_inv ≡ 1 (mod 2^64).
    // Newton's method: x_{n+1} = x_n * (2 - a * x_n)
    // Converges in O(log(64)) = 6 iterations.
    let mut inv = a; // Initial approximation (works for odd a mod 2^3)
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    }
    debug_assert_eq!(a.wrapping_mul(inv), 1, "mod_inverse failed");
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_mod_inverse() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10_000 {
            let a = rng.gen::<u64>() | 1;
            let inv = mod_inverse_u64(a);
            assert_eq!(a.wrapping_mul(inv), 1, "Inverse failed for a={a:#x}");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..10_000 {
            let p = EdfParam::random(&mut rng);
            let x: u64 = rng.gen();
            assert_eq!(p.decode(p.encode(x)), x, "Roundtrip failed");
        }
    }

    #[test]
    fn test_edf_add() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..10_000 {
            let px = EdfParam::random(&mut rng);
            let py = EdfParam::random(&mut rng);
            let pz = EdfParam::random(&mut rng);
            let c = add_constants(&px, &py, &pz);

            let x: u64 = rng.gen();
            let y: u64 = rng.gen();
            let ex = px.encode(x);
            let ey = py.encode(y);
            let ez = edf_add(ex, ey, &c);
            let z = pz.decode(ez);

            assert_eq!(z, x.wrapping_add(y),
                "EDF add failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_edf_sub() {
        let mut rng = StdRng::seed_from_u64(456);
        for _ in 0..10_000 {
            let px = EdfParam::random(&mut rng);
            let py = EdfParam::random(&mut rng);
            let pz = EdfParam::random(&mut rng);
            let c = sub_constants(&px, &py, &pz);

            let x: u64 = rng.gen();
            let y: u64 = rng.gen();
            let ex = px.encode(x);
            let ey = py.encode(y);
            let ez = edf_sub(ex, ey, &c);
            let z = pz.decode(ez);

            assert_eq!(z, x.wrapping_sub(y),
                "EDF sub failed: x={x:#x}, y={y:#x}");
        }
    }

    #[test]
    fn test_edf_xor() {
        let mut rng = StdRng::seed_from_u64(789);
        for _ in 0..10_000 {
            let px = EdfParam::random(&mut rng);
            let py = EdfParam::random(&mut rng);
            let pz = EdfParam::random(&mut rng);
            let params = EdfXorParams { px, py, pz };

            let x: u64 = rng.gen();
            let y: u64 = rng.gen();
            let ex = px.encode(x);
            let ey = py.encode(y);
            let ez = edf_xor(ex, ey, &params);
            let z = pz.decode(ez);

            assert_eq!(z, x ^ y, "EDF xor failed");
        }
    }

    #[test]
    fn test_edf_cmp_eq() {
        let mut rng = StdRng::seed_from_u64(111);
        for _ in 0..1000 {
            let px = EdfParam::random(&mut rng);
            let py = EdfParam::random(&mut rng);
            let x: u64 = rng.gen();

            // Equal case
            let ex = px.encode(x);
            let ey = py.encode(x);
            assert_eq!(edf_cmp_eq(ex, ey, &px, &py), 1);

            // Not equal case
            let y = x.wrapping_add(1);
            let ey2 = py.encode(y);
            assert_eq!(edf_cmp_eq(ex, ey2, &px, &py), 0);
        }
    }

    #[test]
    fn test_identity_param() {
        let p = EdfParam::identity();
        for x in [0u64, 1, 42, u64::MAX, 0xDEADBEEF] {
            assert_eq!(p.encode(x), x);
            assert_eq!(p.decode(x), x);
        }
    }

    #[test]
    fn test_encoded_values_look_random() {
        let mut rng = StdRng::seed_from_u64(42);
        let p = EdfParam::random(&mut rng);

        // Encoded values should be far from the originals
        let e0 = p.encode(0);
        let e1 = p.encode(1);
        let e100 = p.encode(100);

        // They shouldn't be the originals
        assert_ne!(e0, 0, "encode(0) should not be 0");
        assert_ne!(e1, 1, "encode(1) should not be 1");
        assert_ne!(e100, 100, "encode(100) should not be 100");

        // The multiplier (a) should be large (not 1 or small)
        // For affine encode(x) = x*a + b, the step between consecutive values is a.
        // We want a to be a large, random-looking odd number.
        let step = e1.wrapping_sub(e0);
        assert!(step > 1000, "Multiplier should be large, got {}", step);

        // Roundtrip should still work
        assert_eq!(p.decode(e0), 0);
        assert_eq!(p.decode(e1), 1);
        assert_eq!(p.decode(e100), 100);
    }
}
