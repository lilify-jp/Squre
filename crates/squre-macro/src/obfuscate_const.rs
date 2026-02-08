//! Implementation of the `obfuscate_const!()` proc macro.
//!
//! Randomly mixes linear MBA and GF(2^64) MBA for constant synthesis.

use proc_macro2::TokenStream;
use quote::quote;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::Rng;

use squre_core::mba::constant::synthesize_constant;
use squre_core::mba::galois::{generate_gf_const, eval_gf_const};
use crate::codegen::{expr_to_tokens, gf_const_to_tokens};

/// Generate an MBA expression that evaluates to the given u64 constant.
/// Randomly uses either linear MBA or GF(2^64) MBA for diversity.
pub fn generate(value: u64, type_suffix: &str) -> TokenStream {
    let seed = value
        .wrapping_mul(0x517cc1b727220a95)
        .wrapping_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(123),
        );

    let mut rng = StdRng::seed_from_u64(seed);

    // 50% chance: GF(2^64) MBA, 50% chance: linear MBA
    let use_gf = rng.gen_bool(0.5) && value > 1;

    let tokens = if use_gf {
        // GF(2^64) MBA: constant = XOR of gf_mul(a_i, b_i)
        let pairs = generate_gf_const(value, seed, rng.gen_range(3..=5));
        // Verify at compile time
        let check = eval_gf_const(&pairs);
        assert_eq!(check, value, "BUG: GF MBA synthesis produced wrong value for {}", value);
        gf_const_to_tokens(&pairs)
    } else {
        // Linear MBA: constant = MBA expression tree
        let mba = synthesize_constant(value, 2, &mut rng);
        assert_eq!(mba.eval(&[]), value, "BUG: MBA synthesis produced wrong value");
        expr_to_tokens(&mba)
    };

    match type_suffix {
        "u8" => quote! { ( (#tokens) as u8 ) },
        "u16" => quote! { ( (#tokens) as u16 ) },
        "u32" => quote! { ( (#tokens) as u32 ) },
        "u64" => quote! { ( #tokens ) },
        "i8" => quote! { ( (#tokens) as i8 ) },
        "i16" => quote! { ( (#tokens) as i16 ) },
        "i32" => quote! { ( (#tokens) as i32 ) },
        "i64" => quote! { ( (#tokens) as i64 ) },
        "usize" => quote! { ( (#tokens) as usize ) },
        "isize" => quote! { ( (#tokens) as isize ) },
        _ => quote! { ( #tokens ) },
    }
}
