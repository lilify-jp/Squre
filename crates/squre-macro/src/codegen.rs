//! Convert MbaExpr to proc_macro2::TokenStream for code generation.
//!
//! This allows the proc macros to emit Rust code that evaluates MBA
//! expressions at runtime using wrapping arithmetic.

use proc_macro2::TokenStream;
use quote::quote;
use squre_core::mba::linear::MbaExpr;

/// Convert an MbaExpr into a TokenStream that evaluates to the same u64 value.
/// All arithmetic uses wrapping operations to match the evaluation semantics.
pub fn expr_to_tokens(expr: &MbaExpr) -> TokenStream {
    match expr {
        MbaExpr::Lit(v) => {
            let lit = proc_macro2::Literal::u64_suffixed(*v);
            quote! { #lit }
        }
        MbaExpr::Var(name) => {
            let ident = proc_macro2::Ident::new(name, proc_macro2::Span::call_site());
            quote! { ( #ident as u64 ) }
        }
        MbaExpr::Xor(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { ( (#a) ^ (#b) ) }
        }
        MbaExpr::And(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { ( (#a) & (#b) ) }
        }
        MbaExpr::Or(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { ( (#a) | (#b) ) }
        }
        MbaExpr::Not(a) => {
            let a = expr_to_tokens(a);
            quote! { ( ! (#a) ) }
        }
        MbaExpr::Add(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { (#a).wrapping_add(#b) }
        }
        MbaExpr::Sub(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { (#a).wrapping_sub(#b) }
        }
        MbaExpr::Mul(a, b) => {
            let a = expr_to_tokens(a);
            let b = expr_to_tokens(b);
            quote! { (#a).wrapping_mul(#b) }
        }
        MbaExpr::Shl(a, n) => {
            let a = expr_to_tokens(a);
            let n = *n;
            quote! { (#a).wrapping_shl(#n) }
        }
        MbaExpr::Neg(a) => {
            let a = expr_to_tokens(a);
            quote! { (#a).wrapping_neg() }
        }
    }
}

/// Generate a TokenStream that evaluates a GF(2^64) constant expression at runtime.
///
/// The expression is: XOR of gf_mul(a_i, b_i) for each pair.
/// The GF multiplication is inlined as a closure, making it hard to identify.
pub fn gf_const_to_tokens(pairs: &[(u64, u64)]) -> TokenStream {
    let a_vals: Vec<proc_macro2::TokenStream> = pairs.iter()
        .map(|(a, _)| { let lit = proc_macro2::Literal::u64_suffixed(*a); quote! { #lit } })
        .collect();
    let b_vals: Vec<proc_macro2::TokenStream> = pairs.iter()
        .map(|(_, b)| { let lit = proc_macro2::Literal::u64_suffixed(*b); quote! { #lit } })
        .collect();
    let num_pairs = pairs.len();

    quote! {
        {
            // GF(2^64) carry-less multiplication (inlined for obfuscation)
            #[inline(always)]
            fn __squre_gf_mul(mut a: u64, mut b: u64) -> u64 {
                let irr: u64 = 0b11011u64; // x^64 + x^4 + x^3 + x + 1
                let mut r: u64 = 0u64;
                while b != 0u64 {
                    if b & 1u64 != 0u64 { r ^= a; }
                    let c = a >> 63u32;
                    a <<= 1u32;
                    if c != 0u64 { a ^= irr; }
                    b >>= 1u32;
                }
                r
            }
            let __squre_gf_a: [u64; #num_pairs] = [#(#a_vals),*];
            let __squre_gf_b: [u64; #num_pairs] = [#(#b_vals),*];
            let mut __squre_gf_r: u64 = 0u64;
            let mut __squre_gf_i: usize = 0usize;
            while __squre_gf_i < #num_pairs {
                __squre_gf_r ^= __squre_gf_mul(__squre_gf_a[__squre_gf_i], __squre_gf_b[__squre_gf_i]);
                __squre_gf_i += 1usize;
            }
            __squre_gf_r
        }
    }
}
