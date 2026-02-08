//! Implementation of the `#[obfuscate]` attribute macro.
//!
//! Phase 1: Transforms integer literals in function bodies to MBA expressions.
//! Phase 4A: Injects opaque predicate fake branches (quadratic residuosity).
//! Does NOT yet do VM conversion (Phase 2) or EDF (Phase 2).

use proc_macro2::TokenStream;
use quote::quote;
use syn::{visit_mut::VisitMut, Expr, ExprLit, ItemFn, Lit, LitInt};
use rand::SeedableRng;
use rand::Rng;
use rand::rngs::StdRng;

use squre_core::mba::constant::synthesize_constant;
use squre_core::crypto::opaque_predicates::{generate_true_predicate, generate_false_predicate};
use crate::codegen::expr_to_tokens;

/// Transform a function by obfuscating its integer literals and injecting
/// opaque predicate fake branches.
pub fn transform(item: ItemFn) -> TokenStream {
    let mut func = item;

    // Derive seed from function name + entropy
    let fn_name = func.sig.ident.to_string();
    let seed = {
        let mut h: u64 = 0x811c9dc5;
        for b in fn_name.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x01000193);
        }
        h ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(99);
        h
    };

    let mut visitor = ObfuscateVisitor {
        rng: StdRng::seed_from_u64(seed),
    };

    // Walk the AST and replace integer literals
    visitor.visit_item_fn_mut(&mut func);

    // ═══ Generate opaque predicate fake branches ═══
    let mut pred_rng = StdRng::seed_from_u64(seed ^ 0xDEAD_CAFE_BABE_F00D);

    // 6-10 always-false dead branches per function
    let num_false = 6 + (pred_rng.gen::<u32>() % 5) as usize;

    let mut dead_branches = Vec::new();
    for i in 0..num_false {
        let pred = generate_false_predicate(&mut pred_rng);
        let witness = pred.witness;
        let prime = pred.prime;

        // Diverse fake code patterns to confuse decompilers
        let fake_body = match i % 4 {
            0 => quote! { ::std::process::exit(0xDEAD_i32); },
            1 => quote! { ::std::process::abort(); },
            2 => quote! { loop { ::std::hint::spin_loop(); } },
            _ => quote! { panic!("integrity"); },
        };

        dead_branches.push(quote! {
            if ::squre_runtime::opaque::check_qr(#witness, #prime) {
                #fake_body
            }
        });
    }

    // 1 always-true guard — decompiler must consider both paths
    let true_pred = generate_true_predicate(&mut pred_rng);
    let tw = true_pred.witness;
    let tp = true_pred.prime;
    let true_guard = quote! {
        if !::squre_runtime::opaque::check_qr(#tw, #tp) {
            ::std::process::abort();
        }
    };

    // Inject anti-debug check + opaque predicates at function entry
    let body = &func.block;
    let stmts = &body.stmts;

    let new_body: TokenStream = quote! {
        {
            // Anti-debug poison
            let _ = ::squre_runtime::anti_debug::run_all_checks();

            // Opaque predicate dead branches (always-false)
            #(#dead_branches)*

            // Opaque predicate guard (always-true)
            #true_guard

            // Real function body
            #(#stmts)*
        }
    };

    let sig = &func.sig;
    let attrs = &func.attrs;
    let vis = &func.vis;

    quote! {
        #(#attrs)*
        #vis #sig
        #new_body
    }
}

struct ObfuscateVisitor {
    rng: StdRng,
}

impl VisitMut for ObfuscateVisitor {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // First recurse into children
        syn::visit_mut::visit_expr_mut(self, expr);

        // Then check if this is an integer literal we should obfuscate
        if let Expr::Lit(ExprLit { lit: Lit::Int(lit_int), .. }) = expr {
            if let Some(new_expr) = self.obfuscate_int_lit(lit_int) {
                *expr = new_expr;
            }
        }
    }
}

impl ObfuscateVisitor {
    fn obfuscate_int_lit(&mut self, lit: &LitInt) -> Option<Expr> {
        let value: u64 = lit.base10_parse().ok()?;

        // Don't obfuscate 0 and 1 (too simple, and often used in patterns
        // where obfuscation would break things like array indices)
        if value <= 1 {
            return None;
        }

        let suffix = lit.suffix();
        let mba = synthesize_constant(value, 2, &mut self.rng);
        let tokens = expr_to_tokens(&mba);

        let cast_tokens = if suffix.is_empty() {
            // No suffix: MBA expressions are all u64 internally, so the
            // result is naturally u64. No cast needed — avoids type inference
            // failures with `as _` in operator contexts (Rust limitation).
            quote! { (#tokens) }
        } else {
            let suffix_ident = proc_macro2::Ident::new(suffix, proc_macro2::Span::call_site());
            quote! { ( (#tokens) as #suffix_ident ) }
        };

        syn::parse2(cast_tokens).ok()
    }
}
