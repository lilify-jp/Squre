//! Control Flow Flattening (CFF) transformation.
//!
//! Converts a function's sequential control flow into a state machine:
//!
//! ```text
//! // BEFORE:
//! fn check(x: u64) -> u64 {
//!     let a = x + 1;
//!     if a > 10 { return a * 2; }
//!     a + 5
//! }
//!
//! // AFTER (#[obfuscate(cff)]):
//! fn check(x: u64) -> u64 {
//!     let mut __cff_s: u32 = 0x3A7Fu32;
//!     let mut __cff_r: u64 = Default::default();
//!     let mut a: u64 = Default::default();
//!     loop {
//!         match __cff_s {
//!             0x91B2u32 => { a = x + 1; __cff_s = 0x5CD4u32; }
//!             0x5CD4u32 => { if a > 10 { return a * 2; } __cff_s = 0xA1B3u32; }
//!             0xA1B3u32 => { __cff_r = a + 5; __cff_s = 0xE8A0u32; }
//!             0xE8A0u32 => { return __cff_r; }
//!             _ => { ::std::process::abort(); }
//!         }
//!     }
//! }
//! ```
//!
//! This destroys the natural control flow graph, forcing decompilers to
//! show a flat state machine instead of structured if/else/while.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{ItemFn, Stmt, ReturnType, Local, Pat, PatIdent, PatType};
use rand::{Rng, SeedableRng, rngs::StdRng};

use squre_core::crypto::opaque_predicates::generate_false_predicate;

/// Create a u32-suffixed literal from a state ID.
/// This ensures MBA won't introduce `as _` ambiguity.
fn sid_lit(id: u32) -> proc_macro2::Literal {
    proc_macro2::Literal::u32_suffixed(id)
}

/// Apply Control Flow Flattening to a function.
///
/// The function body is split at top-level statement boundaries.
/// Each statement becomes a match arm with a random state ID.
/// `let` bindings are hoisted to the function entry.
pub fn flatten(func: &ItemFn, seed: u64) -> TokenStream {
    let mut rng = StdRng::seed_from_u64(seed);

    let vis = &func.vis;
    let sig = &func.sig;
    let attrs = &func.attrs;

    // Determine return type
    let has_return_type = !matches!(&func.sig.output, ReturnType::Default);
    let ret_type: TokenStream = match &func.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => ty.to_token_stream(),
    };

    // Collect hoisted variable declarations and rewritten statements
    let (hoisted_decls, rewritten_stmts, is_trailing) = process_stmts(&func.block.stmts);

    let n_real = rewritten_stmts.len();
    if n_real == 0 {
        // Empty function body — nothing to flatten
        return quote! {
            #(#attrs)*
            #vis #sig {
                Default::default()
            }
        };
    }

    // Generate unique random state IDs
    let n_fake = 4 + (rng.gen::<usize>() % 5); // 4-8 fake states
    let n_total = n_real + 1 + n_fake; // real + exit + fake
    let state_ids = generate_unique_ids(n_total, &mut rng);

    let init_lit = sid_lit(state_ids[0]);
    let exit_lit = sid_lit(state_ids[n_real]);

    // Build match arms for real states
    let mut arms: Vec<TokenStream> = Vec::new();

    for (i, stmt_ts) in rewritten_stmts.iter().enumerate() {
        let s_lit = sid_lit(state_ids[i]);
        let next_lit = if i + 1 < n_real {
            sid_lit(state_ids[i + 1])
        } else {
            sid_lit(state_ids[n_real]) // exit
        };

        if i == n_real - 1 && is_trailing {
            // Last statement is a trailing expression (implicit return value).
            // Assign to __cff_r and transition to exit.
            let exit = sid_lit(state_ids[n_real]);
            arms.push(quote! {
                #s_lit => {
                    __cff_r = { #stmt_ts };
                    __cff_s = #exit;
                }
            });
        } else {
            arms.push(quote! {
                #s_lit => {
                    #stmt_ts
                    __cff_s = #next_lit;
                }
            });
        }
    }

    // Exit state
    if has_return_type {
        arms.push(quote! {
            #exit_lit => { return __cff_r; }
        });
    } else {
        arms.push(quote! {
            #exit_lit => { return; }
        });
    }

    // Fake dead states — make the decompiler consider more paths
    for i in 0..n_fake {
        let fake_lit = sid_lit(state_ids[n_real + 1 + i]);

        let fake_body = match i % 5 {
            0 => quote! { ::std::process::abort(); },
            1 => {
                let pred = generate_false_predicate(&mut rng);
                let w = pred.witness;
                let p = pred.prime;
                // Always-false predicate guarding a random state transition
                let target_lit = sid_lit(state_ids[rng.gen_range(0..n_real)]);
                quote! {
                    if ::squre_runtime::opaque::check_qr(#w, #p) {
                        __cff_s = #target_lit;
                    } else {
                        ::std::process::abort();
                    }
                }
            }
            2 => quote! { loop { ::std::hint::spin_loop(); } },
            3 => {
                // Fake computation that looks real
                let a = proc_macro2::Literal::u64_suffixed(rng.gen());
                let b = proc_macro2::Literal::u64_suffixed(rng.gen());
                quote! {
                    let _ = (#a).wrapping_mul(#b);
                    ::std::process::abort();
                }
            }
            _ => quote! { panic!("integrity"); },
        };

        arms.push(quote! { #fake_lit => { #fake_body } });
    }

    // Shuffle arms to destroy visual ordering
    shuffle_vec(&mut arms, &mut rng);

    // Assemble the function.
    // Note: anti-debug + opaque predicates are injected by obfuscate_fn::transform()
    // which wraps this output, so CFF does not inject them directly.
    if has_return_type {
        quote! {
            #(#attrs)*
            #vis #sig {
                let mut __cff_s: u32 = #init_lit;
                let mut __cff_r: #ret_type = Default::default();
                #(#hoisted_decls)*
                loop {
                    match __cff_s {
                        #(#arms)*
                        _ => { ::std::process::abort(); }
                    }
                }
            }
        }
    } else {
        quote! {
            #(#attrs)*
            #vis #sig {
                let mut __cff_s: u32 = #init_lit;
                #(#hoisted_decls)*
                loop {
                    match __cff_s {
                        #(#arms)*
                        _ => { ::std::process::abort(); }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Statement processing: hoist let bindings, identify trailing expr
// ═══════════════════════════════════════════════════════════════

/// Process a function body's statements for CFF.
///
/// Returns: (hoisted_declarations, rewritten_statements, has_trailing_expr)
///
/// `let` bindings are split: the declaration is hoisted, the initializer
/// becomes an assignment statement in the rewritten list.
fn process_stmts(stmts: &[Stmt]) -> (Vec<TokenStream>, Vec<TokenStream>, bool) {
    let mut hoisted = Vec::new();
    let mut rewritten = Vec::new();
    let mut is_trailing = false;

    for (i, stmt) in stmts.iter().enumerate() {
        let is_last = i == stmts.len() - 1;

        match stmt {
            Stmt::Local(local) => {
                let (hoist, assign) = hoist_local(local);
                if let Some(h) = hoist {
                    hoisted.push(h);
                }
                if let Some(a) = assign {
                    rewritten.push(a);
                }
            }
            Stmt::Expr(expr, semi) => {
                if is_last && semi.is_none() {
                    // Trailing expression — implicit return value
                    is_trailing = true;
                    rewritten.push(expr.to_token_stream());
                } else {
                    rewritten.push(stmt.to_token_stream());
                }
            }
            Stmt::Item(_) => {
                // Inner items (fn, struct, etc.) — skip, they stay at function scope
            }
            Stmt::Macro(m) => {
                rewritten.push(m.to_token_stream());
            }
        }
    }

    (hoisted, rewritten, is_trailing)
}

/// Hoist a `let` binding: return (hoisted_declaration, assignment_statement).
///
/// - `let x: T = expr;` → hoist `let mut x: T = Default::default();`, assign `x = expr;`
/// - `let x = expr;` → hoist `let mut x = Default::default();`, assign `x = expr;`
/// - `let _ = expr;` → no hoist, assign `let _ = expr;`
fn hoist_local(local: &Local) -> (Option<TokenStream>, Option<TokenStream>) {
    let pat = &local.pat;

    // Extract the variable name
    let name = match extract_ident(pat) {
        Some(n) => n,
        None => {
            // Complex pattern (tuple, struct, etc.) — can't hoist.
            // Keep the full let as-is (it will be scoped to its match arm).
            return (None, Some(local.to_token_stream()));
        }
    };

    // Wildcards: don't hoist, just keep the expression for side effects
    if name == "_" {
        if let Some(init) = &local.init {
            let expr = &init.expr;
            return (None, Some(quote! { let _ = #expr; }));
        }
        return (None, None);
    }

    let name_ident = proc_macro2::Ident::new(&name, proc_macro2::Span::call_site());

    // Generate hoisted declaration
    let hoist = if let Pat::Type(pt) = pat {
        let ty = &pt.ty;
        quote! { let mut #name_ident: #ty = Default::default(); }
    } else {
        // No type annotation — Default::default() with type inference from later assignment
        quote! { let mut #name_ident = Default::default(); }
    };

    // Generate assignment from initializer
    let assign = if let Some(init) = &local.init {
        let expr = &init.expr;
        Some(quote! { #name_ident = #expr; })
    } else {
        // No initializer: `let mut x;` — already hoisted with Default
        None
    };

    (Some(hoist), assign)
}

/// Extract a simple identifier name from a pattern.
fn extract_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(PatIdent { ident, .. }) => Some(ident.to_string()),
        Pat::Type(PatType { pat, .. }) => extract_ident(pat),
        Pat::Wild(_) => Some("_".to_string()),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════

/// Generate `n` unique random u32 state IDs, all >= 0x1000 to avoid
/// looking like small sequential numbers.
fn generate_unique_ids(n: usize, rng: &mut StdRng) -> Vec<u32> {
    let mut ids = Vec::with_capacity(n);
    let mut used = std::collections::HashSet::new();
    while ids.len() < n {
        let id: u32 = rng.gen::<u32>() | 0x1000;
        if used.insert(id) {
            ids.push(id);
        }
    }
    ids
}

/// Fisher-Yates shuffle for a Vec.
fn shuffle_vec<T>(v: &mut Vec<T>, rng: &mut StdRng) {
    let n = v.len();
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        v.swap(i, j);
    }
}
