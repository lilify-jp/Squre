//! Automatic SQURE source transformation.
//!
//! Transforms unprotected Rust source into SQURE-annotated source:
//!   - Adds `#[obfuscate]` or `#[obfuscate(cff)]` to all functions
//!   - Inserts `anti_debug!()` at the start of main()
//!   - Replaces string literals with `encrypt_string!(...)`
//!   - Adds `use squre::prelude::*;` and `extern crate squre_runtime;`

use syn::visit_mut::VisitMut;
use syn::{Expr, ExprLit, ExprMacro, File, ImplItemFn, Item, ItemFn, Lit, LitStr, Stmt};
use quote::ToTokens;

/// Result of transforming a source file.
#[derive(Default, Debug)]
pub struct TransformStats {
    pub functions_annotated: usize,
    pub strings_encrypted: usize,
    pub anti_debug_inserted: bool,
    pub preamble_added: bool,
}

/// Transform a Rust source file with SQURE protections.
///
/// # Arguments
/// * `source` - The original Rust source code
/// * `is_main_file` - Whether this file contains fn main() (gets preamble + anti_debug)
/// * `level` - Protection level: "standard" or "maximum" (cff)
///
/// # Returns
/// Transformed source code and statistics
pub fn transform_file(source: &str, is_main_file: bool, level: &str) -> Result<(String, TransformStats), String> {
    let mut ast: File = syn::parse_str(source).map_err(|e| format!("parse error: {}", e))?;

    let mut visitor = SqureTransformVisitor {
        level: level.to_string(),
        is_main_file,
        in_const_context: false,
        in_pattern: false,
        in_attribute: false,
        stats: TransformStats::default(),
    };

    visitor.visit_file_mut(&mut ast);

    // Inject preamble for main file
    if is_main_file {
        inject_preamble(&mut ast);
        visitor.stats.preamble_added = true;
    }

    // Pretty-print the AST back to source
    let output = prettyplease::unparse(&ast);
    Ok((output, visitor.stats))
}

/// Inject `extern crate squre_runtime;` and `use squre::prelude::*;` at the top.
fn inject_preamble(ast: &mut File) {
    // Check if extern crate squre_runtime already exists
    let has_extern_crate = ast.items.iter().any(|item| {
        if let Item::ExternCrate(ec) = item {
            ec.ident == "squre_runtime"
        } else {
            false
        }
    });

    // Check if use squre::prelude::* already exists
    let has_use_prelude = ast.items.iter().any(|item| {
        if let Item::Use(u) = item {
            u.to_token_stream().to_string().contains("squre")
                && u.to_token_stream().to_string().contains("prelude")
        } else {
            false
        }
    });

    let mut preamble: Vec<Item> = Vec::new();

    if !has_extern_crate {
        let item: Item = syn::parse_quote! { extern crate squre_runtime; };
        preamble.push(item);
    }
    if !has_use_prelude {
        let item: Item = syn::parse_quote! { use squre::prelude::*; };
        preamble.push(item);
    }

    // Insert at position 0 (before everything else)
    for (i, item) in preamble.into_iter().enumerate() {
        ast.items.insert(i, item);
    }
}

struct SqureTransformVisitor {
    level: String,
    is_main_file: bool,
    in_const_context: bool,
    in_pattern: bool,
    in_attribute: bool,
    stats: TransformStats,
}

impl SqureTransformVisitor {
    /// Check if a function should be skipped (test, no_mangle, already annotated, etc.)
    fn should_skip_fn(&self, attrs: &[syn::Attribute]) -> bool {
        let skip_attrs = ["test", "no_mangle", "export_name", "link_section", "naked"];

        for attr in attrs {
            let path_str = attr.path().to_token_stream().to_string();

            // Already has squre annotation
            if path_str.contains("obfuscate") || path_str.contains("virtualize") {
                return true;
            }

            // Skip test functions
            for skip in &skip_attrs {
                if path_str.contains(skip) {
                    return true;
                }
            }

            // cfg(test)
            if path_str == "cfg" {
                let tokens = attr.to_token_stream().to_string();
                if tokens.contains("test") {
                    return true;
                }
            }
        }

        false
    }

    /// Create the obfuscate attribute based on protection level.
    fn make_obfuscate_attr(&self) -> syn::Attribute {
        if self.level == "maximum" {
            syn::parse_quote! { #[obfuscate(cff)] }
        } else {
            syn::parse_quote! { #[obfuscate] }
        }
    }

    /// Check if a string literal should be encrypted.
    fn should_encrypt_string(&self, s: &str) -> bool {
        // Skip empty strings
        if s.is_empty() {
            return false;
        }
        // Skip if in const/static context
        if self.in_const_context {
            return false;
        }
        // Skip if in pattern position (match arms)
        if self.in_pattern {
            return false;
        }
        // Skip if in attribute
        if self.in_attribute {
            return false;
        }
        true
    }
}

impl VisitMut for SqureTransformVisitor {
    fn visit_item_fn_mut(&mut self, func: &mut ItemFn) {
        let is_main = func.sig.ident == "main" && self.is_main_file;
        let should_skip = self.should_skip_fn(&func.attrs);

        // Recurse into function body first
        syn::visit_mut::visit_item_fn_mut(self, func);

        // Insert anti_debug!() in main
        if is_main {
            let has_anti_debug = func.block.stmts.iter().any(|stmt| {
                stmt.to_token_stream().to_string().contains("anti_debug")
            });
            if !has_anti_debug {
                let anti_debug_stmt: Stmt = syn::parse_quote! { anti_debug!(); };
                func.block.stmts.insert(0, anti_debug_stmt);
                self.stats.anti_debug_inserted = true;
            }
        }

        // Add #[obfuscate] only at "maximum" level (requires explicit usize suffixes in source)
        // At "standard" level, we only do string encryption + anti_debug
        // Skip main() to avoid CFF issues with entry point
        if !should_skip && !is_main && self.level == "maximum" {
            func.attrs.push(self.make_obfuscate_attr());
            self.stats.functions_annotated += 1;
        }
    }

    fn visit_impl_item_fn_mut(&mut self, method: &mut ImplItemFn) {
        let should_skip = self.should_skip_fn(&method.attrs);

        // Recurse first
        syn::visit_mut::visit_impl_item_fn_mut(self, method);

        // Add #[obfuscate] only at "maximum" level
        if !should_skip && self.level == "maximum" {
            method.attrs.push(self.make_obfuscate_attr());
            self.stats.functions_annotated += 1;
        }
    }

    fn visit_item_const_mut(&mut self, item: &mut syn::ItemConst) {
        self.in_const_context = true;
        syn::visit_mut::visit_item_const_mut(self, item);
        self.in_const_context = false;
    }

    fn visit_item_static_mut(&mut self, item: &mut syn::ItemStatic) {
        self.in_const_context = true;
        syn::visit_mut::visit_item_static_mut(self, item);
        self.in_const_context = false;
    }

    fn visit_item_mod_mut(&mut self, module: &mut syn::ItemMod) {
        // Skip #[cfg(test)] modules entirely
        let is_test_mod = module.attrs.iter().any(|attr| {
            let tokens = attr.to_token_stream().to_string();
            tokens.contains("cfg") && tokens.contains("test")
        });
        if is_test_mod {
            return;
        }
        syn::visit_mut::visit_item_mod_mut(self, module);
    }

    fn visit_pat_mut(&mut self, pat: &mut syn::Pat) {
        // Track that we're in a pattern (match arm)
        self.in_pattern = true;
        syn::visit_mut::visit_pat_mut(self, pat);
        self.in_pattern = false;
    }

    fn visit_attribute_mut(&mut self, attr: &mut syn::Attribute) {
        self.in_attribute = true;
        syn::visit_mut::visit_attribute_mut(self, attr);
        self.in_attribute = false;
    }

    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // Handle format macros specially (println!, format!, etc.)
        if let Expr::Macro(expr_macro) = expr {
            self.transform_format_macro(expr_macro);
            return;
        }

        // Recurse first
        syn::visit_mut::visit_expr_mut(self, expr);

        // Transform string literals
        if let Expr::Lit(ExprLit { lit: Lit::Str(lit_str), .. }) = expr {
            let value = lit_str.value();
            if self.should_encrypt_string(&value) {
                // Replace with encrypt_string!(...)
                let new_expr: Expr = syn::parse_quote! {
                    encrypt_string!(#lit_str)
                };
                *expr = new_expr;
                self.stats.strings_encrypted += 1;
            }
        }
    }
}

impl SqureTransformVisitor {
    /// Transform format macros (println!, format!, etc.)
    fn transform_format_macro(&mut self, expr_macro: &mut ExprMacro) {
        let macro_path = expr_macro.mac.path.to_token_stream().to_string();

        // List of format macros that take a format string as first argument
        let format_macros = [
            "println", "eprintln", "print", "eprint",
            "format", "write", "writeln", "panic",
        ];

        let is_format_macro = format_macros.iter().any(|m| macro_path.ends_with(m));
        if !is_format_macro {
            return;
        }

        // Parse the macro tokens to find the format string
        let tokens = expr_macro.mac.tokens.clone();

        // Simple heuristic: if the token stream starts with a string literal,
        // check if it has interpolation placeholders
        if let Ok(lit_str) = syn::parse2::<LitStr>(tokens.clone()) {
            let value = lit_str.value();

            // Check for interpolation placeholders
            let has_placeholders = value.contains("{}")
                || value.contains("{:")
                || value.contains("{0")
                || value.contains("{1")
                || value.contains("{2");

            // Only transform if no placeholders and non-empty
            if !has_placeholders && !value.is_empty() {
                // Transform: println!("hello") -> println!("{}", encrypt_string!("hello"))
                let new_tokens = quote::quote! {
                    "{}", encrypt_string!(#lit_str)
                };
                expr_macro.mac.tokens = new_tokens;
                self.stats.strings_encrypted += 1;
            }
        }
        // If parsing fails or has placeholders, leave the macro unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_simple_function_standard() {
        let source = r#"
fn hello() {
    println!("Hello");
}

fn main() {
    hello();
}
"#;
        // Standard level: no #[obfuscate], just anti_debug
        let (output, stats) = transform_file(source, true, "standard").unwrap();
        assert!(!output.contains("#[obfuscate]")); // standard doesn't add obfuscate
        assert!(output.contains("anti_debug!"));
        assert!(output.contains("extern crate squre_runtime"));
        assert!(output.contains("use squre::prelude::*"));
        assert_eq!(stats.functions_annotated, 0); // no obfuscate at standard level
        assert!(stats.anti_debug_inserted);
    }

    #[test]
    fn test_transform_simple_function_maximum() {
        let source = r#"
fn hello() {
    println!("Hello");
}

fn main() {
    hello();
}
"#;
        // Maximum level: adds #[obfuscate(cff)] to all functions except main
        let (output, stats) = transform_file(source, true, "maximum").unwrap();
        assert!(output.contains("#[obfuscate(cff)]"), "Output should contain #[obfuscate(cff)], got:\n{}", output);
        assert!(output.contains("anti_debug!"));
        assert_eq!(stats.functions_annotated, 1); // hello only (main is skipped)
        assert!(stats.anti_debug_inserted);
    }

    #[test]
    fn test_skip_test_functions() {
        let source = r#"
#[test]
fn test_something() {
    assert!(true);
}

fn real_fn() {}
"#;
        // At maximum level, real_fn gets obfuscated but test_something doesn't
        let (output, stats) = transform_file(source, false, "maximum").unwrap();
        // test_something should NOT have #[obfuscate]
        assert!(output.contains("#[test]"));
        // real_fn SHOULD have #[obfuscate] at maximum level
        assert_eq!(stats.functions_annotated, 1);
    }

    #[test]
    fn test_string_encryption() {
        let source = r#"
fn foo() {
    let s = "secret";
}
"#;
        let (output, stats) = transform_file(source, false, "standard").unwrap();
        assert!(output.contains("encrypt_string!"));
        assert_eq!(stats.strings_encrypted, 1);
    }

    #[test]
    fn test_const_strings_not_encrypted() {
        let source = r#"
const MSG: &str = "hello";
"#;
        let (output, stats) = transform_file(source, false, "standard").unwrap();
        // Should NOT have encrypt_string because const context
        assert!(!output.contains("encrypt_string!"));
        assert_eq!(stats.strings_encrypted, 0);
    }

    #[test]
    fn test_format_string_with_placeholders() {
        let source = r#"
fn foo() {
    println!("Hello, {}!", name);
}
"#;
        let (output, stats) = transform_file(source, false, "standard").unwrap();
        // Format string with {} should NOT be encrypted
        // The string_encrypted count depends on whether we transform it
        // With placeholders, we leave it alone
        assert!(output.contains("\"Hello, {}!\""));
    }

    #[test]
    fn test_maximum_level_uses_cff() {
        let source = r#"
fn foo() {}
"#;
        let (output, _) = transform_file(source, false, "maximum").unwrap();
        assert!(output.contains("#[obfuscate(cff)]"));
    }
}
