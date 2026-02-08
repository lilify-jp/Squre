use proc_macro::TokenStream;

mod codegen;
mod encrypt_string;
mod obfuscate_const;
mod obfuscate_fn;
mod anti_debug;
mod vm_protect;
mod virtualize;
mod cff;

/// Encrypt a string literal at compile time, decrypt at runtime.
///
/// The string is encrypted using a multi-round XOR cipher. The encryption
/// key is stored as MBA expressions, making it invisible to static analysis.
///
/// # Example
/// ```ignore
/// let secret = squre::encrypt_string!("my secret password");
/// ```
#[proc_macro]
pub fn encrypt_string(input: TokenStream) -> TokenStream {
    let lit: syn::LitStr = syn::parse_macro_input!(input as syn::LitStr);
    let value = lit.value();
    encrypt_string::generate(&value).into()
}

/// Obfuscate an integer constant using MBA expressions.
///
/// # Example
/// ```ignore
/// let x: u32 = squre::obfuscate_const!(12345u32);
/// ```
#[proc_macro]
pub fn obfuscate_const(input: TokenStream) -> TokenStream {
    let lit: syn::LitInt = syn::parse_macro_input!(input as syn::LitInt);
    let value: u64 = lit.base10_parse().expect("obfuscate_const: expected integer literal");
    let suffix = lit.suffix();
    let suffix_str = if suffix.is_empty() { "u64" } else { suffix };
    obfuscate_const::generate(value, suffix_str).into()
}

/// Apply obfuscation transformations to a function.
///
/// Phase 1: Replaces integer literals with MBA expressions and injects
/// anti-debug checks at function entry.
///
/// # Options
/// - `#[obfuscate]` — MBA + opaque predicates + anti-debug
/// - `#[obfuscate(cff)]` — same, plus Control Flow Flattening (state machine)
///
/// # Example
/// ```ignore
/// #[squre::obfuscate]
/// fn check_license(key: u32) -> bool {
///     key == 12345
/// }
///
/// #[squre::obfuscate(cff)]
/// fn validate(x: u64) -> u64 {
///     if x > 10 { x * 2 } else { x + 5 }
/// }
/// ```
#[proc_macro_attribute]
pub fn obfuscate(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    let attr_str = attr.to_string();
    let use_cff = attr_str.contains("cff");

    if use_cff {
        // CFF first (on original AST), then MBA on top
        let cff_seed = {
            let mut h: u64 = 0xCFF0_1234;
            for b in func.sig.ident.to_string().bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x01000193);
            }
            h ^= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(77);
            h
        };
        let cff_tokens = cff::flatten(&func, cff_seed);
        // Re-parse CFF output, then apply MBA + opaque predicates on top
        match syn::parse2::<syn::ItemFn>(cff_tokens.clone()) {
            Ok(cff_func) => obfuscate_fn::transform(cff_func).into(),
            Err(_) => {
                // If CFF output can't be re-parsed, return it directly
                cff_tokens.into()
            }
        }
    } else {
        obfuscate_fn::transform(func).into()
    }
}

/// Insert anti-debugging checks at the current location.
///
/// Checks PEB.BeingDebugged, timing anomalies, and hardware breakpoints.
/// If a debugger is detected, a poison value is set that silently corrupts
/// subsequent obfuscated calculations.
///
/// # Example
/// ```ignore
/// fn main() {
///     squre::anti_debug!();
///     // ... rest of program
/// }
/// ```
#[proc_macro]
pub fn anti_debug(_input: TokenStream) -> TokenStream {
    anti_debug::generate().into()
}

/// Protect an arithmetic expression by executing it in a virtual machine.
///
/// The expression is compiled to VM bytecode at compile time, with
/// EDF-encoded registers and CEWE-seeded opcode mapping. At runtime,
/// the HC-MVM interpreter executes the bytecode.
///
/// # Example
/// ```ignore
/// let result: u64 = squre::vm_protect!(|x: u64, y: u64| -> u64 {
///     x + y * 42
/// });
/// ```
#[proc_macro]
pub fn vm_protect(input: TokenStream) -> TokenStream {
    vm_protect::generate(input).into()
}

/// Virtualize an entire function body into VM bytecode.
///
/// This is the strongest obfuscation layer: the function's control flow,
/// arithmetic, and logic are all compiled to custom VM bytecode with
/// CEWE-randomized opcodes and EDF-encoded registers.
///
/// # Supported constructs
/// - Integer and boolean arithmetic (`+`, `-`, `*`, `/`, `%`, `^`, `&`, `|`)
/// - Comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`)
/// - Logical operators (`&&`, `||`, `!`)
/// - Control flow (`if`/`else`, `while`, `loop`, `for .. in range`, `break`, `continue`)
/// - `match` on integer/bool literals
/// - `return` statements
/// - `wrapping_*` methods
/// - Type casts (`as u32`, etc.)
///
/// # Limitations
/// - All values are treated as u64 internally
/// - String/slice/reference operations must use VmCall (Phase 5C+)
/// - Closures and async not supported
///
/// # Example
/// ```ignore
/// #[squre::virtualize]
/// fn validate(key: u64, magic: u64) -> u64 {
///     let mut hash = key ^ 0xCAFEBABE;
///     let mut i = 0u64;
///     while i < 16 {
///         hash = hash.wrapping_mul(31).wrapping_add(magic);
///         i += 1;
///     }
///     hash
/// }
/// ```
#[proc_macro_attribute]
pub fn virtualize(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);

    // Parse attributes: nested, depth = N
    let attr_str = attr.to_string();
    let use_nested = attr_str.contains("nested");

    // Parse depth parameter (default is 2 if nested is specified)
    let depth = if use_nested {
        // Extract depth = N from attribute string
        if let Some(pos) = attr_str.find("depth") {
            let after_depth = &attr_str[pos..];
            // Look for "depth = N" or "depth=N"
            if let Some(eq_pos) = after_depth.find('=') {
                let after_eq = &after_depth[eq_pos + 1..];
                // Extract the number
                let num_str: String = after_eq.chars()
                    .skip_while(|c| c.is_whitespace())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                num_str.parse::<usize>().unwrap_or(2)
            } else {
                2
            }
        } else {
            2
        }
    } else {
        1 // Single layer if not nested
    };

    virtualize::transform_with_options(func, depth).into()
}
