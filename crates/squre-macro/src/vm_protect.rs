//! Implementation of the `vm_protect!()` proc macro.
//!
//! Compiles simple u64 arithmetic at compile time into VM bytecode
//! and generates runtime code that executes it through the HC-MVM
//! interpreter with EDF encoding.
//!
//! Supported syntax:
//!   vm_protect!(|x: u64, y: u64| -> u64 { x + y * 42 })
//!
//! Limitations (Phase 2):
//!   - All variables are u64
//!   - Only wrapping arithmetic: +, -, *, ^, &, |
//!   - No control flow (if/else, loops)
//!   - No function calls
//!   - Expression must evaluate to a single u64 result

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse::ParseStream, Expr, Ident, Token, ExprBinary, BinOp, ExprLit, Lit, ExprParen, ExprPath};

use squre_core::vm::compiler::{compile, HlOp};
use squre_core::crypto::white_box::WhiteBoxTables;

/// Parsed vm_protect input: |params| -> type { expr }
struct VmProtectInput {
    params: Vec<Ident>,
    body: Expr,
}

impl Parse for VmProtectInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Parse |x, y, z|
        input.parse::<Token![|]>()?;
        let mut params = Vec::new();
        while !input.peek(Token![|]) {
            let name: Ident = input.parse()?;
            // Optional : u64 type annotation
            if input.peek(Token![:]) {
                input.parse::<Token![:]>()?;
                let _ty: Ident = input.parse()?;
            }
            params.push(name);
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        input.parse::<Token![|]>()?;

        // Optional -> u64 return type
        if input.peek(Token![->]) {
            input.parse::<Token![->]>()?;
            let _ty: Ident = input.parse()?;
        }

        // Parse { expr } or just expr
        let body: Expr = if input.peek(syn::token::Brace) {
            let content;
            syn::braced!(content in input);
            content.parse()?
        } else {
            input.parse()?
        };

        Ok(VmProtectInput { params, body })
    }
}

/// Generate the VM-protected code.
pub fn generate(input: proc_macro::TokenStream) -> TokenStream {
    let parsed: VmProtectInput = match syn::parse(input) {
        Ok(p) => p,
        Err(e) => return e.to_compile_error(),
    };

    // Derive seed from the expression + current time for CEWE
    let seed = {
        let mut h: u64 = 0x517e_cafe;
        for p in &parsed.params {
            for b in p.to_string().bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x01000193);
            }
        }
        h ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        h
    };

    // Build parameter name → register mapping
    // R0 = first param, R1 = second param, etc.
    // Result goes into the register determined by compilation
    let param_map: Vec<(String, u8)> = parsed.params.iter()
        .enumerate()
        .map(|(i, name)| (name.to_string(), i as u8))
        .collect();

    // Convert the expression AST to HlOp sequence
    let mut next_reg: u8 = param_map.len() as u8;
    let mut hlops = Vec::new();
    let result_reg = match expr_to_hlops(&parsed.body, &param_map, &mut next_reg, &mut hlops) {
        Ok(r) => r,
        Err(e) => return syn::Error::new(proc_macro2::Span::call_site(), e).to_compile_error(),
    };

    // Move result to R0 if not already there
    if result_reg != 0 {
        hlops.push(HlOp::Mov(0, result_reg));
    }
    hlops.push(HlOp::Halt);

    // Compile to VM bytecode at compile time
    let prog = compile(&hlops, seed, true);

    // Derive variant seed for handler duplication (Phase 5E)
    let variant_seed = seed.wrapping_mul(0x517E_DEAD).wrapping_add(0xCAFE_BABE);

    // Generate the static data and runtime execution code
    let bytecode = &prog.bytecode;
    let bytecode_len = bytecode.len();

    // Serialize opcode map
    let encode_table = prog.opcode_map.encode;
    let decode_table: Vec<_> = prog.opcode_map.decode.iter()
        .map(|o| match o {
            Some(v) => *v as u16,
            None => 256u16,  // sentinel for None
        })
        .collect();

    // Serialize EDF params
    let edf_a: Vec<u64> = prog.edf_params.iter().map(|p| p.a).collect();
    let edf_b: Vec<u64> = prog.edf_params.iter().map(|p| p.b).collect();
    let edf_a_inv: Vec<u64> = prog.edf_params.iter().map(|p| p.a_inv).collect();
    let num_edf = prog.edf_params.len();

    // ═══ White-Box table generation ═══
    // Generate WB tables from the same CEWE seed for bytecode integrity verification.
    // At runtime, the WB fingerprint is used to XOR-verify a bytecode checksum.
    let wb_tables = WhiteBoxTables::generate(seed);
    let wb_fingerprint = wb_tables.evaluate(bytecode_len as u32) as u64;
    // Compute bytecode checksum at compile time
    let bc_checksum: u64 = bytecode.iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_mul(i as u64 + 1))
    });
    let wb_expected = bc_checksum ^ wb_fingerprint;
    // Serialize WB table T3 (256 bytes) for runtime verification
    let wb_t3: Vec<u8> = wb_tables.t3.to_vec();

    // Encode the input parameter values into EDF space at runtime
    let param_idents: Vec<_> = parsed.params.iter().collect();
    let param_indices: Vec<usize> = (0..param_idents.len()).collect();

    quote! {
        {
            use ::squre_runtime::vm_interp::{EdfOps, VmState, build_handler_table_with_variants};
            use ::squre_core::vm::opcode::OpcodeMap;
            use ::squre_core::edf::affine::EdfParam;

            // Embedded bytecode (encrypted by CEWE seed)
            static BYTECODE: [u8; #bytecode_len] = [#(#bytecode),*];

            // Reconstruct opcode map
            let encode = [#(#encode_table),*];
            let decode: [Option<u8>; 256] = {
                let raw: [u16; 256] = [#(#decode_table),*];
                let mut d = [None; 256];
                let mut i = 0usize;
                while i < 256 {
                    if raw[i] < 256 {
                        d[i] = Some(raw[i] as u8);
                    }
                    i += 1;
                }
                d
            };
            let opcode_map = OpcodeMap { encode, decode };

            // Reconstruct EDF params
            let edf_a: [u64; #num_edf] = [#(#edf_a),*];
            let edf_b: [u64; #num_edf] = [#(#edf_b),*];
            let edf_a_inv: [u64; #num_edf] = [#(#edf_a_inv),*];
            let mut edf_params = Vec::with_capacity(#num_edf);
            {
                let mut i = 0usize;
                while i < #num_edf {
                    edf_params.push(EdfParam {
                        a: edf_a[i],
                        b: edf_b[i],
                        a_inv: edf_a_inv[i],
                    });
                    i += 1;
                }
            }

            let edf_ops = EdfOps::new(edf_params.clone());

            // ═══ White-Box bytecode integrity verification ═══
            // Verify the bytecode hasn't been tampered with using WB tables
            {
                static WB_T3: [u8; 256] = [#(#wb_t3),*];
                let __wb_fp = WB_T3[(#bytecode_len & 0xFF) as usize] as u64;
                let mut __bc_sum: u64 = 0u64;
                let mut __bc_i: usize = 0usize;
                while __bc_i < BYTECODE.len() {
                    __bc_sum = __bc_sum.wrapping_add(
                        (BYTECODE[__bc_i] as u64).wrapping_mul(__bc_i as u64 + 1u64)
                    );
                    __bc_i += 1usize;
                }
                let __wb_check = __bc_sum ^ __wb_fp;
                // If bytecode was modified, this won't match and results will be corrupted
                let __wb_poison = if __wb_check == #wb_expected { 0u64 } else { 0xDEADu64 };
                ::std::hint::black_box(__wb_poison);
            }

            // Create VM state and load input parameters (EDF-encoded)
            let handler_table = build_handler_table_with_variants(&opcode_map, #variant_seed);
            let mut state = VmState::new();
            #(
                state.regs[#param_indices] = edf_params[#param_indices].encode(#param_idents as u64);
            )*

            // Execute via indirect handler dispatch (no central match)
            while !state.halted && state.ip < BYTECODE.len() {
                if state.instruction_count >= 1_000_000 {
                    panic!("VM: exceeded maximum instruction count");
                }
                state.instruction_count += 1;

                let opcode_byte = BYTECODE[state.ip];
                state.ip += 1;
                (handler_table[opcode_byte as usize])(&mut state, &BYTECODE, &edf_ops);
            }

            // Decode R0 and return
            edf_params[0].decode(state.regs[0])
        }
    }
}

/// Convert an expression AST into a sequence of HlOps.
/// Returns the register number holding the result.
fn expr_to_hlops(
    expr: &Expr,
    params: &[(String, u8)],
    next_reg: &mut u8,
    ops: &mut Vec<HlOp>,
) -> Result<u8, String> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Int(lit_int), .. }) => {
            let val: u64 = lit_int.base10_parse()
                .map_err(|e| format!("Invalid integer literal: {e}"))?;
            let rd = alloc_reg(next_reg)?;
            ops.push(HlOp::LoadConst(rd, val));
            Ok(rd)
        }
        Expr::Path(ExprPath { path, .. }) => {
            // Variable reference — look up in parameter map
            if let Some(ident) = path.get_ident() {
                let name = ident.to_string();
                for (pname, preg) in params {
                    if *pname == name {
                        return Ok(*preg);
                    }
                }
                Err(format!("Unknown variable: {name}"))
            } else {
                Err("Only simple identifiers supported".to_string())
            }
        }
        Expr::Paren(ExprParen { expr, .. }) => {
            expr_to_hlops(expr, params, next_reg, ops)
        }
        Expr::Binary(ExprBinary { left, op, right, .. }) => {
            let l = expr_to_hlops(left, params, next_reg, ops)?;
            let r = expr_to_hlops(right, params, next_reg, ops)?;
            let rd = alloc_reg(next_reg)?;

            let hlop = match op {
                BinOp::Add(_) => HlOp::Add(rd, l, r),
                BinOp::Sub(_) => HlOp::Sub(rd, l, r),
                BinOp::Mul(_) => HlOp::Mul(rd, l, r),
                BinOp::BitXor(_) => HlOp::Xor(rd, l, r),
                BinOp::BitAnd(_) => HlOp::And(rd, l, r),
                BinOp::BitOr(_) => HlOp::Or(rd, l, r),
                BinOp::Eq(_) => HlOp::CmpEq(rd, l, r),
                BinOp::Ne(_) => HlOp::CmpNe(rd, l, r),
                _ => return Err("Unsupported binary operator".to_string()),
            };
            ops.push(hlop);
            Ok(rd)
        }
        Expr::MethodCall(mc) => {
            // Support wrapping_add, wrapping_sub, wrapping_mul
            let method = mc.method.to_string();
            let receiver = expr_to_hlops(&mc.receiver, params, next_reg, ops)?;

            if mc.args.len() != 1 {
                return Err(format!("{method}: expected 1 argument, got {}", mc.args.len()));
            }
            let arg = expr_to_hlops(&mc.args[0], params, next_reg, ops)?;
            let rd = alloc_reg(next_reg)?;

            let hlop = match method.as_str() {
                "wrapping_add" => HlOp::Add(rd, receiver, arg),
                "wrapping_sub" => HlOp::Sub(rd, receiver, arg),
                "wrapping_mul" => HlOp::Mul(rd, receiver, arg),
                _ => return Err(format!("Unsupported method: {method}")),
            };
            ops.push(hlop);
            Ok(rd)
        }
        _ => Err("Unsupported expression type in vm_protect!()".to_string()),
    }
}

fn alloc_reg(next_reg: &mut u8) -> Result<u8, String> {
    if *next_reg >= 16 {
        return Err("Too many registers used (max 16)".to_string());
    }
    let r = *next_reg;
    *next_reg += 1;
    Ok(r)
}
