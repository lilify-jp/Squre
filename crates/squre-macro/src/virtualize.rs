//! Implementation of the `#[virtualize]` proc macro.
//!
//! Converts an entire function body into VM bytecode, replacing
//! the original function with one that executes via the HC-MVM interpreter.
//!
//! This is the core of Phase 5C — the most impactful obfuscation layer.
//! After this transformation, a reverser must:
//!   1. Reverse the CEWE-shuffled opcode mapping
//!   2. Undo EDF register encoding
//!   3. Filter out 5x junk instructions
//!   4. Reconstruct the control flow graph
//!   5. Deal with a different bytecode layout on every build

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Expr, ExprBinary, ExprLit, ExprParen, ExprPath, ExprUnary, ExprAssign,
    ExprIf, ExprWhile, ExprLoop, ExprBlock, ExprReturn, ExprBreak, ExprContinue,
    ExprMethodCall, ExprCast, ExprRange,
    ExprForLoop, ExprMatch,
    BinOp, UnOp, Lit, Pat, PatIdent, Stmt, Block, ItemFn, FnArg, ReturnType,
    Type, TypePath,
};

use squre_core::vm::compiler::{compile, HlOp};
use squre_core::vm::opcode::NUM_REGS;
use squre_core::crypto::white_box::WhiteBoxTables;

/// Context for lowering a function body to HlOps.
struct LowerCtx {
    /// Variable name → register index
    vars: Vec<(String, u8)>,
    /// Next available register (0-9 for user, 10-15 reserved for junk)
    next_reg: u8,
    /// HlOp output buffer
    ops: Vec<HlOp>,
    /// Label counter
    next_label: u32,
    /// Loop context stack: (start_label, end_label)
    loop_stack: Vec<(u32, u32)>,
    /// Native function table: (function path, arg count)
    native_funcs: Vec<(String, usize)>,
    /// Max user register (15 = all 16 registers; junk is skipped for label programs)
    max_user_reg: u8,
    /// Temp register base: registers below this hold named variables.
    /// Temps above this are freed after each top-level statement.
    temp_base: u8,
}

impl LowerCtx {
    fn new() -> Self {
        LowerCtx {
            vars: Vec::new(),
            next_reg: 0,
            ops: Vec::new(),
            next_label: 0,
            loop_stack: Vec::new(),
            native_funcs: Vec::new(),
            max_user_reg: 15,  // use all 16 registers (junk skipped for label programs)
            temp_base: 0,
        }
    }

    fn alloc_reg(&mut self) -> Result<u8, String> {
        if self.next_reg > self.max_user_reg {
            return Err(format!(
                "virtualize: too many registers (max {})",
                self.max_user_reg + 1
            ));
        }
        let r = self.next_reg;
        self.next_reg += 1;
        Ok(r)
    }

    fn alloc_label(&mut self) -> u32 {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    fn find_var(&self, name: &str) -> Option<u8> {
        // Search from end to support shadowing
        self.vars.iter().rev().find(|(n, _)| n == name).map(|(_, r)| *r)
    }

    fn define_var(&mut self, name: String) -> Result<u8, String> {
        let r = self.alloc_reg()?;
        self.vars.push((name, r));
        // Update temp_base: variables are permanent, temps start after them
        self.temp_base = self.next_reg;
        Ok(r)
    }

    /// Reset temp registers, freeing all temporaries from previous expression.
    /// Call this at the start of each top-level statement.
    fn reset_temps(&mut self) {
        self.next_reg = self.temp_base;
    }

    fn emit(&mut self, op: HlOp) {
        self.ops.push(op);
    }
}

/// Transform a function with `#[virtualize]` with configurable nesting depth.
///
/// - depth = 1: Single-layer VM (no nesting)
/// - depth = 2: Two-layer VM (outer delegates to inner via VmExecNested)
/// - depth = N: N-layer VM (each layer delegates to the next)
///
/// Each layer has independent CEWE seed, opcode mapping, and EDF parameters.
/// Analysis complexity: O(37!^N) for opcode space alone.
pub fn transform_with_options(func: ItemFn, depth: usize) -> TokenStream {
    let result = if depth <= 1 {
        transform_inner(&func)
    } else {
        transform_nested(&func, depth)
    };
    match result {
        Ok(ts) => ts,
        Err(e) => {
            let msg = format!("virtualize error: {e}");
            syn::Error::new_spanned(&func.sig.ident, msg).to_compile_error()
        }
    }
}

fn transform_inner(func: &ItemFn) -> Result<TokenStream, String> {
    let mut ctx = LowerCtx::new();

    // Parse function parameters → assign registers
    let mut param_names = Vec::new();
    for arg in &func.sig.inputs {
        match arg {
            FnArg::Typed(pat_type) => {
                let name = pat_to_name(&pat_type.pat)?;
                let reg = ctx.define_var(name.clone())?;
                param_names.push((name, reg));
            }
            FnArg::Receiver(_) => {
                return Err("virtualize: self parameters not supported".into());
            }
        }
    }

    // Determine return type handling (needed before body lowering)
    let returns_value = !matches!(&func.sig.output, ReturnType::Default);

    // Lower the function body — use lower_block_as_expr to capture the
    // trailing expression (implicit return value).
    let body_result = lower_block_as_expr(&mut ctx, &func.block)?;

    // Move the implicit return value into R0 (the return register).
    // Explicit `return` statements already emit Mov(0, val) + Halt,
    // but trailing expressions need this final move.
    if returns_value && body_result != 0 {
        ctx.emit(HlOp::Mov(0, body_result));
    }

    // Ensure we end with Halt
    ctx.emit(HlOp::Halt);

    // Derive seed from function name + nanos
    let seed = {
        let mut h: u64 = 0x517e_0107;
        for b in func.sig.ident.to_string().bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x01000193);
        }
        h ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        h
    };

    // Derive variant seed for handler duplication (Phase 5E)
    let variant_seed = seed.wrapping_mul(0x517E_DEAD).wrapping_add(0xCAFE_BABE);

    // Compile to VM bytecode
    let prog = compile(&ctx.ops, seed, true);

    // Generate replacement function
    let vis = &func.vis;
    let sig = &func.sig;
    let _fn_name = &func.sig.ident;

    let bytecode = &prog.bytecode;
    let bytecode_len = bytecode.len();

    // Serialize opcode map
    let encode_table = prog.opcode_map.encode;
    let decode_table: Vec<u16> = prog.opcode_map.decode.iter()
        .map(|o| match o {
            Some(v) => *v as u16,
            None => 256u16,
        })
        .collect();

    // Serialize EDF params
    let edf_a: Vec<u64> = prog.edf_params.iter().map(|p| p.a).collect();
    let edf_b: Vec<u64> = prog.edf_params.iter().map(|p| p.b).collect();
    let edf_a_inv: Vec<u64> = prog.edf_params.iter().map(|p| p.a_inv).collect();
    let num_edf = prog.edf_params.len();

    // White-Box integrity
    let wb_tables = WhiteBoxTables::generate(seed);
    let wb_fingerprint = wb_tables.evaluate(bytecode_len as u32) as u64;
    let bc_checksum: u64 = bytecode.iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_mul(i as u64 + 1))
    });
    let wb_expected = bc_checksum ^ wb_fingerprint;
    let wb_t3: Vec<u8> = wb_tables.t3.to_vec();

    // Parameter encoding at runtime
    let param_idents: Vec<proc_macro2::Ident> = param_names.iter()
        .map(|(name, _)| proc_macro2::Ident::new(name, proc_macro2::Span::call_site()))
        .collect();
    let param_indices: Vec<usize> = param_names.iter()
        .map(|(_, reg)| *reg as usize)
        .collect();

    let decode_result = if returns_value {
        quote! { edf_params[0].decode(__vm_state.regs[0]) }
    } else {
        quote! { () }
    };

    // Build native function pointer table (for VmCall)
    // Each entry is a wrapper fn(&[u64]) -> u64 that calls the native function.
    // Uses FromVmArg/ToVmResult traits for type-safe u64 ↔ native type conversion.
    // The arity is known at compile time, so no match on args.len() is needed.
    let native_func_wrappers: Vec<TokenStream> = ctx.native_funcs.iter()
        .map(|(func_name, arg_count)| {
            let path: syn::Path = syn::parse_str(func_name)
                .unwrap_or_else(|_| panic!("Invalid function path: {}", func_name));

            // Generate per-argument FromVmArg::from_vm_arg(__args[i]) expressions
            let arg_exprs: Vec<TokenStream> = (0..*arg_count).map(|i| {
                quote! {
                    ::squre_runtime::vm_interp::FromVmArg::from_vm_arg(__args[#i])
                }
            }).collect();

            quote! {
                |__args: &[u64]| -> u64 {
                    ::squre_runtime::vm_interp::ToVmResult::to_vm_result(
                        #path(#(#arg_exprs),*)
                    )
                }
            }
        })
        .collect();
    let _num_native_funcs = native_func_wrappers.len();

    Ok(quote! {
        #vis #sig {
            use ::squre_runtime::vm_interp::{EdfOps, VmState, build_handler_table_with_variants};
            use ::squre_core::vm::opcode::OpcodeMap;
            use ::squre_core::edf::affine::EdfParam;

            // ═══ Embedded VM bytecode ═══
            static __VM_BYTECODE: [u8; #bytecode_len] = [#(#bytecode),*];

            // ═══ Opcode map reconstruction ═══
            let __vm_encode = [#(#encode_table),*];
            let __vm_decode: [Option<u8>; 256] = {
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
            let __vm_opmap = OpcodeMap { encode: __vm_encode, decode: __vm_decode };

            // ═══ EDF parameters ═══
            let __vm_edf_a: [u64; #num_edf] = [#(#edf_a),*];
            let __vm_edf_b: [u64; #num_edf] = [#(#edf_b),*];
            let __vm_edf_ai: [u64; #num_edf] = [#(#edf_a_inv),*];
            let mut edf_params = Vec::with_capacity(#num_edf);
            {
                let mut i = 0usize;
                while i < #num_edf {
                    edf_params.push(EdfParam {
                        a: __vm_edf_a[i],
                        b: __vm_edf_b[i],
                        a_inv: __vm_edf_ai[i],
                    });
                    i += 1;
                }
            }
            let __vm_edf = EdfOps::new(edf_params.clone());

            // ═══ White-Box integrity verification ═══
            {
                static __WB_T3: [u8; 256] = [#(#wb_t3),*];
                let __wb_fp = __WB_T3[(#bytecode_len & 0xFF) as usize] as u64;
                let mut __bc_sum: u64 = 0u64;
                let mut __bc_i: usize = 0usize;
                while __bc_i < __VM_BYTECODE.len() {
                    __bc_sum = __bc_sum.wrapping_add(
                        (__VM_BYTECODE[__bc_i] as u64).wrapping_mul(__bc_i as u64 + 1u64)
                    );
                    __bc_i += 1usize;
                }
                let __wb_check = __bc_sum ^ __wb_fp;
                let __wb_poison = if __wb_check == #wb_expected { 0u64 } else { 0xDEADu64 };
                ::std::hint::black_box(__wb_poison);
            }

            // ═══ Native function table (for VmCall) ═══
            let __vm_native_funcs: Vec<fn(&[u64]) -> u64> = vec![
                #(#native_func_wrappers),*
            ];

            // ═══ VM Execution (handler-chain dispatch with variant selection) ═══
            let __vm_htable = build_handler_table_with_variants(&__vm_opmap, #variant_seed);
            let mut __vm_state = VmState::new();
            __vm_state.native_functions = __vm_native_funcs;

            // Load function parameters into VM registers (EDF-encoded)
            #(
                __vm_state.regs[#param_indices] = edf_params[#param_indices].encode(#param_idents as u64);
            )*

            // Execute via indirect handler dispatch (no central match)
            while !__vm_state.halted && __vm_state.ip < __VM_BYTECODE.len() {
                if __vm_state.instruction_count >= 10_000_000 {
                    panic!("VM: exceeded maximum instruction count");
                }
                __vm_state.instruction_count += 1;

                let __opc = __VM_BYTECODE[__vm_state.ip];
                __vm_state.ip += 1;
                (__vm_htable[__opc as usize])(&mut __vm_state, &__VM_BYTECODE, &__vm_edf);
            }

            // Decode result from R0
            #decode_result
        }
    })
}

/// Transform a function with nested N-layer VM execution.
///
/// The function body is compiled as the innermost VM.
/// Each outer layer simply delegates to the next inner layer via VmExecNested.
/// Each layer has independent CEWE seed, opcode mapping, and EDF parameters.
///
/// Analysis complexity: O(37!^depth) for opcode space alone.
fn transform_nested(func: &ItemFn, depth: usize) -> Result<TokenStream, String> {
    if depth <= 1 {
        return transform_inner(func);
    }
    if depth == 2 {
        return transform_nested_2layer(func);
    }
    // For depth > 2, return error for now (can be implemented later)
    Err(format!("virtualize: nested depth > 2 not yet implemented (requested depth: {})", depth))
}

/// Transform a function with nested 2-layer VM execution (original implementation).
///
/// The function body is compiled as the inner VM (with seed A).
/// An outer VM (with seed B) is generated that simply delegates to the inner
/// VM via VmExecNested. This doubles the analysis complexity: each layer has
/// independent CEWE-randomized opcodes and EDF parameters.
fn transform_nested_2layer(func: &ItemFn) -> Result<TokenStream, String> {
    let mut ctx = LowerCtx::new();

    // Parse function parameters
    let mut param_names = Vec::new();
    for arg in &func.sig.inputs {
        match arg {
            FnArg::Typed(pat_type) => {
                let name = pat_to_name(&pat_type.pat)?;
                let reg = ctx.define_var(name.clone())?;
                param_names.push((name, reg));
            }
            FnArg::Receiver(_) => {
                return Err("virtualize: self parameters not supported".into());
            }
        }
    }

    let returns_value = !matches!(&func.sig.output, ReturnType::Default);
    let arg_count = param_names.len();

    // Lower the function body for the inner VM
    let body_result = lower_block_as_expr(&mut ctx, &func.block)?;
    if returns_value && body_result != 0 {
        ctx.emit(HlOp::Mov(0, body_result));
    }
    ctx.emit(HlOp::Halt);

    // Derive seeds — inner and outer get DIFFERENT seeds
    let base_seed = {
        let mut h: u64 = 0x517e_0107;
        for b in func.sig.ident.to_string().bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x01000193);
        }
        h ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        h
    };

    let inner_seed = base_seed;
    let outer_seed = base_seed.wrapping_mul(0xBAAD_FACE_DEAD_BEEFu64).wrapping_add(0x1337);
    let inner_variant_seed = inner_seed.wrapping_mul(0x517E_DEAD).wrapping_add(0xCAFE_BABE);
    let outer_variant_seed = outer_seed.wrapping_mul(0x517E_DEAD).wrapping_add(0xCAFE_BABE);

    // ═══ Compile inner VM (actual function body) ═══
    let inner_prog = compile(&ctx.ops, inner_seed, true);

    // ═══ Compile outer VM (just calls nested program 0) ═══
    let outer_ops = vec![
        HlOp::VmExecNested(0, arg_count as u8, 0),
        HlOp::Halt,
    ];
    let outer_prog = compile(&outer_ops, outer_seed, true);

    // ═══ Serialize both programs ═══
    let vis = &func.vis;
    let sig = &func.sig;

    // Inner bytecode
    let inner_bc = &inner_prog.bytecode;
    let inner_bc_len = inner_bc.len();
    let inner_encode = inner_prog.opcode_map.encode;
    let inner_decode: Vec<u16> = inner_prog.opcode_map.decode.iter()
        .map(|o| match o { Some(v) => *v as u16, None => 256u16 })
        .collect();
    let inner_edf_a: Vec<u64> = inner_prog.edf_params.iter().map(|p| p.a).collect();
    let inner_edf_b: Vec<u64> = inner_prog.edf_params.iter().map(|p| p.b).collect();
    let inner_edf_ai: Vec<u64> = inner_prog.edf_params.iter().map(|p| p.a_inv).collect();
    let inner_num_edf = inner_prog.edf_params.len();

    // Outer bytecode
    let outer_bc = &outer_prog.bytecode;
    let outer_bc_len = outer_bc.len();
    let outer_encode = outer_prog.opcode_map.encode;
    let outer_decode: Vec<u16> = outer_prog.opcode_map.decode.iter()
        .map(|o| match o { Some(v) => *v as u16, None => 256u16 })
        .collect();
    let outer_edf_a: Vec<u64> = outer_prog.edf_params.iter().map(|p| p.a).collect();
    let outer_edf_b: Vec<u64> = outer_prog.edf_params.iter().map(|p| p.b).collect();
    let outer_edf_ai: Vec<u64> = outer_prog.edf_params.iter().map(|p| p.a_inv).collect();
    let outer_num_edf = outer_prog.edf_params.len();

    // White-Box integrity for outer bytecode
    let wb_tables = WhiteBoxTables::generate(outer_seed);
    let wb_fingerprint = wb_tables.evaluate(outer_bc_len as u32) as u64;
    let bc_checksum: u64 = outer_bc.iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_mul(i as u64 + 1))
    });
    let wb_expected = bc_checksum ^ wb_fingerprint;
    let wb_t3: Vec<u8> = wb_tables.t3.to_vec();

    // Parameter handling
    let param_idents: Vec<proc_macro2::Ident> = param_names.iter()
        .map(|(name, _)| proc_macro2::Ident::new(name, proc_macro2::Span::call_site()))
        .collect();
    let param_indices: Vec<usize> = param_names.iter()
        .map(|(_, reg)| *reg as usize)
        .collect();

    let decode_result = if returns_value {
        quote! { outer_edf_params[0].decode(__vm_state.regs[0]) }
    } else {
        quote! { () }
    };

    // Build native function pointer table (for VmCall in nested context)
    let native_func_wrappers: Vec<TokenStream> = ctx.native_funcs.iter()
        .map(|(func_name, arg_count)| {
            let path: syn::Path = syn::parse_str(func_name)
                .unwrap_or_else(|_| panic!("Invalid function path: {}", func_name));

            let arg_exprs: Vec<TokenStream> = (0..*arg_count).map(|i| {
                quote! {
                    ::squre_runtime::vm_interp::FromVmArg::from_vm_arg(__args[#i])
                }
            }).collect();

            quote! {
                |__args: &[u64]| -> u64 {
                    ::squre_runtime::vm_interp::ToVmResult::to_vm_result(
                        #path(#(#arg_exprs),*)
                    )
                }
            }
        })
        .collect();

    Ok(quote! {
        #vis #sig {
            use ::squre_runtime::vm_interp::{
                EdfOps, VmState, NestedVmContext, build_handler_table_with_variants,
            };
            use ::squre_core::vm::opcode::OpcodeMap;
            use ::squre_core::edf::affine::EdfParam;

            // ═══ Inner VM (actual function body — different CEWE seed) ═══
            static __INNER_BC: [u8; #inner_bc_len] = [#(#inner_bc),*];

            let __inner_encode = [#(#inner_encode),*];
            let __inner_decode: [Option<u8>; 256] = {
                let raw: [u16; 256] = [#(#inner_decode),*];
                let mut d = [None; 256];
                let mut i = 0usize;
                while i < 256 {
                    if raw[i] < 256 { d[i] = Some(raw[i] as u8); }
                    i += 1;
                }
                d
            };
            let __inner_opmap = OpcodeMap { encode: __inner_encode, decode: __inner_decode };

            let __ie_a: [u64; #inner_num_edf] = [#(#inner_edf_a),*];
            let __ie_b: [u64; #inner_num_edf] = [#(#inner_edf_b),*];
            let __ie_ai: [u64; #inner_num_edf] = [#(#inner_edf_ai),*];
            let mut __inner_edf_params = Vec::with_capacity(#inner_num_edf);
            {
                let mut i = 0usize;
                while i < #inner_num_edf {
                    __inner_edf_params.push(EdfParam { a: __ie_a[i], b: __ie_b[i], a_inv: __ie_ai[i] });
                    i += 1;
                }
            }
            let __inner_edf = EdfOps::new(__inner_edf_params);
            let __inner_htable = build_handler_table_with_variants(&__inner_opmap, #inner_variant_seed);

            // ═══ Outer VM (wrapper that calls nested — different CEWE seed) ═══
            static __OUTER_BC: [u8; #outer_bc_len] = [#(#outer_bc),*];

            let __outer_encode = [#(#outer_encode),*];
            let __outer_decode: [Option<u8>; 256] = {
                let raw: [u16; 256] = [#(#outer_decode),*];
                let mut d = [None; 256];
                let mut i = 0usize;
                while i < 256 {
                    if raw[i] < 256 { d[i] = Some(raw[i] as u8); }
                    i += 1;
                }
                d
            };
            let __outer_opmap = OpcodeMap { encode: __outer_encode, decode: __outer_decode };

            let __oe_a: [u64; #outer_num_edf] = [#(#outer_edf_a),*];
            let __oe_b: [u64; #outer_num_edf] = [#(#outer_edf_b),*];
            let __oe_ai: [u64; #outer_num_edf] = [#(#outer_edf_ai),*];
            let mut outer_edf_params = Vec::with_capacity(#outer_num_edf);
            {
                let mut i = 0usize;
                while i < #outer_num_edf {
                    outer_edf_params.push(EdfParam { a: __oe_a[i], b: __oe_b[i], a_inv: __oe_ai[i] });
                    i += 1;
                }
            }
            let __outer_edf = EdfOps::new(outer_edf_params.clone());
            let __outer_htable = build_handler_table_with_variants(&__outer_opmap, #outer_variant_seed);

            // ═══ White-Box integrity verification (outer bytecode) ═══
            {
                static __WB_T3: [u8; 256] = [#(#wb_t3),*];
                let __wb_fp = __WB_T3[(#outer_bc_len & 0xFF) as usize] as u64;
                let mut __bc_sum: u64 = 0u64;
                let mut __bc_i: usize = 0usize;
                while __bc_i < __OUTER_BC.len() {
                    __bc_sum = __bc_sum.wrapping_add(
                        (__OUTER_BC[__bc_i] as u64).wrapping_mul(__bc_i as u64 + 1u64)
                    );
                    __bc_i += 1usize;
                }
                let __wb_check = __bc_sum ^ __wb_fp;
                let __wb_poison = if __wb_check == #wb_expected { 0u64 } else { 0xDEADu64 };
                ::std::hint::black_box(__wb_poison);
            }

            // ═══ Native function table (for VmCall) ═══
            let __vm_native_funcs: Vec<fn(&[u64]) -> u64> = vec![
                #(#native_func_wrappers),*
            ];

            // ═══ Assemble nested VM context and execute ═══
            let mut __vm_state = VmState::new();
            __vm_state.native_functions = __vm_native_funcs;

            // Register the inner VM as nested program 0
            __vm_state.nested_programs.push(NestedVmContext {
                bytecode: __INNER_BC.to_vec(),
                handler_table: Box::new(__inner_htable),
                edf_ops: __inner_edf,
                sub_programs: Vec::new(),
            });

            // Load function parameters into outer VM registers (outer EDF-encoded)
            #(
                __vm_state.regs[#param_indices] = outer_edf_params[#param_indices].encode(#param_idents as u64);
            )*

            // Execute outer VM → VmExecNested(0) → inner VM
            while !__vm_state.halted && __vm_state.ip < __OUTER_BC.len() {
                if __vm_state.instruction_count >= 10_000_000 {
                    panic!("VM: exceeded maximum instruction count");
                }
                __vm_state.instruction_count += 1;
                let __opc = __OUTER_BC[__vm_state.ip];
                __vm_state.ip += 1;
                (__outer_htable[__opc as usize])(&mut __vm_state, &__OUTER_BC, &__outer_edf);
            }

            // Decode result from outer R0
            #decode_result
        }
    })
}

// ═══════════════════════════════════════════════════════════════
// Statement / Block lowering
// ═══════════════════════════════════════════════════════════════

fn lower_block(ctx: &mut LowerCtx, block: &Block) -> Result<(), String> {
    for stmt in &block.stmts {
        lower_stmt(ctx, stmt)?;
    }
    Ok(())
}

fn lower_stmt(ctx: &mut LowerCtx, stmt: &Stmt) -> Result<(), String> {
    // Reset temp registers from the previous statement.
    // Only temps (above temp_base) are freed — named variables are permanent.
    ctx.reset_temps();

    match stmt {
        Stmt::Local(local) => {
            // let x = expr; or let x: T = expr;
            let name = pat_to_name(&local.pat)?;
            let reg = ctx.define_var(name)?;

            if let Some(init) = &local.init {
                let val_reg = lower_expr(ctx, &init.expr)?;
                if val_reg != reg {
                    ctx.emit(HlOp::Mov(reg, val_reg));
                }
            } else {
                ctx.emit(HlOp::LoadConst(reg, 0));
            }
            Ok(())
        }
        Stmt::Expr(expr, _semi) => {
            lower_expr(ctx, expr)?;
            Ok(())
        }
        Stmt::Item(_) => {
            // Inner items (fn, struct, etc.) — skip
            Ok(())
        }
        Stmt::Macro(m) => {
            // Try to handle common macros
            let path = &m.mac.path;
            let path_str = quote!(#path).to_string();
            if path_str.contains("println") || path_str.contains("eprintln")
                || path_str.contains("dbg") || path_str.contains("todo")
                || path_str.contains("unimplemented") || path_str.contains("panic")
            {
                // Skip debug/print macros in virtualized code
                return Ok(());
            }
            Err(format!("virtualize: unsupported macro `{}`", path_str))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Expression lowering — returns register holding the result
// ═══════════════════════════════════════════════════════════════

fn lower_expr(ctx: &mut LowerCtx, expr: &Expr) -> Result<u8, String> {
    match expr {
        // ─── Literals ───
        Expr::Lit(ExprLit { lit, .. }) => {
            match lit {
                Lit::Int(li) => {
                    let val: u64 = li.base10_parse()
                        .map_err(|e| format!("Invalid int literal: {e}"))?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, val));
                    Ok(rd)
                }
                Lit::Bool(lb) => {
                    let val = if lb.value { 1u64 } else { 0u64 };
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, val));
                    Ok(rd)
                }
                _ => Err("virtualize: only integer and bool literals supported".into()),
            }
        }

        // ─── Variable reference ───
        Expr::Path(ExprPath { path, .. }) => {
            if let Some(ident) = path.get_ident() {
                let name = ident.to_string();
                // true/false as paths
                if name == "true" {
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, 1));
                    return Ok(rd);
                }
                if name == "false" {
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, 0));
                    return Ok(rd);
                }
                match ctx.find_var(&name) {
                    Some(r) => Ok(r),
                    None => Err(format!("virtualize: unknown variable `{name}`")),
                }
            } else {
                Err("virtualize: only simple idents supported in paths".into())
            }
        }

        // ─── Parenthesized ───
        Expr::Paren(ExprParen { expr, .. }) => lower_expr(ctx, expr),

        // ─── Block expression ───
        Expr::Block(ExprBlock { block, .. }) => {
            if block.stmts.is_empty() {
                let rd = ctx.alloc_reg()?;
                ctx.emit(HlOp::LoadConst(rd, 0));
                return Ok(rd);
            }
            // Lower all but last statement, then lower last as expression
            for stmt in &block.stmts[..block.stmts.len() - 1] {
                lower_stmt(ctx, stmt)?;
            }
            match &block.stmts[block.stmts.len() - 1] {
                Stmt::Expr(expr, None) => lower_expr(ctx, expr),
                stmt => {
                    lower_stmt(ctx, stmt)?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, 0));
                    Ok(rd)
                }
            }
        }

        // ─── Binary operations ───
        Expr::Binary(ExprBinary { left, op, right, .. }) => {
            // Short-circuit operators: && and ||
            match op {
                BinOp::And(_) => {
                    // a && b: if a == 0, result is 0; else result is b
                    let l = lower_expr(ctx, left)?;
                    let rd = ctx.alloc_reg()?;
                    let skip_label = ctx.alloc_label();
                    let end_label = ctx.alloc_label();

                    // if l == 0, short-circuit to false
                    ctx.emit(HlOp::JmpIfZeroLabel(l, skip_label));
                    let r = lower_expr(ctx, right)?;
                    // Normalize to bool: r != 0
                    let zero = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(zero, 0));
                    ctx.emit(HlOp::CmpNe(rd, r, zero));
                    ctx.emit(HlOp::JmpLabel(end_label));
                    ctx.emit(HlOp::Label(skip_label));
                    ctx.emit(HlOp::LoadConst(rd, 0));
                    ctx.emit(HlOp::Label(end_label));
                    return Ok(rd);
                }
                BinOp::Or(_) => {
                    // a || b: if a != 0, result is 1; else result is b
                    let l = lower_expr(ctx, left)?;
                    let rd = ctx.alloc_reg()?;
                    let skip_label = ctx.alloc_label();
                    let end_label = ctx.alloc_label();

                    ctx.emit(HlOp::JmpIfNotZeroLabel(l, skip_label));
                    let r = lower_expr(ctx, right)?;
                    let zero = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(zero, 0));
                    ctx.emit(HlOp::CmpNe(rd, r, zero));
                    ctx.emit(HlOp::JmpLabel(end_label));
                    ctx.emit(HlOp::Label(skip_label));
                    ctx.emit(HlOp::LoadConst(rd, 1));
                    ctx.emit(HlOp::Label(end_label));
                    return Ok(rd);
                }
                _ => {}
            }

            let l = lower_expr(ctx, left)?;
            let r = lower_expr(ctx, right)?;
            let rd = ctx.alloc_reg()?;

            let hlop = match op {
                BinOp::Add(_) | BinOp::AddAssign(_) => HlOp::Add(rd, l, r),
                BinOp::Sub(_) | BinOp::SubAssign(_) => HlOp::Sub(rd, l, r),
                BinOp::Mul(_) | BinOp::MulAssign(_) => HlOp::Mul(rd, l, r),
                BinOp::Div(_) | BinOp::DivAssign(_) => HlOp::Div(rd, l, r),
                BinOp::Rem(_) | BinOp::RemAssign(_) => HlOp::Mod(rd, l, r),
                BinOp::BitXor(_) | BinOp::BitXorAssign(_) => HlOp::Xor(rd, l, r),
                BinOp::BitAnd(_) | BinOp::BitAndAssign(_) => HlOp::And(rd, l, r),
                BinOp::BitOr(_) | BinOp::BitOrAssign(_) => HlOp::Or(rd, l, r),
                BinOp::Shl(_) | BinOp::ShlAssign(_) => {
                    // VM Shl takes immediate, but here we have register.
                    // Decode the shift amount and use it.
                    // For now, lower as: decode r → use as immediate
                    // This is a simplification — in practice shifts by variable
                    // amounts would need a new opcode. For now, just use decode+mul trick.
                    // Actually, our Shl opcode takes imm8. For variable shifts,
                    // we'd need Div/Mod workaround. Let's handle common case:
                    // if right is a literal, extract the constant.
                    if let Expr::Lit(ExprLit { lit: Lit::Int(li), .. }) = right.as_ref() {
                        let imm: u8 = li.base10_parse().unwrap_or(0);
                        ctx.ops.pop(); // remove the alloc for r (unused)
                        // Also pop the rd we allocated — we'll make new one
                        ctx.emit(HlOp::Shl(rd, l, imm));
                        return Ok(rd);
                    }
                    // Variable shift: not yet supported in VM ISA
                    return Err("virtualize: variable shift amounts not yet supported".into());
                }
                BinOp::Shr(_) | BinOp::ShrAssign(_) => {
                    if let Expr::Lit(ExprLit { lit: Lit::Int(li), .. }) = right.as_ref() {
                        let imm: u8 = li.base10_parse().unwrap_or(0);
                        ctx.emit(HlOp::Shr(rd, l, imm));
                        return Ok(rd);
                    }
                    return Err("virtualize: variable shift amounts not yet supported".into());
                }
                BinOp::Eq(_) => HlOp::CmpEq(rd, l, r),
                BinOp::Ne(_) => HlOp::CmpNe(rd, l, r),
                BinOp::Lt(_) => HlOp::CmpLt(rd, l, r),
                BinOp::Gt(_) => HlOp::CmpGt(rd, l, r),
                BinOp::Le(_) => HlOp::CmpLe(rd, l, r),
                BinOp::Ge(_) => HlOp::CmpGe(rd, l, r),
                _ => return Err("virtualize: unsupported binary operator".to_string()),
            };
            ctx.emit(hlop);
            Ok(rd)
        }

        // ─── Unary operations ───
        Expr::Unary(ExprUnary { op, expr, .. }) => {
            let inner = lower_expr(ctx, expr)?;
            let rd = ctx.alloc_reg()?;
            match op {
                UnOp::Not(_) => {
                    // Logical NOT for bools, bitwise NOT for ints
                    // For simplicity: if value != 0 → 0, else → 1
                    // This handles both `!true` and `!false` correctly.
                    // For bitwise NOT on integers, use Not opcode.
                    // We'll use CmpEq(rd, inner, 0) for logical not.
                    let zero = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(zero, 0));
                    ctx.emit(HlOp::CmpEq(rd, inner, zero));
                }
                UnOp::Neg(_) => {
                    ctx.emit(HlOp::Neg(rd, inner));
                }
                _ => return Err("virtualize: unsupported unary op".into()),
            }
            Ok(rd)
        }

        // ─── Assignment ───
        Expr::Assign(ExprAssign { left, right, .. }) => {
            let val = lower_expr(ctx, right)?;
            let target = assign_target(ctx, left)?;
            if val != target {
                ctx.emit(HlOp::Mov(target, val));
            }
            Ok(target)
        }

        // ─── If/else ───
        Expr::If(ExprIf { cond, then_branch, else_branch, .. }) => {
            let cond_reg = lower_expr(ctx, cond)?;
            let else_label = ctx.alloc_label();
            let end_label = ctx.alloc_label();
            let rd = ctx.alloc_reg()?;

            // if cond == 0, jump to else
            ctx.emit(HlOp::JmpIfZeroLabel(cond_reg, else_label));

            // then branch
            let then_result = lower_block_as_expr(ctx, then_branch)?;
            ctx.emit(HlOp::Mov(rd, then_result));
            ctx.emit(HlOp::JmpLabel(end_label));

            // else branch
            ctx.emit(HlOp::Label(else_label));
            if let Some((_, else_expr)) = else_branch {
                let else_result = lower_expr(ctx, else_expr)?;
                ctx.emit(HlOp::Mov(rd, else_result));
            } else {
                ctx.emit(HlOp::LoadConst(rd, 0));
            }

            ctx.emit(HlOp::Label(end_label));
            Ok(rd)
        }

        // ─── While loop ───
        Expr::While(ExprWhile { cond, body, .. }) => {
            let start_label = ctx.alloc_label();
            let end_label = ctx.alloc_label();

            ctx.loop_stack.push((start_label, end_label));

            ctx.emit(HlOp::Label(start_label));
            // Reset temps before each condition evaluation to prevent register exhaustion
            ctx.reset_temps();
            let cond_reg = lower_expr(ctx, cond)?;
            ctx.emit(HlOp::JmpIfZeroLabel(cond_reg, end_label));
            lower_block(ctx, body)?;
            ctx.emit(HlOp::JmpLabel(start_label));
            ctx.emit(HlOp::Label(end_label));

            ctx.loop_stack.pop();

            ctx.reset_temps();
            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }

        // ─── Infinite loop ───
        Expr::Loop(ExprLoop { body, .. }) => {
            let start_label = ctx.alloc_label();
            let end_label = ctx.alloc_label();

            ctx.loop_stack.push((start_label, end_label));

            ctx.emit(HlOp::Label(start_label));
            lower_block(ctx, body)?;
            ctx.emit(HlOp::JmpLabel(start_label));
            ctx.emit(HlOp::Label(end_label));

            ctx.loop_stack.pop();

            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }

        // ─── For loop (desugar: for i in start..end) ───
        Expr::ForLoop(ExprForLoop { pat, expr, body, .. }) => {
            let var_name = pat_to_name(pat)?;

            // Parse the range expression
            match expr.as_ref() {
                Expr::Range(ExprRange { start, end, limits, .. }) => {
                    let counter_reg = ctx.define_var(var_name)?;

                    // Lower start (default 0)
                    if let Some(start_expr) = start {
                        let s = lower_expr(ctx, start_expr)?;
                        ctx.emit(HlOp::Mov(counter_reg, s));
                    } else {
                        ctx.emit(HlOp::LoadConst(counter_reg, 0));
                    }

                    // Lower end bound
                    let end_reg = if let Some(end_expr) = end {
                        lower_expr(ctx, end_expr)?
                    } else {
                        return Err("virtualize: for loop needs end bound".into());
                    };

                    let one_reg = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(one_reg, 1));

                    let start_label = ctx.alloc_label();
                    let end_label = ctx.alloc_label();
                    ctx.loop_stack.push((start_label, end_label));

                    ctx.emit(HlOp::Label(start_label));

                    // Check condition: counter < end (for ..) or counter <= end (for ..=)
                    let cond_reg = ctx.alloc_reg()?;
                    match limits {
                        syn::RangeLimits::HalfOpen(_) => {
                            ctx.emit(HlOp::CmpLt(cond_reg, counter_reg, end_reg));
                        }
                        syn::RangeLimits::Closed(_) => {
                            ctx.emit(HlOp::CmpLe(cond_reg, counter_reg, end_reg));
                        }
                    }
                    ctx.emit(HlOp::JmpIfZeroLabel(cond_reg, end_label));

                    // Loop body
                    lower_block(ctx, body)?;

                    // Increment counter
                    ctx.emit(HlOp::Add(counter_reg, counter_reg, one_reg));
                    ctx.emit(HlOp::JmpLabel(start_label));
                    ctx.emit(HlOp::Label(end_label));

                    ctx.loop_stack.pop();

                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(rd, 0));
                    Ok(rd)
                }
                _ => Err("virtualize: for loop only supports range expressions".into()),
            }
        }

        // ─── Break ───
        Expr::Break(ExprBreak { .. }) => {
            if let Some((_, end_label)) = ctx.loop_stack.last() {
                let end = *end_label;
                ctx.emit(HlOp::JmpLabel(end));
            } else {
                return Err("virtualize: break outside of loop".into());
            }
            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }

        // ─── Continue ───
        Expr::Continue(ExprContinue { .. }) => {
            if let Some((start_label, _)) = ctx.loop_stack.last() {
                let start = *start_label;
                ctx.emit(HlOp::JmpLabel(start));
            } else {
                return Err("virtualize: continue outside of loop".into());
            }
            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }

        // ─── Return ───
        Expr::Return(ExprReturn { expr, .. }) => {
            if let Some(ret_expr) = expr {
                let val = lower_expr(ctx, ret_expr)?;
                ctx.emit(HlOp::Mov(0, val));
            }
            ctx.emit(HlOp::Halt);
            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }

        // ─── Method calls ───
        Expr::MethodCall(ExprMethodCall { receiver, method, args, .. }) => {
            let method_name = method.to_string();
            let recv = lower_expr(ctx, receiver)?;

            match method_name.as_str() {
                "wrapping_add" => {
                    if args.len() != 1 {
                        return Err("wrapping_add: expected 1 arg".into());
                    }
                    let arg = lower_expr(ctx, &args[0])?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::Add(rd, recv, arg));
                    Ok(rd)
                }
                "wrapping_sub" => {
                    if args.len() != 1 {
                        return Err("wrapping_sub: expected 1 arg".into());
                    }
                    let arg = lower_expr(ctx, &args[0])?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::Sub(rd, recv, arg));
                    Ok(rd)
                }
                "wrapping_mul" => {
                    if args.len() != 1 {
                        return Err("wrapping_mul: expected 1 arg".into());
                    }
                    let arg = lower_expr(ctx, &args[0])?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::Mul(rd, recv, arg));
                    Ok(rd)
                }
                "wrapping_div" => {
                    if args.len() != 1 {
                        return Err("wrapping_div: expected 1 arg".into());
                    }
                    let arg = lower_expr(ctx, &args[0])?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::Div(rd, recv, arg));
                    Ok(rd)
                }
                "wrapping_rem" => {
                    if args.len() != 1 {
                        return Err("wrapping_rem: expected 1 arg".into());
                    }
                    let arg = lower_expr(ctx, &args[0])?;
                    let rd = ctx.alloc_reg()?;
                    ctx.emit(HlOp::Mod(rd, recv, arg));
                    Ok(rd)
                }
                _ => {
                    Err(format!("virtualize: unsupported method `{method_name}`"))
                }
            }
        }

        // ─── Type cast ───
        Expr::Cast(ExprCast { expr, ty, .. }) => {
            let val = lower_expr(ctx, expr)?;
            let rd = ctx.alloc_reg()?;

            // Apply type width mask
            let mask = type_mask(ty);
            if mask == u64::MAX {
                ctx.emit(HlOp::Mov(rd, val));
            } else {
                let mask_reg = ctx.alloc_reg()?;
                ctx.emit(HlOp::LoadConst(mask_reg, mask));
                ctx.emit(HlOp::And(rd, val, mask_reg));
            }
            Ok(rd)
        }

        // ─── Match (desugar to if/else chain) ───
        Expr::Match(ExprMatch { expr, arms, .. }) => {
            let scrutinee = lower_expr(ctx, expr)?;
            let rd = ctx.alloc_reg()?;
            let end_label = ctx.alloc_label();

            for arm in arms {
                let arm_label = ctx.alloc_label();

                // Check if this is a wildcard pattern
                let is_wildcard = matches!(&arm.pat, Pat::Wild(_));

                if is_wildcard {
                    // Default arm: always execute
                    let body = lower_expr(ctx, &arm.body)?;
                    ctx.emit(HlOp::Mov(rd, body));
                    ctx.emit(HlOp::JmpLabel(end_label));
                } else {
                    // Try to extract literal value from pattern
                    let pat_val = pat_to_value(&arm.pat)?;
                    let pat_reg = ctx.alloc_reg()?;
                    ctx.emit(HlOp::LoadConst(pat_reg, pat_val));
                    let cmp_reg = ctx.alloc_reg()?;
                    ctx.emit(HlOp::CmpEq(cmp_reg, scrutinee, pat_reg));
                    ctx.emit(HlOp::JmpIfZeroLabel(cmp_reg, arm_label));

                    // This arm matches
                    let body = lower_expr(ctx, &arm.body)?;
                    ctx.emit(HlOp::Mov(rd, body));
                    ctx.emit(HlOp::JmpLabel(end_label));

                    ctx.emit(HlOp::Label(arm_label));
                }
            }

            // Fallthrough (no match): result is 0
            ctx.emit(HlOp::LoadConst(rd, 0));
            ctx.emit(HlOp::Label(end_label));
            Ok(rd)
        }

        // ─── Function call ───
        Expr::Call(call) => {
            // Extract function path
            let func_path = if let Expr::Path(path_expr) = &*call.func {
                path_expr.path.segments.iter()
                    .map(|seg| seg.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
            } else {
                return Err("virtualize: only direct function calls supported (not closures/fn pointers)".into());
            };

            // Register this function in the native function table
            let arg_count = call.args.len();
            let func_id = if let Some(pos) = ctx.native_funcs.iter().position(|(f, _)| f == &func_path) {
                pos as u16
            } else {
                let id = ctx.native_funcs.len() as u16;
                ctx.native_funcs.push((func_path, arg_count));
                id
            };

            // Evaluate arguments and store in R0, R1, R2, ...
            if arg_count > NUM_REGS {
                return Err(format!("virtualize: too many arguments ({} > {})", arg_count, NUM_REGS));
            }

            for (i, arg) in call.args.iter().enumerate() {
                let arg_reg = lower_expr(ctx, arg)?;
                // Move arg result to Ri if not already there
                if arg_reg != i as u8 {
                    ctx.emit(HlOp::Mov(i as u8, arg_reg));
                }
            }

            // Allocate result register
            let ret_reg = ctx.alloc_reg()?;

            // Emit VmCall: calls native function with args from R0..R(arg_count-1)
            ctx.emit(HlOp::VmCall(func_id, arg_count as u8, ret_reg));

            Ok(ret_reg)
        }

        // ─── Tuple / grouping (we just skip for now) ───
        Expr::Tuple(t) => {
            if t.elems.len() == 1 {
                lower_expr(ctx, &t.elems[0])
            } else if t.elems.is_empty() {
                // Unit type ()
                let rd = ctx.alloc_reg()?;
                ctx.emit(HlOp::LoadConst(rd, 0));
                Ok(rd)
            } else {
                Err("virtualize: tuples not supported".into())
            }
        }

        _ => {
            Err(format!(
                "virtualize: unsupported expression type: {}",
                expr_type_name(expr)
            ))
        }
    }
}

/// Lower a block and return the last expression's register (or 0 if no trailing expr).
fn lower_block_as_expr(ctx: &mut LowerCtx, block: &Block) -> Result<u8, String> {
    if block.stmts.is_empty() {
        let rd = ctx.alloc_reg()?;
        ctx.emit(HlOp::LoadConst(rd, 0));
        return Ok(rd);
    }

    for stmt in &block.stmts[..block.stmts.len() - 1] {
        lower_stmt(ctx, stmt)?;
    }

    match &block.stmts[block.stmts.len() - 1] {
        Stmt::Expr(expr, None) => {
            // Reset temps before the trailing expression — lower_stmt does
            // this automatically, but we bypass it for trailing expressions.
            ctx.reset_temps();
            lower_expr(ctx, expr)
        }
        stmt => {
            lower_stmt(ctx, stmt)?;
            let rd = ctx.alloc_reg()?;
            ctx.emit(HlOp::LoadConst(rd, 0));
            Ok(rd)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn pat_to_name(pat: &Pat) -> Result<String, String> {
    match pat {
        Pat::Ident(PatIdent { ident, .. }) => Ok(ident.to_string()),
        Pat::Type(pt) => pat_to_name(&pt.pat),
        Pat::Wild(_) => Ok("_".into()),
        _ => Err(format!("virtualize: unsupported pattern: {:?}", quote!(#pat).to_string())),
    }
}

fn assign_target(ctx: &LowerCtx, expr: &Expr) -> Result<u8, String> {
    match expr {
        Expr::Path(ExprPath { path, .. }) => {
            if let Some(ident) = path.get_ident() {
                let name = ident.to_string();
                ctx.find_var(&name)
                    .ok_or_else(|| format!("virtualize: unknown variable `{name}` in assignment"))
            } else {
                Err("virtualize: complex path in assignment target".into())
            }
        }
        _ => Err("virtualize: unsupported assignment target".into()),
    }
}

fn type_mask(ty: &Type) -> u64 {
    match ty {
        Type::Path(TypePath { path, .. }) => {
            if let Some(ident) = path.get_ident() {
                match ident.to_string().as_str() {
                    "u8" | "i8" => 0xFF,
                    "u16" | "i16" => 0xFFFF,
                    "u32" | "i32" => 0xFFFF_FFFF,
                    "u64" | "i64" | "usize" | "isize" => u64::MAX,
                    "bool" => 1,
                    _ => u64::MAX,
                }
            } else {
                u64::MAX
            }
        }
        _ => u64::MAX,
    }
}

fn pat_to_value(pat: &Pat) -> Result<u64, String> {
    match pat {
        Pat::Lit(pl) => {
            match &pl.lit {
                Lit::Int(li) => li.base10_parse().map_err(|e| format!("pat literal: {e}")),
                Lit::Bool(lb) => Ok(if lb.value { 1 } else { 0 }),
                _ => Err("virtualize: unsupported pattern literal".into()),
            }
        }
        _ => Err("virtualize: unsupported pattern type in match arm".into()),
    }
}

fn expr_type_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::Array(_) => "array",
        Expr::Assign(_) => "assign",
        Expr::Async(_) => "async",
        Expr::Await(_) => "await",
        Expr::Binary(_) => "binary",
        Expr::Block(_) => "block",
        Expr::Break(_) => "break",
        Expr::Call(_) => "call",
        Expr::Cast(_) => "cast",
        Expr::Closure(_) => "closure",
        Expr::Continue(_) => "continue",
        Expr::Field(_) => "field",
        Expr::ForLoop(_) => "for_loop",
        Expr::Group(_) => "group",
        Expr::If(_) => "if",
        Expr::Index(_) => "index",
        Expr::Let(_) => "let",
        Expr::Lit(_) => "lit",
        Expr::Loop(_) => "loop",
        Expr::Macro(_) => "macro",
        Expr::Match(_) => "match",
        Expr::MethodCall(_) => "method_call",
        Expr::Paren(_) => "paren",
        Expr::Path(_) => "path",
        Expr::Range(_) => "range",
        Expr::Reference(_) => "reference",
        Expr::Repeat(_) => "repeat",
        Expr::Return(_) => "return",
        Expr::Struct(_) => "struct",
        Expr::Try(_) => "try",
        Expr::TryBlock(_) => "try_block",
        Expr::Tuple(_) => "tuple",
        Expr::Unary(_) => "unary",
        Expr::Unsafe(_) => "unsafe",
        Expr::While(_) => "while",
        Expr::Yield(_) => "yield",
        _ => "unknown",
    }
}
