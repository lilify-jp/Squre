//! Compile high-level operations to VM bytecode.
//!
//! This module converts a sequence of abstract operations into
//! VM instructions, applying MBA transformations and EDF encoding.
//!
//! Supports 2-pass compilation: Pass 1 records label positions and emits
//! placeholder offsets. Pass 2 resolves label references to concrete byte offsets.

use rand::SeedableRng;
use rand::Rng;
use std::collections::HashMap;
use super::opcode::*;
use crate::edf::affine::EdfParam;
use crate::mba::constant::synthesize_constant;
use crate::junk::semantic::{inject_junk, JunkConfig};

/// A high-level operation to be compiled to VM bytecode.
#[derive(Debug, Clone)]
pub enum HlOp {
    // ─── Constants & Movement ───
    /// Load an immediate value into a register
    LoadConst(u8, u64),
    /// Move Rd = Rs
    Mov(u8, u8),

    // ─── Core Arithmetic ───
    /// Rd = Rs1 + Rs2
    Add(u8, u8, u8),
    /// Rd = Rs1 - Rs2
    Sub(u8, u8, u8),
    /// Rd = Rs1 * Rs2
    Mul(u8, u8, u8),
    /// Rd = Rs1 / Rs2 (unsigned, 0 on div-by-zero)
    Div(u8, u8, u8),
    /// Rd = Rs1 % Rs2 (unsigned, 0 on div-by-zero)
    Mod(u8, u8, u8),

    // ─── Bitwise ───
    /// Rd = Rs1 ^ Rs2
    Xor(u8, u8, u8),
    /// Rd = Rs1 & Rs2
    And(u8, u8, u8),
    /// Rd = Rs1 | Rs2
    Or(u8, u8, u8),
    /// Rd = !Rs (bitwise NOT)
    Not(u8, u8),
    /// Rd = -Rs (two's complement negation)
    Neg(u8, u8),

    // ─── Shifts & Rotates ───
    /// Rd = Rs << imm (logical left shift)
    Shl(u8, u8, u8),
    /// Rd = Rs >> imm (logical right shift)
    Shr(u8, u8, u8),
    /// Rd = Rs.rotate_left(imm)
    Rol(u8, u8, u8),
    /// Rd = Rs.rotate_right(imm)
    Ror(u8, u8, u8),

    // ─── Comparison ───
    /// Rd = (Rs1 == Rs2) ? 1 : 0
    CmpEq(u8, u8, u8),
    /// Rd = (Rs1 != Rs2) ? 1 : 0
    CmpNe(u8, u8, u8),
    /// Rd = (Rs1 < Rs2) unsigned ? 1 : 0
    CmpLt(u8, u8, u8),
    /// Rd = (Rs1 > Rs2) unsigned ? 1 : 0
    CmpGt(u8, u8, u8),
    /// Rd = (Rs1 <= Rs2) unsigned ? 1 : 0
    CmpLe(u8, u8, u8),
    /// Rd = (Rs1 >= Rs2) unsigned ? 1 : 0
    CmpGe(u8, u8, u8),

    // ─── Memory ───
    /// Rd = Memory[Rs] (load from VM memory slot)
    Load(u8, u8),
    /// Memory[Rs1] = Rs2 (store to VM memory slot)
    Store(u8, u8),
    /// Push Rs onto stack
    Push(u8),
    /// Pop into Rd
    Pop(u8),

    // ─── Control Flow (concrete offsets) ───
    /// Unconditional jump to byte offset
    Jmp(i32),
    /// Jump if Rs == 0
    JmpIfZero(u8, i32),
    /// Jump if Rs != 0
    JmpIfNotZero(u8, i32),
    /// Call subroutine at offset (push return addr)
    Call(i32),
    /// Return from subroutine
    Ret,

    // ─── Control Flow (label-based, resolved in pass 2) ───
    /// Define a label at current position
    Label(u32),
    /// Jump to label
    JmpLabel(u32),
    /// Jump to label if Rs == 0
    JmpIfZeroLabel(u8, u32),
    /// Jump to label if Rs != 0
    JmpIfNotZeroLabel(u8, u32),
    /// Call subroutine at label
    CallLabel(u32),

    // ─── Special ───
    /// Halt VM execution
    Halt,
    /// Call native function by index: VmCall(func_id, arg_count, ret_reg)
    VmCall(u16, u8, u8),
    /// Execute nested VM program: VmExecNested(prog_id, arg_count, ret_reg)
    VmExecNested(u16, u8, u8),
}

/// Result of compilation: bytecode + metadata.
#[derive(Debug, Clone)]
pub struct CompiledProgram {
    /// Raw bytecode (encoded using OpcodeMap)
    pub bytecode: Vec<u8>,
    /// The opcode map used for encoding
    pub opcode_map: OpcodeMap,
    /// EDF parameters for each register (for the VM runtime to use)
    pub edf_params: Vec<EdfParam>,
    /// Number of registers used
    pub num_regs_used: usize,
}

/// Emit a 3-register instruction.
fn emit_rrr(instructions: &mut Vec<Instruction>, op: Op, rd: u8, rs1: u8, rs2: u8) {
    instructions.push(Instruction {
        op,
        operands: Operands::RegRegReg(rd, rs1, rs2),
    });
}

/// Emit a 2-register + immediate instruction (shifts/rotates).
fn emit_rri(instructions: &mut Vec<Instruction>, op: Op, rd: u8, rs: u8, imm: u8) {
    instructions.push(Instruction {
        op,
        operands: Operands::RegRegImm8(rd, rs, imm),
    });
}

/// Track the max register used.
fn track3(max_reg: &mut u8, a: u8, b: u8, c: u8) {
    *max_reg = (*max_reg).max(a).max(b).max(c);
}

fn track2(max_reg: &mut u8, a: u8, b: u8) {
    *max_reg = (*max_reg).max(a).max(b);
}

fn track1(max_reg: &mut u8, a: u8) {
    *max_reg = (*max_reg).max(a);
}

/// Internal representation during 2-pass compilation.
/// Label-based jumps use a placeholder offset that gets resolved in pass 2.
#[derive(Debug, Clone)]
struct LabelRef {
    /// Index into the instruction vector
    inst_idx: usize,
    /// Target label ID
    label_id: u32,
    /// Kind of reference (for offset computation)
    kind: LabelRefKind,
}

#[derive(Debug, Clone, Copy)]
enum LabelRefKind {
    Jmp,
    JmpIfZero,
    JmpIfNotZero,
    Call,
}

/// Inject junk instructions into an instruction stream with position tracking.
///
/// Unlike `inject_junk` from the junk module, this version returns a mapping
/// from old instruction indices to new indices. This allows label positions
/// and label references to be updated after junk injection, enabling junk
/// in label-based (virtualized) programs.
fn inject_junk_tracked(
    instructions: &[Instruction],
    junk_ratio: usize,
    junk_regs: &[u8],
    rng: &mut impl Rng,
) -> (Vec<Instruction>, Vec<usize>) {
    let mut result = Vec::new();
    let mut mapping = Vec::with_capacity(instructions.len());

    for inst in instructions {
        let is_halt = inst.op == Op::Halt;

        // Generate junk BEFORE the real instruction
        if !is_halt && junk_regs.len() >= 2 {
            let num_before = rng.gen_range(1..=junk_ratio);
            for _ in 0..num_before {
                let r1 = junk_regs[rng.gen_range(0..junk_regs.len())];
                let r2 = junk_regs[rng.gen_range(0..junk_regs.len())];
                let pattern = rng.gen_range(0..4u32);
                match pattern {
                    0 => {
                        // XOR with constant (self-inverse: before + after cancel)
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, c) });
                        result.push(Instruction { op: Op::Xor, operands: Operands::RegRegReg(r1, r1, r2) });
                    }
                    1 => {
                        // Dead store: load random into junk reg
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r1, c) });
                    }
                    2 => {
                        // Arithmetic noise: add two junk regs
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, c) });
                        result.push(Instruction { op: Op::Add, operands: Operands::RegRegReg(r1, r1, r2) });
                    }
                    _ => {
                        // NOT (self-inverse when paired)
                        result.push(Instruction { op: Op::Not, operands: Operands::Reg(r1) });
                    }
                }
            }
        }

        // Record the NEW position of this original instruction
        mapping.push(result.len());
        result.push(inst.clone());

        // Generate junk AFTER the real instruction (cancel operations)
        if !is_halt && junk_regs.len() >= 2 {
            let num_after = rng.gen_range(1..=junk_ratio);
            for _ in 0..num_after {
                let r1 = junk_regs[rng.gen_range(0..junk_regs.len())];
                let r2 = junk_regs[rng.gen_range(0..junk_regs.len())];
                let pattern = rng.gen_range(0..4u32);
                match pattern {
                    0 => {
                        // XOR cancel (matches before pattern 0)
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, c) });
                        result.push(Instruction { op: Op::Xor, operands: Operands::RegRegReg(r1, r1, r2) });
                    }
                    1 => {
                        // Sub noise
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, c) });
                        result.push(Instruction { op: Op::Sub, operands: Operands::RegRegReg(r1, r1, r2) });
                    }
                    2 => {
                        // Dead store
                        let c: u64 = rng.gen();
                        result.push(Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r1, c) });
                    }
                    _ => {
                        // NOT cancel
                        result.push(Instruction { op: Op::Not, operands: Operands::Reg(r1) });
                    }
                }
            }
        }
    }

    (result, mapping)
}

/// Compile a sequence of high-level operations into VM bytecode.
pub fn compile(
    ops: &[HlOp],
    seed: u64,
    use_edf: bool,
) -> CompiledProgram {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let opcode_map = OpcodeMap::from_rng(&mut rng);

    // Generate EDF parameters for each register
    let edf_params: Vec<EdfParam> = (0..NUM_REGS as u8)
        .map(|_| {
            if use_edf {
                EdfParam::random(&mut rng)
            } else {
                EdfParam::identity()
            }
        })
        .collect();

    let mut instructions: Vec<Instruction> = Vec::new();
    let mut max_reg: u8 = 0;

    // Pass 1: label positions (instruction index) and label references
    let mut label_positions: HashMap<u32, usize> = HashMap::new();
    let mut label_refs: Vec<LabelRef> = Vec::new();

    for op in ops {
        match op {
            HlOp::LoadConst(rd, val) => {
                track1(&mut max_reg, *rd);
                let encoded_val = if use_edf {
                    edf_params[*rd as usize].encode(*val)
                } else {
                    *val
                };
                let obfuscated = synthesize_constant(encoded_val, 1, &mut rng);
                let final_val = obfuscated.eval(&[]);
                instructions.push(Instruction {
                    op: Op::LoadImm,
                    operands: Operands::RegImm64(*rd, final_val),
                });
            }
            HlOp::Mov(rd, rs) => {
                track2(&mut max_reg, *rd, *rs);
                instructions.push(Instruction {
                    op: Op::Mov,
                    operands: Operands::RegReg(*rd, *rs),
                });
            }

            // ─── Core Arithmetic ───
            HlOp::Add(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Add, *rd, *rs1, *rs2);
            }
            HlOp::Sub(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Sub, *rd, *rs1, *rs2);
            }
            HlOp::Mul(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Mul, *rd, *rs1, *rs2);
            }
            HlOp::Div(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Div, *rd, *rs1, *rs2);
            }
            HlOp::Mod(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Mod, *rd, *rs1, *rs2);
            }

            // ─── Bitwise ───
            HlOp::Xor(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Xor, *rd, *rs1, *rs2);
            }
            HlOp::And(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::And, *rd, *rs1, *rs2);
            }
            HlOp::Or(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::Or, *rd, *rs1, *rs2);
            }
            HlOp::Not(rd, rs) => {
                track2(&mut max_reg, *rd, *rs);
                // Not uses single-reg operand form: op + reg
                // But our Op::Not reads 1 register, writes back to same.
                // We need decode rs, apply !x, encode to rd.
                // Current runtime Not reads 1 reg (r), does in-place.
                // For rd != rs, we Mov first then Not.
                if *rd != *rs {
                    instructions.push(Instruction {
                        op: Op::Mov,
                        operands: Operands::RegReg(*rd, *rs),
                    });
                }
                instructions.push(Instruction {
                    op: Op::Not,
                    operands: Operands::Reg(*rd),
                });
            }
            HlOp::Neg(rd, rs) => {
                track2(&mut max_reg, *rd, *rs);
                if *rd != *rs {
                    instructions.push(Instruction {
                        op: Op::Mov,
                        operands: Operands::RegReg(*rd, *rs),
                    });
                }
                instructions.push(Instruction {
                    op: Op::Neg,
                    operands: Operands::Reg(*rd),
                });
            }

            // ─── Shifts & Rotates ───
            HlOp::Shl(rd, rs, imm) => {
                track2(&mut max_reg, *rd, *rs);
                emit_rri(&mut instructions, Op::Shl, *rd, *rs, *imm);
            }
            HlOp::Shr(rd, rs, imm) => {
                track2(&mut max_reg, *rd, *rs);
                emit_rri(&mut instructions, Op::Shr, *rd, *rs, *imm);
            }
            HlOp::Rol(rd, rs, imm) => {
                track2(&mut max_reg, *rd, *rs);
                emit_rri(&mut instructions, Op::Rol, *rd, *rs, *imm);
            }
            HlOp::Ror(rd, rs, imm) => {
                track2(&mut max_reg, *rd, *rs);
                emit_rri(&mut instructions, Op::Ror, *rd, *rs, *imm);
            }

            // ─── Comparison ───
            HlOp::CmpEq(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpEq, *rd, *rs1, *rs2);
            }
            HlOp::CmpNe(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpNe, *rd, *rs1, *rs2);
            }
            HlOp::CmpLt(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpLt, *rd, *rs1, *rs2);
            }
            HlOp::CmpGt(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpGt, *rd, *rs1, *rs2);
            }
            HlOp::CmpLe(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpLe, *rd, *rs1, *rs2);
            }
            HlOp::CmpGe(rd, rs1, rs2) => {
                track3(&mut max_reg, *rd, *rs1, *rs2);
                emit_rrr(&mut instructions, Op::CmpGe, *rd, *rs1, *rs2);
            }

            // ─── Memory ───
            HlOp::Load(rd, rs) => {
                track2(&mut max_reg, *rd, *rs);
                instructions.push(Instruction {
                    op: Op::Load,
                    operands: Operands::RegReg(*rd, *rs),
                });
            }
            HlOp::Store(rs_addr, rs_val) => {
                track2(&mut max_reg, *rs_addr, *rs_val);
                instructions.push(Instruction {
                    op: Op::Store,
                    operands: Operands::RegReg(*rs_addr, *rs_val),
                });
            }
            HlOp::Push(rs) => {
                track1(&mut max_reg, *rs);
                instructions.push(Instruction {
                    op: Op::Push,
                    operands: Operands::Reg(*rs),
                });
            }
            HlOp::Pop(rd) => {
                track1(&mut max_reg, *rd);
                instructions.push(Instruction {
                    op: Op::Pop,
                    operands: Operands::Reg(*rd),
                });
            }

            // ─── Control Flow (concrete offsets) ───
            HlOp::Jmp(offset) => {
                instructions.push(Instruction {
                    op: Op::Jmp,
                    operands: Operands::Branch(*offset),
                });
            }
            HlOp::JmpIfZero(rs, offset) => {
                track1(&mut max_reg, *rs);
                instructions.push(Instruction {
                    op: Op::JmpIfZero,
                    operands: Operands::BranchReg(*rs, *offset),
                });
            }
            HlOp::JmpIfNotZero(rs, offset) => {
                track1(&mut max_reg, *rs);
                instructions.push(Instruction {
                    op: Op::JmpIfNotZero,
                    operands: Operands::BranchReg(*rs, *offset),
                });
            }
            HlOp::Call(offset) => {
                instructions.push(Instruction {
                    op: Op::Call,
                    operands: Operands::Branch(*offset),
                });
            }
            HlOp::Ret => {
                instructions.push(Instruction {
                    op: Op::Ret,
                    operands: Operands::None,
                });
            }

            // ─── Control Flow (label-based) ───
            HlOp::Label(id) => {
                label_positions.insert(*id, instructions.len());
                // Labels don't emit any instruction
            }
            HlOp::JmpLabel(id) => {
                let idx = instructions.len();
                label_refs.push(LabelRef {
                    inst_idx: idx,
                    label_id: *id,
                    kind: LabelRefKind::Jmp,
                });
                instructions.push(Instruction {
                    op: Op::Jmp,
                    operands: Operands::Branch(0), // placeholder
                });
            }
            HlOp::JmpIfZeroLabel(rs, id) => {
                track1(&mut max_reg, *rs);
                let idx = instructions.len();
                label_refs.push(LabelRef {
                    inst_idx: idx,
                    label_id: *id,
                    kind: LabelRefKind::JmpIfZero,
                });
                instructions.push(Instruction {
                    op: Op::JmpIfZero,
                    operands: Operands::BranchReg(*rs, 0), // placeholder
                });
            }
            HlOp::JmpIfNotZeroLabel(rs, id) => {
                track1(&mut max_reg, *rs);
                let idx = instructions.len();
                label_refs.push(LabelRef {
                    inst_idx: idx,
                    label_id: *id,
                    kind: LabelRefKind::JmpIfNotZero,
                });
                instructions.push(Instruction {
                    op: Op::JmpIfNotZero,
                    operands: Operands::BranchReg(*rs, 0), // placeholder
                });
            }
            HlOp::CallLabel(id) => {
                let idx = instructions.len();
                label_refs.push(LabelRef {
                    inst_idx: idx,
                    label_id: *id,
                    kind: LabelRefKind::Call,
                });
                instructions.push(Instruction {
                    op: Op::Call,
                    operands: Operands::Branch(0), // placeholder
                });
            }

            // ─── Special ───
            HlOp::Halt => {
                instructions.push(Instruction {
                    op: Op::Halt,
                    operands: Operands::None,
                });
            }
            HlOp::VmCall(func_id, arg_count, ret_reg) => {
                track1(&mut max_reg, *ret_reg);
                instructions.push(Instruction {
                    op: Op::VmCall,
                    operands: Operands::VmCallArgs(*func_id, *arg_count, *ret_reg),
                });
            }
            HlOp::VmExecNested(prog_id, arg_count, ret_reg) => {
                track1(&mut max_reg, *ret_reg);
                instructions.push(Instruction {
                    op: Op::VmExecNested,
                    operands: Operands::VmExecNestedArgs(*prog_id, *arg_count, *ret_reg),
                });
            }
        }
    }

    // Always end with Halt if not already present
    if instructions.last().map(|i| i.op) != Some(Op::Halt) {
        instructions.push(Instruction {
            op: Op::Halt,
            operands: Operands::None,
        });
    }

    // ═══ Semantic Junk injection ═══
    // Junk uses registers R10-R15 which don't interfere with real computation.
    // For label-based programs, we use tracked injection that returns an
    // old-to-new index mapping, allowing label positions and references to be
    // updated after junk insertion. This enables junk for ALL programs,
    // including #[virtualize] functions with control flow.
    let has_labels = !label_refs.is_empty();

    let instructions = if has_labels {
        // Tracked injection: inject junk and remap label positions/refs
        let junk_regs: &[u8] = &[10, 11, 12, 13, 14, 15];
        let junk_ratio = rng.gen_range(3..=7);
        let (new_instructions, old_to_new) = inject_junk_tracked(
            &instructions, junk_ratio, junk_regs, &mut rng,
        );
        // Update label positions with new instruction indices
        for (_id, idx) in label_positions.iter_mut() {
            if *idx < old_to_new.len() {
                *idx = old_to_new[*idx];
            } else {
                *idx = new_instructions.len();
            }
        }
        // Update label references with new instruction indices
        for lref in label_refs.iter_mut() {
            if lref.inst_idx < old_to_new.len() {
                lref.inst_idx = old_to_new[lref.inst_idx];
            }
        }
        new_instructions
    } else {
        let junk_config = JunkConfig {
            junk_ratio: rng.gen_range(3..=7),
            ..JunkConfig::default()
        };
        inject_junk(&instructions, &junk_config, &mut rng)
    };

    // ═══ Pass 2: Label Resolution ═══
    // Compute byte offsets for each instruction, then resolve label references.
    if has_labels {
        // Compute cumulative byte offset for each instruction index
        let mut byte_offsets: Vec<usize> = Vec::with_capacity(instructions.len() + 1);
        let mut offset = 0usize;
        for inst in &instructions {
            byte_offsets.push(offset);
            offset += inst.encoded_len();
        }
        byte_offsets.push(offset); // sentinel for end

        // Build label → byte offset map
        let mut label_byte_offsets: HashMap<u32, usize> = HashMap::new();
        for (label_id, &inst_idx) in &label_positions {
            // The label's byte position is where the instruction at inst_idx starts.
            // If inst_idx == instructions.len(), it points past the end.
            let byte_off = if inst_idx < byte_offsets.len() {
                byte_offsets[inst_idx]
            } else {
                *byte_offsets.last().unwrap_or(&0)
            };
            label_byte_offsets.insert(*label_id, byte_off);
        }

        // Resolve label references by patching placeholder offsets
        let mut instructions = instructions;
        for lref in &label_refs {
            let target_byte = label_byte_offsets.get(&lref.label_id)
                .unwrap_or_else(|| panic!("VM compiler: undefined label {}", lref.label_id));

            let inst = &instructions[lref.inst_idx];
            // The offset is relative: target_byte - (inst_byte + inst.encoded_len())
            let inst_end = byte_offsets[lref.inst_idx] + inst.encoded_len();
            let rel_offset = (*target_byte as i64) - (inst_end as i64);
            let rel_offset = rel_offset as i32;

            match lref.kind {
                LabelRefKind::Jmp => {
                    instructions[lref.inst_idx].operands = Operands::Branch(rel_offset);
                }
                LabelRefKind::JmpIfZero => {
                    if let Operands::BranchReg(rs, _) = instructions[lref.inst_idx].operands {
                        instructions[lref.inst_idx].operands = Operands::BranchReg(rs, rel_offset);
                    }
                }
                LabelRefKind::JmpIfNotZero => {
                    if let Operands::BranchReg(rs, _) = instructions[lref.inst_idx].operands {
                        instructions[lref.inst_idx].operands = Operands::BranchReg(rs, rel_offset);
                    }
                }
                LabelRefKind::Call => {
                    instructions[lref.inst_idx].operands = Operands::Branch(rel_offset);
                }
            }
        }

        // Encode instructions to bytecode (junk already injected before label resolution)
        let mut bytecode = Vec::new();
        for inst in &instructions {
            bytecode.extend(inst.encode(&opcode_map));
        }

        return CompiledProgram {
            bytecode,
            opcode_map,
            edf_params,
            num_regs_used: (max_reg as usize) + 1,
        };
    }

    // Encode instructions to bytecode (non-label path)
    let mut bytecode = Vec::new();
    for inst in &instructions {
        bytecode.extend(inst.encode(&opcode_map));
    }

    CompiledProgram {
        bytecode,
        opcode_map,
        edf_params,
        num_regs_used: (max_reg as usize) + 1,
    }
}

/// Compile with label support: resolves labels first, then encodes.
/// This is a convenience wrapper that handles the 2-pass correctly for
/// programs that use Label/JmpLabel etc.
pub fn compile_with_labels(
    ops: &[HlOp],
    seed: u64,
    use_edf: bool,
) -> CompiledProgram {
    // The main compile() already handles labels via 2-pass.
    compile(ops, seed, use_edf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_add() {
        let ops = vec![
            HlOp::LoadConst(0, 5),
            HlOp::LoadConst(1, 3),
            HlOp::Add(2, 0, 1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
        assert_eq!(prog.num_regs_used, 3);
    }

    #[test]
    fn test_compile_with_edf() {
        let ops = vec![
            HlOp::LoadConst(0, 100),
            HlOp::LoadConst(1, 200),
            HlOp::Add(2, 0, 1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, true);
        assert!(!prog.bytecode.is_empty());
        assert_ne!(prog.edf_params[0], EdfParam::identity());
    }

    #[test]
    fn test_compile_different_seeds_different_bytecode() {
        let ops = vec![
            HlOp::LoadConst(0, 42),
            HlOp::Halt,
        ];
        let p1 = compile(&ops, 100, false);
        let p2 = compile(&ops, 200, false);
        assert_ne!(p1.bytecode, p2.bytecode);
    }

    #[test]
    fn test_compile_div_mod() {
        let ops = vec![
            HlOp::LoadConst(0, 100),
            HlOp::LoadConst(1, 7),
            HlOp::Div(2, 0, 1),
            HlOp::Mod(3, 0, 1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_shifts() {
        let ops = vec![
            HlOp::LoadConst(0, 0xFF),
            HlOp::Shl(1, 0, 4),
            HlOp::Shr(2, 0, 2),
            HlOp::Rol(3, 0, 8),
            HlOp::Ror(4, 0, 8),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_comparisons() {
        let ops = vec![
            HlOp::LoadConst(0, 10),
            HlOp::LoadConst(1, 20),
            HlOp::CmpLt(2, 0, 1),
            HlOp::CmpGt(3, 0, 1),
            HlOp::CmpLe(4, 0, 1),
            HlOp::CmpGe(5, 0, 1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_labels_simple_jmp() {
        // Jump over a LoadConst
        let ops = vec![
            HlOp::LoadConst(0, 42),
            HlOp::JmpLabel(1),          // jump to label 1
            HlOp::LoadConst(0, 99),     // should be skipped
            HlOp::Label(1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_labels_conditional() {
        // if R0 == 0: goto label_else
        let ops = vec![
            HlOp::LoadConst(0, 0),
            HlOp::JmpIfZeroLabel(0, 10),  // if R0 == 0 goto label 10
            HlOp::LoadConst(1, 111),       // else branch
            HlOp::JmpLabel(20),            // goto end
            HlOp::Label(10),
            HlOp::LoadConst(1, 222),       // then branch
            HlOp::Label(20),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_memory_ops() {
        let ops = vec![
            HlOp::LoadConst(0, 5),    // address
            HlOp::LoadConst(1, 42),   // value
            HlOp::Store(0, 1),        // mem[5] = 42
            HlOp::Load(2, 0),         // R2 = mem[5]
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_stack_ops() {
        let ops = vec![
            HlOp::LoadConst(0, 42),
            HlOp::Push(0),
            HlOp::Pop(1),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }

    #[test]
    fn test_compile_not_neg() {
        let ops = vec![
            HlOp::LoadConst(0, 42),
            HlOp::Not(1, 0),
            HlOp::Neg(2, 0),
            HlOp::Halt,
        ];
        let prog = compile(&ops, 42, false);
        assert!(!prog.bytecode.is_empty());
    }
}
