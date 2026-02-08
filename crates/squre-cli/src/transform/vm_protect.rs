//! CLI VM Protection - converts x86-64 code to VM bytecode
//!
//! This module provides VMProtect-style protection for arbitrary PE files:
//! 1. Disassemble x86-64 instructions from .text section
//! 2. Convert to SQURE VM bytecode (with CEWE-randomized opcodes)
//! 3. Replace original code with VM interpreter stub
//! 4. Embed bytecode in .sqvm section
//!
//! Unlike compile-time virtualize! macro, this works on any PE binary.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use squre_core::vm::opcode::{Op, OpcodeMap};

/// VM bytecode instruction (before encoding)
#[derive(Debug, Clone)]
pub enum VmInstr {
    Halt,
    Nop,
    // Arithmetic
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    Mul { rd: u8, rs1: u8, rs2: u8 },
    Xor { rd: u8, rs1: u8, rs2: u8 },
    And { rd: u8, rs1: u8, rs2: u8 },
    Or { rd: u8, rs1: u8, rs2: u8 },
    Not { rd: u8, rs: u8 },
    Shl { rd: u8, rs: u8, imm: u8 },
    Shr { rd: u8, rs: u8, imm: u8 },
    // Memory
    LoadImm { rd: u8, imm: u64 },
    Load { rd: u8, rs: u8 },
    Store { rd: u8, rs: u8 },
    Push { rs: u8 },
    Pop { rd: u8 },
    // Control flow
    Jmp { offset: i32 },
    JmpIfZero { rs: u8, offset: i32 },
    JmpIfNotZero { rs: u8, offset: i32 },
    Call { offset: i32 },
    Ret,
    // Compare
    CmpEq { rd: u8, rs1: u8, rs2: u8 },
    CmpLt { rd: u8, rs1: u8, rs2: u8 },
    // Move
    Mov { rd: u8, rs: u8 },
    // Native call (for unsupported instructions)
    NativeCall { func_id: u16, arg_count: u8, ret_reg: u8 },
}

/// x86-64 register to VM register mapping
fn x86_reg_to_vm(reg: Register) -> Option<u8> {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Some(0),
        Register::RCX | Register::ECX | Register::CX | Register::CL => Some(1),
        Register::RDX | Register::EDX | Register::DX | Register::DL => Some(2),
        Register::RBX | Register::EBX | Register::BX | Register::BL => Some(3),
        Register::RSP | Register::ESP | Register::SP => Some(4),
        Register::RBP | Register::EBP | Register::BP => Some(5),
        Register::RSI | Register::ESI | Register::SI => Some(6),
        Register::RDI | Register::EDI | Register::DI => Some(7),
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(8),
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(9),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(10),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(11),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(12),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(13),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(14),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(15),
        _ => None,
    }
}

/// Disassemble and convert x86-64 code to VM instructions
pub fn disassemble_to_vm(code: &[u8], rva: u64) -> Result<Vec<VmInstr>, String> {
    let mut decoder = Decoder::with_ip(64, code, rva, DecoderOptions::NONE);
    let mut vm_instrs = Vec::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        match instruction.mnemonic() {
            Mnemonic::Nop => {
                vm_instrs.push(VmInstr::Nop);
            }

            Mnemonic::Mov => {
                // MOV rd, rs or MOV rd, imm
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::Mov { rd, rs });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate64 {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate64();
                        vm_instrs.push(VmInstr::LoadImm { rd, imm });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate32 {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate32() as u64;
                        vm_instrs.push(VmInstr::LoadImm { rd, imm });
                    } else {
                        // Memory operand - use native call stub
                        vm_instrs.push(VmInstr::Nop); // Placeholder
                    }
                }
            }

            Mnemonic::Add => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::Add { rd, rs1: rd, rs2: rs });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate32 {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate32() as u64;
                        // ADD rd, imm → LoadImm temp, imm; Add rd, rd, temp
                        vm_instrs.push(VmInstr::LoadImm { rd: 15, imm }); // Use R15 as temp
                        vm_instrs.push(VmInstr::Add { rd, rs1: rd, rs2: 15 });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Sub => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::Sub { rd, rs1: rd, rs2: rs });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate32 {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate32() as u64;
                        vm_instrs.push(VmInstr::LoadImm { rd: 15, imm });
                        vm_instrs.push(VmInstr::Sub { rd, rs1: rd, rs2: 15 });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Xor => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::Xor { rd, rs1: rd, rs2: rs });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::And => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::And { rd, rs1: rd, rs2: rs });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate32 {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate32() as u64;
                        vm_instrs.push(VmInstr::LoadImm { rd: 15, imm });
                        vm_instrs.push(VmInstr::And { rd, rs1: rd, rs2: 15 });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Or => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported src register")?;
                        vm_instrs.push(VmInstr::Or { rd, rs1: rd, rs2: rs });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Shl => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();

                    if op0_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate8() as u8;
                        vm_instrs.push(VmInstr::Shl { rd, rs: rd, imm });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Shr => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();

                    if op0_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported dest register")?;
                        let imm = instruction.immediate8() as u8;
                        vm_instrs.push(VmInstr::Shr { rd, rs: rd, imm });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Push => {
                if instruction.op0_kind() == OpKind::Register {
                    let rs = x86_reg_to_vm(instruction.op0_register())
                        .ok_or("Unsupported register")?;
                    vm_instrs.push(VmInstr::Push { rs });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Pop => {
                if instruction.op0_kind() == OpKind::Register {
                    let rd = x86_reg_to_vm(instruction.op0_register())
                        .ok_or("Unsupported register")?;
                    vm_instrs.push(VmInstr::Pop { rd });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Ret => {
                vm_instrs.push(VmInstr::Ret);
            }

            Mnemonic::Call => {
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    let target = instruction.near_branch64();
                    let current = instruction.ip();
                    let offset = (target as i64 - current as i64) as i32;
                    vm_instrs.push(VmInstr::Call { offset });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Jmp => {
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    let target = instruction.near_branch64();
                    let current = instruction.ip();
                    let offset = (target as i64 - current as i64) as i32;
                    vm_instrs.push(VmInstr::Jmp { offset });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Je => {
                // JZ: jump if zero flag set (after CMP, TEST, etc.)
                // We need to track flags - for now use R14 as flags register
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    let target = instruction.near_branch64();
                    let current = instruction.ip();
                    let offset = (target as i64 - current as i64) as i32;
                    vm_instrs.push(VmInstr::JmpIfZero { rs: 14, offset });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Jne => {
                if instruction.op0_kind() == OpKind::NearBranch64 {
                    let target = instruction.near_branch64();
                    let current = instruction.ip();
                    let offset = (target as i64 - current as i64) as i32;
                    vm_instrs.push(VmInstr::JmpIfNotZero { rs: 14, offset });
                } else {
                    vm_instrs.push(VmInstr::Nop);
                }
            }

            Mnemonic::Cmp => {
                // CMP sets flags - store result in R14
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rs1 = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported register")?;
                        let rs2 = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported register")?;
                        // Store (rs1 - rs2) in R14 for flag emulation
                        vm_instrs.push(VmInstr::Sub { rd: 14, rs1, rs2 });
                    } else if op0_kind == OpKind::Register && op1_kind == OpKind::Immediate32 {
                        let rs1 = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported register")?;
                        let imm = instruction.immediate32() as u64;
                        vm_instrs.push(VmInstr::LoadImm { rd: 15, imm });
                        vm_instrs.push(VmInstr::Sub { rd: 14, rs1, rs2: 15 });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Test => {
                // TEST rd, rs → AND without storing, just flags
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rs1 = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported register")?;
                        let rs2 = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported register")?;
                        vm_instrs.push(VmInstr::And { rd: 14, rs1, rs2 });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Imul => {
                if instruction.op_count() >= 2 {
                    let op0_kind = instruction.op0_kind();
                    let op1_kind = instruction.op1_kind();

                    if op0_kind == OpKind::Register && op1_kind == OpKind::Register {
                        let rd = x86_reg_to_vm(instruction.op0_register())
                            .ok_or("Unsupported register")?;
                        let rs = x86_reg_to_vm(instruction.op1_register())
                            .ok_or("Unsupported register")?;
                        vm_instrs.push(VmInstr::Mul { rd, rs1: rd, rs2: rs });
                    } else {
                        vm_instrs.push(VmInstr::Nop);
                    }
                }
            }

            Mnemonic::Lea => {
                // LEA is complex - for simple cases we can handle
                // LEA rd, [rs + imm] → Add rd, rs, imm
                vm_instrs.push(VmInstr::Nop); // Placeholder for now
            }

            // Unsupported instructions become NOPs (or native calls in full impl)
            _ => {
                vm_instrs.push(VmInstr::Nop);
            }
        }
    }

    Ok(vm_instrs)
}

/// Encode VM instructions to bytecode with CEWE-randomized opcodes
/// High-entropy mode adds dead instructions and XOR encryption
pub fn encode_bytecode(instrs: &[VmInstr], seed: u64) -> Vec<u8> {
    encode_bytecode_internal(instrs, seed, true) // Default to high entropy
}

/// Low-entropy encoding (for debugging/testing)
#[allow(dead_code)]
pub fn encode_bytecode_low_entropy(instrs: &[VmInstr], seed: u64) -> Vec<u8> {
    encode_bytecode_internal(instrs, seed, false)
}

fn encode_bytecode_internal(instrs: &[VmInstr], seed: u64, high_entropy: bool) -> Vec<u8> {
    let opcode_map = OpcodeMap::from_seed(seed);
    let mut bytecode = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xDEADBEEF_CAFEBABE);

    for instr in instrs {
        // HIGH ENTROPY: Insert 1-3 random dead instructions before each real one
        if high_entropy {
            let dead_count = rng.gen_range(1..=3);
            for _ in 0..dead_count {
                emit_dead_instruction(&mut bytecode, &opcode_map, &mut rng);
            }
        }

        match instr {
            VmInstr::Halt => {
                bytecode.push(opcode_map.encode[Op::Halt as usize]);
            }
            VmInstr::Nop => {
                // HIGH ENTROPY: Replace NOP with random dead instruction
                if high_entropy {
                    emit_dead_instruction(&mut bytecode, &opcode_map, &mut rng);
                } else {
                    bytecode.push(opcode_map.encode[Op::Nop as usize]);
                }
            }
            VmInstr::Add { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::Add as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Sub { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::Sub as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Mul { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::Mul as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Xor { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::Xor as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::And { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::And as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Or { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::Or as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Not { rd, rs } => {
                bytecode.push(opcode_map.encode[Op::Not as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
            }
            VmInstr::Shl { rd, rs, imm } => {
                bytecode.push(opcode_map.encode[Op::Shl as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
                bytecode.push(*imm);
            }
            VmInstr::Shr { rd, rs, imm } => {
                bytecode.push(opcode_map.encode[Op::Shr as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
                bytecode.push(*imm);
            }
            VmInstr::LoadImm { rd, imm } => {
                bytecode.push(opcode_map.encode[Op::LoadImm as usize]);
                bytecode.push(*rd);
                bytecode.extend_from_slice(&imm.to_le_bytes());
            }
            VmInstr::Load { rd, rs } => {
                bytecode.push(opcode_map.encode[Op::Load as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
            }
            VmInstr::Store { rd, rs } => {
                bytecode.push(opcode_map.encode[Op::Store as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
            }
            VmInstr::Push { rs } => {
                bytecode.push(opcode_map.encode[Op::Push as usize]);
                bytecode.push(*rs);
            }
            VmInstr::Pop { rd } => {
                bytecode.push(opcode_map.encode[Op::Pop as usize]);
                bytecode.push(*rd);
            }
            VmInstr::Jmp { offset } => {
                bytecode.push(opcode_map.encode[Op::Jmp as usize]);
                bytecode.extend_from_slice(&offset.to_le_bytes());
            }
            VmInstr::JmpIfZero { rs, offset } => {
                bytecode.push(opcode_map.encode[Op::JmpIfZero as usize]);
                bytecode.push(*rs);
                bytecode.extend_from_slice(&offset.to_le_bytes());
            }
            VmInstr::JmpIfNotZero { rs, offset } => {
                bytecode.push(opcode_map.encode[Op::JmpIfNotZero as usize]);
                bytecode.push(*rs);
                bytecode.extend_from_slice(&offset.to_le_bytes());
            }
            VmInstr::Call { offset } => {
                bytecode.push(opcode_map.encode[Op::Call as usize]);
                bytecode.extend_from_slice(&offset.to_le_bytes());
            }
            VmInstr::Ret => {
                bytecode.push(opcode_map.encode[Op::Ret as usize]);
            }
            VmInstr::CmpEq { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::CmpEq as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::CmpLt { rd, rs1, rs2 } => {
                bytecode.push(opcode_map.encode[Op::CmpLt as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs1);
                bytecode.push(*rs2);
            }
            VmInstr::Mov { rd, rs } => {
                bytecode.push(opcode_map.encode[Op::Mov as usize]);
                bytecode.push(*rd);
                bytecode.push(*rs);
            }
            VmInstr::NativeCall { func_id, arg_count, ret_reg } => {
                bytecode.push(opcode_map.encode[Op::VmCall as usize]);
                bytecode.extend_from_slice(&func_id.to_le_bytes());
                bytecode.push(*arg_count);
                bytecode.push(*ret_reg);
            }
        }
    }

    // Add halt at end
    bytecode.push(opcode_map.encode[Op::Halt as usize]);

    // HIGH ENTROPY: XOR encrypt the entire bytecode stream
    if high_entropy {
        let encrypt_key = derive_stream_key(seed);
        for (i, b) in bytecode.iter_mut().enumerate() {
            *b ^= encrypt_key[i % encrypt_key.len()];
        }
    }

    bytecode
}

/// Generate a dead instruction that affects no visible state
/// Uses unreachable registers or operations that cancel out
fn emit_dead_instruction(
    bytecode: &mut Vec<u8>,
    opcode_map: &OpcodeMap,
    rng: &mut ChaCha20Rng,
) {
    // Dead register 31 is reserved for dead computations
    const DEAD_REG: u8 = 31;

    match rng.gen_range(0..10) {
        0 => {
            // LoadImm to dead register
            bytecode.push(opcode_map.encode[Op::LoadImm as usize]);
            bytecode.push(DEAD_REG);
            bytecode.extend_from_slice(&rng.gen::<u64>().to_le_bytes());
        }
        1 => {
            // Add dead registers
            bytecode.push(opcode_map.encode[Op::Add as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(28..32));
        }
        2 => {
            // Xor dead registers
            bytecode.push(opcode_map.encode[Op::Xor as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(28..32));
        }
        3 => {
            // Mov between dead registers
            bytecode.push(opcode_map.encode[Op::Mov as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
        }
        4 => {
            // Shl dead register
            bytecode.push(opcode_map.encode[Op::Shl as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(0..64));
        }
        5 => {
            // Shr dead register
            bytecode.push(opcode_map.encode[Op::Shr as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(0..64));
        }
        6 => {
            // And dead registers
            bytecode.push(opcode_map.encode[Op::And as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(28..32));
        }
        7 => {
            // Or dead registers
            bytecode.push(opcode_map.encode[Op::Or as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(28..32));
        }
        8 => {
            // Not dead register
            bytecode.push(opcode_map.encode[Op::Not as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
        }
        _ => {
            // CmpEq dead registers
            bytecode.push(opcode_map.encode[Op::CmpEq as usize]);
            bytecode.push(DEAD_REG);
            bytecode.push(rng.gen_range(28..32));
            bytecode.push(rng.gen_range(28..32));
        }
    }
}

/// Derive XOR encryption key stream from seed
fn derive_stream_key(seed: u64) -> [u8; 256] {
    let mut key = [0u8; 256];
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x517CC1B727220A95);
    rng.fill(&mut key);
    key
}

/// Generate VM interpreter shellcode (x86-64)
/// This is a minimal interpreter that executes bytecode
pub fn generate_vm_interpreter(
    bytecode_rva: u32,
    bytecode_size: u32,
    opcode_map: &OpcodeMap,
    orig_entry_rva: u32,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(2048);

    // Prologue: save registers
    // push rbx, rbp, r12-r15
    s.push(0x53); // push rbx
    s.push(0x55); // push rbp
    s.extend_from_slice(&[0x41, 0x54]); // push r12
    s.extend_from_slice(&[0x41, 0x55]); // push r13
    s.extend_from_slice(&[0x41, 0x56]); // push r14
    s.extend_from_slice(&[0x41, 0x57]); // push r15

    // Allocate stack for VM state (16 regs × 8 bytes = 128 bytes)
    // sub rsp, 0x100
    s.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00]);

    // Get ImageBase
    // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // mov rbx, [rax+0x10] ; ImageBase
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);

    // r12 = bytecode pointer (ImageBase + bytecode_rva)
    // lea r12, [rbx + bytecode_rva]
    s.extend_from_slice(&[0x4C, 0x8D, 0xA3]);
    s.extend_from_slice(&bytecode_rva.to_le_bytes());

    // r13 = IP (instruction pointer into bytecode, starts at 0)
    // xor r13d, r13d
    s.extend_from_slice(&[0x45, 0x31, 0xED]);

    // Main dispatch loop
    let loop_start = s.len();

    // Read opcode: movzx eax, byte [r12 + r13]
    s.extend_from_slice(&[0x43, 0x0F, 0xB6, 0x04, 0x2C]);

    // Dispatch table would go here - for now just check for HALT
    // cmp al, HALT_OPCODE
    let halt_opcode = opcode_map.encode[Op::Halt as usize];
    s.extend_from_slice(&[0x3C, halt_opcode]);
    // je exit
    let exit_jmp_offset = s.len();
    s.extend_from_slice(&[0x74, 0x00]); // Placeholder

    // Increment IP
    // inc r13
    s.extend_from_slice(&[0x49, 0xFF, 0xC5]);

    // Loop back
    let loop_back_offset = (loop_start as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, loop_back_offset as u8]);

    // Exit label
    let exit_pos = s.len();
    s[exit_jmp_offset + 1] = (exit_pos - exit_jmp_offset - 2) as u8;

    // Epilogue: restore registers
    // add rsp, 0x100
    s.extend_from_slice(&[0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00]);

    s.extend_from_slice(&[0x41, 0x5F]); // pop r15
    s.extend_from_slice(&[0x41, 0x5E]); // pop r14
    s.extend_from_slice(&[0x41, 0x5D]); // pop r13
    s.extend_from_slice(&[0x41, 0x5C]); // pop r12
    s.push(0x5D); // pop rbp
    s.push(0x5B); // pop rbx

    // Jump to original entry
    // lea rax, [rbx + orig_entry_rva]; jmp rax
    s.extend_from_slice(&[0x48, 0x8D, 0x83]);
    s.extend_from_slice(&orig_entry_rva.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);

    s
}

/// VM protection configuration
#[derive(Debug, Clone)]
pub struct VmProtectConfig {
    /// CEWE seed for opcode randomization
    pub seed: u64,
    /// Functions/regions to virtualize (RVA, size)
    pub regions: Vec<(u32, u32)>,
    /// Enable junk instruction insertion
    pub junk_level: u8,
}

impl Default for VmProtectConfig {
    fn default() -> Self {
        VmProtectConfig {
            seed: 0x5155524556_u64, // "SQREV"
            regions: Vec::new(),
            junk_level: 2,
        }
    }
}

/// Statistics from VM protection
#[derive(Debug, Default)]
pub struct VmProtectStats {
    pub functions_virtualized: usize,
    pub x86_instructions: usize,
    pub vm_instructions: usize,
    pub bytecode_size: usize,
    pub interpreter_size: usize,
}

/// Apply VM protection to specified regions of code
pub fn apply_vm_protection(
    text_data: &[u8],
    text_rva: u32,
    config: &VmProtectConfig,
) -> Result<(Vec<u8>, Vec<u8>, VmProtectStats), String> {
    let mut stats = VmProtectStats::default();
    let mut all_vm_instrs = Vec::new();

    // If no regions specified, virtualize first 256 bytes as demo
    let regions = if config.regions.is_empty() {
        vec![(text_rva, std::cmp::min(256, text_data.len() as u32))]
    } else {
        config.regions.clone()
    };

    for (rva, size) in &regions {
        let offset = (*rva - text_rva) as usize;
        let code = &text_data[offset..offset + *size as usize];

        let vm_instrs = disassemble_to_vm(code, *rva as u64)?;
        stats.x86_instructions += code.len(); // Approximate
        stats.vm_instructions += vm_instrs.len();
        all_vm_instrs.extend(vm_instrs);
        stats.functions_virtualized += 1;
    }

    // Add junk instructions
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let junk_count = (all_vm_instrs.len() * config.junk_level as usize) / 2;
    for _ in 0..junk_count {
        let pos = rng.gen_range(0..=all_vm_instrs.len());
        all_vm_instrs.insert(pos, VmInstr::Nop);
    }

    // Encode to bytecode
    let bytecode = encode_bytecode(&all_vm_instrs, config.seed);
    stats.bytecode_size = bytecode.len();

    // Generate interpreter
    let opcode_map = OpcodeMap::from_seed(config.seed);
    let interpreter = generate_vm_interpreter(
        0, // Will be patched later
        bytecode.len() as u32,
        &opcode_map,
        text_rva,
    );
    stats.interpreter_size = interpreter.len();

    Ok((bytecode, interpreter, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_disassembly() {
        // mov rax, rbx; add rax, rcx; ret
        let code = [
            0x48, 0x89, 0xD8, // mov rax, rbx
            0x48, 0x01, 0xC8, // add rax, rcx
            0xC3,             // ret
        ];

        let instrs = disassemble_to_vm(&code, 0x1000).unwrap();
        assert!(instrs.len() >= 3);
    }

    #[test]
    fn test_bytecode_encoding() {
        let instrs = vec![
            VmInstr::LoadImm { rd: 0, imm: 42 },
            VmInstr::Add { rd: 0, rs1: 0, rs2: 1 },
            VmInstr::Halt,
        ];

        let bytecode = encode_bytecode(&instrs, 0x12345678);
        assert!(!bytecode.is_empty());
    }
}
