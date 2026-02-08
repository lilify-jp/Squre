//! VM instruction set definition.
//!
//! The opcode encoding is determined by a CEWE seed, so each build
//! produces a unique instruction set that cannot be pattern-matched.

use rand::Rng;
use rand::SeedableRng;

/// Number of general-purpose registers.
pub const NUM_REGS: usize = 16;

/// VM instruction opcodes (logical meaning).
/// The actual byte encoding is determined by OpcodeMap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Op {
    /// Halt execution
    Halt = 0,
    /// No operation (padding/junk)
    Nop,

    // ─── Arithmetic (wrapping u64) ───
    /// Rd = Rs1 + Rs2 (wrapping)
    Add,
    /// Rd = Rs1 - Rs2 (wrapping)
    Sub,
    /// Rd = Rs1 * Rs2 (wrapping)
    Mul,
    /// Rd = Rs1 ^ Rs2
    Xor,
    /// Rd = Rs1 & Rs2
    And,
    /// Rd = Rs1 | Rs2
    Or,
    /// Rd = !Rs1
    Not,
    /// Rd = Rs1 << imm5
    Shl,
    /// Rd = Rs1 >> imm5 (logical)
    Shr,
    /// Rd = Rs1.rotate_left(imm6)
    Rol,
    /// Rd = Rs1.rotate_right(imm6)
    Ror,

    // ─── Memory ───
    /// Rd = imm64
    LoadImm,
    /// Rd = Memory[Rs1]
    Load,
    /// Memory[Rs1] = Rs2
    Store,
    /// Push Rs1 onto stack
    Push,
    /// Pop into Rd
    Pop,

    // ─── Control flow ───
    /// Unconditional jump to imm32 offset
    Jmp,
    /// Jump if Rs1 == 0
    JmpIfZero,
    /// Jump if Rs1 != 0
    JmpIfNotZero,
    /// Call subroutine at imm32 offset (push return addr)
    Call,
    /// Return from subroutine (pop return addr)
    Ret,

    // ─── Extended Arithmetic ───
    /// Rd = Rs1 / Rs2 (wrapping, unsigned)
    Div,
    /// Rd = Rs1 % Rs2 (unsigned)
    Mod,
    /// Rd = -Rs1 (two's complement negation)
    Neg,

    // ─── Comparison ───
    /// Rd = (Rs1 == Rs2) ? 1 : 0
    CmpEq,
    /// Rd = (Rs1 != Rs2) ? 1 : 0
    CmpNe,
    /// Rd = (Rs1 < Rs2) unsigned ? 1 : 0
    CmpLt,
    /// Rd = (Rs1 > Rs2) unsigned ? 1 : 0
    CmpGt,
    /// Rd = (Rs1 <= Rs2) unsigned ? 1 : 0
    CmpLe,
    /// Rd = (Rs1 >= Rs2) unsigned ? 1 : 0
    CmpGe,

    // ─── Special ───
    /// Move Rd = Rs1
    Mov,
    /// Rd = Rs1 (with EDF encode applied)
    EdfEncode,
    /// Rd = Rs1 (with EDF decode applied)
    EdfDecode,
    /// Call native function: VmCall(func_id, arg_count, ret_reg)
    VmCall,
    /// Execute nested VM: VmExecNested(prog_id, arg_count, ret_reg)
    VmExecNested,
}

/// Total number of opcodes.
pub const OP_COUNT: usize = 37;

impl Op {
    /// All opcodes in definition order.
    pub const ALL: [Op; OP_COUNT] = [
        Op::Halt, Op::Nop,
        Op::Add, Op::Sub, Op::Mul, Op::Xor, Op::And, Op::Or, Op::Not,
        Op::Shl, Op::Shr, Op::Rol, Op::Ror,
        Op::LoadImm, Op::Load, Op::Store, Op::Push, Op::Pop,
        Op::Jmp, Op::JmpIfZero, Op::JmpIfNotZero, Op::Call, Op::Ret,
        Op::Div, Op::Mod, Op::Neg,
        Op::CmpEq, Op::CmpNe, Op::CmpLt, Op::CmpGt, Op::CmpLe, Op::CmpGe,
        Op::Mov, Op::EdfEncode, Op::EdfDecode, Op::VmCall, Op::VmExecNested,
    ];
}

/// Maps logical opcodes to unique byte values.
/// Generated from CEWE seed — each build has a different mapping.
#[derive(Debug, Clone)]
pub struct OpcodeMap {
    /// logical Op index → encoded byte
    pub encode: [u8; OP_COUNT],
    /// encoded byte → logical Op index (inverse)
    pub decode: [Option<u8>; 256],
}

impl OpcodeMap {
    /// Generate a random opcode mapping from a seed.
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        Self::from_rng(&mut rng)
    }

    /// Generate a random opcode mapping from an RNG.
    pub fn from_rng(rng: &mut impl Rng) -> Self {
        // Create a shuffled mapping: each Op gets a unique random byte
        let mut available: Vec<u8> = (0..=255).collect();
        // Fisher-Yates shuffle
        for i in (1..available.len()).rev() {
            let j = rng.gen_range(0..=i);
            available.swap(i, j);
        }

        let mut encode = [0u8; OP_COUNT];
        let mut decode = [None; 256];

        for (i, &byte) in available.iter().take(OP_COUNT).enumerate() {
            encode[i] = byte;
            decode[byte as usize] = Some(i as u8);
        }

        OpcodeMap { encode, decode }
    }

    /// Encode a logical opcode to its byte representation.
    pub fn encode_op(&self, op: Op) -> u8 {
        self.encode[op as usize]
    }

    /// Decode a byte to its logical opcode.
    pub fn decode_op(&self, byte: u8) -> Option<Op> {
        self.decode[byte as usize].map(|idx| Op::ALL[idx as usize])
    }
}

/// A single VM instruction with operands.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub op: Op,
    pub operands: Operands,
}

/// Operand encoding for different instruction formats.
#[derive(Debug, Clone)]
pub enum Operands {
    /// No operands (Halt, Nop, Ret)
    None,
    /// Single register (Push, Pop, Not)
    Reg(u8),
    /// Two registers (Mov, EdfEncode, EdfDecode)
    RegReg(u8, u8),
    /// Three registers: Rd, Rs1, Rs2 (Add, Sub, Mul, Xor, And, Or, Cmp*)
    RegRegReg(u8, u8, u8),
    /// Register + shift/rotate amount (Shl, Shr, Rol, Ror)
    RegRegImm8(u8, u8, u8),
    /// Register + immediate 64-bit (LoadImm)
    RegImm64(u8, u64),
    /// Signed offset for jumps (Jmp, JmpIfZero, JmpIfNotZero, Call)
    BranchReg(u8, i32),
    /// Unconditional branch offset
    Branch(i32),
    /// VmCall: func_id(u16), arg_count(u8), ret_reg(u8)
    VmCallArgs(u16, u8, u8),
    /// VmExecNested: prog_id(u16), arg_count(u8), ret_reg(u8)
    VmExecNestedArgs(u16, u8, u8),
}

impl Instruction {
    /// Serialize this instruction to bytes using the given opcode map.
    pub fn encode(&self, map: &OpcodeMap) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(map.encode_op(self.op));

        match &self.operands {
            Operands::None => {}
            Operands::Reg(r) => {
                out.push(*r);
            }
            Operands::RegReg(rd, rs) => {
                out.push(*rd);
                out.push(*rs);
            }
            Operands::RegRegReg(rd, rs1, rs2) => {
                out.push(*rd);
                out.push(*rs1);
                out.push(*rs2);
            }
            Operands::RegRegImm8(rd, rs, imm) => {
                out.push(*rd);
                out.push(*rs);
                out.push(*imm);
            }
            Operands::RegImm64(rd, imm) => {
                out.push(*rd);
                out.extend_from_slice(&imm.to_le_bytes());
            }
            Operands::BranchReg(rs, offset) => {
                out.push(*rs);
                out.extend_from_slice(&offset.to_le_bytes());
            }
            Operands::Branch(offset) => {
                out.extend_from_slice(&offset.to_le_bytes());
            }
            Operands::VmCallArgs(func_id, arg_count, ret_reg) => {
                out.extend_from_slice(&func_id.to_le_bytes());
                out.push(*arg_count);
                out.push(*ret_reg);
            }
            Operands::VmExecNestedArgs(prog_id, arg_count, ret_reg) => {
                out.extend_from_slice(&prog_id.to_le_bytes());
                out.push(*arg_count);
                out.push(*ret_reg);
            }
        }

        out
    }

    /// Calculate the encoded byte length of this instruction.
    pub fn encoded_len(&self) -> usize {
        1 + match &self.operands {
            Operands::None => 0,
            Operands::Reg(_) => 1,
            Operands::RegReg(_, _) => 2,
            Operands::RegRegReg(_, _, _) => 3,
            Operands::RegRegImm8(_, _, _) => 3,
            Operands::RegImm64(_, _) => 9,
            Operands::BranchReg(_, _) => 5,
            Operands::Branch(_) => 4,
            Operands::VmCallArgs(_, _, _) => 4,
            Operands::VmExecNestedArgs(_, _, _) => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_map_roundtrip() {
        let map = OpcodeMap::from_seed(42);
        for op in Op::ALL {
            let encoded = map.encode_op(op);
            let decoded = map.decode_op(encoded).unwrap();
            assert_eq!(decoded, op, "Roundtrip failed for {:?}", op);
        }
    }

    #[test]
    fn test_different_seeds_different_maps() {
        let map1 = OpcodeMap::from_seed(100);
        let map2 = OpcodeMap::from_seed(200);
        // At least some opcodes should have different encodings
        let diffs = Op::ALL.iter()
            .filter(|&&op| map1.encode_op(op) != map2.encode_op(op))
            .count();
        assert!(diffs > 0, "Different seeds produced identical maps");
    }

    #[test]
    fn test_all_encoded_opcodes_unique() {
        let map = OpcodeMap::from_seed(999);
        let mut seen = std::collections::HashSet::new();
        for op in Op::ALL {
            let enc = map.encode_op(op);
            assert!(seen.insert(enc), "Duplicate encoding for {:?}", op);
        }
    }

    #[test]
    fn test_instruction_encode_load_imm() {
        let map = OpcodeMap::from_seed(42);
        let inst = Instruction {
            op: Op::LoadImm,
            operands: Operands::RegImm64(3, 0xDEADBEEFCAFEBABE),
        };
        let bytes = inst.encode(&map);
        assert_eq!(bytes.len(), 10); // 1 opcode + 1 reg + 8 imm
        assert_eq!(bytes[0], map.encode_op(Op::LoadImm));
        assert_eq!(bytes[1], 3);
        assert_eq!(u64::from_le_bytes(bytes[2..10].try_into().unwrap()), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn test_instruction_encode_add() {
        let map = OpcodeMap::from_seed(42);
        let inst = Instruction {
            op: Op::Add,
            operands: Operands::RegRegReg(0, 1, 2),
        };
        let bytes = inst.encode(&map);
        assert_eq!(bytes.len(), 4);
    }
}
