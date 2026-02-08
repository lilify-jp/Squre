//! Semantic Junk generation.
//!
//! Inserts junk instructions into VM bytecode that look like real operations
//! but cancel each other out (phantom dependencies). This prevents
//! static analysis from distinguishing real instructions from noise.

use rand::Rng;
use crate::vm::opcode::*;

/// Configuration for semantic junk insertion.
#[derive(Debug, Clone)]
pub struct JunkConfig {
    /// Number of junk instructions per real instruction (average).
    pub junk_ratio: usize,
    /// Registers reserved for junk operations (high-numbered registers).
    pub junk_regs: Vec<u8>,
}

impl Default for JunkConfig {
    fn default() -> Self {
        JunkConfig {
            junk_ratio: 5,
            // Use registers R10-R15 for junk
            junk_regs: vec![10, 11, 12, 13, 14, 15],
        }
    }
}

/// A junk sequence: instructions that modify state then restore it.
#[derive(Debug, Clone)]
struct JunkPair {
    /// Instructions to insert before the real instruction.
    before: Vec<Instruction>,
    /// Instructions to insert after the real instruction to cancel the effect.
    after: Vec<Instruction>,
}

/// Generate semantic junk for a stream of instructions.
///
/// Returns a new instruction stream with junk interleaved.
/// The junk uses phantom dependencies — modifies junk registers with values
/// derived from real registers, then cancels the modifications.
pub fn inject_junk(
    instructions: &[Instruction],
    config: &JunkConfig,
    rng: &mut impl Rng,
) -> Vec<Instruction> {
    let mut result = Vec::new();

    for inst in instructions {
        // Don't inject junk around Halt
        if inst.op == Op::Halt {
            result.push(inst.clone());
            continue;
        }

        // Generate junk before
        let num_before = rng.gen_range(1..=config.junk_ratio);
        let num_after = rng.gen_range(1..=config.junk_ratio);

        let pairs = generate_junk_pairs(
            num_before.max(num_after),
            &config.junk_regs,
            rng,
        );

        // Insert "before" junk
        for pair in pairs.iter().take(num_before) {
            result.extend(pair.before.iter().cloned());
        }

        // Real instruction
        result.push(inst.clone());

        // Insert "after" junk (cancel operations)
        for pair in pairs.iter().take(num_after) {
            result.extend(pair.after.iter().cloned());
        }
    }

    result
}

/// Generate junk instruction pairs that cancel each other.
fn generate_junk_pairs(
    count: usize,
    junk_regs: &[u8],
    rng: &mut impl Rng,
) -> Vec<JunkPair> {
    let mut pairs = Vec::new();

    for _ in 0..count {
        if junk_regs.len() < 2 {
            continue;
        }

        let r1 = junk_regs[rng.gen_range(0..junk_regs.len())];
        let r2 = junk_regs[rng.gen_range(0..junk_regs.len())];

        let pattern = rng.gen_range(0..4u32);
        let pair = match pattern {
            0 => junk_xor_cancel(r1, r2, rng),
            1 => junk_add_sub_cancel(r1, r2, rng),
            2 => junk_not_not_cancel(r1),
            3 => junk_mov_restore(r1, r2, rng),
            _ => unreachable!(),
        };

        pairs.push(pair);
    }

    pairs
}

/// XOR with a constant, then XOR again to cancel.
/// before: R1 = R1 ^ const
/// after:  R1 = R1 ^ const  (XOR is self-inverse)
fn junk_xor_cancel(r1: u8, r2: u8, rng: &mut impl Rng) -> JunkPair {
    let constant = rng.gen::<u64>();
    // Load const into r2, then xor r1 with r2
    JunkPair {
        before: vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, constant) },
            Instruction { op: Op::Xor, operands: Operands::RegRegReg(r1, r1, r2) },
        ],
        after: vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, constant) },
            Instruction { op: Op::Xor, operands: Operands::RegRegReg(r1, r1, r2) },
        ],
    }
}

/// Add a constant, then subtract it to cancel.
/// before: R1 = R1 + const
/// after:  R1 = R1 - const
fn junk_add_sub_cancel(r1: u8, r2: u8, rng: &mut impl Rng) -> JunkPair {
    let constant = rng.gen::<u64>();
    JunkPair {
        before: vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, constant) },
            Instruction { op: Op::Add, operands: Operands::RegRegReg(r1, r1, r2) },
        ],
        after: vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r2, constant) },
            Instruction { op: Op::Sub, operands: Operands::RegRegReg(r1, r1, r2) },
        ],
    }
}

/// Double NOT cancels: !(!x) = x
fn junk_not_not_cancel(r1: u8) -> JunkPair {
    JunkPair {
        before: vec![
            Instruction { op: Op::Not, operands: Operands::Reg(r1) },
        ],
        after: vec![
            Instruction { op: Op::Not, operands: Operands::Reg(r1) },
        ],
    }
}

/// Save R1 to R2, clobber R1, then restore.
fn junk_mov_restore(r1: u8, r2: u8, rng: &mut impl Rng) -> JunkPair {
    let garbage = rng.gen::<u64>();
    JunkPair {
        before: vec![
            // Save r1 into r2
            Instruction { op: Op::Mov, operands: Operands::RegReg(r2, r1) },
            // Clobber r1 with garbage
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(r1, garbage) },
        ],
        after: vec![
            // Restore r1 from r2
            Instruction { op: Op::Mov, operands: Operands::RegReg(r1, r2) },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_junk_injection_preserves_real_instructions() {
        let mut rng = rand::thread_rng();
        let config = JunkConfig::default();

        let real_instructions = vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(0, 42) },
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(1, 10) },
            Instruction { op: Op::Add, operands: Operands::RegRegReg(2, 0, 1) },
            Instruction { op: Op::Halt, operands: Operands::None },
        ];

        let junked = inject_junk(&real_instructions, &config, &mut rng);

        // Junked stream should be longer
        assert!(junked.len() > real_instructions.len());

        // All real instructions should still be present (in order)
        let real_ops: Vec<Op> = real_instructions.iter().map(|i| i.op).collect();
        let junked_real: Vec<Op> = junked.iter()
            .filter(|i| {
                // Filter to only instructions operating on real registers (0-9)
                match &i.operands {
                    Operands::RegImm64(r, _) if *r <= 9 => true,
                    Operands::RegRegReg(rd, _, _) if *rd <= 9 => true,
                    Operands::None if i.op == Op::Halt => true,
                    _ => false,
                }
            })
            .map(|i| i.op)
            .collect();
        assert_eq!(junked_real, real_ops);
    }

    #[test]
    fn test_junk_uses_junk_registers() {
        let mut rng = rand::thread_rng();
        let config = JunkConfig::default();

        let real_instructions = vec![
            Instruction { op: Op::LoadImm, operands: Operands::RegImm64(0, 100) },
            Instruction { op: Op::Halt, operands: Operands::None },
        ];

        let junked = inject_junk(&real_instructions, &config, &mut rng);

        // Check that junk instructions use junk registers (10-15)
        let uses_junk_regs = junked.iter().any(|i| match &i.operands {
            Operands::RegImm64(r, _) => *r >= 10,
            Operands::RegReg(r, _) => *r >= 10,
            Operands::RegRegReg(r, _, _) => *r >= 10,
            Operands::Reg(r) => *r >= 10,
            _ => false,
        });
        assert!(uses_junk_regs, "Junk should use high-numbered registers");
    }
}
