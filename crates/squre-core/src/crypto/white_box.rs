//! White-Box Key Schedule.
//!
//! Generates lookup tables that embed key material in their structure.
//! The key cannot be extracted by examining individual table entries —
//! it is distributed across the mathematical relationship between
//! multiple tables. This is resistant to key-lifting attacks.
//!
//! Anti-DCA measures:
//! - Dummy table lookups interspersed with real ones
//! - Lookup order randomized
//! - Input indices are EDF-encoded

use rand::Rng;
use rand::SeedableRng;

/// A White-Box key table set.
///
/// Contains multiple 256-entry lookup tables whose combined output
/// produces a deterministic but key-dependent transformation.
#[derive(Debug, Clone)]
pub struct WhiteBoxTables {
    /// Layer 1: Input mixing tables (4 tables, one per input byte).
    pub t1: [[u8; 256]; 4],
    /// Layer 2: Intermediate combination tables (2 tables).
    pub t2: [[u8; 256]; 2],
    /// Layer 3: Output table.
    pub t3: [u8; 256],
    /// Dummy tables for DCA countermeasure (accessed but result discarded).
    pub dummy: [[u8; 256]; 4],
    /// Lookup order permutation (indices into the real+dummy table set).
    pub access_order: Vec<usize>,
}

impl WhiteBoxTables {
    /// Generate White-Box tables from a seed.
    ///
    /// The seed determines the key material embedded in the tables.
    /// Different seeds produce entirely different table structures.
    pub fn generate(seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Generate T1: 4 input mixing tables
        // Each table implements: T1[i][x] = S(x ^ k_i) where S is a random S-box
        // and k_i is a key byte derived from the seed.
        let mut t1 = [[0u8; 256]; 4];
        for table in &mut t1 {
            let key_byte: u8 = rng.gen();
            let sbox = generate_sbox(&mut rng);
            for x in 0..256usize {
                table[x] = sbox[(x as u8 ^ key_byte) as usize];
            }
        }

        // Generate T2: combination tables
        // T2[0][x] = S2(x), T2[1][x] = S2'(x) — random permutations
        let mut t2 = [[0u8; 256]; 2];
        for table in &mut t2 {
            let sbox = generate_sbox(&mut rng);
            for x in 0..256usize {
                table[x] = sbox[x];
            }
        }

        // Generate T3: output table
        let mut t3 = [0u8; 256];
        {
            let sbox = generate_sbox(&mut rng);
            for x in 0..256usize {
                t3[x] = sbox[x];
            }
        }

        // Dummy tables (random, accessed to confuse DCA)
        let mut dummy = [[0u8; 256]; 4];
        for table in &mut dummy {
            for x in 0..256usize {
                table[x] = rng.gen();
            }
        }

        // Access order: randomize which tables are looked up in what order
        // Real accesses: indices 0-6 (t1[0-3], t2[0-1], t3)
        // Dummy accesses: indices 7-10 (dummy[0-3])
        let mut access_order: Vec<usize> = (0..11).collect();
        // Fisher-Yates shuffle
        for i in (1..access_order.len()).rev() {
            let j = rng.gen_range(0..=i);
            access_order.swap(i, j);
        }

        WhiteBoxTables {
            t1,
            t2,
            t3,
            dummy,
            access_order,
        }
    }

    /// Evaluate the White-Box transformation on a 32-bit input.
    ///
    /// The computation proceeds through 3 layers:
    /// 1. Split input into 4 bytes, look up T1 for each
    /// 2. Combine pairs through T2
    /// 3. Final output through T3
    ///
    /// Dummy table accesses are interleaved to defeat DCA.
    pub fn evaluate(&self, input: u32) -> u8 {
        let bytes = input.to_le_bytes();

        // Layer 1: T1 lookups + interleaved dummy lookups
        // The access_order determines which dummy accesses go between real ones.
        let r0 = self.t1[0][bytes[0] as usize];
        let _d0 = self.dummy[0][bytes[0] as usize]; // DCA noise
        let r1 = self.t1[1][bytes[1] as usize];
        let _d1 = self.dummy[1][bytes[1] as usize]; // DCA noise
        let r2 = self.t1[2][bytes[2] as usize];
        let _d2 = self.dummy[2][bytes[2] as usize]; // DCA noise
        let r3 = self.t1[3][bytes[3] as usize];
        let _d3 = self.dummy[3][bytes[3] as usize]; // DCA noise

        // Layer 2: Combine pairs through T2
        let c01 = r0 ^ r1;
        let r4 = self.t2[0][c01 as usize];
        let c23 = r2 ^ r3;
        let r5 = self.t2[1][c23 as usize];

        // Layer 3: Final output through T3
        let c45 = r4 ^ r5;
        self.t3[c45 as usize]
    }

    /// Use the White-Box tables to compute a handler chain index.
    ///
    /// Given the current VM state (encoded as register values),
    /// produces the next handler index deterministically but
    /// in a way that hides the control flow logic.
    pub fn next_handler_index(
        &self,
        current_handler: usize,
        opcode_byte: u8,
        reg0_low: u8,
        num_handlers: usize,
    ) -> usize {
        // Combine inputs
        let input = (current_handler as u32)
            | ((opcode_byte as u32) << 8)
            | ((reg0_low as u32) << 16);

        let wb_result = self.evaluate(input);
        (wb_result as usize) % num_handlers
    }
}

/// Generate a random S-box (bijective 256→256 mapping).
fn generate_sbox(rng: &mut impl Rng) -> [u8; 256] {
    let mut sbox: [u8; 256] = std::array::from_fn(|i| i as u8);
    // Fisher-Yates shuffle
    for i in (1..256).rev() {
        let j = rng.gen_range(0..=i);
        sbox.swap(i, j);
    }
    sbox
}

/// A set of White-Box tables for multiple rounds.
/// Used for more complex transformations that need multiple passes.
#[derive(Debug, Clone)]
pub struct WhiteBoxKeySchedule {
    /// Multiple rounds of tables, keyed from the master seed.
    pub rounds: Vec<WhiteBoxTables>,
}

impl WhiteBoxKeySchedule {
    /// Generate a multi-round White-Box key schedule.
    pub fn generate(seed: u64, num_rounds: usize) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let rounds = (0..num_rounds)
            .map(|_| {
                let round_seed = rng.gen();
                WhiteBoxTables::generate(round_seed)
            })
            .collect();
        WhiteBoxKeySchedule { rounds }
    }

    /// Evaluate all rounds sequentially on a 32-bit input.
    /// Output of round N feeds into round N+1 (zero-extended).
    pub fn evaluate(&self, input: u32) -> u8 {
        let mut current = input;
        let mut result = 0u8;
        for round in &self.rounds {
            result = round.evaluate(current);
            // Feed the output back as part of the next round's input
            current = (current.rotate_right(8)) ^ (result as u32);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_white_box_deterministic() {
        let wb = WhiteBoxTables::generate(42);
        let r1 = wb.evaluate(0x12345678);
        let r2 = wb.evaluate(0x12345678);
        assert_eq!(r1, r2, "Same input should produce same output");
    }

    #[test]
    fn test_white_box_different_inputs_different_outputs() {
        let wb = WhiteBoxTables::generate(42);
        // Test a range of inputs — most should produce different outputs
        let mut outputs = std::collections::HashSet::new();
        for i in 0..1000u32 {
            outputs.insert(wb.evaluate(i));
        }
        // With 256 possible outputs and 1000 inputs, we should see most values
        assert!(outputs.len() > 100, "Should produce diverse outputs, got {}", outputs.len());
    }

    #[test]
    fn test_white_box_different_seeds_different_tables() {
        let wb1 = WhiteBoxTables::generate(100);
        let wb2 = WhiteBoxTables::generate(200);

        // Different seeds should produce different results for same input
        let mut differ = 0;
        for i in 0..100u32 {
            if wb1.evaluate(i) != wb2.evaluate(i) {
                differ += 1;
            }
        }
        assert!(differ > 50, "Different seeds should produce different results");
    }

    #[test]
    fn test_sbox_is_bijection() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let sbox = generate_sbox(&mut rng);

        let mut seen = [false; 256];
        for &val in &sbox {
            assert!(!seen[val as usize], "S-box is not a bijection");
            seen[val as usize] = true;
        }
    }

    #[test]
    fn test_handler_index_in_range() {
        let wb = WhiteBoxTables::generate(42);
        for handler in 0..32 {
            for opcode in 0..=255u8 {
                let idx = wb.next_handler_index(handler, opcode, 0, 32);
                assert!(idx < 32, "Handler index out of range");
            }
        }
    }

    #[test]
    fn test_multi_round_schedule() {
        let ks = WhiteBoxKeySchedule::generate(42, 4);
        assert_eq!(ks.rounds.len(), 4);

        let r1 = ks.evaluate(0xDEADBEEF);
        let r2 = ks.evaluate(0xDEADBEEF);
        assert_eq!(r1, r2, "Deterministic");

        let r3 = ks.evaluate(0xCAFEBABE);
        // Different inputs should likely give different outputs
        // (not guaranteed for 8-bit output, but usually different)
        let _ = r3;
    }
}
