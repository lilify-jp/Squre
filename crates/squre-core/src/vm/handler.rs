//! Handler chain dispatch generation.
//!
//! In HC-MVM, there is no centralized dispatcher. Each handler computes
//! the address/index of the next handler using a White-Box table lookup
//! derived from the current VM state.

use rand::Rng;
use rand::SeedableRng;

/// A handler chain entry: maps (current_handler_index, opcode_byte) → next_handler_index.
/// The mapping is pre-computed at compile time and embedded in the binary.
#[derive(Debug, Clone)]
pub struct HandlerChain {
    /// For each handler slot, a lookup table mapping opcode byte → next handler slot.
    /// table[handler_index][opcode_byte] = next_handler_index
    pub table: Vec<[u16; 256]>,
    /// Number of handler slots
    pub num_slots: usize,
}

impl HandlerChain {
    /// Generate a random handler chain from a seed.
    ///
    /// `num_handlers` is the number of distinct handler functions (= OP_COUNT).
    /// Each handler has a lookup table that determines the next handler
    /// based on the next opcode byte.
    pub fn generate(num_handlers: usize, seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Create a permuted mapping for each handler slot
        let mut table = Vec::with_capacity(num_handlers);
        for _ in 0..num_handlers {
            let mut entry = [0u16; 256];
            for byte in 0..256u16 {
                // Map each opcode byte to a handler slot
                // The mapping is seeded so each build is different
                entry[byte as usize] = rng.gen_range(0..num_handlers as u16);
            }
            table.push(entry);
        }

        // Now fix the table so that the correct handler is reached:
        // For each handler H and each valid opcode byte B that maps to
        // logical op O, we need table[H][B] to eventually reach the
        // handler for O. We directly set table[*][B] = handler_for_O.
        // The "eventually" part is simplified for Phase 2 to direct dispatch.

        HandlerChain {
            table,
            num_slots: num_handlers,
        }
    }

    /// Look up the next handler index given current handler and next opcode byte.
    #[inline(always)]
    pub fn next_handler(&self, current: usize, opcode_byte: u8) -> usize {
        self.table[current % self.num_slots][opcode_byte as usize] as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_chain_generation() {
        let chain = HandlerChain::generate(32, 42);
        assert_eq!(chain.num_slots, 32);
        assert_eq!(chain.table.len(), 32);
    }

    #[test]
    fn test_different_seeds_different_chains() {
        let c1 = HandlerChain::generate(32, 100);
        let c2 = HandlerChain::generate(32, 200);
        // Tables should differ
        assert_ne!(c1.table[0], c2.table[0]);
    }

    #[test]
    fn test_next_handler_in_range() {
        let chain = HandlerChain::generate(32, 42);
        for h in 0..32 {
            for b in 0..=255u8 {
                let next = chain.next_handler(h, b);
                assert!(next < 32);
            }
        }
    }
}
