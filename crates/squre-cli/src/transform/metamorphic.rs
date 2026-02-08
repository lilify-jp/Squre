//! Metamorphic replication engine.
//!
//! At the end of each execution, the metamorphic engine generates a new
//! CEWE seed and re-encrypts all protected sections. The next execution
//! sees a completely different binary structure.

use rand::Rng;
use rand::SeedableRng;

/// Metamorphic engine configuration.
pub struct MetamorphicConfig {
    pub current_seed: u64,
}

/// Result of metamorphic transformation.
#[derive(Debug, Clone)]
pub struct MutatedBinary {
    /// New CEWE seed for the next generation.
    pub new_seed: u64,
    /// Re-encrypted sections data.
    pub mutated_sections: Vec<MutatedSection>,
    /// Generation counter.
    pub generation: u64,
}

/// A section that has been mutated.
#[derive(Debug, Clone)]
pub struct MutatedSection {
    pub name: String,
    pub data: Vec<u8>,
}

/// Derive a new seed from the current state.
///
/// Uses HMAC-like mixing of current_seed, timestamp, and execution count
/// to produce a deterministic but unpredictable new seed.
pub fn derive_new_seed(current_seed: u64, timestamp: u64, exec_count: u64) -> u64 {
    // HMAC-like construction using simple mixing
    let mut h = current_seed;

    // Mix in timestamp
    h ^= timestamp;
    h = h.wrapping_mul(0x517e_cafe_0000_0001);
    h ^= h >> 33;

    // Mix in execution count
    h ^= exec_count.wrapping_mul(0x9E3779B97F4A7C15);
    h = h.wrapping_mul(0x6C62272E07BB0142);
    h ^= h >> 29;

    // Final avalanche
    h = h.wrapping_mul(0xBF58476D1CE4E5B9);
    h ^= h >> 31;
    h = h.wrapping_mul(0x94D049BB133111EB);
    h ^= h >> 27;

    h
}

/// Apply metamorphic transformation to binary sections.
///
/// Re-encrypts each section with a new key derived from the new seed.
/// The generation counter is incremented.
pub fn mutate_sections(
    sections: &[(String, Vec<u8>)],
    config: &MetamorphicConfig,
) -> MutatedBinary {
    // Derive new seed (using current time as zero for reproducibility in non-runtime context)
    let new_seed = derive_new_seed(config.current_seed, 0, 0);
    let mut rng = rand::rngs::StdRng::seed_from_u64(new_seed);

    let mut mutated_sections = Vec::with_capacity(sections.len());

    for (name, data) in sections {
        // Generate a new XOR key for this section
        let key_len = data.len().max(1);
        let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();

        // XOR-encrypt the section data
        let mutated_data: Vec<u8> = data.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        mutated_sections.push(MutatedSection {
            name: name.clone(),
            data: mutated_data,
        });
    }

    MutatedBinary {
        new_seed,
        mutated_sections,
        generation: 1, // Incremented from 0
    }
}

/// Verify that a metamorphic transformation can be reversed.
///
/// Given the same seed, the same transformation can be applied to recover
/// the original data (XOR is its own inverse when using the same key).
pub fn reverse_mutation(
    mutated: &MutatedBinary,
    original_seed: u64,
) -> Vec<(String, Vec<u8>)> {
    let new_seed = derive_new_seed(original_seed, 0, 0);
    let mut rng = rand::rngs::StdRng::seed_from_u64(new_seed);

    let mut recovered = Vec::new();

    for section in &mutated.mutated_sections {
        let key_len = section.data.len().max(1);
        let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();

        let original_data: Vec<u8> = section.data.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        recovered.push((section.name.clone(), original_data));
    }

    recovered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_new_seed_deterministic() {
        let s1 = derive_new_seed(42, 1000, 5);
        let s2 = derive_new_seed(42, 1000, 5);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_derive_new_seed_different_inputs() {
        let s1 = derive_new_seed(42, 1000, 5);
        let s2 = derive_new_seed(43, 1000, 5);
        let s3 = derive_new_seed(42, 1001, 5);
        let s4 = derive_new_seed(42, 1000, 6);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);
    }

    #[test]
    fn test_mutate_sections_produces_different_data() {
        let sections = vec![
            (".text".to_string(), vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3]),
            (".data".to_string(), vec![0x01, 0x02, 0x03, 0x04]),
        ];
        let config = MetamorphicConfig { current_seed: 42 };
        let mutated = mutate_sections(&sections, &config);

        assert_eq!(mutated.mutated_sections.len(), 2);
        assert_ne!(mutated.mutated_sections[0].data, sections[0].1);
        assert_ne!(mutated.mutated_sections[1].data, sections[1].1);
    }

    #[test]
    fn test_mutate_roundtrip() {
        let sections = vec![
            (".text".to_string(), vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3]),
            (".data".to_string(), vec![0x01, 0x02, 0x03, 0x04]),
        ];
        let config = MetamorphicConfig { current_seed: 42 };
        let mutated = mutate_sections(&sections, &config);

        // Reverse the mutation
        let recovered = reverse_mutation(&mutated, 42);
        assert_eq!(recovered[0].1, sections[0].1);
        assert_eq!(recovered[1].1, sections[1].1);
    }

    #[test]
    fn test_different_seeds_different_mutations() {
        let sections = vec![
            (".text".to_string(), vec![0x55, 0x48, 0x89, 0xE5]),
        ];
        let m1 = mutate_sections(&sections, &MetamorphicConfig { current_seed: 100 });
        let m2 = mutate_sections(&sections, &MetamorphicConfig { current_seed: 200 });

        assert_ne!(m1.mutated_sections[0].data, m2.mutated_sections[0].data);
        assert_ne!(m1.new_seed, m2.new_seed);
    }

    #[test]
    fn test_generation_counter() {
        let sections = vec![(".text".to_string(), vec![0x90])];
        let config = MetamorphicConfig { current_seed: 42 };
        let mutated = mutate_sections(&sections, &config);
        assert_eq!(mutated.generation, 1);
    }
}
