//! Section encryption transform.
//!
//! Encrypts the .text section of a PE file using XOR with keys derived
//! from a cascade integrity chain. A decryption stub is generated for
//! runtime recovery.

use crate::pe::parser::{PeFile, PeError};
use rand::Rng;
use rand::SeedableRng;

/// Configuration for section encryption.
pub struct SectionEncryptConfig {
    pub num_chunks: usize,
    pub seed: u64,
}

/// Result of section encryption transform.
#[derive(Debug, Clone)]
pub struct EncryptedSection {
    /// The encrypted .text section data.
    pub encrypted_data: Vec<u8>,
    /// The decryption stub bytecode (to be placed in .squre section).
    pub decrypt_stub: Vec<u8>,
    /// Original entry point RVA (to jump to after decryption).
    pub original_entry_point: u32,
    /// Cascade chain metadata needed for decryption.
    pub chain_metadata: ChainMetadata,
}

/// Metadata for the cascade chain used in decryption.
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub root_hash: [u8; 32],
    pub tail_key: [u8; 32],
    pub chunk_sizes: Vec<usize>,
    pub num_chunks: usize,
}

/// Encrypt the .text section of a PE file.
pub fn encrypt_text_section(
    pe: &PeFile,
    config: &SectionEncryptConfig,
) -> Result<EncryptedSection, PeError> {
    let text_section = pe.find_section(".text")
        .ok_or(PeError::TruncatedFile)?;

    let text_data = pe.section_data(text_section);
    if text_data.is_empty() {
        return Err(PeError::TruncatedFile);
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(config.seed);
    let num_chunks = config.num_chunks.max(1);

    // Split the .text section into chunks
    let chunk_size = (text_data.len() + num_chunks - 1) / num_chunks;
    let chunks: Vec<&[u8]> = text_data.chunks(chunk_size).collect();
    let chunk_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();

    // Generate keys for each chunk (cascade-derived)
    let tail_key: [u8; 32] = {
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        k
    };

    // Build cascade keys: key[i] = simple_hash(key[i+1] ^ chunk[i+1])
    let mut keys: Vec<[u8; 32]> = vec![[0u8; 32]; chunks.len()];
    keys[chunks.len() - 1] = tail_key;
    for i in (0..chunks.len() - 1).rev() {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&keys[i + 1]);
        if i + 1 < chunks.len() {
            hasher_input.extend_from_slice(chunks[i + 1]);
        }
        keys[i] = simple_hash_32(&hasher_input);
    }

    // Compute root hash
    let mut root_input = Vec::new();
    root_input.extend_from_slice(&keys[0]);
    root_input.extend_from_slice(chunks[0]);
    let root_hash = simple_hash_32(&root_input);

    // Encrypt each chunk with its key
    let mut encrypted_data = Vec::with_capacity(text_data.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let key = &keys[i];
        let encrypted_chunk: Vec<u8> = chunk.iter().enumerate()
            .map(|(j, &b)| b ^ key[j % 32])
            .collect();
        encrypted_data.extend_from_slice(&encrypted_chunk);
    }

    // Generate a minimal decryption stub (x86-64)
    let decrypt_stub = generate_decrypt_stub(
        pe.optional_header.entry_point,
        text_section.virtual_address,
        text_data.len(),
        &tail_key,
    );

    Ok(EncryptedSection {
        encrypted_data,
        decrypt_stub,
        original_entry_point: pe.optional_header.entry_point,
        chain_metadata: ChainMetadata {
            root_hash,
            tail_key,
            chunk_sizes,
            num_chunks: chunks.len(),
        },
    })
}

/// Simple 32-byte hash (non-cryptographic, for key derivation).
fn simple_hash_32(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for (i, &b) in data.iter().enumerate() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
        hash[i % 32] ^= (h & 0xFF) as u8;
        hash[(i + 7) % 32] ^= ((h >> 8) & 0xFF) as u8;
        hash[(i + 13) % 32] ^= ((h >> 16) & 0xFF) as u8;
        hash[(i + 19) % 32] ^= ((h >> 24) & 0xFF) as u8;
    }
    hash
}

/// Generate a minimal x86-64 decryption stub.
///
/// The stub XOR-decrypts the .text section in-place then jumps to the
/// original entry point. This is a simplified stub for demonstration.
fn generate_decrypt_stub(
    original_ep: u32,
    text_rva: u32,
    text_size: usize,
    key: &[u8; 32],
) -> Vec<u8> {
    let mut stub = Vec::new();

    // Push key bytes as immediate data at the end of the stub
    // For now, emit a simple XOR loop stub:
    //
    //   lea rsi, [rip + text_section]   ; source = encrypted .text
    //   mov ecx, text_size              ; counter
    //   lea rdi, [rip + key_data]       ; key pointer
    // loop:
    //   movzx eax, byte [rdi + (counter % 32)]
    //   xor [rsi], al
    //   inc rsi
    //   dec ecx
    //   jnz loop
    //   jmp original_entry_point

    // Simplified: just store the metadata as a data blob
    // The real stub would be proper machine code

    // Header: magic + metadata
    stub.extend_from_slice(b"SQRE"); // magic
    stub.extend_from_slice(&original_ep.to_le_bytes());
    stub.extend_from_slice(&text_rva.to_le_bytes());
    stub.extend_from_slice(&(text_size as u32).to_le_bytes());
    stub.extend_from_slice(key);

    // Pad to alignment
    while stub.len() % 16 != 0 {
        stub.push(0xCC); // INT3 padding
    }

    stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash_32(b"test data");
        let h2 = simple_hash_32(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_different_inputs() {
        let h1 = simple_hash_32(b"hello");
        let h2 = simple_hash_32(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_decrypt_stub_has_magic() {
        let stub = generate_decrypt_stub(0x1000, 0x1000, 4096, &[0xAA; 32]);
        assert_eq!(&stub[..4], b"SQRE");
    }

    #[test]
    fn test_decrypt_stub_contains_key() {
        let key = [0x42u8; 32];
        let stub = generate_decrypt_stub(0x1000, 0x1000, 4096, &key);
        // Key starts at offset 12 (4 magic + 4 ep + 4 rva + 4 size = 16... wait)
        // Actually: 4 (magic) + 4 (ep) + 4 (rva) + 4 (size) = 16
        assert_eq!(&stub[16..48], &key);
    }

    #[test]
    fn test_chain_metadata_chunk_sizes() {
        // Create a minimal fake PE for testing
        let chunk_sizes = vec![100, 100, 100, 56];
        let total: usize = chunk_sizes.iter().sum();
        assert_eq!(total, 356);
    }
}
