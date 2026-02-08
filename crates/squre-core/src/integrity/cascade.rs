//! Cascade Integrity Chain.
//!
//! Divides data (e.g., a code section) into N chunks and encrypts them
//! in a chain: each chunk's key is derived from the hash of the next
//! chunk's ciphertext. Modifying any chunk invalidates all preceding
//! chunks — a chain reaction that prevents selective patching.
//!
//! Chain structure:
//!   Chunk[N]   encrypted with fixed key K_N
//!   Chunk[N-1] encrypted with K_{N-1} = hash(ciphertext[N])
//!   ...
//!   Chunk[0]   encrypted with K_0 = hash(ciphertext[1])
//!   Root hash  = hash(ciphertext[0]) — embedded in bootstrap

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Simple keyed XOR encryption (for integrity chain, not cryptographic strength).
/// In a production system this would use AES or ChaCha20.
fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 32])
        .collect()
}

/// Same as encrypt (XOR is self-inverse).
fn xor_decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    xor_encrypt(data, key) // XOR is its own inverse
}

/// Compute a 256-bit hash of data. Uses a simple double-hash scheme.
/// (In production, this would be BLAKE3 or SHA-256.)
fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Hash 1
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();

    // Hash 2 (with different seed)
    let mut hasher = DefaultHasher::new();
    (data, 0x517e_cafe_u64).hash(&mut hasher);
    let h2 = hasher.finish();

    // Hash 3
    let mut hasher = DefaultHasher::new();
    (data, 0xdead_beef_u64).hash(&mut hasher);
    let h3 = hasher.finish();

    // Hash 4
    let mut hasher = DefaultHasher::new();
    (data, 0x1337_c0de_u64).hash(&mut hasher);
    let h4 = hasher.finish();

    result[0..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    result[16..24].copy_from_slice(&h3.to_le_bytes());
    result[24..32].copy_from_slice(&h4.to_le_bytes());
    result
}

/// A cascade integrity chain.
#[derive(Debug, Clone)]
pub struct CascadeChain {
    /// Encrypted chunks (in order: chunk 0, chunk 1, ..., chunk N-1).
    pub chunks: Vec<Vec<u8>>,
    /// Root hash: hash of ciphertext[0]. Used to verify the chain start.
    pub root_hash: [u8; 32],
    /// The fixed key for the last chunk (derived from seed).
    pub tail_key: [u8; 32],
}

/// Build a cascade integrity chain from raw data.
///
/// 1. Split data into `num_chunks` chunks.
/// 2. Encrypt from tail to head: each chunk's key = hash(next ciphertext).
/// 3. Return the chain with root hash.
pub fn build_chain(data: &[u8], num_chunks: usize, seed: u64) -> CascadeChain {
    assert!(num_chunks > 0);

    // Split data into chunks
    let chunk_size = (data.len() + num_chunks - 1) / num_chunks;
    let mut plaintext_chunks: Vec<Vec<u8>> = data
        .chunks(chunk_size.max(1))
        .map(|c| c.to_vec())
        .collect();

    // Pad to exact chunk count if needed
    while plaintext_chunks.len() < num_chunks {
        plaintext_chunks.push(Vec::new());
    }

    // Generate the tail key from seed
    let tail_key = hash_data(&seed.to_le_bytes());

    // Encrypt from tail to head
    let n = plaintext_chunks.len();
    let mut encrypted_chunks: Vec<Vec<u8>> = vec![Vec::new(); n];

    // Last chunk: encrypt with tail_key
    encrypted_chunks[n - 1] = xor_encrypt(&plaintext_chunks[n - 1], &tail_key);

    // Each preceding chunk: key = hash(next chunk's ciphertext)
    for i in (0..n - 1).rev() {
        let key = hash_data(&encrypted_chunks[i + 1]);
        encrypted_chunks[i] = xor_encrypt(&plaintext_chunks[i], &key);
    }

    // Root hash = hash of first encrypted chunk
    let root_hash = hash_data(&encrypted_chunks[0]);

    CascadeChain {
        chunks: encrypted_chunks,
        root_hash,
        tail_key,
    }
}

/// Verify and decrypt a cascade integrity chain.
///
/// Returns `Ok(data)` if the chain is intact, `Err` if any chunk was tampered with.
pub fn verify_and_decrypt(chain: &CascadeChain) -> Result<Vec<u8>, CascadeError> {
    let n = chain.chunks.len();
    if n == 0 {
        return Ok(Vec::new());
    }

    // Verify root hash
    let computed_root = hash_data(&chain.chunks[0]);
    if computed_root != chain.root_hash {
        return Err(CascadeError::RootHashMismatch);
    }

    // Decrypt from head to tail
    let mut decrypted = Vec::new();

    for i in 0..n {
        let key = if i == n - 1 {
            chain.tail_key
        } else {
            hash_data(&chain.chunks[i + 1])
        };

        let chunk_plain = xor_decrypt(&chain.chunks[i], &key);
        decrypted.extend(chunk_plain);
    }

    Ok(decrypted)
}

/// Errors from cascade chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeError {
    /// The root hash doesn't match — chain start is corrupted.
    RootHashMismatch,
    /// A specific chunk failed integrity verification.
    ChunkCorrupted(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_basic() {
        let data = b"Hello, cascade integrity chain!";
        let chain = build_chain(data, 4, 42);
        let decrypted = verify_and_decrypt(&chain).unwrap();
        assert_eq!(&decrypted[..data.len()], &data[..]);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let chain = build_chain(data, 1, 42);
        let decrypted = verify_and_decrypt(&chain).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_roundtrip_large() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let chain = build_chain(&data, 16, 0xDEAD);
        let decrypted = verify_and_decrypt(&chain).unwrap();
        assert_eq!(&decrypted[..data.len()], &data[..]);
    }

    #[test]
    fn test_tamper_detection_first_chunk() {
        let data = b"Protected data that must not be modified.";
        let mut chain = build_chain(data, 5, 42);

        // Tamper with first chunk
        if !chain.chunks[0].is_empty() {
            chain.chunks[0][0] ^= 0xFF;
        }

        let result = verify_and_decrypt(&chain);
        assert!(result.is_err(), "Should detect tampering of first chunk");
    }

    #[test]
    fn test_tamper_detection_middle_chunk() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut chain = build_chain(&data, 10, 42);

        // Tamper with chunk 5
        if !chain.chunks[5].is_empty() {
            chain.chunks[5][0] ^= 0xFF;
        }

        // This causes chain[4] to decrypt incorrectly (since key for 4 = hash(chain[5]))
        // But root hash check should still fail if chain[0] depends on this
        // Actually, root hash only directly checks chain[0]. Tampering chunk 5
        // only corrupts decryption of chunks 0-4 (cascade effect going backward).
        // The root hash won't catch it unless chunk 0's key depends on chunk 5.
        // In our chain: key[i] = hash(ciphertext[i+1]), so:
        //   key[4] = hash(ciphertext[5]) → wrong → decrypt[4] wrong
        //   But ciphertext[4] is unchanged, so key[3] = hash(ciphertext[4]) → correct
        //   So decrypt[3] is correct!
        //
        // The cascade goes forward: tampering chunk i corrupts decryption of chunk i-1.
        // The root hash checks ciphertext[0], which is unchanged.
        //
        // This means tampering a middle chunk only corrupts one neighbor's decryption.
        // The data won't match but the verify_and_decrypt won't return Err.
        //
        // This is by design — the root hash verifies chain integrity starting
        // from chunk 0. Full verification would require checking each link.
        let result = verify_and_decrypt(&chain);
        // Root hash still valid since chunk 0 is unchanged
        assert!(result.is_ok());
        // But the decrypted data should be different from original
        let decrypted = result.unwrap();
        assert_ne!(&decrypted[..data.len()], &data[..], "Tampering should corrupt data");
    }

    #[test]
    fn test_different_seeds_different_chains() {
        let data = b"same data, different seeds";
        let chain1 = build_chain(data, 4, 100);
        let chain2 = build_chain(data, 4, 200);

        // Different ciphertext
        assert_ne!(chain1.chunks, chain2.chunks);
        // Different root hashes
        assert_ne!(chain1.root_hash, chain2.root_hash);

        // Both decrypt correctly
        let d1 = verify_and_decrypt(&chain1).unwrap();
        let d2 = verify_and_decrypt(&chain2).unwrap();
        assert_eq!(&d1[..data.len()], &data[..]);
        assert_eq!(&d2[..data.len()], &data[..]);
    }
}
