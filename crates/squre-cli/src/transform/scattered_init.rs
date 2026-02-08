//! Scattered initialization injection.
//!
//! Splits initialization code across multiple PE entry points:
//! TLS callbacks, CRT initializers, entry point stubs, exception-based
//! init, and lazy initialization. All fragments must execute for the
//! VM to function correctly.

use rand::Rng;
use rand::SeedableRng;

/// Types of initialization points in a PE.
#[derive(Debug, Clone, Copy)]
pub enum InitPoint {
    /// TLS callback
    TlsCallback,
    /// CRT initializer (.CRT$XCU section)
    CrtInitializer,
    /// Entry point stub
    EntryPointStub,
    /// VEH-based init (trigger via intentional exception)
    ExceptionInit,
    /// Lazy init on first API call
    LazyInit,
}

/// A single initialization fragment.
#[derive(Debug, Clone)]
pub struct InitFragment {
    /// Type of initialization point.
    pub init_type: InitPoint,
    /// The x86-64 machine code for this fragment.
    pub code: Vec<u8>,
    /// Offset into the global init token where this fragment writes.
    pub token_offset: usize,
    /// The value this fragment writes to the token.
    pub token_value: u64,
}

/// Generate scattered initialization fragments from a seed.
///
/// Each fragment sets a portion of a global initialization token.
/// All fragments must execute for the full token to be assembled,
/// making it harder to bypass initialization.
pub fn generate_init_fragments(seed: u64, num_fragments: usize) -> Vec<InitFragment> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let num_fragments = num_fragments.min(5).max(1);

    let init_types = [
        InitPoint::TlsCallback,
        InitPoint::CrtInitializer,
        InitPoint::EntryPointStub,
        InitPoint::ExceptionInit,
        InitPoint::LazyInit,
    ];

    let mut fragments = Vec::with_capacity(num_fragments);

    for i in 0..num_fragments {
        let init_type = init_types[i % init_types.len()];
        let token_value: u64 = rng.gen();
        let token_offset = i * 8; // Each fragment writes 8 bytes at a different offset

        // Generate x86-64 stub: mov [rip+offset], imm64
        let code = generate_init_stub(token_offset, token_value, &mut rng);

        fragments.push(InitFragment {
            init_type,
            code,
            token_offset,
            token_value,
        });
    }

    fragments
}

/// Compute the expected full initialization token from fragments.
pub fn compute_expected_token(fragments: &[InitFragment]) -> Vec<u8> {
    let total_size = fragments.iter()
        .map(|f| f.token_offset + 8)
        .max()
        .unwrap_or(0);
    let mut token = vec![0u8; total_size];
    for frag in fragments {
        let bytes = frag.token_value.to_le_bytes();
        for (j, &b) in bytes.iter().enumerate() {
            if frag.token_offset + j < token.len() {
                token[frag.token_offset + j] = b;
            }
        }
    }
    token
}

/// Generate x86-64 machine code for an init stub.
///
/// The stub writes `token_value` to `[global_token_base + token_offset]`.
/// For simplicity, this generates a sequence of `mov` instructions
/// using absolute addressing (the actual base would be patched at link time).
fn generate_init_stub(token_offset: usize, token_value: u64, rng: &mut impl Rng) -> Vec<u8> {
    let mut code = Vec::new();

    // NOP sled (variable length for diversity)
    let nop_count = rng.gen_range(0..4);
    for _ in 0..nop_count {
        code.push(0x90); // NOP
    }

    // mov rax, imm64 (REX.W + B8+rd)
    code.push(0x48); // REX.W
    code.push(0xB8); // MOV RAX, imm64
    code.extend_from_slice(&token_value.to_le_bytes());

    // mov rcx, token_offset (if offset > 0)
    if token_offset > 0 {
        code.push(0x48); // REX.W
        code.push(0xB9); // MOV RCX, imm64
        code.extend_from_slice(&(token_offset as u64).to_le_bytes());
    }

    // ret (the actual store would need the base address, patched later)
    code.push(0xC3); // RET

    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_fragments() {
        let fragments = generate_init_fragments(42, 5);
        assert_eq!(fragments.len(), 5);

        // Each fragment should have different token offsets
        let offsets: Vec<usize> = fragments.iter().map(|f| f.token_offset).collect();
        let mut unique_offsets = offsets.clone();
        unique_offsets.sort();
        unique_offsets.dedup();
        assert_eq!(unique_offsets.len(), 5);
    }

    #[test]
    fn test_fragments_cover_all_init_types() {
        let fragments = generate_init_fragments(42, 5);
        let has_tls = fragments.iter().any(|f| matches!(f.init_type, InitPoint::TlsCallback));
        let has_crt = fragments.iter().any(|f| matches!(f.init_type, InitPoint::CrtInitializer));
        let has_ep = fragments.iter().any(|f| matches!(f.init_type, InitPoint::EntryPointStub));
        assert!(has_tls && has_crt && has_ep);
    }

    #[test]
    fn test_expected_token_computation() {
        let fragments = generate_init_fragments(42, 3);
        let token = compute_expected_token(&fragments);
        assert_eq!(token.len(), 24); // 3 fragments * 8 bytes each

        // Verify each fragment's value is in the token
        for frag in &fragments {
            let expected = frag.token_value.to_le_bytes();
            let actual = &token[frag.token_offset..frag.token_offset + 8];
            assert_eq!(actual, &expected);
        }
    }

    #[test]
    fn test_different_seeds_different_fragments() {
        let f1 = generate_init_fragments(100, 3);
        let f2 = generate_init_fragments(200, 3);
        // Token values should differ
        assert_ne!(f1[0].token_value, f2[0].token_value);
    }

    #[test]
    fn test_stub_code_is_valid() {
        let fragments = generate_init_fragments(42, 1);
        let code = &fragments[0].code;
        // Should contain at least MOV RAX, imm64 + RET
        assert!(code.len() >= 11); // 2 (REX+opcode) + 8 (imm64) + 1 (RET)
        // Should end with RET
        assert_eq!(*code.last().unwrap(), 0xC3);
    }
}
