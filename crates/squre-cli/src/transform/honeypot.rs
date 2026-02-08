//! SQURE Honeypot Module
//!
//! Implements decoy code and trap mechanisms to waste cracker time:
//!
//! 1. DECOY FUNCTIONS: Fake license checks that look real but do nothing
//! 2. TRAP CODE PATHS: Patchable-looking code that corrupts execution
//! 3. HONEYPOT STRINGS: Misleading strings to attract analysis
//! 4. POISON PATCHES: NOP-ing certain bytes corrupts crypto keys
//! 5. FAKE CRITICAL SECTIONS: Functions that appear important but are decoys

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Honeypot configuration
#[derive(Debug, Clone)]
pub struct HoneypotConfig {
    /// Number of decoy license check functions
    pub decoy_functions: u8,
    /// Number of trap code paths
    pub trap_paths: u8,
    /// Enable honeypot strings
    pub honeypot_strings: bool,
    /// Enable poison patches (CRC-linked code)
    pub poison_patches: bool,
    /// Enable cascade loop trap (patch→error→fix→error loop)
    pub cascade_loop: bool,
    /// Number of cascade chain nodes (each patch leads to next error)
    pub cascade_depth: u8,
    /// CEWE seed for randomization
    pub seed: u64,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            decoy_functions: 3,
            trap_paths: 2,
            honeypot_strings: true,
            poison_patches: true,
            cascade_loop: true,
            cascade_depth: 5,  // 5 levels of frustration
            seed: 0xDECAF_C0FFEE,
        }
    }
}

/// Generate honeypot section data
/// Returns (code_section, string_table, patch_locations)
pub fn generate_honeypot_section(config: &HoneypotConfig) -> HoneypotData {
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let mut code = Vec::new();
    let mut strings = Vec::new();
    let mut trap_offsets = Vec::new();
    let mut poison_offsets = Vec::new();

    // ═══ 1. Decoy License Check Functions ═══
    // These look like real license validation but always fail silently
    for i in 0..config.decoy_functions {
        let func_offset = code.len() as u32;
        emit_decoy_license_check(&mut code, &mut rng, i);
        trap_offsets.push(TrapLocation {
            offset: func_offset,
            trap_type: TrapType::DecoyFunction,
            description: format!("Decoy license check #{}", i),
        });
    }

    // ═══ 2. Trap Code Paths ═══
    // Code that looks like it bypasses protection but triggers anti-tamper
    for i in 0..config.trap_paths {
        let trap_offset = code.len() as u32;
        let poison_loc = emit_trap_code_path(&mut code, &mut rng, i);
        trap_offsets.push(TrapLocation {
            offset: trap_offset,
            trap_type: TrapType::TrapPath,
            description: format!("Trap path #{}", i),
        });
        if let Some(loc) = poison_loc {
            poison_offsets.push(loc);
        }
    }

    // ═══ 3. Honeypot Strings ═══
    if config.honeypot_strings {
        strings.extend_from_slice(&generate_honeypot_strings(&mut rng));
    }

    // ═══ 4. Poison Patch Locations ═══
    if config.poison_patches {
        let poison_trap = emit_poison_patch_trap(&mut code, &mut rng);
        poison_offsets.push(poison_trap);
    }

    // ═══ 5. Fake Critical Section ═══
    let fake_critical_offset = code.len() as u32;
    emit_fake_critical_section(&mut code, &mut rng);
    trap_offsets.push(TrapLocation {
        offset: fake_critical_offset,
        trap_type: TrapType::FakeCritical,
        description: "Fake critical protection check".to_string(),
    });

    // ═══ 6. Cascade Loop Trap ═══
    // パッチ→エラー→修正→エラー治ってない...無限ループ
    if config.cascade_loop {
        let cascade_data = emit_cascade_corruption_chain(&mut code, &mut rng, config.cascade_depth);
        for (i, node) in cascade_data.nodes.iter().enumerate() {
            trap_offsets.push(TrapLocation {
                offset: node.offset,
                trap_type: TrapType::CascadeLoop,
                description: format!("Cascade trap #{} -> #{}", i, (i + 1) % cascade_data.nodes.len()),
            });
            poison_offsets.push(PoisonLocation {
                check_offset: node.offset,
                protected_start: node.checksum_region_start,
                protected_size: node.checksum_region_size,
                expected_value: node.expected_checksum,
            });
        }
    }

    // Pad to 16-byte alignment
    while code.len() % 16 != 0 {
        code.push(0xCC); // INT3 padding (trap if executed)
    }

    HoneypotData {
        code,
        strings,
        trap_locations: trap_offsets,
        poison_locations: poison_offsets,
    }
}

/// Honeypot data to embed in PE
#[derive(Debug)]
pub struct HoneypotData {
    /// Executable code section
    pub code: Vec<u8>,
    /// String table (misleading strings)
    pub strings: Vec<u8>,
    /// Locations of trap code
    pub trap_locations: Vec<TrapLocation>,
    /// Locations that corrupt keys if patched
    pub poison_locations: Vec<PoisonLocation>,
}

#[derive(Debug, Clone)]
pub struct TrapLocation {
    pub offset: u32,
    pub trap_type: TrapType,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum TrapType {
    DecoyFunction,
    TrapPath,
    FakeCritical,
    HoneypotString,
    /// Cascading corruption - patching one location breaks another in a chain
    CascadeLoop,
}

#[derive(Debug, Clone)]
pub struct PoisonLocation {
    /// Offset of the poison check instruction
    pub check_offset: u32,
    /// Offset of bytes that must not be modified
    pub protected_start: u32,
    /// Size of protected region
    pub protected_size: u32,
    /// Expected checksum/hash of protected region
    pub expected_value: u64,
}

/// A node in the cascade corruption chain
#[derive(Debug, Clone)]
pub struct CascadeNode {
    /// Code offset of this node
    pub offset: u32,
    /// Region whose checksum affects the NEXT node's error
    pub checksum_region_start: u32,
    pub checksum_region_size: u32,
    pub expected_checksum: u64,
    /// Error string index shown when THIS node is corrupted
    pub error_string_index: u8,
}

/// The entire cascade chain data
#[derive(Debug)]
pub struct CascadeChainData {
    pub nodes: Vec<CascadeNode>,
    /// Misleading error strings embedded in the code
    pub error_strings: Vec<String>,
}

/// Emit a decoy license check function
/// Looks like real validation but always returns 0 (invalid)
fn emit_decoy_license_check(s: &mut Vec<u8>, rng: &mut ChaCha20Rng, index: u8) {
    // Function prologue - looks like a real function
    s.push(0x55); // push rbp
    s.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]); // sub rsp, 0x40

    // Save "important" registers (makes it look legit)
    s.push(0x53); // push rbx
    s.push(0x56); // push rsi
    s.push(0x57); // push rdi

    // Fake license key validation loop
    // This looks like it's checking a license but does nothing useful
    s.extend_from_slice(&[0x48, 0x89, 0xCE]); // mov rsi, rcx (license key ptr)
    s.extend_from_slice(&[0x31, 0xDB]); // xor ebx, ebx (counter = 0)
    s.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi (hash = 0)

    // Loop header
    let loop_start = s.len();
    s.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x1E]); // movzx eax, byte [rsi+rbx]
    s.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    let exit_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]); // jz exit (patch later)

    // Fake hash computation (looks complex but result is discarded)
    s.extend_from_slice(&[0xC1, 0xCF, 0x0D]); // ror edi, 13
    s.extend_from_slice(&[0x01, 0xC7]); // add edi, eax
    s.extend_from_slice(&[0x69, 0xFF]); // imul edi, edi, random_const
    s.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    s.extend_from_slice(&[0x31, 0xC7]); // xor edi, eax

    // Increment counter
    s.extend_from_slice(&[0x48, 0xFF, 0xC3]); // inc rbx
    s.extend_from_slice(&[0x48, 0x83, 0xFB, 0x20]); // cmp rbx, 32
    let loop_jl = s.len();
    let disp = (loop_start as i8) - (loop_jl as i8 + 2);
    s.extend_from_slice(&[0x7C, disp as u8]); // jl loop_start

    // Patch exit jump
    let exit_target = s.len();
    s[exit_jz + 1] = (exit_target - exit_jz - 2) as u8;

    // THE TRAP: This comparison looks like the real check
    // Crackers will try to patch this, but it's a decoy
    s.extend_from_slice(&[0x81, 0xFF]); // cmp edi, magic_const
    s.extend_from_slice(&(0x5152_4553_u32 ^ (index as u32)).to_le_bytes()); // "SQRE" XOR index

    // Fake success path (never taken in real execution)
    s.extend_from_slice(&[0x75, 0x0C]); // jnz fail  <-- Crackers will NOP this
    // But even if they do, this path just returns 0 anyway!
    s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0 (fake success)
    s.extend_from_slice(&[0xEB, 0x05]); // jmp epilogue

    // Fail path
    s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0 (fail)

    // Epilogue
    s.push(0x5F); // pop rdi
    s.push(0x5E); // pop rsi
    s.push(0x5B); // pop rbx
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]); // add rsp, 0x40
    s.push(0x5D); // pop rbp
    s.push(0xC3); // ret

    // Add some junk data that looks like lookup tables
    for _ in 0..16 {
        s.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    }
}

/// Emit trap code path
/// Looks like it can be patched to bypass protection, but patching corrupts execution
fn emit_trap_code_path(s: &mut Vec<u8>, rng: &mut ChaCha20Rng, index: u8) -> Option<PoisonLocation> {
    let start_offset = s.len() as u32;

    // This looks like a conditional check that can be bypassed
    s.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    s.extend_from_slice(&[0x74, 0x15]); // jz skip_protection

    // "Protection code" that looks important
    // But actually, these bytes are checksummed elsewhere
    let protected_start = s.len() as u32;
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    let poison_key = rng.gen::<u64>();
    s.extend_from_slice(&poison_key.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x31, 0xC1]); // xor rcx, rax
    let protected_end = s.len() as u32;

    // Skip label
    s.extend_from_slice(&[0x90, 0x90]); // nop nop (looks like patch target)

    // More decoy code
    s.extend_from_slice(&[0x48, 0x89, 0xC8]); // mov rax, rcx
    s.push(0xC3); // ret

    // Add fake error strings reference
    s.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // null padding
    s.extend_from_slice(&((0x4C696365 ^ (index as u32)) as u32).to_le_bytes()); // "Lice" obfuscated

    Some(PoisonLocation {
        check_offset: start_offset,
        protected_start,
        protected_size: protected_end - protected_start,
        expected_value: poison_key,
    })
}

/// Generate honeypot strings that attract crackers
fn generate_honeypot_strings(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut strings = Vec::new();

    // These strings look like success messages but are never actually used
    let decoy_strings = [
        "License validated successfully!\0",
        "Premium features unlocked!\0",
        "Full version activated!\0",
        "Registration complete!\0",
        "License key accepted!\0",
        "Pro features enabled!\0",
        "VALID_LICENSE_MARKER\0",
        "PROTECTION_BYPASSED\0",  // Obvious bait
        "DEBUG_MODE_ENABLED\0",   // More bait
        "check_license_real\0",   // Fake function name
        "bypass_protection\0",    // More fake names
        "patch_here_to_crack\0",  // Obvious honeypot
    ];

    for s in decoy_strings.iter() {
        // XOR with random value to make it look like decrypted data
        let xor_key = rng.gen::<u8>();
        for &b in s.as_bytes() {
            strings.push(b ^ xor_key);
        }
        strings.push(xor_key); // Store key at end (crackers will find this pattern)
    }

    // Add some fake API names that look like protection checks
    let fake_apis = [
        "IsDebuggerPresent_real\0",
        "CheckRemoteDebugger\0",
        "VerifyLicenseKey\0",
        "DecryptProtectedCode\0",
    ];

    for s in fake_apis.iter() {
        strings.extend_from_slice(s.as_bytes());
    }

    strings
}

/// Emit poison patch trap
/// If certain bytes are NOPped out, this corrupts the crypto key
fn emit_poison_patch_trap(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) -> PoisonLocation {
    let start_offset = s.len() as u32;

    // This looks like an anti-debug check that can be NOPped
    // But it's actually computing a value used in key derivation!
    let protected_start = s.len() as u32;

    // Looks like: if (debugger) { exit(); }
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25]); // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]); // movzx eax, byte [rax+2]
    s.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    s.extend_from_slice(&[0x75, 0x05]); // jnz exit_program

    let protected_end = s.len() as u32;

    // "Normal" path
    s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    s.extend_from_slice(&[0xEB, 0x03]); // jmp continue

    // "Exit" path (looks like it exits, but actually just returns 0)
    s.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    s.push(0x90); // nop

    // Continue
    s.push(0xC3); // ret

    // The checksum of the protected region is used in key derivation
    // If patched, the key becomes wrong -> silent decryption failure
    let expected = compute_region_hash(s, protected_start as usize, (protected_end - protected_start) as usize);

    PoisonLocation {
        check_offset: start_offset,
        protected_start,
        protected_size: protected_end - protected_start,
        expected_value: expected,
    }
}

/// Emit fake critical section
/// Looks like the heart of protection but is actually a decoy
fn emit_fake_critical_section(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // Function header with impressive-looking name data nearby
    let magic = 0x53515552_u32; // "SQUR"

    // Prologue
    s.push(0x55); // push rbp
    s.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    s.extend_from_slice(&[0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00]); // sub rsp, 0x80

    // Fake XTEA-like operations (looks like decryption)
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    s.extend_from_slice(&rng.gen::<u64>().to_le_bytes());
    s.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
    s.extend_from_slice(&0x9E3779B9_u64.to_le_bytes()); // XTEA delta (bait!)

    // Fake round loop
    s.extend_from_slice(&[0xBB, 0x20, 0x00, 0x00, 0x00]); // mov ebx, 32 (looks like XTEA rounds)
    let loop_start = s.len();
    s.extend_from_slice(&[0x48, 0x01, 0xC8]); // add rax, rcx
    s.extend_from_slice(&[0x48, 0xC1, 0xC0, 0x05]); // rol rax, 5
    s.extend_from_slice(&[0x48, 0x31, 0xC8]); // xor rax, rcx
    s.extend_from_slice(&[0xFF, 0xCB]); // dec ebx
    let disp = (loop_start as i8) - (s.len() as i8 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop

    // Fake comparison (THE TRAP)
    s.extend_from_slice(&[0x48, 0x3D]); // cmp eax, imm32
    s.extend_from_slice(&magic.to_le_bytes());
    s.extend_from_slice(&[0x75, 0x0A]); // jnz fail <-- Patch target!

    // "Success" - but actually does nothing useful
    s.extend_from_slice(&[0x48, 0x31, 0xC0]); // xor rax, rax
    s.extend_from_slice(&[0x48, 0xFF, 0xC0]); // inc rax (return 1 = "success")
    s.extend_from_slice(&[0xEB, 0x03]); // jmp epilogue

    // Fail path
    s.extend_from_slice(&[0x48, 0x31, 0xC0]); // xor rax, rax (return 0)

    // Epilogue
    s.extend_from_slice(&[0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00]); // add rsp, 0x80
    s.push(0x5D); // pop rbp
    s.push(0xC3); // ret

    // Fake key data (looks like embedded encryption key)
    for _ in 0..4 {
        s.extend_from_slice(&rng.gen::<u64>().to_le_bytes());
    }
}

/// Compute hash of a region (used for poison detection)
fn compute_region_hash(data: &[u8], start: usize, len: usize) -> u64 {
    let mut hash: u64 = 0x517CC1B727220A95;
    for i in 0..len {
        if start + i < data.len() {
            let b = data[start + i] as u64;
            hash = hash.wrapping_mul(0x5DEECE66D);
            hash = hash.wrapping_add(b);
            hash ^= hash >> 17;
        }
    }
    hash
}

/// Emit cascade corruption chain
/// Each node checksums the PREVIOUS node. Patching node N corrupts node N+1's check.
/// Error messages point to the NEXT node, creating an infinite loop of frustration.
///
/// パッチ→エラー→修正→エラー治ってない...無限ループ
fn emit_cascade_corruption_chain(s: &mut Vec<u8>, rng: &mut ChaCha20Rng, depth: u8) -> CascadeChainData {
    let mut nodes = Vec::new();
    let mut error_strings = Vec::new();

    // Misleading error messages that point crackers in circles
    let error_templates = [
        "License check failed at offset 0x{:04X}. Try patching the jump.",
        "Invalid key derivation at 0x{:04X}. Check the XOR operation.",
        "Decryption error near 0x{:04X}. The constant looks wrong.",
        "Validation mismatch at 0x{:04X}. NOP the comparison?",
        "Hash verification failed at 0x{:04X}. Fix the loop counter.",
        "CRC error detected at 0x{:04X}. The magic constant is off.",
        "Key expansion error at 0x{:04X}. Check the shift amount.",
        "Anti-tamper triggered at 0x{:04X}. Try changing the branch.",
    ];

    // First pass: create all nodes (we need to know offsets before computing checksums)
    let mut node_offsets = Vec::new();
    let base_offset = s.len() as u32;

    for i in 0..depth {
        let node_offset = s.len() as u32;
        node_offsets.push(node_offset);

        // Each node looks like a patchable check
        emit_cascade_node(s, rng, i, base_offset);
    }

    // Add misleading error string table
    let error_table_offset = s.len() as u32;
    for i in 0..depth {
        // Error for node i points to node (i+1) % depth
        let next_node_offset = node_offsets[((i as usize) + 1) % (depth as usize)];
        let error_msg = format!(
            "{}",
            error_templates[rng.gen_range(0..error_templates.len())]
        ).replace("{:04X}", &format!("{:04X}", next_node_offset));
        error_strings.push(error_msg.clone());

        // Embed the string (XOR obfuscated)
        let xor_key = rng.gen::<u8>().wrapping_add(0x41); // Ensure printable
        for &b in error_msg.as_bytes() {
            s.push(b ^ xor_key);
        }
        s.push(0x00 ^ xor_key); // Null terminator
        s.push(xor_key); // Store key for "decryption"
    }

    // Second pass: compute checksums
    // Node i checksums node (i-1), so patching (i-1) breaks node i's check
    for i in 0..depth {
        let prev_idx = if i == 0 { depth - 1 } else { i - 1 };
        let prev_offset = node_offsets[prev_idx as usize];
        let curr_offset = node_offsets[i as usize];

        // Region to checksum: from prev node start to curr node start
        let checksum_start = prev_offset;
        let checksum_size = if prev_idx < i {
            curr_offset - prev_offset
        } else {
            // Wrap around case
            (s.len() as u32 - prev_offset).min(64)
        };

        let expected = compute_region_hash(s, checksum_start as usize, checksum_size as usize);

        nodes.push(CascadeNode {
            offset: curr_offset,
            checksum_region_start: checksum_start,
            checksum_region_size: checksum_size.min(64),
            expected_checksum: expected,
            error_string_index: i,
        });
    }

    CascadeChainData { nodes, error_strings }
}

/// Emit a single cascade node - looks like a patchable protection check
fn emit_cascade_node(s: &mut Vec<u8>, rng: &mut ChaCha20Rng, index: u8, base_offset: u32) {
    // Vary the appearance so crackers don't recognize the pattern
    let variant = index % 4;

    match variant {
        0 => emit_cascade_variant_debugger_check(s, rng),
        1 => emit_cascade_variant_license_check(s, rng),
        2 => emit_cascade_variant_crc_check(s, rng),
        3 => emit_cascade_variant_timing_check(s, rng),
        _ => unreachable!(),
    }

    // Add variable padding to make offsets less predictable
    let padding = rng.gen_range(4..16);
    for _ in 0..padding {
        s.push(rng.gen::<u8>());
    }
}

/// Cascade variant: looks like a debugger check
fn emit_cascade_variant_debugger_check(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // push rbp; mov rbp, rsp
    s.push(0x55);
    s.extend_from_slice(&[0x48, 0x89, 0xE5]);

    // PEB.BeingDebugged check
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25]); // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]); // movzx eax, byte [rax+2]
    s.extend_from_slice(&[0x85, 0xC0]); // test eax, eax

    // THE TRAP: This JNZ looks patchable but is checksummed by next node
    s.extend_from_slice(&[0x75, 0x08]); // jnz detected

    // "Safe" path
    s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    s.extend_from_slice(&[0xEB, 0x05]); // jmp end

    // "Detected" path
    s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0

    // Epilogue
    s.push(0x5D); // pop rbp
    s.push(0xC3); // ret

    // Random junk that looks like data
    for _ in 0..4 {
        s.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    }
}

/// Cascade variant: looks like a license key check
fn emit_cascade_variant_license_check(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // push rbx
    s.push(0x53);
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

    // Load "license key" and compute hash
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, key_constant
    s.extend_from_slice(&rng.gen::<u64>().to_le_bytes());
    s.extend_from_slice(&[0x48, 0xB9]); // mov rcx, expected
    s.extend_from_slice(&rng.gen::<u64>().to_le_bytes());

    // XOR and compare
    s.extend_from_slice(&[0x48, 0x31, 0xC8]); // xor rax, rcx
    s.extend_from_slice(&[0x48, 0x3D]); // cmp eax, magic
    s.extend_from_slice(&(0x4C494345_u32).to_le_bytes()); // "LICE"

    // THE TRAP: JNE that looks like the bypass point
    s.extend_from_slice(&[0x75, 0x07]); // jne invalid

    // Valid path
    s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    s.extend_from_slice(&[0xEB, 0x05]); // jmp end

    // Invalid path
    s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0

    // Epilogue
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
    s.push(0x5B); // pop rbx
    s.push(0xC3); // ret
}

/// Cascade variant: looks like a CRC/checksum verification
fn emit_cascade_variant_crc_check(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    s.push(0x55); // push rbp
    s.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    s.push(0x57); // push rdi
    s.push(0x56); // push rsi

    // CRC32 lookalike
    s.extend_from_slice(&[0xBF]); // mov edi, init_crc
    s.extend_from_slice(&(0xFFFFFFFF_u32).to_le_bytes());
    s.extend_from_slice(&[0xBE, 0x10, 0x00, 0x00, 0x00]); // mov esi, 16 (count)

    // Fake CRC loop
    let loop_start = s.len();
    s.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    s.extend_from_slice(&[0xC1, 0xCF, 0x08]); // ror edi, 8
    s.extend_from_slice(&[0x31, 0xC7]); // xor edi, eax
    s.extend_from_slice(&[0xFF, 0xCE]); // dec esi
    let disp = (loop_start as i8) - (s.len() as i8 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop

    // Compare with expected CRC
    s.extend_from_slice(&[0x81, 0xFF]); // cmp edi, expected_crc
    s.extend_from_slice(&rng.gen::<u32>().to_le_bytes());

    // THE TRAP: conditional jump
    s.extend_from_slice(&[0x74, 0x05]); // je valid

    // Invalid
    s.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    s.extend_from_slice(&[0xEB, 0x05]); // jmp end

    // Valid
    s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1

    // Epilogue
    s.push(0x5E); // pop rsi
    s.push(0x5F); // pop rdi
    s.push(0x5D); // pop rbp
    s.push(0xC3); // ret
}

/// Cascade variant: looks like a timing/RDTSC check
fn emit_cascade_variant_timing_check(s: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    s.push(0x53); // push rbx
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x10]); // sub rsp, 0x10

    // RDTSC (read timestamp counter)
    s.extend_from_slice(&[0x0F, 0x31]); // rdtsc
    s.extend_from_slice(&[0x48, 0xC1, 0xE2, 0x20]); // shl rdx, 32
    s.extend_from_slice(&[0x48, 0x09, 0xD0]); // or rax, rdx
    s.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax

    // Some "work"
    s.extend_from_slice(&[0xB9, 0x64, 0x00, 0x00, 0x00]); // mov ecx, 100
    let loop_start = s.len();
    s.push(0x90); // nop
    s.push(0x90); // nop
    s.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let disp = (loop_start as i8) - (s.len() as i8 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop

    // Second RDTSC
    s.extend_from_slice(&[0x0F, 0x31]); // rdtsc
    s.extend_from_slice(&[0x48, 0xC1, 0xE2, 0x20]); // shl rdx, 32
    s.extend_from_slice(&[0x48, 0x09, 0xD0]); // or rax, rdx

    // Check time difference
    s.extend_from_slice(&[0x48, 0x29, 0xD8]); // sub rax, rbx
    s.extend_from_slice(&[0x48, 0x3D]); // cmp eax, threshold
    s.extend_from_slice(&(0x10000_u32).to_le_bytes());

    // THE TRAP: JA that looks like anti-debug bypass
    s.extend_from_slice(&[0x77, 0x05]); // ja timeout

    // OK path
    s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    s.extend_from_slice(&[0xEB, 0x05]); // jmp end

    // Timeout path
    s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0

    // Epilogue
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x10]); // add rsp, 0x10
    s.push(0x5B); // pop rbx
    s.push(0xC3); // ret
}

/// Generate honeypot section name (looks like real protection section)
pub fn generate_honeypot_section_name(seed: u64) -> String {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let names = [".check", ".valid", ".licen", ".prot", ".auth", ".key"];
    let base = names[rng.gen_range(0..names.len())];
    format!("{}{}", base, rng.gen_range(0..10))
}

/// Create runtime verification code that checks poison locations
/// This should be called from the main protection code
pub fn emit_poison_verification(s: &mut Vec<u8>, poison_locs: &[PoisonLocation], rng: &mut ChaCha20Rng) {
    if poison_locs.is_empty() {
        return;
    }

    // For each poison location, compute hash and compare
    // If mismatch, corrupt r8 (poison accumulator)
    for loc in poison_locs {
        // lea rsi, [rip + protected_region]
        let lea_patch = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);

        // mov ecx, protected_size
        s.extend_from_slice(&[0xB9]);
        s.extend_from_slice(&loc.protected_size.to_le_bytes());

        // Compute hash
        s.extend_from_slice(&[0x48, 0xB8]); // mov rax, initial_hash
        s.extend_from_slice(&0x517CC1B727220A95_u64.to_le_bytes());

        let hash_loop = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x16]); // movzx edx, byte [rsi]
        // imul rax, rax, 0x5DEECE66D requires movabs + imul
        s.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
        s.extend_from_slice(&0x5DEECE66D_u64.to_le_bytes());
        s.extend_from_slice(&[0x48, 0x0F, 0xAF, 0xC2]); // imul rax, rdx
        s.extend_from_slice(&[0x48, 0x01, 0xD0]); // add rax, rdx
        s.extend_from_slice(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x11]); // shr rdx, 17
        s.extend_from_slice(&[0x48, 0x31, 0xD0]); // xor rax, rdx
        s.extend_from_slice(&[0x48, 0xFF, 0xC6]); // inc rsi
        s.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
        let disp = (hash_loop as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0x75, disp as u8]); // jnz hash_loop

        // Compare with expected
        s.extend_from_slice(&[0x48, 0xB9]); // mov rcx, expected
        s.extend_from_slice(&loc.expected_value.to_le_bytes());
        s.extend_from_slice(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
        s.extend_from_slice(&[0x74, 0x08]); // je ok
        s.extend_from_slice(&[0x49, 0x81, 0xC8]); // or r8, poison
        s.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        // ok:

        // Add some junk to vary the pattern
        super::hardening::emit_junk_code(s, rng, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeypot_generation() {
        let config = HoneypotConfig::default();
        let data = generate_honeypot_section(&config);

        assert!(!data.code.is_empty());
        assert!(!data.strings.is_empty());
        assert!(!data.trap_locations.is_empty());
        assert!(!data.poison_locations.is_empty());
    }

    #[test]
    fn test_decoy_function_size() {
        let mut code = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        emit_decoy_license_check(&mut code, &mut rng, 0);

        // Should be substantial but not huge
        assert!(code.len() > 50);
        assert!(code.len() < 500);
    }
}
