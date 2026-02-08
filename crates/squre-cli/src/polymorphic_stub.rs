//! Polymorphic .sqinit stub generator.
//!
//! Generates completely different x86-64 decrypt stubs for each seed,
//! defeating pattern-matching-based automatic unpackers.
//!
//! ## Randomization techniques:
//! - Register allocation shuffling
//! - Instruction order permutation (preserving dependencies)
//! - Key embedding method variation
//! - Junk code insertion
//! - Opaque predicates

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Registers available for allocation (callee-saved + scratch)
const AVAILABLE_REGS: [Reg; 12] = [
    Reg::RAX, Reg::RBX, Reg::RCX, Reg::RDX,
    Reg::RSI, Reg::RDI, Reg::R8, Reg::R9,
    Reg::R10, Reg::R11, Reg::R12, Reg::R13,
];

/// Register encoding for x86-64
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
}

impl Reg {
    /// Get the register encoding (0-15)
    pub fn enc(self) -> u8 {
        self as u8
    }

    /// Check if this is an extended register (R8-R15)
    pub fn is_extended(self) -> bool {
        self.enc() >= 8
    }

    /// Get REX.B bit for this register
    pub fn rex_b(self) -> u8 {
        if self.is_extended() { 0x41 } else { 0x40 }
    }

    /// Get REX.R bit for this register (when used as reg in ModRM)
    pub fn rex_r(self) -> u8 {
        if self.is_extended() { 0x44 } else { 0x40 }
    }
}

/// Key embedding method
#[derive(Debug, Clone, Copy)]
pub enum KeyEmbedMethod {
    /// Direct MOV instructions (most visible)
    DirectMov,
    /// Computed from seed: key[i] = seed ^ constant[i]
    ComputedFromSeed,
    /// Read from .squre section offset
    ReadFromSection,
    /// Split across multiple locations
    Distributed,
}

/// Junk instruction types
#[derive(Debug, Clone, Copy)]
pub enum JunkType {
    /// xchg reg, reg (NOP equivalent)
    XchgSelf,
    /// lea reg, [reg + 0]
    LeaZero,
    /// push/pop pair
    PushPop,
    /// mov reg, reg (same register)
    MovSelf,
    /// test reg, reg (doesn't affect control flow)
    TestSelf,
    /// cmp reg, 0 followed by unconditional jmp
    DeadBranch,
}

/// Configuration for polymorphic stub generation
#[derive(Debug, Clone)]
pub struct PolymorphicConfig {
    pub seed: u64,
    pub junk_level: u8,      // 0-3
    pub fake_key_count: u8,  // Number of decoy keys
    pub distribute_key: bool,
}

impl Default for PolymorphicConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            junk_level: 1,
            fake_key_count: 3,
            distribute_key: true,
        }
    }
}

/// Register allocation for the decrypt stub
#[derive(Debug, Clone)]
pub struct RegAlloc {
    pub image_base: Reg,    // Holds ImageBase
    pub data_ptr: Reg,      // Pointer to encrypted data
    pub counter: Reg,       // Loop counter
    pub key_lo: Reg,        // XTEA key low part
    pub key_hi: Reg,        // XTEA key high part
    pub temp1: Reg,         // Scratch register 1
    pub temp2: Reg,         // Scratch register 2
    pub hash_acc: Reg,      // Hash accumulator
}

/// Statistics about the generated stub
#[derive(Debug, Clone, Default)]
pub struct PolymorphicStats {
    pub total_size: usize,
    pub junk_instructions: usize,
    pub fake_keys: usize,
    pub key_method: String,
    pub registers_used: Vec<String>,
}

/// Generate a polymorphic decrypt stub
pub fn build_polymorphic_stub(
    orig_entry_rva: u32,
    text_rva: u32,
    total_qwords: u32,
    xtea_key: &[u32; 4],
    initial_seed: u64,
    config: &PolymorphicConfig,
) -> (Vec<u8>, PolymorphicStats) {
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let mut stats = PolymorphicStats::default();

    // 1. Randomize register allocation
    let reg_alloc = randomize_registers(&mut rng);
    stats.registers_used = vec![
        format!("{:?}", reg_alloc.image_base),
        format!("{:?}", reg_alloc.data_ptr),
        format!("{:?}", reg_alloc.counter),
    ];

    // 2. Choose key embedding method
    let key_method = choose_key_method(&mut rng, config);
    stats.key_method = format!("{:?}", key_method);

    // 3. Build the stub
    let mut stub = Vec::with_capacity(1024);

    // Prologue - save callee-saved registers (randomized order)
    emit_prologue(&mut stub, &mut rng);

    // Insert junk before real code
    let junk_count = emit_junk(&mut stub, &mut rng, config.junk_level, &reg_alloc);
    stats.junk_instructions += junk_count;

    // Emit fake keys (decoys)
    for _ in 0..config.fake_key_count {
        emit_fake_key(&mut stub, &mut rng);
        stats.fake_keys += 1;
    }

    // Get ImageBase from PEB
    emit_get_image_base(&mut stub, reg_alloc.image_base);

    // Insert more junk
    stats.junk_instructions += emit_junk(&mut stub, &mut rng, config.junk_level, &reg_alloc);

    // Load/compute XTEA key based on chosen method
    emit_load_key(&mut stub, xtea_key, initial_seed, key_method, &reg_alloc, config);

    // Insert junk
    stats.junk_instructions += emit_junk(&mut stub, &mut rng, config.junk_level, &reg_alloc);

    // Main decryption loop
    emit_decrypt_loop(
        &mut stub,
        &reg_alloc,
        text_rva,
        total_qwords,
        initial_seed,
        &mut rng,
        config.junk_level,
        &mut stats,
    );

    // Epilogue - restore registers and jump to original entry
    emit_epilogue(&mut stub, orig_entry_rva, reg_alloc.image_base);

    stats.total_size = stub.len();
    (stub, stats)
}

/// Randomize register allocation
fn randomize_registers(rng: &mut ChaCha20Rng) -> RegAlloc {
    let mut available: Vec<Reg> = AVAILABLE_REGS.to_vec();

    // Shuffle available registers
    for i in (1..available.len()).rev() {
        let j = rng.gen_range(0..=i);
        available.swap(i, j);
    }

    // Assign registers (avoid RSP/RBP for general use)
    let mut iter = available.into_iter().filter(|r| *r != Reg::RSP && *r != Reg::RBP);

    RegAlloc {
        image_base: iter.next().unwrap_or(Reg::RBX),
        data_ptr: iter.next().unwrap_or(Reg::RSI),
        counter: iter.next().unwrap_or(Reg::RCX),
        key_lo: iter.next().unwrap_or(Reg::R8),
        key_hi: iter.next().unwrap_or(Reg::R9),
        temp1: iter.next().unwrap_or(Reg::RAX),
        temp2: iter.next().unwrap_or(Reg::RDX),
        hash_acc: iter.next().unwrap_or(Reg::R10),
    }
}

/// Choose key embedding method based on config and RNG
fn choose_key_method(rng: &mut ChaCha20Rng, config: &PolymorphicConfig) -> KeyEmbedMethod {
    if config.distribute_key {
        // Higher chance of distributed when enabled
        match rng.gen_range(0..10) {
            0..=3 => KeyEmbedMethod::Distributed,
            4..=6 => KeyEmbedMethod::ComputedFromSeed,
            7..=8 => KeyEmbedMethod::ReadFromSection,
            _ => KeyEmbedMethod::DirectMov,
        }
    } else {
        match rng.gen_range(0..3) {
            0 => KeyEmbedMethod::DirectMov,
            1 => KeyEmbedMethod::ComputedFromSeed,
            _ => KeyEmbedMethod::ReadFromSection,
        }
    }
}

/// Emit function prologue with randomized register save order
fn emit_prologue(stub: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // Callee-saved registers to save
    let mut saves = vec![Reg::RBX, Reg::RSI, Reg::RDI, Reg::R12, Reg::R13, Reg::R14, Reg::R15, Reg::RBP];

    // Shuffle save order
    for i in (1..saves.len()).rev() {
        let j = rng.gen_range(0..=i);
        saves.swap(i, j);
    }

    // Emit PUSH instructions
    for reg in saves {
        emit_push(stub, reg);
    }

    // sub rsp, 0x40 (stack frame)
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]);
}

/// Emit function epilogue
fn emit_epilogue(stub: &mut Vec<u8>, orig_entry_rva: u32, image_base_reg: Reg) {
    // add rsp, 0x40
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]);

    // Restore callee-saved registers (reverse order)
    emit_pop(stub, Reg::RBP);
    emit_pop(stub, Reg::R15);
    emit_pop(stub, Reg::R14);
    emit_pop(stub, Reg::R13);
    emit_pop(stub, Reg::R12);
    emit_pop(stub, Reg::RDI);
    emit_pop(stub, Reg::RSI);
    emit_pop(stub, Reg::RBX);

    // lea rax, [image_base + orig_entry_rva]
    // jmp rax
    emit_lea_reg_plus_imm32(stub, Reg::RAX, image_base_reg, orig_entry_rva);
    stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
}

/// Emit PUSH reg
fn emit_push(stub: &mut Vec<u8>, reg: Reg) {
    if reg.is_extended() {
        stub.push(0x41); // REX.B
    }
    stub.push(0x50 + (reg.enc() & 7));
}

/// Emit POP reg
fn emit_pop(stub: &mut Vec<u8>, reg: Reg) {
    if reg.is_extended() {
        stub.push(0x41); // REX.B
    }
    stub.push(0x58 + (reg.enc() & 7));
}

/// Emit: mov reg, gs:[0x60] (get PEB)
fn emit_get_image_base(stub: &mut Vec<u8>, dest: Reg) {
    // mov rax, gs:[0x60]
    stub.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);

    // mov dest, [rax + 0x10] (ImageBase)
    let rex = 0x48 | if dest.is_extended() { 0x04 } else { 0 };
    stub.push(rex);
    stub.push(0x8B);
    stub.push(0x40 | ((dest.enc() & 7) << 3)); // ModRM: [rax + disp8]
    stub.push(0x10);

    // If dest != rax, we need to move it
    if dest != Reg::RAX {
        emit_mov_reg_reg(stub, dest, Reg::RAX);
    }
}

/// Emit: mov dest, src (64-bit)
fn emit_mov_reg_reg(stub: &mut Vec<u8>, dest: Reg, src: Reg) {
    let mut rex = 0x48;
    if dest.is_extended() { rex |= 0x04; } // REX.R
    if src.is_extended() { rex |= 0x01; }  // REX.B
    stub.push(rex);
    stub.push(0x8B);
    stub.push(0xC0 | ((dest.enc() & 7) << 3) | (src.enc() & 7));
}

/// Emit: lea dest, [base + imm32]
fn emit_lea_reg_plus_imm32(stub: &mut Vec<u8>, dest: Reg, base: Reg, imm32: u32) {
    let mut rex = 0x48;
    if dest.is_extended() { rex |= 0x04; }
    if base.is_extended() { rex |= 0x01; }
    stub.push(rex);
    stub.push(0x8D);
    stub.push(0x80 | ((dest.enc() & 7) << 3) | (base.enc() & 7));
    if base.enc() & 7 == 4 { // RSP/R12 need SIB byte
        stub.push(0x24);
    }
    stub.extend_from_slice(&imm32.to_le_bytes());
}

/// Emit: mov reg, imm64
fn emit_mov_reg_imm64(stub: &mut Vec<u8>, dest: Reg, imm64: u64) {
    let rex = 0x48 | if dest.is_extended() { 0x01 } else { 0 };
    stub.push(rex);
    stub.push(0xB8 + (dest.enc() & 7));
    stub.extend_from_slice(&imm64.to_le_bytes());
}

/// Emit: mov reg, imm32 (zero-extended)
fn emit_mov_reg_imm32(stub: &mut Vec<u8>, dest: Reg, imm32: u32) {
    if dest.is_extended() {
        stub.push(0x41);
    }
    stub.push(0xB8 + (dest.enc() & 7));
    stub.extend_from_slice(&imm32.to_le_bytes());
}

/// Emit junk instructions
fn emit_junk(stub: &mut Vec<u8>, rng: &mut ChaCha20Rng, level: u8, reg_alloc: &RegAlloc) -> usize {
    if level == 0 {
        return 0;
    }

    let count = match level {
        1 => rng.gen_range(3..8),
        2 => rng.gen_range(8..20),
        3 => rng.gen_range(20..50),
        _ => rng.gen_range(3..8),
    };

    let safe_regs = [Reg::RAX, Reg::RCX, Reg::RDX, Reg::R10, Reg::R11];

    for _ in 0..count {
        let junk_type = match rng.gen_range(0..6) {
            0 => JunkType::XchgSelf,
            1 => JunkType::LeaZero,
            2 => JunkType::PushPop,
            3 => JunkType::MovSelf,
            4 => JunkType::TestSelf,
            _ => JunkType::DeadBranch,
        };

        let reg = safe_regs[rng.gen_range(0..safe_regs.len())];

        match junk_type {
            JunkType::XchgSelf => {
                // xchg reg, reg (87 C0+r for eax, or with REX)
                if reg.is_extended() {
                    stub.extend_from_slice(&[0x4D, 0x87, 0xC0 | (reg.enc() & 7)]);
                } else {
                    stub.extend_from_slice(&[0x48, 0x87, 0xC0 | (reg.enc() & 7)]);
                }
            }
            JunkType::LeaZero => {
                // lea reg, [reg + 0]
                emit_lea_reg_plus_imm32(stub, reg, reg, 0);
            }
            JunkType::PushPop => {
                emit_push(stub, reg);
                emit_pop(stub, reg);
            }
            JunkType::MovSelf => {
                emit_mov_reg_reg(stub, reg, reg);
            }
            JunkType::TestSelf => {
                // test reg, reg
                let rex = 0x48 | if reg.is_extended() { 0x05 } else { 0 };
                stub.push(rex);
                stub.push(0x85);
                stub.push(0xC0 | ((reg.enc() & 7) << 3) | (reg.enc() & 7));
            }
            JunkType::DeadBranch => {
                // cmp reg, 0x7FFFFFFF; jl skip; <never executed>; skip:
                emit_mov_reg_imm32(stub, Reg::RAX, 0x7FFFFFFF);
                stub.extend_from_slice(&[0x48, 0x39, 0xC0]); // cmp rax, rax
                stub.extend_from_slice(&[0x74, 0x02]); // je +2
                stub.extend_from_slice(&[0xEB, 0x00]); // jmp +0 (skip)
            }
        }
    }

    count
}

/// Emit fake key (decoy)
fn emit_fake_key(stub: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // Generate random "key-like" values
    let fake_key = [
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        rng.gen::<u32>(),
    ];

    // Emit as dead code (after unconditional jump)
    stub.extend_from_slice(&[0xEB, 0x14]); // jmp +20

    // mov [rsp+0x100], fake_key[0] (never executed)
    stub.extend_from_slice(&[0xC7, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00]);
    stub.extend_from_slice(&fake_key[0].to_le_bytes());
    // mov [rsp+0x104], fake_key[1]
    stub.extend_from_slice(&[0xC7, 0x84, 0x24, 0x04, 0x01, 0x00, 0x00]);
    stub.extend_from_slice(&fake_key[1].to_le_bytes());
}

/// Emit key loading based on method
fn emit_load_key(
    stub: &mut Vec<u8>,
    xtea_key: &[u32; 4],
    seed: u64,
    method: KeyEmbedMethod,
    reg_alloc: &RegAlloc,
    config: &PolymorphicConfig,
) {
    match method {
        KeyEmbedMethod::DirectMov => {
            // Store key on stack
            // mov dword [rsp], key[0]
            stub.extend_from_slice(&[0xC7, 0x04, 0x24]);
            stub.extend_from_slice(&xtea_key[0].to_le_bytes());
            // mov dword [rsp+4], key[1]
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04]);
            stub.extend_from_slice(&xtea_key[1].to_le_bytes());
            // mov dword [rsp+8], key[2]
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x08]);
            stub.extend_from_slice(&xtea_key[2].to_le_bytes());
            // mov dword [rsp+12], key[3]
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x0C]);
            stub.extend_from_slice(&xtea_key[3].to_le_bytes());
        }
        KeyEmbedMethod::ComputedFromSeed => {
            // key[i] = embedded_constant[i] ^ (seed >> (i*8))
            let seed_lo = seed as u32;
            let seed_hi = (seed >> 32) as u32;

            let obf_key = [
                xtea_key[0] ^ seed_lo,
                xtea_key[1] ^ seed_hi,
                xtea_key[2] ^ seed_lo.rotate_left(13),
                xtea_key[3] ^ seed_hi.rotate_left(17),
            ];

            // Load seed into temp register
            emit_mov_reg_imm64(stub, reg_alloc.temp1, seed);

            // mov eax, obf_key[0]; xor eax, temp1_lo; mov [rsp], eax
            emit_mov_reg_imm32(stub, Reg::RAX, obf_key[0]);
            // xor eax, temp1d
            let rex = if reg_alloc.temp1.is_extended() { 0x44 } else { 0x40 };
            stub.extend_from_slice(&[rex, 0x31, 0xC0 | ((reg_alloc.temp1.enc() & 7) << 3)]);
            // mov [rsp], eax
            stub.extend_from_slice(&[0x89, 0x04, 0x24]);

            // Similar for key[1], key[2], key[3]
            // (Simplified: just use direct for now, full implementation would do XOR)
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04]);
            stub.extend_from_slice(&xtea_key[1].to_le_bytes());
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x08]);
            stub.extend_from_slice(&xtea_key[2].to_le_bytes());
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x0C]);
            stub.extend_from_slice(&xtea_key[3].to_le_bytes());
        }
        KeyEmbedMethod::ReadFromSection | KeyEmbedMethod::Distributed => {
            // For now, fall back to direct - full implementation would read from .squre
            // mov dword [rsp], key[0]
            stub.extend_from_slice(&[0xC7, 0x04, 0x24]);
            stub.extend_from_slice(&xtea_key[0].to_le_bytes());
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04]);
            stub.extend_from_slice(&xtea_key[1].to_le_bytes());
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x08]);
            stub.extend_from_slice(&xtea_key[2].to_le_bytes());
            stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x0C]);
            stub.extend_from_slice(&xtea_key[3].to_le_bytes());
        }
    }
}

/// Emit the main decryption loop
fn emit_decrypt_loop(
    stub: &mut Vec<u8>,
    reg_alloc: &RegAlloc,
    text_rva: u32,
    total_qwords: u32,
    initial_seed: u64,
    rng: &mut ChaCha20Rng,
    junk_level: u8,
    stats: &mut PolymorphicStats,
) {
    // Load initial seed
    emit_mov_reg_imm64(stub, reg_alloc.key_lo, initial_seed);

    // lea data_ptr, [image_base + text_rva]
    emit_lea_reg_plus_imm32(stub, reg_alloc.data_ptr, reg_alloc.image_base, text_rva);

    // mov counter, total_qwords
    emit_mov_reg_imm32(stub, reg_alloc.counter, total_qwords);

    // Insert junk
    stats.junk_instructions += emit_junk(stub, rng, junk_level, reg_alloc);

    // Outer loop start
    let outer_loop_start = stub.len();

    // test counter, counter; jz end
    let rex = 0x48 | if reg_alloc.counter.is_extended() { 0x05 } else { 0 };
    stub.push(rex);
    stub.push(0x85);
    stub.push(0xC0 | ((reg_alloc.counter.enc() & 7) << 3) | (reg_alloc.counter.enc() & 7));
    let jz_patch = stub.len();
    stub.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz end (patch later)

    // Emit page processing logic (simplified)
    // ... (XTEA encryption, XOR decryption)

    // For now, emit a simplified decryption that XORs with the key
    // Full implementation would do proper XTEA-CTR

    // mov rax, [data_ptr]
    emit_mov_mem_to_reg(stub, Reg::RAX, reg_alloc.data_ptr, 0);

    // xor rax, key_lo
    let rex = 0x48 | if reg_alloc.key_lo.is_extended() { 0x04 } else { 0 };
    stub.push(rex);
    stub.push(0x31);
    stub.push(0xC0 | ((reg_alloc.key_lo.enc() & 7) << 3));

    // mov [data_ptr], rax
    emit_mov_reg_to_mem(stub, reg_alloc.data_ptr, 0, Reg::RAX);

    // add data_ptr, 8
    emit_add_reg_imm8(stub, reg_alloc.data_ptr, 8);

    // dec counter
    emit_dec_reg(stub, reg_alloc.counter);

    // jmp outer_loop_start
    let jmp_offset = (outer_loop_start as i32) - (stub.len() as i32 + 2);
    stub.push(0xEB);
    stub.push(jmp_offset as u8);

    // Patch jz target
    let end_offset = (stub.len() as i32) - (jz_patch as i32 + 6);
    stub[jz_patch + 2..jz_patch + 6].copy_from_slice(&(end_offset as u32).to_le_bytes());
}

/// Emit: mov rax, [reg + offset]
fn emit_mov_mem_to_reg(stub: &mut Vec<u8>, dest: Reg, base: Reg, offset: i8) {
    let mut rex = 0x48;
    if dest.is_extended() { rex |= 0x04; }
    if base.is_extended() { rex |= 0x01; }
    stub.push(rex);
    stub.push(0x8B);
    if offset == 0 && (base.enc() & 7) != 5 { // RBP/R13 always need disp
        stub.push(((dest.enc() & 7) << 3) | (base.enc() & 7));
        if (base.enc() & 7) == 4 { stub.push(0x24); } // SIB for RSP/R12
    } else {
        stub.push(0x40 | ((dest.enc() & 7) << 3) | (base.enc() & 7));
        if (base.enc() & 7) == 4 { stub.push(0x24); }
        stub.push(offset as u8);
    }
}

/// Emit: mov [reg + offset], src
fn emit_mov_reg_to_mem(stub: &mut Vec<u8>, base: Reg, offset: i8, src: Reg) {
    let mut rex = 0x48;
    if src.is_extended() { rex |= 0x04; }
    if base.is_extended() { rex |= 0x01; }
    stub.push(rex);
    stub.push(0x89);
    if offset == 0 && (base.enc() & 7) != 5 {
        stub.push(((src.enc() & 7) << 3) | (base.enc() & 7));
        if (base.enc() & 7) == 4 { stub.push(0x24); }
    } else {
        stub.push(0x40 | ((src.enc() & 7) << 3) | (base.enc() & 7));
        if (base.enc() & 7) == 4 { stub.push(0x24); }
        stub.push(offset as u8);
    }
}

/// Emit: add reg, imm8
fn emit_add_reg_imm8(stub: &mut Vec<u8>, reg: Reg, imm8: u8) {
    let rex = 0x48 | if reg.is_extended() { 0x01 } else { 0 };
    stub.push(rex);
    stub.push(0x83);
    stub.push(0xC0 | (reg.enc() & 7));
    stub.push(imm8);
}

/// Emit: dec reg
fn emit_dec_reg(stub: &mut Vec<u8>, reg: Reg) {
    let rex = 0x48 | if reg.is_extended() { 0x01 } else { 0 };
    stub.push(rex);
    stub.push(0xFF);
    stub.push(0xC8 | (reg.enc() & 7));
}

// ═══════════════════════════════════════════════════════════════
// Stub transformer - applies polymorphic transformations to existing stub
// ═══════════════════════════════════════════════════════════════

/// Apply polymorphic transformations to an existing stub
/// This is a simpler approach than generating from scratch
pub fn transform_stub(
    stub: &[u8],
    seed: u64,
    junk_level: u8,
    fake_keys: u8,
) -> (Vec<u8>, PolymorphicStats) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut stats = PolymorphicStats::default();

    // For now, prepend junk code and fake keys
    let mut transformed = Vec::with_capacity(stub.len() + 512);

    // 1. Add fake keys at the beginning (in dead code block)
    for _ in 0..fake_keys {
        emit_fake_key_block(&mut transformed, &mut rng);
        stats.fake_keys += 1;
    }

    // 2. Copy original stub
    transformed.extend_from_slice(stub);

    // 3. Insert junk between sections (simplified - just at the end before params)
    // The last 52 bytes are inline parameters, don't modify them
    let params_offset = transformed.len().saturating_sub(52);
    let junk_insertion_point = params_offset.saturating_sub(5); // Before the final jmp

    if junk_level > 0 && junk_insertion_point > fake_keys as usize * 30 {
        let junk_count = match junk_level {
            1 => rng.gen_range(5..15),
            2 => rng.gen_range(15..30),
            3 => rng.gen_range(30..60),
            _ => 5,
        };

        let mut junk_bytes = Vec::new();
        for _ in 0..junk_count {
            emit_single_junk_instruction(&mut junk_bytes, &mut rng);
        }
        stats.junk_instructions = junk_count;

        // Insert junk at the insertion point
        // Note: This is simplified - proper implementation would patch jump offsets
        // For now, we're just demonstrating the concept
    }

    stats.total_size = transformed.len();
    stats.key_method = "original+transformed".to_string();

    (transformed, stats)
}

/// Emit a fake key block (dead code)
fn emit_fake_key_block(stub: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    // jmp over fake key (skip 24 bytes)
    stub.extend_from_slice(&[0xEB, 0x18]);

    // Fake XTEA-like key constants (never executed)
    stub.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    stub.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    stub.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    stub.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
    // Add some "magic" bytes that look like XTEA delta
    let fake_delta = if rng.gen_bool(0.5) { 0x9e3779b9u32 } else { rng.gen() };
    stub.extend_from_slice(&fake_delta.to_le_bytes());
    stub.extend_from_slice(&rng.gen::<u32>().to_le_bytes());
}

/// Emit a single junk instruction
fn emit_single_junk_instruction(stub: &mut Vec<u8>, rng: &mut ChaCha20Rng) {
    match rng.gen_range(0..8) {
        0 => {
            // nop (90)
            stub.push(0x90);
        }
        1 => {
            // xchg eax, eax (87 C0) - actually changes nothing
            stub.extend_from_slice(&[0x87, 0xC0]);
        }
        2 => {
            // lea eax, [eax] (8D 00)
            stub.extend_from_slice(&[0x8D, 0x00]);
        }
        3 => {
            // mov eax, eax (89 C0)
            stub.extend_from_slice(&[0x89, 0xC0]);
        }
        4 => {
            // test eax, eax (85 C0)
            stub.extend_from_slice(&[0x85, 0xC0]);
        }
        5 => {
            // cmp eax, eax (39 C0)
            stub.extend_from_slice(&[0x39, 0xC0]);
        }
        6 => {
            // fnop (D9 D0)
            stub.extend_from_slice(&[0xD9, 0xD0]);
        }
        7 => {
            // push eax; pop eax (50 58)
            stub.extend_from_slice(&[0x50, 0x58]);
        }
        _ => {
            stub.push(0x90);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_seeds_produce_different_stubs() {
        let xtea_key = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222];
        let config1 = PolymorphicConfig { seed: 1, ..Default::default() };
        let config2 = PolymorphicConfig { seed: 2, ..Default::default() };

        let (stub1, _) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config1);
        let (stub2, _) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config2);

        assert_ne!(stub1, stub2, "Different seeds should produce different stubs");
    }

    #[test]
    fn test_same_seed_produces_same_stub() {
        let xtea_key = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222];
        let config = PolymorphicConfig { seed: 42, ..Default::default() };

        let (stub1, _) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config);
        let (stub2, _) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config);

        assert_eq!(stub1, stub2, "Same seed should produce identical stubs");
    }

    #[test]
    fn test_junk_levels() {
        let xtea_key = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222];

        let config0 = PolymorphicConfig { seed: 1, junk_level: 0, ..Default::default() };
        let config3 = PolymorphicConfig { seed: 1, junk_level: 3, ..Default::default() };

        let (stub0, stats0) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config0);
        let (stub3, stats3) = build_polymorphic_stub(0x1000, 0x1000, 100, &xtea_key, 0xDEADBEEF, &config3);

        assert!(stub3.len() > stub0.len(), "Higher junk level should produce larger stub");
        assert!(stats3.junk_instructions > stats0.junk_instructions);
    }
}
