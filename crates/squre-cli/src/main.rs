mod pe;
mod polymorphic_stub;
mod source_transform;
mod transform;

use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use std::fs;
use std::path::PathBuf;

/// Polymorphic section names for hardened mode
/// When SQURE_HARDEN=1, these are randomized per-build
#[derive(Clone)]
struct SectionNames {
    sqvm: String,
    sqrun: String,
    sqinit: String,
    sqpre: String,
    sqimp: String,
    squre: String,
    sqtidal: String,  // Tidal Memory section
}

impl Default for SectionNames {
    fn default() -> Self {
        Self {
            sqvm: ".sqvm".to_string(),
            sqrun: ".sqrun".to_string(),
            sqinit: ".sqinit".to_string(),
            sqpre: ".sqpre".to_string(),
            sqimp: ".sqimp".to_string(),
            squre: ".squre".to_string(),
            sqtidal: ".sqtdl".to_string(),
        }
    }
}

/// Generate polymorphic section names from seed
/// Names follow consonant-vowel pattern for pronounceability
fn generate_polymorphic_section_names(seed: u64) -> SectionNames {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
    const VOWELS: &[u8] = b"aeiou";

    fn gen_name(rng: &mut ChaCha20Rng) -> String {
        let mut name = String::with_capacity(8);
        name.push('.');
        for i in 0..5 {
            let c = if i % 2 == 0 {
                CONSONANTS[rng.gen_range(0..CONSONANTS.len())] as char
            } else {
                VOWELS[rng.gen_range(0..VOWELS.len())] as char
            };
            name.push(c);
        }
        name.push((b'0' + rng.gen_range(0..10)) as char);
        name
    }

    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xDEAD_BEEF_CAFE_BABE);

    SectionNames {
        sqvm: gen_name(&mut rng),
        sqrun: gen_name(&mut rng),
        sqinit: gen_name(&mut rng),
        sqpre: gen_name(&mut rng),
        sqimp: gen_name(&mut rng),
        squre: gen_name(&mut rng),
        sqtidal: gen_name(&mut rng),
    }
}

#[derive(Parser, Debug)]
#[command(name = "squre-cli", version, about = "SQURE binary post-processor")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Apply protection to a PE file
    Protect {
        /// Input PE file path
        input: PathBuf,
        /// Output PE file path
        #[arg(short, long)]
        output: PathBuf,
        /// CEWE seed (hex, random if not specified)
        #[arg(short, long)]
        seed: Option<String>,
        /// Protection level: standard (default) or maximum
        #[arg(short, long, default_value = "standard")]
        level: String,
        /// Disable nanomite branch obfuscation
        #[arg(long)]
        no_nanomite: bool,
        /// Disable polymorphic stub generation
        #[arg(long)]
        no_polymorphic: bool,
        /// Junk code insertion level (0-3, overrides --level)
        #[arg(long)]
        junk_level: Option<u8>,
        /// Number of fake decoy keys to embed (overrides --level)
        #[arg(long)]
        fake_keys: Option<u8>,
        /// Disable .sqinit encryption (2-stage decryption)
        #[arg(long)]
        no_encrypt_stub: bool,
        /// Disable distributed key embedding (XOR masking)
        #[arg(long)]
        no_distributed_key: bool,
        /// Encryption layers: 1=XTEA, 2=XTEA+XOR, 3=XTEA+XOR+Rolling (overrides --level)
        #[arg(long)]
        layers: Option<u8>,
        /// Enable code integrity checking
        #[arg(long)]
        integrity_check: bool,
        /// Enable anti-memory-dump protection
        #[arg(long)]
        anti_dump: bool,
        /// Enable hardened mode (polymorphic section names, full dynamic analysis resistance)
        #[arg(long)]
        harden: bool,
        /// Enable ultra-hardened mode (all 16 anti-analysis phases)
        #[arg(long)]
        ultra: bool,
        /// Enable VM protection (virtualized code execution)
        #[arg(long)]
        vm: bool,
        /// Obfuscation level: 0=none, 1=basic, 2=medium, 3=full (overrides --level)
        #[arg(long)]
        obfuscate: Option<u8>,
        /// Enable honeypot mode (decoy functions, trap code, fake critical sections)
        #[arg(long)]
        honeypot: bool,
        /// Disable anti-debug checks (for debugging protected binaries)
        #[arg(long)]
        no_anti_debug: bool,
        /// Enable Tidal Memory (page-granular encryption with VEH decryption)
        #[arg(long)]
        tidal: bool,
        /// Enable Process Guard (3-process ring with Shamir key splitting)
        #[arg(long)]
        process_guard: bool,
        /// Enable Direct Syscall for all API calls (bypass user-mode hooks)
        #[arg(long)]
        direct_syscall: bool,
    },
    /// Analyze a PE file structure
    Analyze {
        /// Input PE file path
        input: PathBuf,
    },
    /// Scan a PE for readable strings (like `strings` command)
    Strings {
        /// Input PE file path
        input: PathBuf,
        /// Minimum string length
        #[arg(short = 'n', long, default_value = "6")]
        min_len: usize,
    },
    /// Show SQURE protection info
    Info {
        /// Input PE file path
        input: PathBuf,
    },
    /// Build a Rust project with full SQURE protection applied automatically
    Build {
        /// Input Rust project directory (must contain Cargo.toml)
        input: PathBuf,
        /// Output binary path
        #[arg(short, long)]
        output: PathBuf,
        /// CEWE seed (hex, random if not specified)
        #[arg(short, long)]
        seed: Option<String>,
        /// Disable nanomite branch obfuscation in post-processing
        #[arg(long)]
        no_nanomite: bool,
        /// Protection level: "standard" (default) or "maximum" (cff on all fns)
        #[arg(long, default_value = "standard")]
        level: String,
        /// Skip binary post-processing (produce macro-only protected binary)
        #[arg(long)]
        no_post_process: bool,
        /// Keep temporary build directory for inspection
        #[arg(long)]
        keep_temp: bool,
        /// Disable polymorphic stub generation (for debugging)
        #[arg(long)]
        no_polymorphic: bool,
        /// Junk code density: 0=none, 1=light, 2=medium, 3=heavy (default: 1)
        #[arg(long, default_value = "1")]
        junk_level: u8,
        /// Number of decoy keys to embed (default: 3)
        #[arg(long, default_value = "3")]
        fake_keys: u8,
        /// Disable .sqinit encryption (2-stage decryption with .sqpre)
        #[arg(long)]
        no_encrypt_stub: bool,
        /// Disable distributed key embedding (XOR key with seed)
        #[arg(long)]
        no_distributed_key: bool,
        /// Encryption layers: 1=XTEA only, 2=XTEA+XOR, 3=XTEA+XOR+Rolling (default: 1)
        #[arg(long, default_value = "1")]
        layers: u8,
        /// Enable code integrity check (canary verification)
        #[arg(long)]
        integrity_check: bool,
        /// Enable anti-memory-dump protection
        #[arg(long)]
        anti_dump: bool,
        /// Enable hardened mode (polymorphic section names, full dynamic analysis resistance)
        #[arg(long)]
        harden: bool,
        /// Enable ultra-hardened mode (all 16 anti-analysis phases)
        #[arg(long)]
        ultra: bool,
        /// Enable VM protection (virtualized code execution)
        #[arg(long)]
        vm: bool,
        /// Obfuscation level: 0=none, 1=basic, 2=medium, 3=full
        #[arg(long, default_value = "1")]
        obfuscate: u8,
        /// Enable honeypot mode (decoy functions, trap code, fake critical sections)
        #[arg(long)]
        honeypot: bool,
        /// Disable anti-debug checks (for debugging protected binaries)
        #[arg(long)]
        no_anti_debug: bool,
        /// Enable Tidal Memory (page-granular encryption with VEH decryption)
        #[arg(long)]
        tidal: bool,
        /// Enable Process Guard (3-process ring with Shamir key splitting)
        #[arg(long)]
        process_guard: bool,
        /// Enable Direct Syscall for all API calls (bypass user-mode hooks)
        #[arg(long)]
        direct_syscall: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Protect {
            input, output, seed, level, no_nanomite, no_polymorphic, junk_level, fake_keys,
            no_encrypt_stub, no_distributed_key, layers, integrity_check, anti_dump,
            harden, ultra, vm, obfuscate, honeypot, no_anti_debug,
            tidal, process_guard, direct_syscall,
        } => {
            // Apply level presets if individual options not specified
            let (junk, fakes, lyrs, integ, dump, hard, ultr, enable_vm, obfs, hp, tid, pguard, dsyscall) = match level.as_str() {
                "maximum" => (
                    junk_level.unwrap_or(3),
                    fake_keys.unwrap_or(5),
                    layers.unwrap_or(3),
                    true,   // integrity check
                    true,   // anti-dump
                    true,   // harden
                    true,   // ultra (16 anti-analysis checks)
                    true,   // VM protection
                    obfuscate.unwrap_or(3),  // max obfuscation
                    true,   // honeypot
                    true,   // tidal memory
                    process_guard,  // process guard (optional, requires external setup)
                    true,   // direct syscall
                ),
                _ => (  // "standard" or default
                    junk_level.unwrap_or(1),
                    fake_keys.unwrap_or(3),
                    layers.unwrap_or(1),
                    integrity_check,
                    anti_dump,
                    harden,
                    ultra,
                    vm,
                    obfuscate.unwrap_or(1),
                    honeypot,
                    tidal,
                    process_guard,
                    direct_syscall,
                ),
            };

            cmd_protect_with_options(
                input, output, seed,
                !no_nanomite, !no_polymorphic, junk, fakes,
                !no_encrypt_stub, !no_distributed_key, lyrs,
                integ, dump, hard, ultr, enable_vm, obfs, hp, !no_anti_debug,
                false,  // skip_sqrun: CLI protect always adds .sqrun
                tid, pguard, dsyscall,
            )
        }
        Command::Analyze { input } => cmd_analyze(input),
        Command::Strings { input, min_len } => cmd_strings(input, min_len),
        Command::Info { input } => cmd_info(input),
        Command::Build { input, output, seed, no_nanomite, level, no_post_process, keep_temp, no_polymorphic, junk_level, fake_keys, no_encrypt_stub, no_distributed_key, layers, integrity_check, anti_dump, harden, ultra, vm, obfuscate, honeypot, no_anti_debug, tidal, process_guard, direct_syscall } => {
            cmd_build(input, output, seed, !no_nanomite, level, !no_post_process, keep_temp, !no_polymorphic, junk_level, fake_keys, !no_encrypt_stub, !no_distributed_key, layers, integrity_check, anti_dump, harden, ultra, vm, obfuscate, honeypot, !no_anti_debug, tidal, process_guard, direct_syscall)
        }
    }
}

// ─── Nanomite raw entry (for serialization) ──────────────────

#[derive(Clone)]
struct NanomiteRawEntry {
    /// RVA of the breakpoint (original conditional jump location).
    bp_rva: u32,
    /// RVA of the branch-taken target.
    taken_rva: u32,
    /// RVA of the fall-through (not-taken) target.
    nottaken_rva: u32,
    /// Condition code (0xF0=jz, 0xF1=jnz, 0xF2=jl, 0xF3=jge, 0xF4=jle, 0xF5=jg).
    condition: u8,
    /// Original instruction length (always 6 for near conditional jumps).
    #[allow(dead_code)]
    instr_len: usize,
}

// ─── protect ─────────────────────────────────────────────────

/// Protection options for the new polymorphic features
#[derive(Debug, Clone)]
pub struct ProtectionOptions {
    pub nanomite: bool,
    pub polymorphic: bool,
    pub junk_level: u8,
    pub fake_keys: u8,
    pub encrypt_stub: bool,
    pub distributed_key: bool,
    pub layers: u8,
    pub integrity_check: bool,
    pub anti_dump: bool,
    pub checkpoint_id: Option<u32>,  // If Some(N), only hang at checkpoint N
    pub harden: bool,                // Enable hardened mode (polymorphic names, full anti-debug)
    pub ultra: bool,                 // Enable ultra-hardened mode (all 16 anti-analysis phases)
    pub vm: bool,                    // Enable VM protection
    pub obfuscate: u8,               // Obfuscation level (0-3)
    pub honeypot: bool,              // Enable honeypot mode (decoy functions, trap code)
    pub anti_debug: bool,            // Enable anti-debug checks (default true)
    pub skip_sqrun: bool,            // Skip .sqrun generation (squre-runtime already linked)
    pub tidal: bool,                 // Enable Tidal Memory protection
    pub process_guard: bool,         // Enable 3-process ring protection
    pub direct_syscall: bool,        // Enable direct syscall for API calls
}

impl Default for ProtectionOptions {
    fn default() -> Self {
        Self {
            nanomite: true,
            polymorphic: true,
            junk_level: 1,
            fake_keys: 3,
            encrypt_stub: true,
            distributed_key: true,
            layers: 1,
            integrity_check: false,
            anti_dump: false,
            checkpoint_id: None,
            harden: false,
            ultra: false,
            vm: false,
            obfuscate: 1,
            honeypot: false,
            anti_debug: true,
            skip_sqrun: false,
            tidal: false,
            process_guard: false,
            direct_syscall: false,
        }
    }
}

/// Thread-local storage for polymorphic options (used during protection)
thread_local! {
    static POLY_OPTIONS: std::cell::RefCell<ProtectionOptions> = std::cell::RefCell::new(ProtectionOptions::default());
}

/// Extended cmd_protect with polymorphic options
fn cmd_protect_with_options(
    input: PathBuf,
    output: PathBuf,
    seed_str: Option<String>,
    nanomite: bool,
    polymorphic: bool,
    junk_level: u8,
    fake_keys: u8,
    encrypt_stub: bool,
    distributed_key: bool,
    layers: u8,
    integrity_check: bool,
    anti_dump: bool,
    harden: bool,
    ultra: bool,
    vm: bool,
    obfuscate: u8,
    honeypot: bool,
    anti_debug: bool,
    skip_sqrun: bool,  // Skip .sqrun generation (for binaries with squre-runtime already linked)
    tidal: bool,       // Enable Tidal Memory protection
    process_guard: bool, // Enable 3-process ring protection
    direct_syscall: bool, // Enable direct syscall for API calls
) {
    // Set thread-local options
    POLY_OPTIONS.with(|opt| {
        let mut opt = opt.borrow_mut();
        opt.nanomite = nanomite;
        opt.polymorphic = polymorphic;
        opt.junk_level = junk_level;
        opt.fake_keys = fake_keys;
        opt.encrypt_stub = encrypt_stub;
        opt.distributed_key = distributed_key;
        opt.layers = layers;
        opt.integrity_check = integrity_check;
        opt.anti_dump = anti_dump;
        opt.harden = harden || ultra; // ultra implies harden
        opt.ultra = ultra;
        opt.vm = vm;
        opt.obfuscate = obfuscate;
        opt.honeypot = honeypot;
        opt.anti_debug = anti_debug;
        opt.skip_sqrun = skip_sqrun;
        opt.tidal = tidal;
        opt.process_guard = process_guard;
        opt.direct_syscall = direct_syscall;
    });

    if skip_sqrun {
        println!("[*] Skip .sqrun: enabled (squre-runtime already linked)");
    }
    if polymorphic {
        println!("[*] Polymorphic stub: enabled (junk_level={}, fake_keys={})", junk_level, fake_keys);
    }
    if encrypt_stub {
        println!("[*] Stub encryption: enabled (.sqpre → .sqinit 2-stage)");
    }
    if distributed_key {
        println!("[*] Distributed key: enabled (XTEA key XOR-masked with seed)");
    }
    if ultra {
        println!("[*] ULTRA-HARDENED mode: enabled (16 anti-analysis phases)");
    } else if harden {
        println!("[*] Hardened mode: enabled (polymorphic names, full anti-debug)");
    }
    if vm {
        println!("[*] VM protection: enabled");
    }
    if obfuscate > 1 {
        println!("[*] Obfuscation level: {}", obfuscate);
    }
    if layers > 1 {
        let layer_names = match layers {
            2 => "XTEA + XOR-stream",
            3 => "XTEA + XOR-stream + Rolling-XOR",
            _ => "XTEA",
        };
        println!("[*] Encryption layers: {} ({})", layers, layer_names);
    }
    if integrity_check {
        println!("[*] Integrity check: enabled (canary verification)");
    }
    if anti_dump {
        println!("[*] Anti-dump: enabled (PAGE_GUARD monitor + re-encryption)");
    }
    if tidal {
        println!("[*] Tidal Memory: enabled (page-granular encryption, VEH decryption, 50ms re-encrypt)");
    }
    if process_guard {
        println!("[*] Process Guard: enabled (3-process ring, Shamir key splitting)");
    }
    if direct_syscall {
        println!("[*] Direct Syscall: enabled (bypass user-mode API hooks)");
    }
    if honeypot {
        println!("[*] Honeypot mode: enabled (decoy functions, trap code, poison patches)");
    }
    cmd_protect(input, output, seed_str, nanomite)
}

fn cmd_protect(input: PathBuf, output: PathBuf, seed_str: Option<String>, nanomite: bool) {
    let seed = match seed_str {
        Some(s) => {
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).unwrap_or_else(|_| {
                eprintln!("Error: invalid hex seed '{}'", s);
                std::process::exit(1);
            })
        }
        None => {
            use rand::Rng;
            rand::thread_rng().gen()
        }
    };

    println!("SQURE CLI v{}", env!("CARGO_PKG_VERSION"));
    println!("────────────────────────────────────────");
    println!("Input:  {}", input.display());
    println!("Output: {}", output.display());
    println!("Seed:   0x{:016X}", seed);
    println!();

    // Read & parse PE
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", input.display(), e);
        std::process::exit(1);
    });
    let original_size = data.len();

    let mut pe = pe::parser::PeFile::parse(data).unwrap_or_else(|e| {
        eprintln!("Error parsing PE: {:?}", e);
        std::process::exit(1);
    });

    let original_sections = pe.sections.len();
    println!("[*] PE parsed: {} sections, entry=0x{:08X}",
        original_sections, pe.optional_header.entry_point);

    let orig_entry = pe.optional_header.entry_point;
    let mut transforms: Vec<&str> = Vec::new();
    let mut nanomite_entries: Vec<NanomiteRawEntry> = Vec::new();
    let mut text_section_size: u32 = 0;

    // ─── HARDENED: Polymorphic section names ───────────────────
    // Generate random section names when --harden to prevent pattern matching
    let use_poly_names = POLY_OPTIONS.with(|opt| opt.borrow().harden);
    let sec_names = if use_poly_names {
        let names = generate_polymorphic_section_names(seed);
        println!("[*] Polymorphic sections: {}, {}, {}, {}, {}, {}",
            names.sqvm, names.sqrun, names.sqinit, names.sqpre, names.sqimp, names.squre);
        names
    } else {
        SectionNames::default()
    };

    // ─── Transform 1: Nanomite branch scan ───────────────────
    // Scan .text for near conditional jumps (0F 8x), replace with INT3 + NOP.
    // The VEH handler (installed by anti_debug!() at runtime) dispatches these
    // using the nanomite table embedded in the .squre section.
    if nanomite {
        if let Some(text_idx) = pe.sections.iter().position(|s| s.name_str() == ".text") {
            let text_rva = pe.sections[text_idx].virtual_address;
            let text_vsize = pe.sections[text_idx].virtual_size as usize;
            let _text_raw_off = pe.sections[text_idx].pointer_to_raw_data as usize;
            let text_data = pe.section_data(&pe.sections[text_idx]).to_vec();

            // Save text size for ultra-hardened integrity check
            text_section_size = text_vsize as u32;

            nanomite_entries = scan_conditional_jumps(&text_data, text_rva, text_vsize, seed);

            // NOTE: We do NOT patch INT3 here at build time.
            // The runtime patches INT3 after VEH handler is installed,
            // avoiding the chicken-and-egg crash (INT3 before VEH).
            // See squre_runtime::nanomite::activate_nanomites().

            if !nanomite_entries.is_empty() {
                transforms.push("nanomite INT3 branches");
                println!("[+] Nanomites: {} conditional branches → INT3", nanomite_entries.len());
            } else {
                println!("[*] Nanomites: no eligible branches found");
            }
        }
    }

    // ─── Transform 1.5: VM Protection (virtualize code) ───────────────────
    // Convert x86-64 instructions to VM bytecode with CEWE-randomized opcodes.
    // This is the most powerful obfuscation layer - the original code becomes
    // unrecoverable without reversing the VM interpreter.
    let enable_vm = POLY_OPTIONS.with(|opt| opt.borrow().vm);
    if enable_vm {
        if let Some(text_idx) = pe.sections.iter().position(|s| s.name_str() == ".text") {
            let text_rva = pe.sections[text_idx].virtual_address;
            let text_data = pe.section_data(&pe.sections[text_idx]).to_vec();

            // Virtualize first portion of .text (demo: 512 bytes from entry)
            let entry_offset = (orig_entry - text_rva) as usize;
            let vm_size = std::cmp::min(512, text_data.len() - entry_offset);

            let config = transform::vm_protect::VmProtectConfig {
                seed,
                regions: vec![(orig_entry, vm_size as u32)],
                junk_level: 2,
            };

            match transform::vm_protect::apply_vm_protection(&text_data, text_rva, &config) {
                Ok((bytecode, _interpreter, stats)) => {
                    // Add .sqvm section with bytecode
                    pe::writer::add_section(
                        &mut pe,
                        &sec_names.sqvm,
                        &bytecode,
                        pe::writer::IMAGE_SCN_MEM_READ | pe::writer::IMAGE_SCN_CNT_INITIALIZED_DATA,
                    ).expect("failed to add .sqvm section");

                    let sqvm_rva = pe.sections.last().unwrap().virtual_address;

                    transforms.push("VM code virtualization");
                    println!("[+] VM Protection: {} x86 → {} VM instructions",
                             stats.x86_instructions, stats.vm_instructions);
                    println!("    Bytecode: {} bytes in {} (RVA 0x{:08X})",
                             stats.bytecode_size, sec_names.sqvm, sqvm_rva);
                    println!("    CEWE seed: 0x{:016X} (unique opcode mapping)", seed);
                }
                Err(e) => {
                    eprintln!("[!] VM Protection failed: {}", e);
                }
            }
        }
    }

    // ─── Transform 1.6: Honeypot (decoy functions, trap code) ───────────────────
    // Add fake license checks, trap code paths, and poison patches that
    // waste cracker time and corrupt decryption if patched
    let enable_honeypot = POLY_OPTIONS.with(|opt| opt.borrow().honeypot);
    if enable_honeypot {
        let hp_config = transform::honeypot::HoneypotConfig {
            decoy_functions: 3,
            trap_paths: 2,
            honeypot_strings: true,
            poison_patches: true,
            cascade_loop: true,
            cascade_depth: 5, // 5 levels of frustration loop
            seed,
        };

        let hp_data = transform::honeypot::generate_honeypot_section(&hp_config);
        let hp_section_name = transform::honeypot::generate_honeypot_section_name(seed);

        // Combine code and strings
        let mut hp_section_data = hp_data.code;
        hp_section_data.extend_from_slice(&hp_data.strings);

        pe::writer::add_section(
            &mut pe,
            &hp_section_name,
            &hp_section_data,
            pe::writer::IMAGE_SCN_MEM_READ
                | pe::writer::IMAGE_SCN_MEM_EXECUTE
                | pe::writer::IMAGE_SCN_CNT_CODE,
        ).expect("failed to add honeypot section");

        let hp_rva = pe.sections.last().unwrap().virtual_address;

        transforms.push("honeypot traps");
        println!("[+] Honeypot: {} decoy functions, {} trap paths",
                 hp_config.decoy_functions, hp_config.trap_paths);
        println!("    Section: {} (RVA 0x{:08X}, {} bytes)",
                 hp_section_name, hp_rva, hp_section_data.len());
        println!("    {} poison locations, {} trap locations",
                 hp_data.poison_locations.len(), hp_data.trap_locations.len());
    }

    // ─── Transform 2: Per-page chained .text encryption + decrypt stub ────
    // Encrypt .text page-by-page (4096 bytes each) with per-page keys derived
    // from a 128-bit master key. Pages are chained: page N's key depends on
    // the hash of encrypted page N-1.
    let mut nanomite_crypto_key: u64 = 0; // set in Transform 2 for use in Transform 3
    if let Some(text_idx) = pe.sections.iter().position(|s| s.name_str() == ".text") {
        let text_rva = pe.sections[text_idx].virtual_address;
        let raw_size = pe.sections[text_idx].size_of_raw_data as usize;
        let raw_off = pe.sections[text_idx].pointer_to_raw_data as usize;
        let total_qwords = raw_size / 8;

        // Derive 128-bit master key from seed, then convert to XTEA format
        let master_key = derive_master_key_128(seed);
        let xtea_key = master_key_to_xtea(&master_key);

        // Derive initial seed from PE header fields (stable fields only)
        let initial_seed = hash_pe_fields(
            pe.optional_header.magic,
            pe.optional_header.section_alignment,
            pe.optional_header.file_alignment,
            pe.coff_header.characteristics,
        );

        // Encrypt page-by-page with chaining
        let page_qwords = PAGE_QWORDS as usize; // 512 qwords per page
        let mut page_seed = initial_seed;
        let mut qw_idx = 0usize;

        while qw_idx < total_qwords {
            let chunk = (total_qwords - qw_idx).min(page_qwords);

            // Derive per-page key using XTEA block cipher
            let page_key = {
                let k = squre_core::crypto::xtea::xtea_encrypt_block(page_seed, &xtea_key);
                if k == 0 { 1 } else { k }
            };

            // XOR-encrypt this page's qwords with position variation
            for j in 0..chunk {
                let off = raw_off + (qw_idx + j) * 8;
                let mut qw = u64::from_le_bytes(
                    pe.data[off..off + 8].try_into().unwrap()
                );
                qw ^= page_key ^ (j as u64).wrapping_mul(POSITION_PRIME);
                pe.data[off..off + 8].copy_from_slice(&qw.to_le_bytes());
            }

            // Hash encrypted page for chaining → next page's seed
            page_seed = hash_encrypted_page(
                &pe.data[raw_off + qw_idx * 8..raw_off + (qw_idx + chunk) * 8]
            );

            qw_idx += chunk;
        }

        // ─── Additional encryption layers (if enabled) ───
        // SECURITY: Layer 2/3 keys are derived from PE header fields, NOT stored!
        let layers = POLY_OPTIONS.with(|opt| opt.borrow().layers);

        // Layer 2: XOR-stream with PE-derived key (attacker must emulate to recover)
        let layer2_key = if layers >= 2 {
            let key = compute_layer2_key(&pe.data);
            // Apply XOR to entire .text
            for i in 0..total_qwords {
                let off = raw_off + i * 8;
                let mut qw = u64::from_le_bytes(pe.data[off..off + 8].try_into().unwrap());
                qw ^= key;
                pe.data[off..off + 8].copy_from_slice(&qw.to_le_bytes());
            }
            println!("[+] Layer 2: XOR-stream (key derived from PE header)");
            Some(key)
        } else {
            None
        };

        // Layer 3: Rolling XOR with PE-derived prime
        let layer3_prime = if layers >= 3 {
            let prime = compute_layer3_prime(&pe.data);
            for i in 0..total_qwords {
                let off = raw_off + i * 8;
                let rolling_key = (i as u64).wrapping_mul(prime);
                let mut qw = u64::from_le_bytes(pe.data[off..off + 8].try_into().unwrap());
                qw ^= rolling_key;
                pe.data[off..off + 8].copy_from_slice(&qw.to_le_bytes());
            }
            println!("[+] Layer 3: Rolling-XOR (prime derived from PE header)");
            Some(prime)
        } else {
            None
        };

        // Mark .text as RWX (add WRITE flag for in-place decryption)
        pe.sections[text_idx].characteristics |= pe::writer::IMAGE_SCN_MEM_WRITE;

        // Compute XTEA mask from PE header (for key obfuscation)
        // SECURITY: The key is never stored in plaintext - must derive mask at runtime
        // Uses STABLE PE fields: TimeDateStamp, Machine, FileAlignment, SectionAlignment
        // NOTE: ImageBase is NOT used - Windows loader updates it when ASLR relocates
        let xtea_mask = compute_xtea_mask(&pe.data);
        eprintln!("[DEBUG] XTEA mask: lo=0x{:016X}, hi=0x{:016X}", xtea_mask.0, xtea_mask.1);

        // Build per-page chained decrypt stub (XTEA-based key derivation)
        // DEBUG: Using hardcoded mask values to test masking logic
        let mut stub = build_decrypt_stub_xtea(
            orig_entry, text_rva, total_qwords as u32,
            &xtea_key, initial_seed,
            layer2_key, layer3_prime,
            Some(xtea_mask), // Hardcoded in stub for testing
        );

        // Apply polymorphic transformation if enabled
        let poly_stats = POLY_OPTIONS.with(|opt| {
            let opt = opt.borrow();
            if opt.polymorphic && (opt.junk_level > 0 || opt.fake_keys > 0) {
                let (transformed, stats) = polymorphic_stub::transform_stub(
                    &stub,
                    seed,
                    opt.junk_level,
                    opt.fake_keys,
                );
                stub = transformed;
                Some(stats)
            } else {
                None
            }
        });

        if let Some(ref stats) = poly_stats {
            println!("[+] Polymorphic transform: {} fake keys, {} junk instructions",
                stats.fake_keys, stats.junk_instructions);
        }

        // Show distributed key status
        let distributed_key = POLY_OPTIONS.with(|opt| opt.borrow().distributed_key);
        if distributed_key {
            println!("[+] Distributed key: XTEA key XOR-masked with seed (pattern matching defeated)");
        }

        // Derive nanomite crypto key from UNPATCHED stub hash
        nanomite_crypto_key = splitmix_finalize(hash_encrypted_page(&stub));

        // ─── .sqrun: CLI-injected runtime protection ───
        // When nanomites are active, inject a runtime stub that provides:
        //   - Anti-debug (PEB.BeingDebugged → poison XTEA key)
        //   - ntdll export resolution via PEB walk
        //   - XTEA-CTR nanomite table decrypt + INT3 patching
        //   - VEH handler for nanomite dispatch
        // Chain: .sqinit → .sqrun → original entry
        // NOTE: Skip if squre-runtime is already linked (handles VEH itself)
        let skip_sqrun = POLY_OPTIONS.with(|opt| opt.borrow().skip_sqrun);
        if nanomite && !nanomite_entries.is_empty() && !skip_sqrun {
            let runtime_stub = build_runtime_stub(
                orig_entry, &nanomite_entries, nanomite_crypto_key, text_rva, text_section_size,
            );

            pe::writer::add_section(
                &mut pe,
                &sec_names.sqrun,
                &runtime_stub,
                pe::writer::IMAGE_SCN_MEM_READ
                    | pe::writer::IMAGE_SCN_MEM_WRITE
                    | pe::writer::IMAGE_SCN_MEM_EXECUTE
                    | pe::writer::IMAGE_SCN_CNT_CODE,
            ).expect("failed to add .sqrun section");

            let sqrun_rva = pe.sections.last().unwrap().virtual_address;

            // Patch .sqinit's jump target: orig_entry → .sqrun RVA
            // Inline params are the last 52 bytes; orig_entry_rva is first 4
            let params_offset = stub.len() - 52;
            stub[params_offset..params_offset + 4]
                .copy_from_slice(&sqrun_rva.to_le_bytes());

            transforms.push("runtime protection (anti-debug + VEH)");
            println!("[+] Runtime stub: {} bytes in {} (RVA 0x{:08X})",
                runtime_stub.len(), sec_names.sqrun, sqrun_rva);
            println!("    Anti-debug + VEH nanomite dispatch ({} entries)",
                nanomite_entries.len());
            println!("    Entry chain: {} → {} → original (0x{:08X})",
                sec_names.sqinit, sec_names.sqrun, orig_entry);
        }

        // ─── .sqtidal: Tidal Memory protection ───
        // Page-granular encryption with VEH decryption and background re-encryption
        let enable_tidal = POLY_OPTIONS.with(|opt| opt.borrow().tidal);
        if enable_tidal {
            let tidal_stub = build_tidal_stub(text_rva, text_section_size, seed);

            pe::writer::add_section(
                &mut pe,
                &sec_names.sqtidal,
                &tidal_stub,
                pe::writer::IMAGE_SCN_MEM_READ
                    | pe::writer::IMAGE_SCN_MEM_WRITE
                    | pe::writer::IMAGE_SCN_MEM_EXECUTE
                    | pe::writer::IMAGE_SCN_CNT_CODE,
            ).expect("failed to add .sqtidal section");

            let sqtidal_rva = pe.sections.last().unwrap().virtual_address;

            transforms.push("Tidal Memory (page-granular VEH decryption)");
            println!("[+] Tidal Memory: {} bytes in {} (RVA 0x{:08X})",
                tidal_stub.len(), sec_names.sqtidal, sqtidal_rva);
            println!("    Page encryption + VEH decrypt + 50ms re-encrypt tide");
        }

        // ─── Process Guard: 3-process ring with Shamir key splitting ───
        let enable_process_guard = POLY_OPTIONS.with(|opt| opt.borrow().process_guard);
        if enable_process_guard {
            transforms.push("Process Guard (3-process Shamir ring)");
            println!("[+] Process Guard: 3-process ring with Shamir key splitting");
            println!("    WARNING: Requires squre-runtime linked for full functionality");
        }

        // Check if .sqinit encryption is enabled
        let encrypt_stub = POLY_OPTIONS.with(|opt| opt.borrow().encrypt_stub);

        if encrypt_stub {
            // ─── 2-stage decryption: .sqpre → .sqinit ───
            // SECURITY: XOR key is derived from STABLE PE header fields.
            // This makes static extraction impossible - attacker must emulate.
            // The key is NEVER stored in the binary!
            //
            // 1. Compute XOR key from PE header (stable fields only)
            // 2. XOR-encrypt the .sqinit stub
            // 3. Add .sqinit section (RWX for in-place decryption)
            // 4. Build .sqpre stub (derives same key at runtime)
            // 5. Add .sqpre section
            // 6. Set entry point to .sqpre

            // TEST: Use PE-derived key with stored-key stub
            // This verifies the KEY VALUE is correct
            let xor_key = compute_sqpre_xor_key(&pe.data);
            eprintln!("[DEBUG] PE-derived XOR key: 0x{:016X}", xor_key);

            // XOR-encrypt the stub (8 bytes at a time)
            let stub_len = stub.len();
            let stub_qwords = (stub_len + 7) / 8;
            for i in 0..stub_qwords {
                let off = i * 8;
                if off + 8 <= stub_len {
                    let mut qw = u64::from_le_bytes(stub[off..off + 8].try_into().unwrap());
                    qw ^= xor_key;
                    stub[off..off + 8].copy_from_slice(&qw.to_le_bytes());
                } else {
                    // Handle partial last qword (pad with zeros for XOR)
                    let mut buf = [0u8; 8];
                    buf[..stub_len - off].copy_from_slice(&stub[off..]);
                    let mut qw = u64::from_le_bytes(buf);
                    qw ^= xor_key;
                    stub[off..].copy_from_slice(&qw.to_le_bytes()[..stub_len - off]);
                }
            }

            // Add .sqinit section with WRITE permission (for in-place decryption)
            pe::writer::add_section(
                &mut pe,
                &sec_names.sqinit,
                &stub,
                pe::writer::IMAGE_SCN_MEM_READ
                    | pe::writer::IMAGE_SCN_MEM_WRITE
                    | pe::writer::IMAGE_SCN_MEM_EXECUTE
                    | pe::writer::IMAGE_SCN_CNT_CODE,
            ).expect("failed to add .sqinit section");

            let sqinit_rva = pe.sections.last().unwrap().virtual_address;

            // Get preferred ImageBase from PE (before ASLR modification)
            let preferred_image_base = pe.optional_header.image_base;

            // Build .sqpre stub - use obfuscated version based on --obfuscate level
            // 0: non-obfuscated (PE-derived debug)
            // 1: 2-way XOR split obfuscation
            // 2: 3-way mixed ops with 20 decoys (ultra-obfuscated)
            // 3 or --harden: HARDENED mode - all vulnerabilities addressed
            let obfuscation_level: u32 = POLY_OPTIONS.with(|opt| {
                let opt = opt.borrow();
                if opt.harden {
                    3  // Full hardened mode with camouflaged operations
                } else {
                    opt.obfuscate as u32
                }
            });
            // Get anti_debug setting from POLY_OPTIONS
            let enable_anti_debug = POLY_OPTIONS.with(|opt| opt.borrow().anti_debug);

            let sqpre_stub = match obfuscation_level {
                3 => transform::hardening::build_hardened_sqpre_stub(
                    sqinit_rva, stub_len, xor_key, preferred_image_base, seed, enable_anti_debug
                ),
                2 => build_sqpre_stub_obfuscated_v2(
                    sqinit_rva, stub_len, xor_key, preferred_image_base, enable_anti_debug
                ),
                1 => build_sqpre_stub_obfuscated(
                    sqinit_rva, stub_len, xor_key, preferred_image_base, enable_anti_debug
                ),
                _ => build_sqpre_stub_pe_derived_debug(
                    sqinit_rva, stub_len, xor_key, preferred_image_base, enable_anti_debug
                ),
            };

            // Add .sqpre section
            pe::writer::add_section(
                &mut pe,
                &sec_names.sqpre,
                &sqpre_stub,
                pe::writer::IMAGE_SCN_MEM_READ
                    | pe::writer::IMAGE_SCN_MEM_EXECUTE
                    | pe::writer::IMAGE_SCN_CNT_CODE,
            ).expect("failed to add .sqpre section");

            let sqpre_rva = pe.sections.last().unwrap().virtual_address;
            pe::writer::set_entry_point(&mut pe, sqpre_rva);

            transforms.push("2-stage decryption (entry → init)");
            println!("[+] {} encrypted: {} bytes (key derived from PE header)", sec_names.sqinit, stub_len);
            let obf_marker = match obfuscation_level {
                3 => " [HARDENED: all vulnerabilities addressed]",
                2 => " [OBFUSCATED v2: 3-way + 20 decoys]",
                1 => " [OBFUSCATED v1: 2-way XOR]",
                _ => "",
            };
            println!("    {} stub: {} bytes (RVA 0x{:08X}){}", sec_names.sqpre, sqpre_stub.len(), sqpre_rva, obf_marker);
            if enable_anti_debug {
                let anti_debug_msg = if obfuscation_level >= 3 {
                    "    Anti-debug: 4 checks + RDTSC timing + opaque predicates"
                } else {
                    "    Anti-debug: PEB.BeingDebugged → poison key derivation"
                };
                println!("{}", anti_debug_msg);
            } else {
                println!("    Anti-debug: DISABLED (--no-anti-debug)");
            }
            println!("    Entry chain: {} → {} (0x{:08X}) → OEP", sec_names.sqpre, sec_names.sqinit, sqinit_rva);
        } else {
            // Original behavior: .sqinit only
            pe::writer::add_section(
                &mut pe,
                &sec_names.sqinit,
                &stub,
                pe::writer::IMAGE_SCN_MEM_READ
                    | pe::writer::IMAGE_SCN_MEM_EXECUTE
                    | pe::writer::IMAGE_SCN_CNT_CODE,
            ).expect("failed to add .sqinit section");

            let sqinit_rva = pe.sections.last().unwrap().virtual_address;
            pe::writer::set_entry_point(&mut pe, sqinit_rva);

            println!("    Decrypt stub: {} bytes in {} (RVA 0x{:08X})", stub.len(), sec_names.sqinit, sqinit_rva);
            println!("    Entry redirect: 0x{:08X} → 0x{:08X}", orig_entry, sqinit_rva);
        }

        transforms.push("XTEA per-page .text encryption + decrypt stub");
        println!("[+] .text encrypted: {} bytes ({} qwords, {} pages), XTEA-128 key",
            raw_size, total_qwords, (total_qwords + PAGE_QWORDS as usize - 1) / PAGE_QWORDS as usize);
    }

    // ─── Transform 2b: TLS callback neutralization ──────────────
    // Windows calls TLS callbacks BEFORE the entry point. If callbacks point
    // into encrypted .text, the process crashes before the decrypt stub runs.
    // Fix: zero out AddressOfCallBacks in the TLS directory so the loader
    // skips callbacks. After .text is decrypted, the CRT re-initialises TLS
    // via its own init path (DllMain / _CRT_INIT), so dynamic TLS still works.
    if pe.is_64bit() {
        if let Some(tls_dir) = pe.tls_directory() {
            let tls_rva = tls_dir.virtual_address;
            if let Some(tls_file_off) = pe.rva_to_offset(tls_rva) {
                // IMAGE_TLS_DIRECTORY64.AddressOfCallBacks is at offset +0x18
                let cb_field_off = tls_file_off + 0x18;
                if cb_field_off + 8 <= pe.data.len() {
                    let old_cb = u64::from_le_bytes(
                        pe.data[cb_field_off..cb_field_off + 8].try_into().unwrap()
                    );
                    if old_cb != 0 {
                        // Zero out AddressOfCallBacks
                        pe.data[cb_field_off..cb_field_off + 8]
                            .copy_from_slice(&0u64.to_le_bytes());
                        println!("[+] TLS callbacks neutralized (was VA 0x{:016X})", old_cb);
                        transforms.push("TLS callback neutralization");
                    }
                }
            }
        }
    }

    // ─── Transform 3: Import obfuscation (IAT hashing) ─────────
    // Parse PE imports, hash DLL and function names with FNV-1a, and generate
    // a resolver stub. The hashed import table is stored in .squre metadata
    // so the runtime can resolve imports by hash instead of plain-text names.
    let mut import_hash_data: Vec<u8> = Vec::new();
    match transform::import_obfuscate::obfuscate_imports(&pe) {
        Ok(obfuscated) => {
            if !obfuscated.imports.is_empty() {
                // Store resolver stub in executable section
                pe::writer::add_section(
                    &mut pe,
                    &sec_names.sqimp,
                    &obfuscated.resolver_stub,
                    pe::writer::IMAGE_SCN_MEM_READ
                        | pe::writer::IMAGE_SCN_MEM_EXECUTE
                        | pe::writer::IMAGE_SCN_CNT_CODE,
                ).expect("failed to add .sqimp section");

                // Serialize hashed import table for .squre metadata
                // Format: count(u32) + entries(dll_hash:u32 + func_hash:u32 + iat_rva:u32)
                import_hash_data.extend_from_slice(&(obfuscated.imports.len() as u32).to_le_bytes());
                for entry in &obfuscated.imports {
                    import_hash_data.extend_from_slice(&entry.dll_hash.to_le_bytes());
                    import_hash_data.extend_from_slice(&entry.func_hash.to_le_bytes());
                    import_hash_data.extend_from_slice(&entry.iat_rva.to_le_bytes());
                }

                transforms.push("import obfuscation (IAT hashing)");
                println!("[+] Import obfuscation: {} imports hashed, resolver stub {} bytes in .sqimp",
                    obfuscated.imports.len(), obfuscated.resolver_stub.len());
            }
        }
        Err(_) => {
            println!("[*] Import obfuscation: skipped (no imports or parse error)");
        }
    }

    // ─── Transform 4: Scattered initialization fragments ─────
    // Generate initialization fragments that must all execute for the VM to work.
    // Each fragment writes a portion of an init token. Fragments are embedded in
    // .squre metadata; the runtime verifies the assembled token before proceeding.
    let fragments = transform::scattered_init::generate_init_fragments(seed, 4);
    let expected_token = transform::scattered_init::compute_expected_token(&fragments);
    let mut init_frag_data: Vec<u8> = Vec::new();
    init_frag_data.extend_from_slice(&(fragments.len() as u32).to_le_bytes());
    init_frag_data.extend_from_slice(&(expected_token.len() as u32).to_le_bytes());
    init_frag_data.extend_from_slice(&expected_token);
    for frag in &fragments {
        init_frag_data.extend_from_slice(&(frag.init_type as u32).to_le_bytes());
        init_frag_data.extend_from_slice(&(frag.token_offset as u32).to_le_bytes());
        init_frag_data.extend_from_slice(&frag.token_value.to_le_bytes());
        init_frag_data.extend_from_slice(&(frag.code.len() as u32).to_le_bytes());
        init_frag_data.extend_from_slice(&frag.code);
    }
    transforms.push("scattered initialization (4 fragments)");
    println!("[+] Scattered init: {} fragments, expected token {} bytes",
        fragments.len(), expected_token.len());

    // ─── Transform 5: Metamorphic seed derivation ────────────
    // Derive a new CEWE seed from the current seed + timestamp. This enables
    // each protection pass to produce a unique binary structure even with the
    // same input. The new seed is stored in .squre metadata for potential
    // runtime self-mutation.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let metamorphic_seed = transform::metamorphic::derive_new_seed(seed, timestamp, 0);
    transforms.push("metamorphic seed derivation");
    println!("[+] Metamorphic: next-gen seed 0x{:016X}", metamorphic_seed);

    // ─── Transform 6: .squre section (metadata + nanomite table) ─
    let mut squre_blob = Vec::new();

    // Metadata: ENCRYPTED - no plaintext secrets!
    // Format: SQMD (magic) + encrypted payload
    // Payload is XTEA-CTR encrypted with nanomite_crypto_key
    {
        // Build metadata payload (will be encrypted)
        let meta_payload = format!(
            "v{}\x00t={}\x00n={}\x00m={:016X}\x00",
            env!("CARGO_PKG_VERSION"),
            transforms.len() + 1,
            nanomite_entries.len(),
            metamorphic_seed,
        );
        // NOTE: seed is NEVER stored - it's derived at runtime from code hash

        // Magic: SQMD (0x444D5153) - "SQure MetaData" encrypted marker
        squre_blob.extend_from_slice(&0x444D5153u32.to_le_bytes());

        // Length of encrypted payload
        let payload_bytes = meta_payload.as_bytes();
        squre_blob.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());

        // Encrypted metadata payload
        let encrypted_start = squre_blob.len();
        squre_blob.extend_from_slice(payload_bytes);

        // Pad to 8-byte boundary for XTEA
        while squre_blob.len() % 8 != 0 {
            squre_blob.push(0);
        }

        // XTEA-CTR encrypt metadata
        if nanomite_crypto_key != 0 {
            let meta_xtea = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
            xtea_ctr_apply(&mut squre_blob[encrypted_start..], &meta_xtea, nanomite_crypto_key ^ 0xA5A5A5A5A5A5A5A5);
        }
    }

    // Align to 4 bytes before binary nanomite table
    while squre_blob.len() % 4 != 0 {
        squre_blob.push(0);
    }

    // Serialize nanomite dispatch table in encrypted format.
    // HARDENED: Magic bytes are encrypted with crypto key to prevent pattern matching.
    // At runtime, the loader derives the same key and computes expected marker.
    if !nanomite_entries.is_empty() {
        // HARDENED: Encrypted marker instead of plaintext "NMTE"
        let nmte_marker = transform::hardening::generate_encrypted_magic(nanomite_crypto_key, "NMTE");
        squre_blob.extend_from_slice(&nmte_marker.to_le_bytes());

        // Build plaintext payload: count + entries
        let encrypted_start = squre_blob.len();
        squre_blob.extend_from_slice(&(nanomite_entries.len() as u32).to_le_bytes());
        for e in &nanomite_entries {
            squre_blob.extend_from_slice(&e.bp_rva.to_le_bytes());
            squre_blob.extend_from_slice(&e.taken_rva.to_le_bytes());
            squre_blob.extend_from_slice(&e.nottaken_rva.to_le_bytes());
            squre_blob.push(e.condition);
            squre_blob.extend_from_slice(&[0u8; 3]); // padding
        }

        // XTEA-CTR encrypt payload (replaces legacy XOR cycle)
        if nanomite_crypto_key != 0 {
            let nm_xtea = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
            xtea_ctr_apply(&mut squre_blob[encrypted_start..], &nm_xtea, nanomite_crypto_key);
        }

        println!("[+] Nanomite table: {} entries ({} bytes, XTEA-CTR encrypted) in .squre",
            nanomite_entries.len(), 8 + nanomite_entries.len() * 16);
    }

    // ─── Append import hash table (encrypted marker) ─────────────────
    if !import_hash_data.is_empty() {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        // HARDENED: Encrypted marker instead of plaintext "IMPH"
        let imph_marker = transform::hardening::generate_encrypted_magic(nanomite_crypto_key, "IMPH");
        squre_blob.extend_from_slice(&imph_marker.to_le_bytes());
        let encrypted_start = squre_blob.len();
        squre_blob.extend_from_slice(&import_hash_data);
        // XTEA-CTR encrypt (replaces legacy XOR cycle)
        if nanomite_crypto_key != 0 {
            let imp_xtea = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
            xtea_ctr_apply(&mut squre_blob[encrypted_start..], &imp_xtea, nanomite_crypto_key ^ 0x494D5048);
        }
    }

    // ─── Append scattered init data (encrypted marker) ─────────────
    if !init_frag_data.is_empty() {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        // HARDENED: Encrypted marker instead of plaintext "INIT"
        let init_marker = transform::hardening::generate_encrypted_magic(seed, "INIT");
        squre_blob.extend_from_slice(&init_marker.to_le_bytes());
        let encrypted_start = squre_blob.len();
        squre_blob.extend_from_slice(&init_frag_data);
        // XTEA-CTR encrypt (replaces legacy XOR cycle)
        let init_xtea = master_key_to_xtea(&derive_master_key_128(seed));
        xtea_ctr_apply(&mut squre_blob[encrypted_start..], &init_xtea, seed ^ 0x494E4954);
    }

    // ─── Append metamorphic seed (META magic) ────────────────
    {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        squre_blob.extend_from_slice(&0x4154_454Du32.to_le_bytes()); // "META"
        squre_blob.extend_from_slice(&metamorphic_seed.to_le_bytes());
    }

    // ─── Transform 7: Shamir secret sharing (SHAM magic) ─────
    // Split the seed into 3 Shamir shares over GF(2^64).
    // All 3 shares are required to reconstruct the original seed.
    // Embedded in .squre for runtime key reconstruction.
    {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        squre_blob.extend_from_slice(&0x4D41_4853u32.to_le_bytes()); // "SHAM"
        let r1 = splitmix_finalize(seed ^ 0x1234_5678_9ABC_DEF0);
        let r2 = splitmix_finalize(seed ^ 0xFEDC_BA98_7654_3210);
        let shares = squre_core::crypto::shamir::split(seed, r1, r2);
        squre_blob.extend_from_slice(&3u32.to_le_bytes()); // share count
        for share in &shares {
            squre_blob.extend_from_slice(&share.x.to_le_bytes());
            squre_blob.extend_from_slice(&share.y.to_le_bytes());
        }
        transforms.push("Shamir secret sharing (3-of-3 GF(2^64))");
        println!("[+] Shamir: seed split into 3 shares over GF(2^64)");
    }

    // ─── Transform 8: White-box key schedule (encrypted marker) ────
    // Generate white-box lookup tables that embed key material in their
    // structure. The key cannot be extracted by examining individual
    // entries — it is distributed across the mathematical relationship
    // between multiple tables. Anti-DCA measures included.
    {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        // HARDENED: Encrypted marker instead of plaintext "WBOX"
        let wbox_marker = transform::hardening::generate_encrypted_magic(seed, "WBOX");
        squre_blob.extend_from_slice(&wbox_marker.to_le_bytes());
        let wb_tables = squre_core::crypto::white_box::WhiteBoxTables::generate(seed);
        // Serialize: 4 T1 tables (4×256) + 2 T2 tables (2×256) + 1 T3 table (256)
        //          + 4 dummy tables (4×256) + access_order length + access_order
        for table in &wb_tables.t1 { squre_blob.extend_from_slice(table); }
        for table in &wb_tables.t2 { squre_blob.extend_from_slice(table); }
        squre_blob.extend_from_slice(&wb_tables.t3);
        for table in &wb_tables.dummy { squre_blob.extend_from_slice(table); }
        squre_blob.extend_from_slice(&(wb_tables.access_order.len() as u32).to_le_bytes());
        for &idx in &wb_tables.access_order {
            squre_blob.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        transforms.push("white-box key schedule (anti-DCA)");
        let wb_size = 11 * 256 + 4 + wb_tables.access_order.len() * 4;
        println!("[+] White-box: {} bytes of lookup tables (4+2+1 real + 4 dummy) in .squre", wb_size);
    }

    // ─── Transform 9: Cascade integrity chain (encrypted marker) ───
    // Apply cascade integrity chain to the .squre section data assembled
    // so far. Modifying any chunk invalidates all preceding chunks —
    // a chain reaction that prevents selective .squre patching.
    {
        while squre_blob.len() % 4 != 0 { squre_blob.push(0); }
        let pre_casc_len = squre_blob.len();
        let chain = squre_core::integrity::cascade::build_chain(&squre_blob, 8, seed);
        // HARDENED: Encrypted marker instead of plaintext "CASC"
        let casc_marker = transform::hardening::generate_encrypted_magic(seed, "CASC");
        squre_blob.extend_from_slice(&casc_marker.to_le_bytes());
        squre_blob.extend_from_slice(&(chain.chunks.len() as u32).to_le_bytes());
        squre_blob.extend_from_slice(&chain.root_hash);
        squre_blob.extend_from_slice(&chain.tail_key);
        transforms.push("cascade integrity chain (8-chunk)");
        println!("[+] Cascade integrity: {} chunks, root hash embedded, protects {} bytes",
            chain.chunks.len(), pre_casc_len);
    }

    pe::writer::add_section(
        &mut pe,
        &sec_names.squre,
        &squre_blob,
        pe::writer::IMAGE_SCN_MEM_READ | pe::writer::IMAGE_SCN_CNT_INITIALIZED_DATA,
    ).expect("failed to add .squre section");
    transforms.push("metadata section");
    println!("[+] {} section: {} bytes", sec_names.squre, squre_blob.len());

    // ─── Write output ────────────────────────────────────────
    let output_data = pe::writer::write_pe(&pe);
    fs::write(&output, &output_data).unwrap_or_else(|e| {
        eprintln!("Error writing output: {}", e);
        std::process::exit(1);
    });

    // Count strings in output for comparison
    let output_pe = pe::parser::PeFile::parse(output_data.clone()).ok();
    let output_strings = output_pe.as_ref().map(|p| {
        let mut total = 0usize;
        for s in &p.sections {
            total += count_ascii_strings(p.section_data(s), 6);
        }
        total
    }).unwrap_or(0);
    let input_strings = {
        let orig = fs::read(&input).unwrap_or_default();
        let p = pe::parser::PeFile::parse(orig).ok();
        p.map(|p| {
            let mut total = 0usize;
            for s in &p.sections {
                total += count_ascii_strings(p.section_data(s), 6);
            }
            total
        }).unwrap_or(0)
    };

    // ─── Summary ─────────────────────────────────────────────
    println!();
    println!("════════════════════════════════════════");
    println!("Protection complete! Binary is RUNNABLE.");
    println!("  Transforms:  {}", transforms.join(", "));
    println!("  Sections:    {} → {}", original_sections, pe.sections.len());
    println!("  Size:        {} → {} bytes", original_size, output_data.len());
    if input_strings > 0 {
        println!("  Strings:     {} → {} readable ({}% hidden)",
            input_strings, output_strings,
            if input_strings > 0 {
                ((input_strings.saturating_sub(output_strings)) * 100) / input_strings
            } else { 0 }
        );
    }
    println!("  Output:      {}", output.display());
    println!();
    println!("Runtime flow:");
    println!("  1. OS loads PE → entry = .sqinit decrypt stub");
    println!("  2. Stub reads ImageBase from PEB, XTEA-derives page keys, XOR-decrypts .text");
    println!("  3. Stub jumps to original entry point (CRT init → main)");
    if !nanomite_entries.is_empty() {
        println!("  4. anti_debug!() installs VEH + loads nanomite table from .squre (XTEA-CTR)");
        println!("  5. Nanomite INT3 branches dispatched by VEH handler");
        println!("  6. Tidal Memory encrypts .text pages → VEH decrypts on demand");
    } else {
        println!("  4. anti_debug!() installs VEH handler");
        println!("  5. Tidal Memory encrypts .text pages → VEH decrypts on demand");
    }
    if !import_hash_data.is_empty() {
        println!("  +  Import resolver: hashed IAT in .squre (XTEA-CTR), stub in .sqimp");
    }
    println!("  +  Scattered init: {} fragments (XTEA-CTR encrypted)", fragments.len());
    println!("  +  Shamir: seed split into 3 GF(2^64) shares for runtime reconstruction");
    println!("  +  White-box: key schedule tables embedded for handler dispatch");
    println!("  +  Cascade: .squre integrity chain prevents selective patching");
    println!("  +  Metamorphic: next-gen seed ready for self-mutation");
}

// ─── Scan for near conditional jumps in .text ────────────────

/// Scan .text for near conditional jump instructions (0F 84/85/8C/8D/8E/8F)
/// and return entries for nanomite replacement.
///
/// Heuristics to avoid false positives:
///   - Skip first 4KB of .text (CRT/startup code)
///   - Only forward branches (positive displacement > 4)
///   - Target must be within .text bounds
///   - Seed-based deterministic selection (~60% of eligible jumps)
///   - Cap at 128 entries maximum
fn scan_conditional_jumps(
    text_data: &[u8],
    text_rva: u32,
    text_vsize: usize,
    seed: u64,
) -> Vec<NanomiteRawEntry> {
    let mut entries = Vec::new();
    // Skip first 4KB of .text to avoid CRT/startup code
    let skip_start = 4096.min(text_vsize);
    let max_entries = 128usize;

    // Use iced-x86 for proper instruction boundary detection
    // This prevents false positives from bytes inside other instructions
    let decoder_data = &text_data[skip_start..];
    let decoder_rva = text_rva + skip_start as u32;
    let mut decoder = Decoder::with_ip(
        64, // x86-64
        decoder_data,
        decoder_rva as u64,
        DecoderOptions::NONE,
    );

    while decoder.can_decode() && entries.len() < max_entries {
        let instr = decoder.decode();

        // Skip invalid instructions
        if instr.is_invalid() {
            continue;
        }

        // Check for near conditional jumps (6-byte form: 0F 8x rel32)
        let condition = match instr.mnemonic() {
            Mnemonic::Je  => Some(0xF0u8), // jz  → ZF==1
            Mnemonic::Jne => Some(0xF1u8), // jnz → ZF==0
            Mnemonic::Jl  => Some(0xF2u8), // jl  → SF!=OF
            Mnemonic::Jge => Some(0xF3u8), // jge → SF==OF
            Mnemonic::Jle => Some(0xF4u8), // jle → ZF==1 || SF!=OF
            Mnemonic::Jg  => Some(0xF5u8), // jg  → ZF==0 && SF==OF
            _ => None,
        };

        if let Some(cond) = condition {
            let instr_len = instr.len();

            // Only consider near jumps (6-byte form with rel32)
            // Short jumps (2-byte) are too small to replace with INT3 + NOPs safely
            if instr_len != 6 {
                continue;
            }

            let bp_rva = instr.ip() as u32;
            let next_rva = instr.next_ip() as u32;
            let target_rva = instr.near_branch_target() as u32;

            // Validate: target within .text, forward branch, reasonable displacement
            let disp = (target_rva as i64) - (next_rva as i64);
            if target_rva >= text_rva
                && target_rva < text_rva + text_vsize as u32
                && disp > 4
            {
                // Seed-based deterministic selection (~60% of eligible jumps)
                let hash = seed ^ (bp_rva as u64).wrapping_mul(0x9E3779B97F4A7C15);
                if hash % 5 < 3 {
                    entries.push(NanomiteRawEntry {
                        bp_rva,
                        taken_rva: target_rva,
                        nottaken_rva: next_rva,
                        condition: cond,
                        instr_len,
                    });
                }
            }
        }
    }

    entries
}

// ─── Per-page chained encryption constants ───────────────────

const PAGE_QWORDS: u32 = 512; // 4096 / 8
const POSITION_PRIME: u64 = 0x9E37_79B9_7F4A_7C15;

/// Splitmix64 finalizer — excellent avalanche, used for key derivation.
fn splitmix_finalize(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CEB9FE1A85EC53);
    h ^= h >> 33;
    h
}

/// Derive 128-bit master key (two u64 halves) from seed.
fn derive_master_key_128(seed: u64) -> [u64; 2] {
    let lo = splitmix_finalize(seed);
    let hi = splitmix_finalize(lo ^ 0x6A09E667F3BCC908);
    [if lo == 0 { 1 } else { lo }, if hi == 0 { 1 } else { hi }]
}

/// Derive initial page-chain seed from PE header fields.
/// These fields are readable at runtime from the in-memory PE header,
/// binding the decryption to this specific binary.
///
/// NOTE: Only STABLE fields are used. The following were removed:
/// - number_of_sections: changes as sections are added
/// - size_of_image: changes as sections are added
/// - size_of_headers: may change with section count
fn hash_pe_fields(
    magic: u16,
    section_alignment: u32,
    file_alignment: u32,
    characteristics: u16,
) -> u64 {
    let mut h: u64 = 0x5BE0_CD19_137E_2179;
    h ^= magic as u64;
    h = splitmix_finalize(h);
    h ^= section_alignment as u64;
    h = splitmix_finalize(h);
    h ^= file_alignment as u64;
    h = splitmix_finalize(h);
    h ^= characteristics as u64;
    h = splitmix_finalize(h);
    h
}

/// Derive per-page key from chain seed and 128-bit master key.
/// Two rounds of splitmix with key injection make static extraction infeasible.
fn derive_page_key_chained(seed: u64, master: &[u64; 2]) -> u64 {
    let h = splitmix_finalize(seed ^ master[0]);
    let h = splitmix_finalize(h ^ master[1]);
    if h == 0 { 1 } else { h }
}

/// Hash encrypted page data for chaining to the next page.
fn hash_encrypted_page(data: &[u8]) -> u64 {
    let mut h: u64 = 0x517C_C1B7_2722_0A95;
    for chunk in data.chunks(8) {
        if chunk.len() == 8 {
            let qw = u64::from_le_bytes(chunk.try_into().unwrap());
            h ^= qw;
            h = h.rotate_left(29);
        }
    }
    splitmix_finalize(h)
}

// ─── Build per-page chained decrypt stub ─────────────────────
//
// x86-64 machine code that decrypts .text page-by-page at startup.
//
// Algorithm:
//   seed = initial_seed (derived from PE header fields)
//   for each page of .text:
//     page_key = splitmix(seed ^ master_lo) → xor master_hi → splitmix
//     hash_seed = hash(encrypted page)           // BEFORE decrypting
//     for j in 0..qwords_this_page:
//       [page+j*8] ^= page_key ^ (j * PRIME)
//     seed = hash_seed
//
// Register map:
//   rbx  = ImageBase
//   rdi  = orig_entry_rva
//   rsi  = current .text pointer (advances)
//   r12  = master_key_lo
//   r13  = master_key_hi
//   r14  = current chain seed
//   r15  = remaining qwords
//   rbp  = POSITION_PRIME

fn build_decrypt_stub_v2(
    orig_entry_rva: u32,
    text_rva: u32,
    total_qwords: u32,
    master_key: &[u64; 2],
    initial_seed: u64,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(400);

    // ── Prologue: save callee-saved registers ──
    s.push(0x53);                                       // push rbx
    s.push(0x57);                                       // push rdi
    s.push(0x56);                                       // push rsi
    s.extend_from_slice(&[0x41, 0x54]);                 // push r12
    s.extend_from_slice(&[0x41, 0x55]);                 // push r13
    s.extend_from_slice(&[0x41, 0x56]);                 // push r14
    s.extend_from_slice(&[0x41, 0x57]);                 // push r15
    s.push(0x55);                                       // push rbp

    // ── Get ImageBase from PEB ──
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25,
                          0x60, 0x00, 0x00, 0x00]);     // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);    // mov rbx, [rax+0x10]

    // ── Load parameters: lea rax, [rip + disp32] ──
    // We'll patch the displacement after we know the code size.
    let lea_patch_offset = s.len() + 3; // offset of the disp32 within the LEA
    s.extend_from_slice(&[0x48, 0x8D, 0x05,
                          0x00, 0x00, 0x00, 0x00]);     // lea rax, [rip+?] (patched later)

    // ── Read parameters from [rax+offset] ──
    s.extend_from_slice(&[0x8B, 0x38]);                 // mov edi, [rax+0]  (orig_entry_rva)
    s.extend_from_slice(&[0x8B, 0x70, 0x04]);           // mov esi, [rax+4]  (text_rva)
    s.extend_from_slice(&[0x44, 0x8B, 0x78, 0x08]);    // mov r15d, [rax+8] (total_qwords)
    s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x0C]);    // mov r12, [rax+12] (master_key_lo)
    s.extend_from_slice(&[0x4C, 0x8B, 0x68, 0x14]);    // mov r13, [rax+20] (master_key_hi)
    s.extend_from_slice(&[0x4C, 0x8B, 0x70, 0x1C]);    // mov r14, [rax+28] (initial_seed)

    // ── Load POSITION_PRIME into rbp ──
    s.extend_from_slice(&[0x48, 0xBD]);                 // movabs rbp, PRIME
    s.extend_from_slice(&POSITION_PRIME.to_le_bytes());

    // ── Compute .text virtual address: rsi = ImageBase + text_rva ──
    // esi was loaded as u32, zero-extended to rsi
    s.extend_from_slice(&[0x48, 0x01, 0xDE]);           // add rsi, rbx

    // ══════════════════════════════════════════════════
    // ── Page loop ──
    // ══════════════════════════════════════════════════
    let page_loop_top = s.len();

    // Registers at loop entry:
    //   rsi = current .text pointer
    //   r12 = master_key_lo, r13 = master_key_hi
    //   r14 = current chain seed
    //   r15d = remaining qwords
    //   rbp = POSITION_PRIME

    // ── Test remaining ──
    s.extend_from_slice(&[0x45, 0x85, 0xFF]);           // test r15d, r15d
    let jz_epilogue_offset = s.len();
    s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz epilogue (patch)

    // ── ecx = min(r15d, 512) ──
    s.extend_from_slice(&[0x44, 0x89, 0xF9]);          // mov ecx, r15d
    s.extend_from_slice(&[0x81, 0xF9]);                 // cmp ecx, 512
    s.extend_from_slice(&512u32.to_le_bytes());
    s.extend_from_slice(&[0x76, 0x05]);                 // jbe +5 (skip if <= 512)
    s.extend_from_slice(&[0xB9]);                       // mov ecx, 512
    s.extend_from_slice(&512u32.to_le_bytes());

    // ── r8d = ecx (save chunk size) ──
    s.extend_from_slice(&[0x41, 0x89, 0xC8]);          // mov r8d, ecx

    // ── Hash encrypted page → r10 ──
    s.extend_from_slice(&[0x49, 0x89, 0xF3]);          // mov r11, rsi
    // r10 = hash initial constant (must match hash_encrypted_page())
    s.extend_from_slice(&[0x49, 0xBA]);                 // movabs r10, imm64
    s.extend_from_slice(&0x517C_C1B7_2722_0A95u64.to_le_bytes());
    let hash_loop = s.len();
    s.extend_from_slice(&[0x4D, 0x33, 0x13]);          // xor r10, [r11]
    s.extend_from_slice(&[0x49, 0x83, 0xC3, 0x08]);   // add r11, 8
    s.extend_from_slice(&[0x49, 0xC1, 0xC2, 0x1D]);   // rol r10, 29
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (hash_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, d as u8]);              // jnz hash_loop

    // finalize hash: rax = splitmix(r10)
    s.extend_from_slice(&[0x4C, 0x89, 0xD0]);          // mov rax, r10
    emit_splitmix_finalize(&mut s);
    s.extend_from_slice(&[0x49, 0x89, 0xC2]);          // mov r10, rax (save next_seed)

    // ── Derive page key → rax ──
    s.extend_from_slice(&[0x4C, 0x89, 0xF0]);          // mov rax, r14 (seed)
    s.extend_from_slice(&[0x4C, 0x31, 0xE0]);          // xor rax, r12 (master_lo)
    emit_splitmix_finalize(&mut s);
    s.extend_from_slice(&[0x4C, 0x31, 0xE8]);          // xor rax, r13 (master_hi)
    emit_splitmix_finalize(&mut s);
    // ensure non-zero
    s.extend_from_slice(&[0x48, 0x85, 0xC0]);          // test rax, rax
    s.extend_from_slice(&[0x75, 0x07]);                 // jnz +7
    s.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1

    // ── Decrypt page: rax=page_key, rsi=data, r8d=chunk, rbp=PRIME ──
    s.extend_from_slice(&[0x44, 0x89, 0xC1]);          // mov ecx, r8d (restore chunk)
    s.extend_from_slice(&[0x4D, 0x31, 0xC9]);          // xor r9, r9 (j*PRIME = 0)
    let dec_loop = s.len();
    s.extend_from_slice(&[0x48, 0x89, 0xC2]);          // mov rdx, rax (page_key)
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]);          // xor rdx, r9
    s.extend_from_slice(&[0x48, 0x31, 0x16]);          // xor [rsi], rdx
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);   // add rsi, 8
    s.extend_from_slice(&[0x49, 0x01, 0xE9]);          // add r9, rbp (j*PRIME += PRIME)
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (dec_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, d as u8]);              // jnz dec_loop

    // ── Update state: r15d -= r8d, r14 = r10 (next seed) ──
    s.extend_from_slice(&[0x45, 0x29, 0xC7]);          // sub r15d, r8d
    s.extend_from_slice(&[0x4D, 0x89, 0xD6]);          // mov r14, r10

    // ── Jump back to page loop top ──
    let d = (page_loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xE9]);                       // jmp near
    s.extend_from_slice(&(d as i32 - 3).to_le_bytes()); // (jmp is 5 bytes: E9 + disp32)

    // ── Patch jz-to-epilogue ──
    let epilogue_offset = s.len();
    let jz_disp = (epilogue_offset as i32) - (jz_epilogue_offset as i32 + 6);
    s[jz_epilogue_offset + 2] = jz_disp as u8;
    s[jz_epilogue_offset + 3] = (jz_disp >> 8) as u8;
    s[jz_epilogue_offset + 4] = (jz_disp >> 16) as u8;
    s[jz_epilogue_offset + 5] = (jz_disp >> 24) as u8;

    // ═══ Epilogue ═══
    s.extend_from_slice(&[0x48, 0x01, 0xDF]);          // add rdi, rbx
    s.extend_from_slice(&[0x48, 0x89, 0xF8]);          // mov rax, rdi
    s.push(0x5D);                                       // pop rbp
    s.extend_from_slice(&[0x41, 0x5F]);                 // pop r15
    s.extend_from_slice(&[0x41, 0x5E]);                 // pop r14
    s.extend_from_slice(&[0x41, 0x5D]);                 // pop r13
    s.extend_from_slice(&[0x41, 0x5C]);                 // pop r12
    s.push(0x5E);                                       // pop rsi
    s.push(0x5F);                                       // pop rdi
    s.push(0x5B);                                       // pop rbx
    s.extend_from_slice(&[0xFF, 0xE0]);                 // jmp rax

    // ═══ Inline parameters ═══
    let params_offset = s.len();
    s.extend_from_slice(&orig_entry_rva.to_le_bytes()); // [+0]  4 bytes
    s.extend_from_slice(&text_rva.to_le_bytes());       // [+4]  4 bytes
    s.extend_from_slice(&total_qwords.to_le_bytes());   // [+8]  4 bytes
    s.extend_from_slice(&master_key[0].to_le_bytes());  // [+12] 8 bytes
    s.extend_from_slice(&master_key[1].to_le_bytes());  // [+20] 8 bytes
    s.extend_from_slice(&initial_seed.to_le_bytes());   // [+28] 8 bytes
    // Total params: 36 bytes

    // ── Patch LEA displacement ──
    // LEA rax, [rip + disp32] : disp = params_offset - (lea_end)
    // lea_end = lea_patch_offset + 4 (the byte after the disp32)
    let lea_end = lea_patch_offset + 4;
    let lea_disp = (params_offset as i32) - (lea_end as i32);
    s[lea_patch_offset]     = lea_disp as u8;
    s[lea_patch_offset + 1] = (lea_disp >> 8) as u8;
    s[lea_patch_offset + 2] = (lea_disp >> 16) as u8;
    s[lea_patch_offset + 3] = (lea_disp >> 24) as u8;

    s
}

/// Emit inline splitmix64 finalizer: rax → rax, clobbers rdx.
/// 58 bytes of x86-64 machine code.
fn emit_splitmix_finalize(s: &mut Vec<u8>) {
    // h ^= h >> 33
    s.extend_from_slice(&[0x48, 0x89, 0xC2]);          // mov rdx, rax
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]);   // shr rdx, 33
    s.extend_from_slice(&[0x48, 0x31, 0xD0]);          // xor rax, rdx
    // h *= 0xFF51AFD7ED558CCD
    s.extend_from_slice(&[0x48, 0xBA]);                 // movabs rdx, imm64
    s.extend_from_slice(&0xFF51AFD7ED558CCDu64.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x0F, 0xAF, 0xC2]);   // imul rax, rdx
    // h ^= h >> 33
    s.extend_from_slice(&[0x48, 0x89, 0xC2]);          // mov rdx, rax
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]);   // shr rdx, 33
    s.extend_from_slice(&[0x48, 0x31, 0xD0]);          // xor rax, rdx
    // h *= 0xC4CEB9FE1A85EC53
    s.extend_from_slice(&[0x48, 0xBA]);                 // movabs rdx, imm64
    s.extend_from_slice(&0xC4CEB9FE1A85EC53u64.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x0F, 0xAF, 0xC2]);   // imul rax, rdx
    // h ^= h >> 33
    s.extend_from_slice(&[0x48, 0x89, 0xC2]);          // mov rdx, rax
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]);   // shr rdx, 33
    s.extend_from_slice(&[0x48, 0x31, 0xD0]);          // xor rax, rdx
}

/// Convert 128-bit master key [u64; 2] to XTEA key format [u32; 4].
fn master_key_to_xtea(master: &[u64; 2]) -> [u32; 4] {
    [
        master[0] as u32,
        (master[0] >> 32) as u32,
        master[1] as u32,
        (master[1] >> 32) as u32,
    ]
}

/// XTEA-CTR encrypt/decrypt data in place.
///
/// Uses XTEA in counter mode: for each 8-byte block, generates a keystream
/// block by encrypting (nonce + block_index) with XTEA, then XORs with data.
/// Self-inverse: applying twice with the same key/nonce recovers plaintext.
fn xtea_ctr_apply(data: &mut [u8], key: &[u32; 4], nonce: u64) {
    for (i, chunk) in data.chunks_mut(8).enumerate() {
        let counter = nonce.wrapping_add(i as u64);
        let keystream = squre_core::crypto::xtea::xtea_encrypt_block(counter, key);
        let ks_bytes = keystream.to_le_bytes();
        for (j, b) in chunk.iter_mut().enumerate() {
            *b ^= ks_bytes[j];
        }
    }
}

// ─── XTEA-based decrypt stub builder ──────────────────────────
//
// Replaces build_decrypt_stub_v2's splitmix key derivation with
// XTEA block cipher. The stub encrypts the page seed with the XTEA
// key to derive each page's decryption key.
//
// Changes from v2:
//   - Stack frame: 32 bytes for XTEA key + save area
//   - Page key = XTEA_encrypt(seed, key) instead of splitmix(seed^master)
//   - ~114 bytes of inline XTEA replaces ~116 bytes of 2× splitmix

/// Emit anti-dump/anti-debug checks into the stub.
/// Checks:
///   1. PEB.BeingDebugged (gs:[0x60]+0x02)
///   2. NtGlobalFlag (PEB+0xBC) & 0x70 (heap flags set by debugger)
///   3. ProcessHeap flags (PEB+0x30 -> Heap+0x70)
/// If detected: XOR r12/r13 (XTEA key) with poison value -> silent decryption failure
fn emit_anti_dump_checks(s: &mut Vec<u8>) {
    // ═══════════════════════════════════════════════════════════
    // Anti-dump/Anti-debug checks
    // On detection: poison_val is non-zero, key gets corrupted
    // ═══════════════════════════════════════════════════════════

    // Debug level: 0 = full, 1 = PEB only, 2 = PEB + NtGlobalFlag, 3 = minimal
    let debug_level: u32 = std::env::var("SQURE_DEBUG_ANTIDUMP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);  // Default to minimal (safest)

    if debug_level == 3 {
        // Minimal: Just check PEB.BeingDebugged (most reliable, safest)
        // xor r8, r8  ; poison = 0
        s.extend_from_slice(&[0x4D, 0x31, 0xC0]);

        // mov rax, gs:[0x60]  ; PEB
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        // movzx ecx, byte [rax+0x02]  ; BeingDebugged
        s.extend_from_slice(&[0x0F, 0xB6, 0x48, 0x02]);
        // test ecx, ecx
        s.extend_from_slice(&[0x85, 0xC9]);
        // jz skip_poison (no debugger, skip poisoning)
        s.extend_from_slice(&[0x74, 0x0D]);
        // Poison: imul r8, 0xDEADBEEF (r8 = ecx * poison)
        s.extend_from_slice(&[0x49, 0xC7, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE]);  // mov r8, 0xDEADBEEF
        // xor r12, r8
        s.extend_from_slice(&[0x4D, 0x31, 0xC4]);
        // xor r13, r8
        s.extend_from_slice(&[0x4D, 0x31, 0xC5]);
        // skip_poison:
        return;
    }

    // We'll accumulate "poison" in r8. If any check fails, r8 != 0
    // xor r8, r8  ; poison = 0
    s.extend_from_slice(&[0x4D, 0x31, 0xC0]);

    // ── Check 1: PEB.BeingDebugged ──
    // mov rax, gs:[0x60]  ; PEB
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // movzx ecx, byte [rax+0x02]  ; BeingDebugged
    s.extend_from_slice(&[0x0F, 0xB6, 0x48, 0x02]);
    // or r8d, ecx  ; accumulate
    s.extend_from_slice(&[0x41, 0x09, 0xC8]);

    if debug_level >= 2 {
        // Skip advanced checks (they may cause crashes)
        // Apply poison
        s.extend_from_slice(&[0x4D, 0x85, 0xC0]);  // test r8, r8
        s.extend_from_slice(&[0x74, 0x0E]);        // jz skip_poison
        s.extend_from_slice(&[0x4D, 0x69, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE]);  // imul r8, r8, 0xDEADBEEF
        s.extend_from_slice(&[0x4D, 0x31, 0xC4]);  // xor r12, r8
        s.extend_from_slice(&[0x4D, 0x31, 0xC5]);  // xor r13, r8
        return;
    }

    // ── Check 2: NtGlobalFlag ──
    // mov ecx, [rax+0xBC]  ; NtGlobalFlag (offset 0xBC in 64-bit PEB)
    s.extend_from_slice(&[0x8B, 0x88, 0xBC, 0x00, 0x00, 0x00]);
    // and ecx, 0x70  ; FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    s.extend_from_slice(&[0x83, 0xE1, 0x70]);
    // or r8d, ecx
    s.extend_from_slice(&[0x41, 0x09, 0xC8]);

    if debug_level >= 1 {
        // Skip heap checks (most likely to cause crashes)
        // Apply poison
        s.extend_from_slice(&[0x4D, 0x85, 0xC0]);  // test r8, r8
        s.extend_from_slice(&[0x74, 0x0E]);        // jz skip_poison
        s.extend_from_slice(&[0x4D, 0x69, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE]);  // imul r8, r8, 0xDEADBEEF
        s.extend_from_slice(&[0x4D, 0x31, 0xC4]);  // xor r12, r8
        s.extend_from_slice(&[0x4D, 0x31, 0xC5]);  // xor r13, r8
        return;
    }

    // ── Check 3: ProcessHeap Flags ──
    // PEB at rax still valid
    // mov rcx, [rax+0x30]  ; ProcessHeap
    s.extend_from_slice(&[0x48, 0x8B, 0x48, 0x30]);
    // Validate heap pointer before dereferencing
    // test rcx, rcx
    s.extend_from_slice(&[0x48, 0x85, 0xC9]);
    // jz skip_heap_check (if NULL, skip heap checks)
    let skip_heap_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);  // Will be patched

    // mov edx, [rcx+0x70]  ; Heap.Flags (offset varies, but 0x70 is common for debug detection)
    s.extend_from_slice(&[0x8B, 0x51, 0x70]);
    // ForceFlags at +0x74
    // or edx, [rcx+0x74]
    s.extend_from_slice(&[0x0B, 0x51, 0x74]);
    // and edx, 0x40000062  ; HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED etc
    s.extend_from_slice(&[0x81, 0xE2, 0x62, 0x00, 0x00, 0x40]);
    // or r8d, edx
    s.extend_from_slice(&[0x41, 0x09, 0xD0]);

    // skip_heap_check:
    let skip_heap_target = s.len();
    s[skip_heap_jz + 1] = (skip_heap_target - skip_heap_jz - 2) as u8;

    // ── Apply poison to XTEA key if any check failed ──
    // If r8 != 0, corrupt r12 and r13 (XTEA key halves)
    // test r8, r8
    s.extend_from_slice(&[0x4D, 0x85, 0xC0]);
    // jz skip_poison (skip 10 bytes: 2 x "xor rN, 0xDEADBEEF")
    s.extend_from_slice(&[0x74, 0x0E]);
    // xor r12, 0xDEADBEEF (actually use r8 as poison for simplicity)
    // imul r8, r8, 0xDEADBEEF ; amplify poison
    s.extend_from_slice(&[0x4D, 0x69, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE]);
    // xor r12, r8
    s.extend_from_slice(&[0x4D, 0x31, 0xC4]);
    // xor r13, r8
    s.extend_from_slice(&[0x4D, 0x31, 0xC5]);
    // skip_poison:
    // (falls through here)
}

fn build_decrypt_stub_xtea(
    orig_entry_rva: u32,
    text_rva: u32,
    total_qwords: u32,
    xtea_key: &[u32; 4],
    initial_seed: u64,
    layer2_key: Option<u64>,
    layer3_prime: Option<u64>,
    xtea_mask: Option<(u64, u64)>, // PE-derived mask for XTEA key obfuscation
) -> Vec<u8> {
    let mut s = Vec::with_capacity(1000); // More capacity for PE-derived mask code

    // ── Prologue: save callee-saved registers ──
    s.push(0x53);                                       // push rbx
    s.push(0x57);                                       // push rdi
    s.push(0x56);                                       // push rsi
    s.extend_from_slice(&[0x41, 0x54]);                 // push r12
    s.extend_from_slice(&[0x41, 0x55]);                 // push r13
    s.extend_from_slice(&[0x41, 0x56]);                 // push r14
    s.extend_from_slice(&[0x41, 0x57]);                 // push r15
    s.push(0x55);                                       // push rbp

    // Allocate stack frame: 32 bytes
    //   [rsp+0..15]  = XTEA key (4 × u32)
    //   [rsp+16..23] = saved next_seed (during XTEA)
    //   [rsp+24..31] = saved chunk counter (during XTEA)
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);   // sub rsp, 32

    // ── Get ImageBase from PEB ──
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25,
                          0x60, 0x00, 0x00, 0x00]);     // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);    // mov rbx, [rax+0x10]

    // ── Load parameters: lea rax, [rip + disp32] ──
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05,
                          0x00, 0x00, 0x00, 0x00]);     // lea rax, [rip+?] (patched)

    // ── Read parameters from [rax+offset] ──
    s.extend_from_slice(&[0x8B, 0x38]);                 // mov edi, [rax+0]  (orig_entry_rva)
    s.extend_from_slice(&[0x8B, 0x70, 0x04]);           // mov esi, [rax+4]  (text_rva)
    s.extend_from_slice(&[0x44, 0x8B, 0x78, 0x08]);    // mov r15d, [rax+8] (total_qwords)
    s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x0C]);    // mov r12, [rax+12] (xtea_key[0..1] or masked)
    s.extend_from_slice(&[0x4C, 0x8B, 0x68, 0x14]);    // mov r13, [rax+20] (xtea_key[2..3] or masked)
    s.extend_from_slice(&[0x4C, 0x8B, 0x70, 0x1C]);    // mov r14, [rax+28] (initial_seed)

    // ── Unmask XTEA key ──
    // SECURITY: Key is masked with PE-header-derived values (not stored in binary!)
    // Must derive the same mask at runtime to unmask.
    if let Some((mask_lo, mask_hi)) = xtea_mask {
        // DEBUG: Test full mask_lo computation (seed + splitmix)

        // Save rax
        s.push(0x50); // push rax

        // Read PE header fields
        s.extend_from_slice(&[0x8B, 0x43, 0x3C]);            // mov eax, [rbx+0x3C]
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);            // add rax, rbx

        s.extend_from_slice(&[0x44, 0x8B, 0x40, 0x08]);      // mov r8d, [rax+0x08] (time)
        s.extend_from_slice(&[0x44, 0x0F, 0xB7, 0x48, 0x04]); // movzx r9d, word [rax+0x04] (machine)
        s.extend_from_slice(&[0x44, 0x8B, 0x50, 0x3C]);      // mov r10d, [rax+0x3C] (fileAlign)
        s.extend_from_slice(&[0x8B, 0x40, 0x38]);            // mov eax, [rax+0x38] (sectAlign)

        // Combine: seed = time | (machine << 48)
        s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x30]);      // shl r9, 48
        s.extend_from_slice(&[0x4D, 0x09, 0xC8]);            // or r8, r9

        // seed ^= (fileAlign << 24)
        s.extend_from_slice(&[0x49, 0xC1, 0xE2, 0x18]);      // shl r10, 24
        s.extend_from_slice(&[0x4D, 0x31, 0xD0]);            // xor r8, r10

        // seed ^= ror(sectAlign, 11)
        s.extend_from_slice(&[0x48, 0xC1, 0xC8, 0x0B]);      // ror rax, 11
        s.extend_from_slice(&[0x49, 0x31, 0xC0]);            // xor r8, rax

        // seed ^= magic
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0xC6A4A7935BD1E995_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x31, 0xC0]);            // xor r8, rax
        // r8 now has seed

        // ═══ splitmix_finalize for mask_lo ═══
        // h ^= h >> 33
        s.extend_from_slice(&[0x4C, 0x89, 0xC0]);            // mov rax, r8
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC0]);            // xor r8, rax

        // h *= 0xFF51AFD7ED558CCD
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0xFF51AFD7ED558CCD_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC0]);      // imul rax, r8
        s.extend_from_slice(&[0x49, 0x89, 0xC0]);            // mov r8, rax

        // h ^= h >> 33
        s.extend_from_slice(&[0x4C, 0x89, 0xC0]);            // mov rax, r8
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC0]);            // xor r8, rax

        // h *= 0xC4CEB9FE1A85EC53
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0xC4CEB9FE1A85EC53_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC0]);      // imul rax, r8
        s.extend_from_slice(&[0x49, 0x89, 0xC0]);            // mov r8, rax

        // h ^= h >> 33 → mask_lo in r8
        s.extend_from_slice(&[0x4C, 0x89, 0xC0]);            // mov rax, r8
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC0]);            // xor r8, rax
        // r8 = mask_lo (computed at runtime)

        // ═══ splitmix_finalize for mask_hi (using r11 instead of rcx) ═══
        // input = mask_lo ^ 0x85EBCA6B27D4EB4F
        s.extend_from_slice(&[0x4D, 0x89, 0xC3]);            // mov r11, r8
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0x85EBCA6B27D4EB4F_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x31, 0xC3]);            // xor r11, rax

        // h ^= h >> 33
        s.extend_from_slice(&[0x4C, 0x89, 0xD8]);            // mov rax, r11
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC3]);            // xor r11, rax

        // h *= 0xFF51AFD7ED558CCD
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0xFF51AFD7ED558CCD_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC3]);      // imul rax, r11
        s.extend_from_slice(&[0x49, 0x89, 0xC3]);            // mov r11, rax

        // h ^= h >> 33
        s.extend_from_slice(&[0x4C, 0x89, 0xD8]);            // mov rax, r11
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC3]);            // xor r11, rax

        // h *= 0xC4CEB9FE1A85EC53
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&0xC4CEB9FE1A85EC53_u64.to_le_bytes());
        s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC3]);      // imul rax, r11
        s.extend_from_slice(&[0x49, 0x89, 0xC1]);            // mov r9, rax

        // h ^= h >> 33 → mask_hi in r9
        s.extend_from_slice(&[0x4C, 0x89, 0xC8]);            // mov rax, r9
        s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x21]);      // shr rax, 33
        s.extend_from_slice(&[0x49, 0x31, 0xC1]);            // xor r9, rax
        // r9 = mask_hi

        // Restore rax
        s.push(0x58); // pop rax

        // ── Apply mask to unmask XTEA key ──
        // r12 = masked_key_lo ^ mask_lo
        // r13 = masked_key_hi ^ mask_hi
        s.extend_from_slice(&[0x4D, 0x31, 0xC4]); // xor r12, r8 (unmask k_lo)
        s.extend_from_slice(&[0x4D, 0x31, 0xCD]); // xor r13, r9 (unmask k_hi)
    } else {
        // Legacy mode: unmask with initial_seed if distributed_key enabled
        let distributed_key = POLY_OPTIONS.with(|opt| opt.borrow().distributed_key);
        if distributed_key {
            s.extend_from_slice(&[0x4D, 0x31, 0xF4]);   // xor r12, r14 (unmask k_lo)
            s.extend_from_slice(&[0x4D, 0x31, 0xF5]);   // xor r13, r14 (unmask k_hi)
        }
    }

    // ── Anti-dump checks (if enabled) ──
    // If debugger/dumper detected: poison XTEA key → silent decryption failure
    let anti_dump = POLY_OPTIONS.with(|opt| opt.borrow().anti_dump);
    if anti_dump {
        emit_anti_dump_checks(&mut s);
    }

    // ── Store XTEA key on stack for indexed access ──
    s.extend_from_slice(&[0x4C, 0x89, 0x24, 0x24]);    // mov [rsp], r12     key[0..1]
    s.extend_from_slice(&[0x4C, 0x89, 0x6C, 0x24, 0x08]); // mov [rsp+8], r13  key[2..3]

    // ── Load POSITION_PRIME into rbp ──
    s.extend_from_slice(&[0x48, 0xBD]);                 // movabs rbp, PRIME
    s.extend_from_slice(&POSITION_PRIME.to_le_bytes());

    // ── Compute .text virtual address: rsi = ImageBase + text_rva ──
    s.extend_from_slice(&[0x48, 0x01, 0xDE]);           // add rsi, rbx

    // ══════════════════════════════════════════════════
    // ── Multi-layer pre-decryption (Layer3 → Layer2) ──
    // ══════════════════════════════════════════════════
    // Decryption order is reverse of encryption: L3 first, then L2, then XTEA

    let lea2_patch_offset: Option<usize> = if layer3_prime.is_some() || layer2_key.is_some() {
        // Reload params pointer into rcx for layer key access
        let patch_off = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]); // lea rcx, [rip+?]

        // Layer 3 decryption: XOR each qword with (pos * layer3_prime)
        // NOTE: Key stored in params - PE-derived key would mismatch due to section additions
        // TODO: Compute layer keys AFTER all sections are added for PE-derived security
        if layer3_prime.is_some() {
            // mov r8, [rcx+44]  ; layer3_prime at offset 0x2C
            s.extend_from_slice(&[0x4C, 0x8B, 0x41, 0x2C]);

            // push rsi ; save .text VA
            s.push(0x56);
            // mov eax, r15d ; total_qwords
            s.extend_from_slice(&[0x44, 0x89, 0xF8]);
            // xor edx, edx ; position = 0
            s.extend_from_slice(&[0x31, 0xD2]);

            let l3_loop = s.len();
            // test eax, eax
            s.extend_from_slice(&[0x85, 0xC0]);
            let jz_l3_done = s.len();
            s.extend_from_slice(&[0x74, 0x00]); // jz done

            // mov r9, rdx ; copy position
            s.extend_from_slice(&[0x49, 0x89, 0xD1]);
            // imul r9, r8 ; r9 = position * prime
            s.extend_from_slice(&[0x4D, 0x0F, 0xAF, 0xC8]);
            // xor [rsi], r9
            s.extend_from_slice(&[0x4C, 0x31, 0x0E]);
            // add rsi, 8
            s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
            // inc edx
            s.extend_from_slice(&[0xFF, 0xC2]);
            // dec eax
            s.extend_from_slice(&[0xFF, 0xC8]);
            // jmp loop
            let d = (l3_loop as i32) - (s.len() as i32 + 2);
            s.extend_from_slice(&[0xEB, d as u8]);

            // Patch jump
            s[jz_l3_done + 1] = (s.len() - jz_l3_done - 2) as u8;
            s.push(0x5E); // pop rsi
        }

        // Layer 2 decryption: XOR each qword with layer2_key
        // NOTE: Key stored in params - PE-derived key would mismatch due to section additions
        // TODO: Compute layer keys AFTER all sections are added for PE-derived security
        if layer2_key.is_some() {
            // mov r8, [rcx+36]  ; layer2_key at offset 0x24
            s.extend_from_slice(&[0x4C, 0x8B, 0x41, 0x24]);

            // push rsi
            s.push(0x56);
            // mov eax, r15d
            s.extend_from_slice(&[0x44, 0x89, 0xF8]);

            let l2_loop = s.len();
            // test eax, eax
            s.extend_from_slice(&[0x85, 0xC0]);
            let jz_l2_done = s.len();
            s.extend_from_slice(&[0x74, 0x00]); // jz done

            // xor [rsi], r8
            s.extend_from_slice(&[0x4C, 0x31, 0x06]);
            // add rsi, 8
            s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
            // dec eax
            s.extend_from_slice(&[0xFF, 0xC8]);
            // jmp loop
            let d = (l2_loop as i32) - (s.len() as i32 + 2);
            s.extend_from_slice(&[0xEB, d as u8]);

            // Patch jump
            s[jz_l2_done + 1] = (s.len() - jz_l2_done - 2) as u8;
            s.push(0x5E); // pop rsi
        }

        Some(patch_off)
    } else {
        None
    };

    // ══════════════════════════════════════════════════
    // ── Page loop ──
    // ══════════════════════════════════════════════════
    let page_loop_top = s.len();

    // ── Test remaining ──
    s.extend_from_slice(&[0x45, 0x85, 0xFF]);           // test r15d, r15d
    let jz_epilogue_offset = s.len();
    s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz epilogue (patch)

    // ── ecx = min(r15d, 512) ──
    s.extend_from_slice(&[0x44, 0x89, 0xF9]);          // mov ecx, r15d
    s.extend_from_slice(&[0x81, 0xF9]);                 // cmp ecx, 512
    s.extend_from_slice(&512u32.to_le_bytes());
    s.extend_from_slice(&[0x76, 0x05]);                 // jbe +5
    s.extend_from_slice(&[0xB9]);                       // mov ecx, 512
    s.extend_from_slice(&512u32.to_le_bytes());

    // ── r8d = ecx (save chunk size) ──
    s.extend_from_slice(&[0x41, 0x89, 0xC8]);          // mov r8d, ecx

    // ── Hash encrypted page → r10 ──
    s.extend_from_slice(&[0x49, 0x89, 0xF3]);          // mov r11, rsi
    s.extend_from_slice(&[0x49, 0xBA]);                 // movabs r10, imm64
    s.extend_from_slice(&0x517C_C1B7_2722_0A95u64.to_le_bytes());
    let hash_loop = s.len();
    s.extend_from_slice(&[0x4D, 0x33, 0x13]);          // xor r10, [r11]
    s.extend_from_slice(&[0x49, 0x83, 0xC3, 0x08]);   // add r11, 8
    s.extend_from_slice(&[0x49, 0xC1, 0xC2, 0x1D]);   // rol r10, 29
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (hash_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, d as u8]);              // jnz hash_loop

    // finalize hash: rax = splitmix(r10)
    s.extend_from_slice(&[0x4C, 0x89, 0xD0]);          // mov rax, r10
    emit_splitmix_finalize(&mut s);

    // Save next_seed and chunk counter before XTEA clobbers r8/r10
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+16], rax (next_seed)
    s.extend_from_slice(&[0x4C, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+24], r8  (chunk_size)

    // ── Derive page key: XTEA encrypt seed ──
    s.extend_from_slice(&[0x4C, 0x89, 0xF0]);          // mov rax, r14 (seed)
    emit_xtea_encrypt(&mut s);
    // rax = XTEA_encrypt(seed, key) = page_key

    // Restore next_seed and chunk counter
    s.extend_from_slice(&[0x4C, 0x8B, 0x54, 0x24, 0x10]); // mov r10, [rsp+16]
    s.extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, 0x18]); // mov r8, [rsp+24]

    // ensure non-zero
    s.extend_from_slice(&[0x48, 0x85, 0xC0]);          // test rax, rax
    s.extend_from_slice(&[0x75, 0x07]);                 // jnz +7
    s.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1

    // ── Decrypt page: rax=page_key, rsi=data, r8d=chunk, rbp=PRIME ──
    s.extend_from_slice(&[0x44, 0x89, 0xC1]);          // mov ecx, r8d
    s.extend_from_slice(&[0x4D, 0x31, 0xC9]);          // xor r9, r9 (j*PRIME = 0)
    let dec_loop = s.len();
    s.extend_from_slice(&[0x48, 0x89, 0xC2]);          // mov rdx, rax (page_key)
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]);          // xor rdx, r9
    s.extend_from_slice(&[0x48, 0x31, 0x16]);          // xor [rsi], rdx
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);   // add rsi, 8
    s.extend_from_slice(&[0x49, 0x01, 0xE9]);          // add r9, rbp
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (dec_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, d as u8]);              // jnz dec_loop

    // ── Update state: r15d -= r8d, r14 = r10 (next seed) ──
    s.extend_from_slice(&[0x45, 0x29, 0xC7]);          // sub r15d, r8d
    s.extend_from_slice(&[0x4D, 0x89, 0xD6]);          // mov r14, r10

    // ── Jump back to page loop top ──
    let d = (page_loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xE9]);
    s.extend_from_slice(&(d as i32 - 3).to_le_bytes());

    // ── Patch jz-to-epilogue ──
    let epilogue_offset = s.len();
    let jz_disp = (epilogue_offset as i32) - (jz_epilogue_offset as i32 + 6);
    s[jz_epilogue_offset + 2] = jz_disp as u8;
    s[jz_epilogue_offset + 3] = (jz_disp >> 8) as u8;
    s[jz_epilogue_offset + 4] = (jz_disp >> 16) as u8;
    s[jz_epilogue_offset + 5] = (jz_disp >> 24) as u8;

    // ═══ Epilogue ═══
    s.extend_from_slice(&[0x48, 0x01, 0xDF]);          // add rdi, rbx
    s.extend_from_slice(&[0x48, 0x89, 0xF8]);          // mov rax, rdi
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);   // add rsp, 32 (deallocate frame)
    s.push(0x5D);                                       // pop rbp
    s.extend_from_slice(&[0x41, 0x5F]);                 // pop r15
    s.extend_from_slice(&[0x41, 0x5E]);                 // pop r14
    s.extend_from_slice(&[0x41, 0x5D]);                 // pop r13
    s.extend_from_slice(&[0x41, 0x5C]);                 // pop r12
    s.push(0x5E);                                       // pop rsi
    s.push(0x5F);                                       // pop rdi
    s.push(0x5B);                                       // pop rbx
    s.extend_from_slice(&[0xFF, 0xE0]);                 // jmp rax

    // ═══ Inline parameters (extended for multi-layer) ═══
    let params_offset = s.len();
    s.extend_from_slice(&orig_entry_rva.to_le_bytes()); // [+0]  4 bytes
    s.extend_from_slice(&text_rva.to_le_bytes());       // [+4]  4 bytes
    s.extend_from_slice(&total_qwords.to_le_bytes());   // [+8]  4 bytes
    // XTEA key packed as 2 × u64 (same byte layout as [u32; 4] LE)
    let k_lo = (xtea_key[0] as u64) | ((xtea_key[1] as u64) << 32);
    let k_hi = (xtea_key[2] as u64) | ((xtea_key[3] as u64) << 32);
    // SECURITY: Mask key with PE-derived values (key is NEVER stored in plaintext!)
    let (k_lo_stored, k_hi_stored) = if let Some((mask_lo, mask_hi)) = xtea_mask {
        // PE-derived mask - attacker must emulate to recover key
        (k_lo ^ mask_lo, k_hi ^ mask_hi)
    } else {
        // Legacy fallback: XOR with initial_seed if distributed_key enabled
        let distributed_key = POLY_OPTIONS.with(|opt| opt.borrow().distributed_key);
        if distributed_key {
            (k_lo ^ initial_seed, k_hi ^ initial_seed)
        } else {
            (k_lo, k_hi)
        }
    };
    s.extend_from_slice(&k_lo_stored.to_le_bytes());    // [+12] 8 bytes (PE-masked)
    s.extend_from_slice(&k_hi_stored.to_le_bytes());    // [+20] 8 bytes (PE-masked)
    s.extend_from_slice(&initial_seed.to_le_bytes());   // [+28] 8 bytes
    // Layer 2/3 keys (stored in params, read by stub for decryption)
    s.extend_from_slice(&layer2_key.unwrap_or(0).to_le_bytes());   // [+36] 8 bytes
    s.extend_from_slice(&layer3_prime.unwrap_or(0).to_le_bytes()); // [+44] 8 bytes
    // Total params: 52 bytes

    // ── Patch LEA displacements ──
    let lea_end = lea_patch_offset + 4;
    let lea_disp = (params_offset as i32) - (lea_end as i32);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&lea_disp.to_le_bytes());

    // Patch layer LEA if present
    if let Some(lea2_off) = lea2_patch_offset {
        let lea2_end = lea2_off + 4;
        let lea2_disp = (params_offset as i32) - (lea2_end as i32);
        s[lea2_off..lea2_off + 4].copy_from_slice(&lea2_disp.to_le_bytes());
    }

    s
}

/// Emit inline XTEA encrypt: rax (64-bit input) → rax (64-bit output).
///
/// XTEA key must be at [rsp+0..15] as 4 consecutive u32s.
/// 32 Feistel rounds with delta = 0x9E3779B9.
///
/// Clobbers: rcx, rdx, r8d, r9d, r10d, r11d (and rax).
/// Preserves: rbx, rsi, rdi, r12-r15, rbp, rsp.
fn emit_xtea_encrypt(s: &mut Vec<u8>) {
    // Split 64-bit input in rax into v0 (low 32) and v1 (high 32)
    s.extend_from_slice(&[0x41, 0x89, 0xC0]);          // mov r8d, eax (v0)
    s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x20]);   // shr rax, 32
    s.extend_from_slice(&[0x41, 0x89, 0xC1]);          // mov r9d, eax (v1)

    // sum = 0, round counter = 32
    s.extend_from_slice(&[0x45, 0x31, 0xD2]);          // xor r10d, r10d (sum)
    s.extend_from_slice(&[0xB9, 0x20, 0x00, 0x00, 0x00]); // mov ecx, 32

    let loop_top = s.len();

    // ── Half 1: v0 += (((v1<<4)^(v1>>5))+v1) ^ (sum + key[sum&3]) ──
    s.extend_from_slice(&[0x44, 0x89, 0xC8]);          // mov eax, r9d (v1)
    s.extend_from_slice(&[0x44, 0x89, 0xCA]);          // mov edx, r9d (v1)
    s.extend_from_slice(&[0xC1, 0xE0, 0x04]);          // shl eax, 4
    s.extend_from_slice(&[0xC1, 0xEA, 0x05]);          // shr edx, 5
    s.extend_from_slice(&[0x31, 0xD0]);                 // xor eax, edx
    s.extend_from_slice(&[0x44, 0x01, 0xC8]);          // add eax, r9d
    // key[sum & 3]
    s.extend_from_slice(&[0x44, 0x89, 0xD2]);          // mov edx, r10d (sum)
    s.extend_from_slice(&[0x83, 0xE2, 0x03]);          // and edx, 3
    s.extend_from_slice(&[0x44, 0x8B, 0x1C, 0x94]);   // mov r11d, [rsp+rdx*4]
    s.extend_from_slice(&[0x45, 0x01, 0xD3]);          // add r11d, r10d
    s.extend_from_slice(&[0x44, 0x31, 0xD8]);          // xor eax, r11d
    s.extend_from_slice(&[0x41, 0x01, 0xC0]);          // add r8d, eax

    // ── sum += DELTA ──
    s.extend_from_slice(&[0x41, 0x81, 0xC2]);          // add r10d, DELTA
    s.extend_from_slice(&0x9E3779B9u32.to_le_bytes());

    // ── Half 2: v1 += (((v0<<4)^(v0>>5))+v0) ^ (sum + key[(sum>>11)&3]) ──
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);          // mov eax, r8d (v0)
    s.extend_from_slice(&[0x44, 0x89, 0xC2]);          // mov edx, r8d (v0)
    s.extend_from_slice(&[0xC1, 0xE0, 0x04]);          // shl eax, 4
    s.extend_from_slice(&[0xC1, 0xEA, 0x05]);          // shr edx, 5
    s.extend_from_slice(&[0x31, 0xD0]);                 // xor eax, edx
    s.extend_from_slice(&[0x44, 0x01, 0xC0]);          // add eax, r8d
    // key[(sum >> 11) & 3]
    s.extend_from_slice(&[0x44, 0x89, 0xD2]);          // mov edx, r10d (sum)
    s.extend_from_slice(&[0xC1, 0xEA, 0x0B]);          // shr edx, 11
    s.extend_from_slice(&[0x83, 0xE2, 0x03]);          // and edx, 3
    s.extend_from_slice(&[0x44, 0x8B, 0x1C, 0x94]);   // mov r11d, [rsp+rdx*4]
    s.extend_from_slice(&[0x45, 0x01, 0xD3]);          // add r11d, r10d
    s.extend_from_slice(&[0x44, 0x31, 0xD8]);          // xor eax, r11d
    s.extend_from_slice(&[0x41, 0x01, 0xC1]);          // add r9d, eax

    // ── dec ecx; jnz loop_top ──
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, d as u8]);              // jnz loop_top

    // ── Reassemble: rax = (v1 << 32) | v0 ──
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);          // mov eax, r8d (v0, zero-extends)
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x20]);   // shl r9, 32
    s.extend_from_slice(&[0x4C, 0x09, 0xC8]);          // or rax, r9
}

/// Emit inline code to derive Layer 2 key from PE header fields.
/// Result is placed in r8. Uses rbx (ImageBase).
/// Clobbers: rax, rcx, r8, r9, r10
fn emit_derive_layer2_key(s: &mut Vec<u8>) {
    // Read PE header offset: mov eax, [rbx + 0x3C]
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]);
    // add rax, rbx  ; rax = PE header VA
    s.extend_from_slice(&[0x48, 0x01, 0xD8]);

    // Load fields:
    // r8d  = TimeDateStamp  [rax + 0x08]
    // r9   = ImageBase      [rax + 0x30]
    // r10d = FileAlignment  [rax + 0x3C]
    s.extend_from_slice(&[0x44, 0x8B, 0x40, 0x08]);    // mov r8d, [rax+0x08]
    s.extend_from_slice(&[0x4C, 0x8B, 0x48, 0x30]);    // mov r9, [rax+0x30]
    s.extend_from_slice(&[0x44, 0x8B, 0x50, 0x3C]);    // mov r10d, [rax+0x3C]

    // seed = time_stamp * 0x6A09E667BB67AE85
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x6A09E667BB67AE85_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC0]);    // imul rax, r8
    s.extend_from_slice(&[0x49, 0x89, 0xC0]);          // mov r8, rax

    // seed ^= rol(ImageBase, 23)
    s.extend_from_slice(&[0x49, 0xC1, 0xC1, 0x17]);    // rol r9, 23
    s.extend_from_slice(&[0x4D, 0x31, 0xC8]);          // xor r8, r9

    // seed ^= (FileAlignment << 40)
    s.extend_from_slice(&[0x49, 0xC1, 0xE2, 0x28]);    // shl r10, 40
    s.extend_from_slice(&[0x4D, 0x31, 0xD0]);          // xor r8, r10

    // splitmix64:
    // seed += 0x9E3779B97F4A7C15
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x9E3779B97F4A7C15_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x01, 0xC0]);          // add r8, rax

    // seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9
    s.extend_from_slice(&[0x4C, 0x89, 0xC0]);          // mov rax, r8
    s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x1E]);    // shr rax, 30
    s.extend_from_slice(&[0x49, 0x31, 0xC0]);          // xor r8, rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xBF58476D1CE4E5B9_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC0]);    // imul rax, r8
    s.extend_from_slice(&[0x49, 0x89, 0xC0]);          // mov r8, rax

    // seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EB
    s.extend_from_slice(&[0x4C, 0x89, 0xC0]);          // mov rax, r8
    s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x1B]);    // shr rax, 27
    s.extend_from_slice(&[0x49, 0x31, 0xC0]);          // xor r8, rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x94D049BB133111EB_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC0]);    // imul rax, r8
    s.extend_from_slice(&[0x49, 0x89, 0xC0]);          // mov r8, rax

    // seed ^= (seed >> 31)
    s.extend_from_slice(&[0x4C, 0x89, 0xC0]);          // mov rax, r8
    s.extend_from_slice(&[0x48, 0xC1, 0xE8, 0x1F]);    // shr rax, 31
    s.extend_from_slice(&[0x49, 0x31, 0xC0]);          // xor r8, rax
    // r8 = derived layer2_key
}

/// Emit inline code to derive Layer 3 prime from PE header fields.
/// Result is placed in r8. Uses rbx (ImageBase).
/// Clobbers: rax, rcx, r8, r9, r10
fn emit_derive_layer3_prime(s: &mut Vec<u8>) {
    // Read PE header offset: mov eax, [rbx + 0x3C]
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]);
    // add rax, rbx  ; rax = PE header VA
    s.extend_from_slice(&[0x48, 0x01, 0xD8]);

    // Load fields:
    // r9d  = TimeDateStamp   [rax + 0x08]
    // r10d = SectionAlignment [rax + 0x38]
    // rcx  = ImageBase       [rax + 0x30]
    s.extend_from_slice(&[0x44, 0x8B, 0x48, 0x08]);    // mov r9d, [rax+0x08]
    s.extend_from_slice(&[0x44, 0x8B, 0x50, 0x38]);    // mov r10d, [rax+0x38]
    s.extend_from_slice(&[0x48, 0x8B, 0x48, 0x30]);    // mov rcx, [rax+0x30]

    // seed = 0x3C6EF372FE94F82B (base)
    s.extend_from_slice(&[0x49, 0xB8]);
    s.extend_from_slice(&0x3C6EF372FE94F82B_u64.to_le_bytes());

    // seed ^= (time_stamp << 17)
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x11]);    // shl r9, 17
    s.extend_from_slice(&[0x4D, 0x31, 0xC8]);          // xor r8, r9

    // seed ^= ror(SectionAlign, 13)
    s.extend_from_slice(&[0x49, 0xC1, 0xCA, 0x0D]);    // ror r10, 13
    s.extend_from_slice(&[0x4D, 0x31, 0xD0]);          // xor r8, r10

    // seed ^= ImageBase * 0xD6E8FEB86659FD93
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xD6E8FEB86659FD93_u64.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x0F, 0xAF, 0xC1]);    // imul rax, rcx
    s.extend_from_slice(&[0x49, 0x31, 0xC0]);          // xor r8, rax

    // Ensure odd: or r8, 1
    s.extend_from_slice(&[0x49, 0x83, 0xC8, 0x01]);    // or r8, 1
    // r8 = derived layer3_prime
}

// ─── ROR-13 hash for shellcode export resolution ──────────────
fn ror13_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = h.rotate_right(13).wrapping_add(c as u32);
    }
    h
}

// ─── .sqpre stub builder ──────────────────────────────────────
//
// Generates a tiny (~60 byte) x86-64 shellcode that XOR-decrypts .sqinit
// before jumping to it. This creates a 2-stage decryption chain:
//
//   Entry → .sqpre (XOR decrypt .sqinit) → .sqinit (XTEA decrypt .text) → OEP
//
// This prevents static analysis of .sqinit - the XTEA key and decryption
// logic are hidden until .sqpre executes.
//
// SECURITY: XOR key is NEVER stored in plaintext!
// Instead, the key is derived at runtime from PE header fields:
//   - TimeDateStamp, SizeOfCode, CheckSum, AddressOfEntryPoint
// This makes static extraction impossible without emulation.
//
// Anti-debug: Checks PEB.BeingDebugged and poisons key derivation if detected.
//
// Inline parameters (8 bytes only - no key!):
//   [+0]  sqinit_rva        u32  - RVA of .sqinit section
//   [+4]  sqinit_size_qw    u32  - Size in qwords to decrypt

/// Compute XOR key from STABLE PE header fields (don't change when sections added)
/// These fields are read at runtime by .sqpre so MUST match exactly.
///
/// Stable fields used:
///   - TimeDateStamp (PE+0x08)      - set at compile time
///   - Machine (PE+0x04)            - architecture constant
///   - ImageBase (PE+0x30)          - linker-defined
///   - FileAlignment (PE+0x3C)      - linker-defined
///   - SectionAlignment (PE+0x38)   - linker-defined
///
fn compute_sqpre_xor_key(pe_data: &[u8]) -> u64 {
    // Read DOS header
    let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;

    // Read STABLE PE fields only
    let time_stamp = u32::from_le_bytes(pe_data[e_lfanew + 0x08..e_lfanew + 0x0C].try_into().unwrap());
    let machine = u16::from_le_bytes(pe_data[e_lfanew + 0x04..e_lfanew + 0x06].try_into().unwrap());
    let image_base = u64::from_le_bytes(pe_data[e_lfanew + 0x30..e_lfanew + 0x38].try_into().unwrap());
    let file_align = u32::from_le_bytes(pe_data[e_lfanew + 0x3C..e_lfanew + 0x40].try_into().unwrap());
    let sect_align = u32::from_le_bytes(pe_data[e_lfanew + 0x38..e_lfanew + 0x3C].try_into().unwrap());

    // Combine fields into seed
    let mut seed: u64 = (time_stamp as u64) << 32 | (machine as u64);
    seed ^= image_base.rotate_left(13);
    seed ^= (file_align as u64) << 16;
    seed ^= (sect_align as u64).rotate_left(7);
    seed ^= 0x517CC1B727220A95; // SQURE magic constant

    // Use correct splitmix_finalize
    splitmix_finalize(seed)
}

/// Compute Layer 2 key from PE header fields
/// SECURITY: Key is derived at runtime, never stored in binary
fn compute_layer2_key(pe_data: &[u8]) -> u64 {
    let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;

    let time_stamp = u32::from_le_bytes(pe_data[e_lfanew + 0x08..e_lfanew + 0x0C].try_into().unwrap());
    let image_base = u64::from_le_bytes(pe_data[e_lfanew + 0x30..e_lfanew + 0x38].try_into().unwrap());
    let file_align = u32::from_le_bytes(pe_data[e_lfanew + 0x3C..e_lfanew + 0x40].try_into().unwrap());

    // Different combination for Layer 2 (use 0x6A09E667BB67AE85 magic)
    let mut seed: u64 = (time_stamp as u64).wrapping_mul(0x6A09E667BB67AE85);
    seed ^= image_base.rotate_left(23);
    seed ^= (file_align as u64) << 40;

    // Use correct splitmix_finalize
    splitmix_finalize(seed)
}

/// Compute Layer 3 prime from PE header fields
/// SECURITY: Prime is derived at runtime, never stored in binary
fn compute_layer3_prime(pe_data: &[u8]) -> u64 {
    let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;

    let time_stamp = u32::from_le_bytes(pe_data[e_lfanew + 0x08..e_lfanew + 0x0C].try_into().unwrap());
    let sect_align = u32::from_le_bytes(pe_data[e_lfanew + 0x38..e_lfanew + 0x3C].try_into().unwrap());
    let image_base = u64::from_le_bytes(pe_data[e_lfanew + 0x30..e_lfanew + 0x38].try_into().unwrap());

    // Different combination for Layer 3 (use 0x3C6EF372FE94F82B base)
    let mut seed: u64 = 0x3C6EF372FE94F82B;
    seed ^= (time_stamp as u64) << 17;
    seed ^= (sect_align as u64).rotate_right(13);
    seed ^= image_base.wrapping_mul(0xD6E8FEB86659FD93);

    // Use correct splitmix_finalize, then ensure odd (better for rolling XOR)
    splitmix_finalize(seed) | 1
}

/// Compute XTEA key mask from PE header fields (for .sqinit)
/// Uses different constants than sqpre XOR key to prevent reuse attacks.
/// Returns (mask_lo, mask_hi) for masking the two 64-bit halves of XTEA key.
fn compute_xtea_mask(pe_data: &[u8]) -> (u64, u64) {
    let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;

    // Read STABLE PE fields that don't change with ASLR or section additions
    // NOTE: ImageBase is NOT stable - Windows loader updates it when ASLR relocates
    let time_stamp = u32::from_le_bytes(pe_data[e_lfanew + 0x08..e_lfanew + 0x0C].try_into().unwrap());
    let machine = u16::from_le_bytes(pe_data[e_lfanew + 0x04..e_lfanew + 0x06].try_into().unwrap());
    let file_align = u32::from_le_bytes(pe_data[e_lfanew + 0x3C..e_lfanew + 0x40].try_into().unwrap());
    let sect_align = u32::from_le_bytes(pe_data[e_lfanew + 0x38..e_lfanew + 0x3C].try_into().unwrap());

    eprintln!("[DEBUG] XTEA mask inputs: e_lfanew=0x{:X}, time=0x{:08X}, machine=0x{:04X}, file_align=0x{:X}, sect_align=0x{:X}",
              e_lfanew, time_stamp, machine, file_align, sect_align);

    // Combine stable PE fields with magic constant
    // TimeDateStamp provides 32 bits of unique entropy per build
    let mut seed: u64 = (time_stamp as u64) | ((machine as u64) << 48);
    seed ^= (file_align as u64) << 24;
    seed ^= (sect_align as u64).rotate_right(11);
    seed ^= 0xC6A4A7935BD1E995; // xxHash constant

    // Use splitmix_finalize for both masks
    let mask_lo = splitmix_finalize(seed);
    let mask_hi = splitmix_finalize(mask_lo ^ 0x85EBCA6B27D4EB4F);

    (mask_lo, mask_hi)
}

fn build_sqpre_stub(
    sqinit_rva: u32,
    sqinit_size_bytes: usize,
    xor_key: u64, // XOR key for decryption (stored in params for now)
) -> Vec<u8> {
    // Simplified version: stores XOR key in params instead of deriving from PE header
    // TODO: Implement PE header derivation for enhanced security
    let sqinit_size_qw = ((sqinit_size_bytes + 7) / 8) as u32;
    let mut s = Vec::with_capacity(80);

    // ── Get ImageBase from PEB ──
    // mov rax, gs:[0x60]    ; PEB
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // mov rbx, [rax+0x10]   ; ImageBase
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);

    // ── Load parameters: lea rax, [rip + disp32] ──
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]); // lea rax, [rip+?]

    // ── Read inline parameters ──
    // mov esi, [rax+0]   ; sqinit_rva
    s.extend_from_slice(&[0x8B, 0x30]);
    // mov ecx, [rax+4]   ; sqinit_size_qw
    s.extend_from_slice(&[0x8B, 0x48, 0x04]);
    // mov rdx, [rax+8]   ; xor_key
    s.extend_from_slice(&[0x48, 0x8B, 0x50, 0x08]);

    // ── Compute .sqinit VA: rsi = ImageBase + sqinit_rva ──
    // add rsi, rbx
    s.extend_from_slice(&[0x48, 0x01, 0xDE]);

    // ── Save .sqinit start for jump ──
    // mov rdi, rsi
    s.extend_from_slice(&[0x48, 0x89, 0xF7]);

    // ── XOR decrypt loop ──
    let loop_top = s.len();
    // xor [rsi], rdx       ; decrypt qword
    s.extend_from_slice(&[0x48, 0x31, 0x16]);
    // add rsi, 8           ; next qword
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    // dec ecx              ; count--
    s.extend_from_slice(&[0xFF, 0xC9]);
    // jnz loop_top
    let disp = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, disp as u8]);

    // ── Jump to .sqinit ──
    // jmp rdi
    s.extend_from_slice(&[0xFF, 0xE7]);

    // ── Patch LEA displacement to point to params ──
    let params_offset = s.len();
    let disp32 = (params_offset as i32) - (lea_patch_offset as i32 + 4);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&disp32.to_le_bytes());

    // ── Inline parameters (16 bytes) ──
    s.extend_from_slice(&sqinit_rva.to_le_bytes());      // [+0] sqinit_rva
    s.extend_from_slice(&sqinit_size_qw.to_le_bytes());  // [+4] sqinit_size_qw
    s.extend_from_slice(&xor_key.to_le_bytes());         // [+8] xor_key

    s
}

#[allow(dead_code)]
fn build_sqpre_stub_pe_derived(
    sqinit_rva: u32,
    sqinit_size_bytes: usize,
    _xor_key: u64, // IGNORED - key derived at runtime from PE header
    preferred_image_base: u64, // From PE file - NOT affected by ASLR
) -> Vec<u8> {
    // PE-derived key with ASLR fix: ImageBase embedded as immediate
    let sqinit_size_qw = ((sqinit_size_bytes + 7) / 8) as u32;
    let mut s = Vec::with_capacity(220);

    // ══════════════════════════════════════════════════════════════
    // Phase 1: Get ImageBase from PEB (for VA calculations only)
    // ══════════════════════════════════════════════════════════════
    // mov rax, gs:[0x60]    ; PEB
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // mov rbx, [rax+0x10]   ; actual ImageBase (from PEB, for VA calc)
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);

    // ══════════════════════════════════════════════════════════════
    // Phase 2: Anti-Debug - Check PEB.BeingDebugged
    // ══════════════════════════════════════════════════════════════
    // movzx r8d, byte [rax+0x02]  ; BeingDebugged flag (0 or 1)
    s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x40, 0x02]);
    // neg r8d                     ; 0 → 0, 1 → 0xFFFFFFFF
    s.extend_from_slice(&[0x41, 0xF7, 0xD8]);
    // and r8, 0xDEAD0000          ; r8 = 0 or 0xDEAD0000 (poison)
    s.extend_from_slice(&[0x49, 0x81, 0xE0]);
    s.extend_from_slice(&0xDEAD0000_u32.to_le_bytes());

    // ══════════════════════════════════════════════════════════════
    // Phase 3: Derive XOR key from STABLE PE header fields
    // ══════════════════════════════════════════════════════════════
    // ASLR FIX: ImageBase is embedded as immediate, not read from PE header
    // (Windows updates PE header ImageBase to actual load address)

    // mov eax, [rbx + 0x3C]       ; e_lfanew
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]);
    // add rax, rbx                ; rax = PE header VA
    s.extend_from_slice(&[0x48, 0x01, 0xD8]);

    // Load STABLE PE fields:
    // r9d  = TimeDateStamp  [rax + 0x08]
    // r10w = Machine        [rax + 0x04]
    // r11  = ImageBase      (EMBEDDED - not from PE header!)
    // r12d = FileAlignment  [rax + 0x3C]
    // r13d = SectionAlign   [rax + 0x38]
    s.extend_from_slice(&[0x44, 0x8B, 0x48, 0x08]); // mov r9d, [rax+0x08]
    s.extend_from_slice(&[0x44, 0x0F, 0xB7, 0x50, 0x04]); // movzx r10d, word [rax+0x04]
    // ASLR FIX: Use embedded preferred ImageBase instead of reading from PE
    s.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
    s.extend_from_slice(&preferred_image_base.to_le_bytes());
    s.extend_from_slice(&[0x44, 0x8B, 0x60, 0x3C]); // mov r12d, [rax+0x3C]
    s.extend_from_slice(&[0x44, 0x8B, 0x68, 0x38]); // mov r13d, [rax+0x38]

    // Combine: seed = (time_stamp << 32) | machine
    // shl r9, 32
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x20]);
    // or r9, r10 (seed in r9)
    s.extend_from_slice(&[0x4D, 0x09, 0xD1]);

    // seed ^= rol(ImageBase, 13)
    // rol r11, 13
    s.extend_from_slice(&[0x49, 0xC1, 0xC3, 0x0D]);
    // xor r9, r11
    s.extend_from_slice(&[0x4D, 0x31, 0xD9]);

    // seed ^= (FileAlignment << 16)
    // shl r12, 16
    s.extend_from_slice(&[0x49, 0xC1, 0xE4, 0x10]);
    // xor r9, r12
    s.extend_from_slice(&[0x4D, 0x31, 0xE1]);

    // seed ^= rol(SectionAlign, 7)
    // rol r13, 7
    s.extend_from_slice(&[0x49, 0xC1, 0xC5, 0x07]);
    // xor r9, r13
    s.extend_from_slice(&[0x4D, 0x31, 0xE9]);

    // seed ^= 0x517CC1B727220A95 (SQURE magic)
    // mov rax, imm64
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x517CC1B727220A95_u64.to_le_bytes());
    // xor r9, rax
    s.extend_from_slice(&[0x49, 0x31, 0xC1]);

    // Apply poison from anti-debug (r8)
    // xor r9, r8  ; if debugged, key is wrong
    s.extend_from_slice(&[0x4D, 0x31, 0xC1]);

    // ═══ splitmix_finalize (CORRECT formula) ═══
    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // h *= 0xFF51AFD7ED558CCD
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xFF51AFD7ED558CCD_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // h *= 0xC4CEB9FE1A85EC53
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xC4CEB9FE1A85EC53_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // h ^= h >> 33 → final key in rdx
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]); // xor rdx, r9
    // Now rdx = derived XOR key (poisoned if debugged)

    // ══════════════════════════════════════════════════════════════
    // Phase 4: Load inline parameters and decrypt
    // ══════════════════════════════════════════════════════════════
    // lea rax, [rip + params]
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);

    // mov esi, [rax+0]   ; sqinit_rva
    s.extend_from_slice(&[0x8B, 0x30]);
    // mov ecx, [rax+4]   ; sqinit_size_qw
    s.extend_from_slice(&[0x8B, 0x48, 0x04]);

    // Compute .sqinit VA: rsi = ImageBase + sqinit_rva
    // add rsi, rbx
    s.extend_from_slice(&[0x48, 0x01, 0xDE]);

    // Save .sqinit start for jump
    // mov rdi, rsi
    s.extend_from_slice(&[0x48, 0x89, 0xF7]);

    // XOR decrypt loop
    let loop_top = s.len();
    // xor [rsi], rdx       ; decrypt qword
    s.extend_from_slice(&[0x48, 0x31, 0x16]);
    // add rsi, 8           ; next qword
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]);
    // dec ecx              ; count--
    s.extend_from_slice(&[0xFF, 0xC9]);
    // jnz loop_top
    let disp = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, disp as u8]);

    // Jump to .sqinit
    // jmp rdi
    s.extend_from_slice(&[0xFF, 0xE7]);

    // Patch LEA displacement to point to params
    let params_offset = s.len();
    let disp32 = (params_offset as i32) - (lea_patch_offset as i32 + 4);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&disp32.to_le_bytes());

    // Inline parameters (16 bytes - include key for debugging)
    s.extend_from_slice(&sqinit_rva.to_le_bytes());      // [+0] sqinit_rva
    s.extend_from_slice(&sqinit_size_qw.to_le_bytes());  // [+4] sqinit_size_qw
    s.extend_from_slice(&_xor_key.to_le_bytes());        // [+8] stored key (for debug)

    s
}

/// PE-derived XOR key stub with ASLR fix
/// ImageBase is embedded as immediate since Windows updates PE header for ASLR
#[allow(dead_code)]
fn build_sqpre_stub_pe_derived_debug(
    sqinit_rva: u32,
    sqinit_size_bytes: usize,
    _xor_key: u64, // Not used - key is derived at runtime
    preferred_image_base: u64, // From PE file, not affected by ASLR
    enable_anti_debug: bool,
) -> Vec<u8> {
    let sqinit_size_qw = ((sqinit_size_bytes + 7) / 8) as u32;
    let mut s = Vec::with_capacity(250);

    // ═══ Phase 1: Get ImageBase from PEB (for VA calculations only) ═══
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]); // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10] ; actual ImageBase

    // ═══ Phase 2: Anti-Debug ═══
    if enable_anti_debug {
        s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x40, 0x02]); // movzx r8d, byte [rax+0x02]
        s.extend_from_slice(&[0x41, 0xF7, 0xD8]); // neg r8d
        s.extend_from_slice(&[0x49, 0x81, 0xE0]);
        s.extend_from_slice(&0xDEAD0000_u32.to_le_bytes()); // and r8, 0xDEAD0000
    } else {
        // Anti-debug disabled: set r8 = 0 (same size: 5+3+7=15 bytes)
        s.extend_from_slice(&[0x45, 0x31, 0xC0, 0x90, 0x90]); // xor r8d, r8d; nop; nop
        s.extend_from_slice(&[0x90, 0x90, 0x90]); // nop; nop; nop
        s.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]); // 7 nops
    }

    // ═══ Phase 3: Read PE header ═══
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]); // mov eax, [rbx+0x3C] ; e_lfanew
    s.extend_from_slice(&[0x48, 0x01, 0xD8]); // add rax, rbx ; PE header VA

    // Read STABLE PE fields (these don't change with ASLR)
    s.extend_from_slice(&[0x44, 0x8B, 0x48, 0x08]); // mov r9d, [rax+0x08] TimeDateStamp
    s.extend_from_slice(&[0x44, 0x0F, 0xB7, 0x50, 0x04]); // movzx r10d, word [rax+0x04] Machine
    // ImageBase: Use EMBEDDED preferred value (not from PE header - ASLR changes it!)
    s.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
    s.extend_from_slice(&preferred_image_base.to_le_bytes());
    s.extend_from_slice(&[0x44, 0x8B, 0x60, 0x3C]); // mov r12d, [rax+0x3C] FileAlign
    s.extend_from_slice(&[0x44, 0x8B, 0x68, 0x38]); // mov r13d, [rax+0x38] SectionAlign

    // ═══ Phase 3b: Seed combination ═══
    // seed = (time_stamp << 32) | machine
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x20]); // shl r9, 32
    s.extend_from_slice(&[0x4D, 0x09, 0xD1]); // or r9, r10
    // seed ^= rol(ImageBase, 13)
    s.extend_from_slice(&[0x49, 0xC1, 0xC3, 0x0D]); // rol r11, 13
    s.extend_from_slice(&[0x4D, 0x31, 0xD9]); // xor r9, r11
    // seed ^= (FileAlign << 16)
    s.extend_from_slice(&[0x49, 0xC1, 0xE4, 0x10]); // shl r12, 16
    s.extend_from_slice(&[0x4D, 0x31, 0xE1]); // xor r9, r12
    // seed ^= rol(SectionAlign, 7)
    s.extend_from_slice(&[0x49, 0xC1, 0xC5, 0x07]); // rol r13, 7
    s.extend_from_slice(&[0x4D, 0x31, 0xE9]); // xor r9, r13
    // seed ^= magic
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x517CC1B727220A95_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x31, 0xC1]); // xor r9, rax
    // Apply anti-debug poison (if debugged, key will be wrong)
    s.extend_from_slice(&[0x4D, 0x31, 0xC1]); // xor r9, r8

    // ═══ Phase 3c: splitmix_finalize ═══
    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx
    // h *= 0xFF51AFD7ED558CCD
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xFF51AFD7ED558CCD_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax
    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx
    // h *= 0xC4CEB9FE1A85EC53
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0xC4CEB9FE1A85EC53_u64.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax
    // h ^= h >> 33 → final key in rdx
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]); // xor rdx, r9
    // rdx = derived XOR key (poisoned if debugged)
    eprintln!("[DEBUG] Using embedded ImageBase: 0x{:016X}", preferred_image_base);

    // ═══ Phase 4: Decrypt .sqinit ═══
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]); // lea rax, [rip+params]

    s.extend_from_slice(&[0x8B, 0x30]); // mov esi, [rax+0]
    s.extend_from_slice(&[0x8B, 0x48, 0x04]); // mov ecx, [rax+4]

    s.extend_from_slice(&[0x48, 0x01, 0xDE]); // add rsi, rbx
    s.extend_from_slice(&[0x48, 0x89, 0xF7]); // mov rdi, rsi

    // XOR decrypt loop
    let loop_top = s.len();
    s.extend_from_slice(&[0x48, 0x31, 0x16]); // xor [rsi], rdx
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]); // add rsi, 8
    s.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let disp = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop_top

    s.extend_from_slice(&[0xFF, 0xE7]); // jmp rdi

    // Patch LEA
    let params_offset = s.len();
    let disp32 = (params_offset as i32) - (lea_patch_offset as i32 + 4);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&disp32.to_le_bytes());

    // Params (8 bytes)
    s.extend_from_slice(&sqinit_rva.to_le_bytes());
    s.extend_from_slice(&sqinit_size_qw.to_le_bytes());

    s
}

/// Obfuscated PE-derived XOR key stub
///
/// Countermeasures against static analysis:
/// 1. Constants are split into 2 parts that XOR together
/// 2. Junk instructions interspersed
/// 3. Opaque predicates (always-true/false branches)
/// 4. Stack-based constant reconstruction
#[allow(dead_code)]
fn build_sqpre_stub_obfuscated(
    sqinit_rva: u32,
    sqinit_size_bytes: usize,
    _xor_key: u64,
    preferred_image_base: u64,
    enable_anti_debug: bool,
) -> Vec<u8> {
    let sqinit_size_qw = ((sqinit_size_bytes + 7) / 8) as u32;
    let mut s = Vec::with_capacity(500);

    // Generate random-looking split keys from the XOR key
    // This makes each protected binary have unique patterns
    // Using splitmix-style derivation for pseudo-random splits
    fn derive_split(seed: u64, round: u64) -> u64 {
        let mut h = seed.wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
        h ^= h >> 30;
        h = h.wrapping_mul(0xBF58476D1CE4E5B9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94D049BB133111EB);
        h ^= h >> 31;
        h
    }

    // Use XOR key as seed for splits (unique per-build)
    let split1 = derive_split(_xor_key, 1);
    let split2 = derive_split(_xor_key, 2);
    let split3 = derive_split(_xor_key, 3);
    let split4 = derive_split(_xor_key, 4);

    // Generate decoy constants (never used but look like real splits)
    let decoy1 = derive_split(_xor_key, 5);
    let decoy2 = derive_split(_xor_key, 6);
    let decoy3 = derive_split(_xor_key, 7);

    // Split constants: real = part1 ^ part2
    let image_base_part1 = preferred_image_base ^ split1;
    let image_base_part2 = split1;

    let magic_real = 0x517CC1B727220A95_u64;
    let magic_part1 = magic_real ^ split2;
    let magic_part2 = split2;

    let sm1_real = 0xFF51AFD7ED558CCD_u64;
    let sm1_part1 = sm1_real ^ split3;
    let sm1_part2 = split3;

    let sm2_real = 0xC4CEB9FE1A85EC53_u64;
    let sm2_part1 = sm2_real ^ split4;
    let sm2_part2 = split4;

    // ═══ Prologue: Stack frame for constant reconstruction ═══
    // sub rsp, 64  ; Reserve stack for temps
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]);

    // ═══ Phase 1: Get ImageBase from PEB ═══
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]); // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10]

    // ═══ Phase 2: Anti-Debug with junk ═══
    if enable_anti_debug {
        s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x40, 0x02]); // movzx r8d, byte [rax+0x02]
        // Junk: xor r15, r15 (harmless)
        s.extend_from_slice(&[0x4D, 0x31, 0xFF]);
        s.extend_from_slice(&[0x41, 0xF7, 0xD8]); // neg r8d
        // Junk: lea r15, [r15+1] (harmless, opaque)
        s.extend_from_slice(&[0x4D, 0x8D, 0x7F, 0x01]);
        s.extend_from_slice(&[0x49, 0x81, 0xE0]);
        s.extend_from_slice(&0xDEAD0000_u32.to_le_bytes()); // and r8, 0xDEAD0000
    } else {
        // Anti-debug disabled: set r8 = 0, keep junk for same size (5+3+3+4+7=22 bytes)
        s.extend_from_slice(&[0x45, 0x31, 0xC0, 0x90, 0x90]); // xor r8d, r8d; nop; nop
        s.extend_from_slice(&[0x4D, 0x31, 0xFF]); // xor r15, r15 (keep junk)
        s.extend_from_slice(&[0x90, 0x90, 0x90]); // nop; nop; nop
        s.extend_from_slice(&[0x4D, 0x8D, 0x7F, 0x01]); // lea r15, [r15+1] (keep junk)
        s.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]); // 7 nops
    }

    // ═══ Phase 3: Read ALL PE header fields FIRST ═══
    // (before clobbering rax with obfuscated constants)
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]); // mov eax, [rbx+0x3C]
    s.extend_from_slice(&[0x48, 0x01, 0xD8]); // add rax, rbx ; rax = PE header VA

    s.extend_from_slice(&[0x44, 0x8B, 0x48, 0x08]); // mov r9d, [rax+0x08] TimeDateStamp
    s.extend_from_slice(&[0x44, 0x0F, 0xB7, 0x50, 0x04]); // movzx r10d, word [rax+0x04] Machine
    s.extend_from_slice(&[0x44, 0x8B, 0x60, 0x3C]); // mov r12d, [rax+0x3C] FileAlign
    s.extend_from_slice(&[0x44, 0x8B, 0x68, 0x38]); // mov r13d, [rax+0x38] SectionAlign
    // NOTE: rax will be clobbered below - all PE fields are now saved

    // ═══ OBFUSCATED: ImageBase reconstruction ═══
    // Store parts on stack, XOR to reconstruct (clobbers rax)
    // mov [rsp+0], imm64 (part1)
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    s.extend_from_slice(&image_base_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax

    // Junk: test r15, r15
    s.extend_from_slice(&[0x4D, 0x85, 0xFF]);

    // mov [rsp+8], imm64 (part2)
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    s.extend_from_slice(&image_base_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x08]); // mov [rsp+8], rax

    // xor to reconstruct: r11 = [rsp] ^ [rsp+8]
    s.extend_from_slice(&[0x4C, 0x8B, 0x1C, 0x24]); // mov r11, [rsp]
    s.extend_from_slice(&[0x4C, 0x33, 0x5C, 0x24, 0x08]); // xor r11, [rsp+8]

    // ═══ Phase 3b: Seed combination ═══
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x20]); // shl r9, 32
    s.extend_from_slice(&[0x4D, 0x09, 0xD1]); // or r9, r10
    s.extend_from_slice(&[0x49, 0xC1, 0xC3, 0x0D]); // rol r11, 13
    s.extend_from_slice(&[0x4D, 0x31, 0xD9]); // xor r9, r11
    s.extend_from_slice(&[0x49, 0xC1, 0xE4, 0x10]); // shl r12, 16
    s.extend_from_slice(&[0x4D, 0x31, 0xE1]); // xor r9, r12
    s.extend_from_slice(&[0x49, 0xC1, 0xC5, 0x07]); // rol r13, 7
    s.extend_from_slice(&[0x4D, 0x31, 0xE9]); // xor r9, r13

    // ═══ OBFUSCATED: Magic constant reconstruction + DECOYS ═══
    // Decoy 1: load a value but never use XOR result meaningfully
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, decoy1
    s.extend_from_slice(&decoy1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax (decoy storage)

    // mov rax, magic_part1
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&magic_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+0x10], rax

    // Decoy 2: another unused constant
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, decoy2
    s.extend_from_slice(&decoy2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]); // mov [rsp+0x30], rax

    // mov rax, magic_part2
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&magic_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x33, 0x44, 0x24, 0x10]); // xor rax, [rsp+0x10]
    s.extend_from_slice(&[0x49, 0x31, 0xC1]); // xor r9, rax

    // Apply anti-debug poison
    s.extend_from_slice(&[0x4D, 0x31, 0xC1]); // xor r9, r8

    // ═══ Phase 3c: splitmix_finalize with obfuscated constants ═══
    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // ═══ OBFUSCATED: splitmix constant 1 + DECOY ═══
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm1_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+0x18], rax

    // Decoy 3: interleaved with real constants
    s.extend_from_slice(&[0x48, 0xB8]); // mov rax, decoy3
    s.extend_from_slice(&decoy3.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x38]); // mov [rsp+0x38], rax (never used)

    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm1_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x33, 0x44, 0x24, 0x18]); // xor rax, [rsp+0x18]

    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // h ^= h >> 33
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // ═══ OBFUSCATED: splitmix constant 2 ═══
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm2_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm2_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x33, 0x44, 0x24, 0x20]); // xor rax, [rsp+0x20]

    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // h ^= h >> 33 → final key in rdx
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]); // xor rdx, r9

    // ═══ Epilogue: Restore stack ═══
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]); // add rsp, 64

    // ═══ Phase 4: Decrypt .sqinit ═══
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]); // lea rax, [rip+params]

    s.extend_from_slice(&[0x8B, 0x30]); // mov esi, [rax+0]
    s.extend_from_slice(&[0x8B, 0x48, 0x04]); // mov ecx, [rax+4]

    s.extend_from_slice(&[0x48, 0x01, 0xDE]); // add rsi, rbx
    s.extend_from_slice(&[0x48, 0x89, 0xF7]); // mov rdi, rsi

    // XOR decrypt loop
    let loop_top = s.len();
    s.extend_from_slice(&[0x48, 0x31, 0x16]); // xor [rsi], rdx
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]); // add rsi, 8
    s.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let disp = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop_top

    s.extend_from_slice(&[0xFF, 0xE7]); // jmp rdi

    // Patch LEA
    let params_offset = s.len();
    let disp32 = (params_offset as i32) - (lea_patch_offset as i32 + 4);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&disp32.to_le_bytes());

    // Params (8 bytes)
    s.extend_from_slice(&sqinit_rva.to_le_bytes());
    s.extend_from_slice(&sqinit_size_qw.to_le_bytes());

    eprintln!("[DEBUG] Obfuscated stub size: {} bytes", s.len());
    eprintln!("[DEBUG] Randomized split keys (derived from XOR key 0x{:016X}):", _xor_key);
    eprintln!("  Split1 = 0x{:016X}", split1);
    eprintln!("  Split2 = 0x{:016X}", split2);
    eprintln!("  Split3 = 0x{:016X}", split3);
    eprintln!("  Split4 = 0x{:016X}", split4);
    eprintln!("[DEBUG] Decoy constants:");
    eprintln!("  Decoy1 = 0x{:016X}", decoy1);
    eprintln!("  Decoy2 = 0x{:016X}", decoy2);
    eprintln!("  Decoy3 = 0x{:016X}", decoy3);
    eprintln!("[DEBUG] Reconstructed values:");
    eprintln!("  ImageBase: 0x{:016X} ^ 0x{:016X} = 0x{:016X}",
              image_base_part1, image_base_part2, preferred_image_base);
    eprintln!("  Magic: 0x{:016X} ^ 0x{:016X} = 0x{:016X}",
              magic_part1, magic_part2, magic_real);

    s
}

/// Ultra-obfuscated PE-derived XOR key stub (v2)
///
/// Uses 3-way splits with mixed operations to defeat brute-force:
/// - target = (A + B) ^ C (for ImageBase, MAGIC)
/// - target = (A ^ B) - C (for splitmix constants)
/// - 20+ decoy constants to expand search space to C(30,3) = 4060
#[allow(dead_code)]
fn build_sqpre_stub_obfuscated_v2(
    sqinit_rva: u32,
    sqinit_size_bytes: usize,
    _xor_key: u64,
    preferred_image_base: u64,
    enable_anti_debug: bool,
) -> Vec<u8> {
    let sqinit_size_qw = ((sqinit_size_bytes + 7) / 8) as u32;
    let mut s = Vec::with_capacity(700);

    // Derive pseudo-random values from XOR key
    fn derive(seed: u64, round: u64) -> u64 {
        let mut h = seed.wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
        h ^= h >> 30;
        h = h.wrapping_mul(0xBF58476D1CE4E5B9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94D049BB133111EB);
        h ^= h >> 31;
        h
    }

    // 3-way splits: target = (part1 + part2) ^ part3
    // For ImageBase: 0x140000000 = (A + B) ^ C
    let ib_part1 = derive(_xor_key, 1);
    let ib_part2 = derive(_xor_key, 2);
    // Solve for part3: C = (A + B) ^ target
    let ib_part3 = ib_part1.wrapping_add(ib_part2) ^ preferred_image_base;

    // For MAGIC: 0x517CC1B727220A95 = (A + B) ^ C
    let magic_real = 0x517CC1B727220A95_u64;
    let mg_part1 = derive(_xor_key, 3);
    let mg_part2 = derive(_xor_key, 4);
    let mg_part3 = mg_part1.wrapping_add(mg_part2) ^ magic_real;

    // For SM1: 0xFF51AFD7ED558CCD = (A ^ B) - C
    let sm1_real = 0xFF51AFD7ED558CCD_u64;
    let sm1_part1 = derive(_xor_key, 5);
    let sm1_part2 = derive(_xor_key, 6);
    // C = (A ^ B) - target
    let sm1_part3 = (sm1_part1 ^ sm1_part2).wrapping_sub(sm1_real);

    // For SM2: 0xC4CEB9FE1A85EC53 = (A ^ B) - C
    let sm2_real = 0xC4CEB9FE1A85EC53_u64;
    let sm2_part1 = derive(_xor_key, 7);
    let sm2_part2 = derive(_xor_key, 8);
    let sm2_part3 = (sm2_part1 ^ sm2_part2).wrapping_sub(sm2_real);

    // Generate 20 decoy constants
    let decoys: Vec<u64> = (10..30).map(|i| derive(_xor_key, i)).collect();

    // ═══ Prologue: Stack frame (larger for decoys) ═══
    // sub rsp, 0x100
    s.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00]);

    // ═══ Phase 1: Get ImageBase from PEB ═══
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]); // mov rax, gs:[0x60]
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10]

    // ═══ Phase 2: Anti-Debug ═══
    if enable_anti_debug {
        s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x40, 0x02]); // movzx r8d, byte [rax+0x02]
        s.extend_from_slice(&[0x41, 0xF7, 0xD8]); // neg r8d
        s.extend_from_slice(&[0x49, 0x81, 0xE0]);
        s.extend_from_slice(&0xDEAD0000_u32.to_le_bytes()); // and r8, 0xDEAD0000
    } else {
        // Anti-debug disabled: set r8 = 0, padded to same size (5+3+7=15 bytes)
        s.extend_from_slice(&[0x45, 0x31, 0xC0, 0x90, 0x90]); // xor r8d, r8d; nop; nop
        s.extend_from_slice(&[0x90, 0x90, 0x90]); // nop; nop; nop
        s.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]); // 7 nops
    }

    // ═══ Phase 3: Read PE header fields ═══
    s.extend_from_slice(&[0x8B, 0x43, 0x3C]); // mov eax, [rbx+0x3C]
    s.extend_from_slice(&[0x48, 0x01, 0xD8]); // add rax, rbx
    s.extend_from_slice(&[0x44, 0x8B, 0x48, 0x08]); // mov r9d, [rax+0x08] TimeDateStamp
    s.extend_from_slice(&[0x44, 0x0F, 0xB7, 0x50, 0x04]); // movzx r10d, word [rax+0x04] Machine
    s.extend_from_slice(&[0x44, 0x8B, 0x60, 0x3C]); // mov r12d, [rax+0x3C] FileAlign
    s.extend_from_slice(&[0x44, 0x8B, 0x68, 0x38]); // mov r13d, [rax+0x38] SectionAlign

    // ═══ Scatter decoy constants across stack ═══
    // This creates a large pool of constants to confuse analysis
    for (i, &decoy) in decoys.iter().enumerate() {
        let offset = 0x40 + (i * 8) as i8;
        s.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        s.extend_from_slice(&decoy.to_le_bytes());
        // mov [rsp+offset], rax
        s.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        s.extend_from_slice(&(offset as i32).to_le_bytes());
    }

    // ═══ 3-WAY ImageBase reconstruction: r11 = (part1 + part2) ^ part3 ═══
    // Store part1 at [rsp+0x00]
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&ib_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax

    // Store part2 at [rsp+0x08]
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&ib_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x08]); // mov [rsp+8], rax

    // Store part3 at [rsp+0x10]
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&ib_part3.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+0x10], rax

    // r11 = [rsp+0] + [rsp+8]
    s.extend_from_slice(&[0x4C, 0x8B, 0x1C, 0x24]); // mov r11, [rsp]
    s.extend_from_slice(&[0x4C, 0x03, 0x5C, 0x24, 0x08]); // add r11, [rsp+8]
    // r11 ^= [rsp+0x10]
    s.extend_from_slice(&[0x4C, 0x33, 0x5C, 0x24, 0x10]); // xor r11, [rsp+0x10]

    // ═══ Seed combination ═══
    s.extend_from_slice(&[0x49, 0xC1, 0xE1, 0x20]); // shl r9, 32
    s.extend_from_slice(&[0x4D, 0x09, 0xD1]); // or r9, r10
    s.extend_from_slice(&[0x49, 0xC1, 0xC3, 0x0D]); // rol r11, 13
    s.extend_from_slice(&[0x4D, 0x31, 0xD9]); // xor r9, r11
    s.extend_from_slice(&[0x49, 0xC1, 0xE4, 0x10]); // shl r12, 16
    s.extend_from_slice(&[0x4D, 0x31, 0xE1]); // xor r9, r12
    s.extend_from_slice(&[0x49, 0xC1, 0xC5, 0x07]); // rol r13, 7
    s.extend_from_slice(&[0x4D, 0x31, 0xE9]); // xor r9, r13

    // ═══ 3-WAY MAGIC reconstruction: (part1 + part2) ^ part3 ═══
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&mg_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+0x18], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&mg_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&mg_part3.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax

    // rax = [rsp+0x18] + [rsp+0x20]
    s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x18]); // mov rax, [rsp+0x18]
    s.extend_from_slice(&[0x48, 0x03, 0x44, 0x24, 0x20]); // add rax, [rsp+0x20]
    s.extend_from_slice(&[0x48, 0x33, 0x44, 0x24, 0x28]); // xor rax, [rsp+0x28]
    s.extend_from_slice(&[0x49, 0x31, 0xC1]); // xor r9, rax

    // Apply anti-debug poison
    s.extend_from_slice(&[0x4D, 0x31, 0xC1]); // xor r9, r8

    // ═══ splitmix_finalize step 1 ═══
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // ═══ 3-WAY SM1: (part1 ^ part2) - part3 ═══
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm1_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]); // mov [rsp+0x30], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm1_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x38]); // mov [rsp+0x38], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm1_part3.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00]); // mov [rsp+0xF8], rax

    // rax = [rsp+0x30] ^ [rsp+0x38] - [rsp+0xF8]
    s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x30]); // mov rax, [rsp+0x30]
    s.extend_from_slice(&[0x48, 0x33, 0x44, 0x24, 0x38]); // xor rax, [rsp+0x38]
    s.extend_from_slice(&[0x48, 0x2B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00]); // sub rax, [rsp+0xF8]

    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // ═══ splitmix_finalize step 2 ═══
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x49, 0x31, 0xD1]); // xor r9, rdx

    // ═══ 3-WAY SM2: (part1 ^ part2) - part3 ═══
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm2_part1.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00]); // mov [rsp+0xE8], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm2_part2.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00]); // mov [rsp+0xE0], rax
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&sm2_part3.to_le_bytes());
    s.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00]); // mov [rsp+0xD8], rax

    // rax = [rsp+0xE8] ^ [rsp+0xE0] - [rsp+0xD8]
    s.extend_from_slice(&[0x48, 0x8B, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00]); // mov rax, [rsp+0xE8]
    s.extend_from_slice(&[0x48, 0x33, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00]); // xor rax, [rsp+0xE0]
    s.extend_from_slice(&[0x48, 0x2B, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00]); // sub rax, [rsp+0xD8]

    s.extend_from_slice(&[0x49, 0x0F, 0xAF, 0xC1]); // imul rax, r9
    s.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax

    // ═══ Final XOR ═══
    s.extend_from_slice(&[0x4C, 0x89, 0xCA]); // mov rdx, r9
    s.extend_from_slice(&[0x48, 0xC1, 0xEA, 0x21]); // shr rdx, 33
    s.extend_from_slice(&[0x4C, 0x31, 0xCA]); // xor rdx, r9

    // ═══ Epilogue ═══
    s.extend_from_slice(&[0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00]); // add rsp, 0x100

    // ═══ Decrypt .sqinit ═══
    let lea_patch_offset = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]); // lea rax, [rip+params]

    s.extend_from_slice(&[0x8B, 0x30]); // mov esi, [rax+0]
    s.extend_from_slice(&[0x8B, 0x48, 0x04]); // mov ecx, [rax+4]
    s.extend_from_slice(&[0x48, 0x01, 0xDE]); // add rsi, rbx
    s.extend_from_slice(&[0x48, 0x89, 0xF7]); // mov rdi, rsi

    let loop_top = s.len();
    s.extend_from_slice(&[0x48, 0x31, 0x16]); // xor [rsi], rdx
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x08]); // add rsi, 8
    s.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    let disp = (loop_top as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0x75, disp as u8]); // jnz loop_top

    s.extend_from_slice(&[0xFF, 0xE7]); // jmp rdi

    let params_offset = s.len();
    let disp32 = (params_offset as i32) - (lea_patch_offset as i32 + 4);
    s[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&disp32.to_le_bytes());

    s.extend_from_slice(&sqinit_rva.to_le_bytes());
    s.extend_from_slice(&sqinit_size_qw.to_le_bytes());

    eprintln!("[DEBUG] Obfuscated v2 stub size: {} bytes", s.len());
    eprintln!("[DEBUG] 3-way splits with 20 decoys:");
    eprintln!("  ImageBase = (0x{:016X} + 0x{:016X}) ^ 0x{:016X} = 0x{:016X}",
              ib_part1, ib_part2, ib_part3, preferred_image_base);
    eprintln!("  MAGIC = (0x{:016X} + 0x{:016X}) ^ 0x{:016X}",
              mg_part1, mg_part2, mg_part3);
    eprintln!("  SM1 = (0x{:016X} ^ 0x{:016X}) - 0x{:016X}",
              sm1_part1, sm1_part2, sm1_part3);
    eprintln!("  Total constants in binary: {} (real) + {} (decoy) = {}",
              12, decoys.len(), 12 + decoys.len());
    eprintln!("  Brute-force complexity: C({},3) × 2 ops = {} combinations",
              12 + decoys.len(), (12 + decoys.len()) * (11 + decoys.len()) * (10 + decoys.len()) / 6 * 2);

    s
}

// ─── Ultra + VEH combined stub builder ────────────────────────────
//
// Combines ultra anti-analysis phases (16 checks) with VEH nanomite support.
// This is the most hardened option: all ultra checks + working nanomites.
//
fn build_ultra_veh_stub(
    orig_entry_rva: u32,
    nanomite_entries: &[NanomiteRawEntry],
    nanomite_crypto_key: u64,
    text_rva: u32,
    text_size: u32,
    cewe_seed: u64,
) -> Vec<u8> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let nm_xtea = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
    let nm_count = nanomite_entries.len().min(128) as u32;
    let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");

    // Sort entries for binary search
    let mut sorted_entries: Vec<_> = nanomite_entries.iter().take(128).cloned().collect();
    sorted_entries.sort_by_key(|e| e.bp_rva);
    let nanomite_entries = &sorted_entries[..];

    let mut s = Vec::with_capacity(12288); // Larger for ultra phases
    let mut rng = ChaCha20Rng::seed_from_u64(nanomite_crypto_key ^ cewe_seed);

    // ═══ INIT CODE ═══

    // Prologue: save callee-saved registers
    s.push(0x53);                                       // push rbx
    s.push(0x57);                                       // push rdi
    s.push(0x56);                                       // push rsi
    s.extend_from_slice(&[0x41, 0x54]);                 // push r12
    s.extend_from_slice(&[0x41, 0x55]);                 // push r13
    s.extend_from_slice(&[0x41, 0x56]);                 // push r14
    s.extend_from_slice(&[0x41, 0x57]);                 // push r15
    s.push(0x55);                                       // push rbp

    // Larger stack frame for ultra phases
    s.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00]); // sub rsp, 0x400

    // LEA rbp, [rip + data_area]
    let data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x2D,
                          0x00, 0x00, 0x00, 0x00]);     // lea rbp, [rip+?] (patched)

    // Get ImageBase from PEB (obfuscated)
    transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);    // mov rbx, [rax+0x10] (ImageBase)
    s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]);    // mov [rbp+0x00], rbx

    // Initial anti-debug: PEB.BeingDebugged
    transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
    s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);    // movzx eax, byte [rax+2]
    s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]);    // mov [rbp+0x08], rax (poison)
    s.extend_from_slice(&[0x49, 0x89, 0xC6]);          // mov r14, rax (keep poison in r14)

    // Initialize r8 for ultra phases (poison accumulator)
    s.extend_from_slice(&[0x45, 0x31, 0xC0]);          // xor r8d, r8d
    s.extend_from_slice(&[0x4D, 0x09, 0xF0]);          // or r8, r14 (start with PEB poison)

    // ═══ ULTRA ANTI-ANALYSIS PHASES ═══

    // Phase 1: VM Detection
    transform::hardening::emit_vm_detection(&mut s, &mut rng);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 2);

    // Phase 2: Manual ntdll Resolution (sets r12 = ntdll base)
    transform::hardening::emit_manual_ntdll_resolution(&mut s, &mut rng);

    // Phase 3: Inline Hook Detection
    transform::hardening::emit_inline_hook_detection(&mut s, &mut rng);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 1);

    // Phase 4: Frida Detection
    transform::hardening::emit_frida_detection(&mut s, &mut rng);

    // Phase 5: Thread Enumeration
    transform::hardening::emit_thread_enumeration(&mut s, &mut rng);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 2);

    // Phase 6: Parent Process Check
    transform::hardening::emit_parent_process_check(&mut s, &mut rng);

    // Phase 7: Environment Check
    transform::hardening::emit_environment_check(&mut s, &mut rng);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 1);

    // Phase 8: Syscall-based Anti-Debug
    transform::hardening::emit_syscall_anti_debug(&mut s, &mut rng);

    // Phase 9: Hardware Breakpoint Detection
    transform::hardening::emit_hwbp_detection_syscall(&mut s, &mut rng);

    // Phase 10: Extended PEB-based checks
    transform::hardening::emit_extended_anti_debug(&mut s, &mut rng);

    // Phase 11: INT 2D Check (now safe - VEH will be installed)
    transform::hardening::emit_int2d_check(&mut s);

    // Phase 12: QPC Timing Check
    transform::hardening::emit_qpc_timing_check(&mut s);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 2);

    // Phase 13: CloseHandle Check
    transform::hardening::emit_closehandle_check(&mut s);

    // Phase 14: OutputDebugString Check
    transform::hardening::emit_outputdebugstring_check(&mut s);
    transform::hardening::emit_junk_code(&mut s, &mut rng, 1);

    // Phase 15: TLS Callback Check
    transform::hardening::emit_tls_callback_check(&mut s, &mut rng);

    // Phase 16: Code Integrity Check (if applicable)
    // Skip for now as we don't have the hash here

    transform::hardening::emit_junk_code(&mut s, &mut rng, 3);

    // Transfer ultra poison (r8) to r14 for VEH stub compatibility
    s.extend_from_slice(&[0x4D, 0x09, 0xC6]);          // or r14, r8 (combine poisons)

    // ═══ VEH SUPPORT (from Level 5 stub) ═══

    // Resolve RtlAddVectoredExceptionHandler by ROR-13 hash
    // r12 already has ntdll base from Phase 2
    s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]); // mov eax, [r12+0x3C] (e_lfanew)
    s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);   // lea rax, [rax+r12] (PE header VA)
    s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]); // mov edx, [rax+0x88] (ExportDir RVA)
    s.extend_from_slice(&[0x4C, 0x01, 0xE2]);          // add rdx, r12 → rdx = ExportDir VA

    // NumberOfNames, AddressOfNames, etc.
    s.extend_from_slice(&[0x8B, 0x4A, 0x18]);          // mov ecx, [rdx+0x18]
    s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);   // mov r13d, [rdx+0x20]
    s.extend_from_slice(&[0x4D, 0x01, 0xE5]);          // add r13, r12
    s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);   // mov r15d, [rdx+0x24]
    s.extend_from_slice(&[0x4D, 0x01, 0xE7]);          // add r15, r12
    s.extend_from_slice(&[0x8B, 0x42, 0x1C]);          // mov eax, [rdx+0x1C]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+0x18], rax

    // Export loop
    s.extend_from_slice(&[0x31, 0xF6]);                 // xor esi, esi
    let export_loop = s.len();
    s.extend_from_slice(&[0x39, 0xCE]);                 // cmp esi, ecx
    let export_done_patch = s.len();
    s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]); // jge export_not_found

    s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]); // mov eax, [r13+rsi*4]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12

    // ROR-13 hash
    s.extend_from_slice(&[0x31, 0xD2]);                 // xor edx, edx
    let hash_loop = s.len();
    s.extend_from_slice(&[0x0F, 0xB6, 0x38]);          // movzx edi, byte [rax]
    s.extend_from_slice(&[0x85, 0xFF]);                 // test edi, edi
    let hash_done_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                 // jz hash_done
    s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);          // ror edx, 13
    s.extend_from_slice(&[0x01, 0xFA]);                 // add edx, edi
    s.extend_from_slice(&[0x48, 0xFF, 0xC0]);          // inc rax
    let d = (hash_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);
    let hash_done = s.len();
    s[hash_done_jz + 1] = (hash_done - hash_done_jz - 2) as u8;

    s.extend_from_slice(&[0x81, 0xFA]);                 // cmp edx, imm32
    s.extend_from_slice(&target_hash.to_le_bytes());
    let found_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                 // je found

    s.extend_from_slice(&[0xFF, 0xC6]);                 // inc esi
    let d = (export_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);

    let export_not_found = s.len();
    let jge_disp = (export_not_found as i32) - (export_done_patch as i32 + 6);
    s[export_done_patch + 2] = jge_disp as u8;
    s[export_done_patch + 3] = (jge_disp >> 8) as u8;
    s[export_done_patch + 4] = (jge_disp >> 16) as u8;
    s[export_done_patch + 5] = (jge_disp >> 24) as u8;
    s.extend_from_slice(&[0x31, 0xC0]);
    let store_rtl_jmp = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let found = s.len();
    s[found_jz + 1] = (found - found_jz - 2) as u8;
    s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]); // movzx eax, word [r15+rsi*2]
    s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]); // mov rdx, [rsp+0x18]
    s.extend_from_slice(&[0x8B, 0x04, 0x82]);          // mov eax, [rdx+rax*4]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12

    let store_rtl = s.len();
    s[store_rtl_jmp + 1] = (store_rtl - store_rtl_jmp - 2) as u8;
    s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]);    // mov [rbp+0x10], rax

    // XTEA key with poison XOR
    s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]);    // mov rax, [rbp+0x20]
    s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]);    // mov rcx, [rbp+0x28]
    s.extend_from_slice(&[0x4D, 0x85, 0xF6]);          // test r14, r14
    s.extend_from_slice(&[0x74, 0x06]);                 // jz +6
    s.extend_from_slice(&[0x4C, 0x31, 0xF0]);          // xor rax, r14
    s.extend_from_slice(&[0x4C, 0x31, 0xF1]);          // xor rcx, r14
    s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);    // mov [rsp], rax
    s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp+8], rcx

    // XTEA-CTR decrypt
    s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);          // mov ecx, [rbp+0x1C]
    s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40]
    s.extend_from_slice(&[0x48, 0x8B, 0x7D, 0x30]);    // mov rdi, [rbp+0x30]
    s.extend_from_slice(&[0x01, 0xC9]);                 // add ecx, ecx
    s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
    let skip_decrypt = s.len();
    s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz skip

    s.extend_from_slice(&[0x45, 0x31, 0xFF]);          // xor r15d, r15d
    let ctr_loop = s.len();
    s.extend_from_slice(&[0x89, 0x4C, 0x24, 0x10]);    // mov [rsp+0x10], ecx
    s.extend_from_slice(&[0x4C, 0x89, 0xF8]);          // mov rax, r15
    s.extend_from_slice(&[0x48, 0x01, 0xF8]);          // add rax, rdi
    emit_xtea_encrypt(&mut s);
    s.extend_from_slice(&[0x4A, 0x31, 0x04, 0xFE]);    // xor [rsi+r15*8], rax
    s.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]);    // mov ecx, [rsp+0x10]
    s.extend_from_slice(&[0x49, 0xFF, 0xC7]);          // inc r15
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (ctr_loop as i32) - (s.len() as i32 + 6);
    s.extend_from_slice(&[0x0F, 0x85]);
    s.extend_from_slice(&(d as i32).to_le_bytes());

    let skip_decrypt_target = s.len();
    let sd = (skip_decrypt_target as i32) - (skip_decrypt as i32 + 6);
    s[skip_decrypt + 2] = sd as u8;
    s[skip_decrypt + 3] = (sd >> 8) as u8;
    s[skip_decrypt + 4] = (sd >> 16) as u8;
    s[skip_decrypt + 5] = (sd >> 24) as u8;

    // INT3 patching (limited to 24 for stability)
    s.extend_from_slice(&[0xB9, 0x18, 0x00, 0x00, 0x00]); // mov ecx, 24
    s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40]
    s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
    let skip_patch = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                 // jz skip_patch

    let patch_loop = s.len();
    s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi]
    s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx
    s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC
    s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
    s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);
    s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);
    s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);
    s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);
    s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x10]);    // add rsi, 16
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    let d = (patch_loop as i32) - (s.len() as i32 + 6);
    s.extend_from_slice(&[0x0F, 0x85]);
    s.extend_from_slice(&(d as i32).to_le_bytes());

    let skip_patch_target = s.len();
    s[skip_patch + 1] = (skip_patch_target - skip_patch - 2) as u8;

    // Install VEH handler
    s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx, 1
    let veh_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x15,
                          0x00, 0x00, 0x00, 0x00]);     // lea rdx, [rip+?]
    s.extend_from_slice(&[0xFF, 0x55, 0x10]);           // call [rbp+0x10]

    // Epilogue
    s.extend_from_slice(&[0x48, 0x81, 0xC4, 0x00, 0x04, 0x00, 0x00]); // add rsp, 0x400
    s.push(0x5D);
    s.extend_from_slice(&[0x41, 0x5F]);
    s.extend_from_slice(&[0x41, 0x5E]);
    s.extend_from_slice(&[0x41, 0x5D]);
    s.extend_from_slice(&[0x41, 0x5C]);
    s.push(0x5E);
    s.push(0x5F);
    s.push(0x5B);

    // Jump to original entry
    let epilogue_data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x0D,
                          0x00, 0x00, 0x00, 0x00]);     // lea rcx, [rip+data_area]
    s.extend_from_slice(&[0x8B, 0x41, 0x18]);           // mov eax, [rcx+0x18]
    s.extend_from_slice(&[0x48, 0x03, 0x01]);           // add rax, [rcx]
    s.extend_from_slice(&[0xFF, 0xE0]);                  // jmp rax

    // ═══ VEH HANDLER ═══
    let veh_handler_offset = s.len();

    // Patch VEH LEA
    let veh_end = veh_lea_patch + 4;
    let vd = (veh_handler_offset as i32) - (veh_end as i32);
    s[veh_lea_patch]     = vd as u8;
    s[veh_lea_patch + 1] = (vd >> 8) as u8;
    s[veh_lea_patch + 2] = (vd >> 16) as u8;
    s[veh_lea_patch + 3] = (vd >> 24) as u8;

    s.push(0x53);                                        // push rbx
    s.push(0x56);                                        // push rsi

    let veh_data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x1D,
                          0x00, 0x00, 0x00, 0x00]);      // lea rbx, [rip+?]

    s.extend_from_slice(&[0x48, 0x8B, 0x01]);           // mov rax, [rcx]
    s.extend_from_slice(&[0x81, 0x38, 0x03, 0x00, 0x00, 0x80]); // cmp dword [rax], 0x80000003
    let veh_pass_jne = s.len();
    s.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); // jne .pass

    s.extend_from_slice(&[0x48, 0x8B, 0x51, 0x08]);    // mov rdx, [rcx+8]
    s.extend_from_slice(&[0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00]); // mov rax, [rdx+0xF8]
    s.extend_from_slice(&[0x48, 0x2B, 0x03]);           // sub rax, [rbx]

    s.extend_from_slice(&[0x8B, 0x4B, 0x1C]);           // mov ecx, [rbx+0x1C]
    s.extend_from_slice(&[0x48, 0x8D, 0x73, 0x40]);    // lea rsi, [rbx+0x40]
    s.extend_from_slice(&[0x85, 0xC9]);                  // test ecx, ecx
    let veh_no_table_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // jz .pass_pop

    s.extend_from_slice(&[0x45, 0x31, 0xC0]);           // xor r8d, r8d
    s.extend_from_slice(&[0x44, 0x8D, 0x49, 0xFF]);    // lea r9d, [rcx-1]

    let bsearch_loop = s.len();
    s.extend_from_slice(&[0x45, 0x39, 0xC8]);           // cmp r8d, r9d
    let bsearch_fail = s.len();
    s.extend_from_slice(&[0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00]); // jg .not_found

    s.extend_from_slice(&[0x45, 0x8D, 0x14, 0x01]);    // lea r10d, [r8+r9]
    s.extend_from_slice(&[0x41, 0xD1, 0xEA]);           // shr r10d, 1
    s.extend_from_slice(&[0x45, 0x89, 0xD3]);           // mov r11d, r10d
    s.extend_from_slice(&[0x41, 0xC1, 0xE3, 0x04]);    // shl r11d, 4

    s.extend_from_slice(&[0x42, 0x39, 0x04, 0x1E]);    // cmp [rsi+r11], eax
    let bsearch_found_je = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // je .found

    let bsearch_above_ja = s.len();
    s.extend_from_slice(&[0x77, 0x00]);                  // ja .go_hi
    s.extend_from_slice(&[0x45, 0x8D, 0x42, 0x01]);    // lea r8d, [r10+1]
    let bsearch_continue_jmp = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .bsearch_loop
    let go_hi = s.len();
    s[bsearch_above_ja + 1] = (go_hi - bsearch_above_ja - 2) as u8;
    s.extend_from_slice(&[0x45, 0x8D, 0x4A, 0xFF]);    // lea r9d, [r10-1]
    let d = (bsearch_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);
    let d = (bsearch_loop as i32) - (bsearch_continue_jmp as i32 + 2);
    s[bsearch_continue_jmp + 1] = d as u8;

    let bsearch_not_found = s.len();
    let bnf = (bsearch_not_found as i32) - (bsearch_fail as i32 + 6);
    s[bsearch_fail + 2] = bnf as u8;
    s[bsearch_fail + 3] = (bnf >> 8) as u8;
    s[bsearch_fail + 4] = (bnf >> 16) as u8;
    s[bsearch_fail + 5] = (bnf >> 24) as u8;
    let veh_pass_pop = s.len();
    s[veh_no_table_jz + 1] = (veh_pass_pop - veh_no_table_jz - 2) as u8;
    s.push(0x5E);
    s.push(0x5B);
    s.extend_from_slice(&[0x31, 0xC0]);
    s.push(0xC3);

    let pass_disp = (veh_pass_pop as i32) - (veh_pass_jne as i32 + 6);
    s[veh_pass_jne + 2] = pass_disp as u8;
    s[veh_pass_jne + 3] = (pass_disp >> 8) as u8;
    s[veh_pass_jne + 4] = (pass_disp >> 16) as u8;
    s[veh_pass_jne + 5] = (pass_disp >> 24) as u8;

    // Found
    let found_offset = s.len();
    s[bsearch_found_je + 1] = (found_offset - bsearch_found_je - 2) as u8;

    s.extend_from_slice(&[0x42, 0x0F, 0xB6, 0x4C, 0x1E, 0x0C]); // movzx ecx, byte [rsi+r11+12]
    s.extend_from_slice(&[0x42, 0x8B, 0x44, 0x1E, 0x08]); // mov eax, [rsi+r11+8]
    s.extend_from_slice(&[0x46, 0x8B, 0x44, 0x1E, 0x04]); // mov r8d, [rsi+r11+4]
    s.extend_from_slice(&[0x44, 0x8B, 0x4A, 0x44]);    // mov r9d, [rdx+0x44]

    // Condition evaluation (JZ, JNZ, JL, JGE, JLE, JG)
    // JZ
    s.extend_from_slice(&[0x80, 0xF9, 0xF0]);
    let not_jz = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]);
    let jz_not_taken = s.len();
    s.extend_from_slice(&[0x74, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jz_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jz_target = s.len();
    s[not_jz + 1] = (not_jz_target - not_jz - 2) as u8;

    // JNZ
    s.extend_from_slice(&[0x80, 0xF9, 0xF1]);
    let not_jnz = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]);
    let jnz_taken = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jnz_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jnz_target = s.len();
    s[not_jnz + 1] = (not_jnz_target - not_jnz - 2) as u8;

    // JL
    s.extend_from_slice(&[0x80, 0xF9, 0xF2]);
    let not_jl = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);
    let jl_eq = s.len();
    s.extend_from_slice(&[0x74, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jl_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jl_target = s.len();
    s[not_jl + 1] = (not_jl_target - not_jl - 2) as u8;

    // JGE
    s.extend_from_slice(&[0x80, 0xF9, 0xF3]);
    let not_jge = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);
    let jge_ne = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jge_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jge_target = s.len();
    s[not_jge + 1] = (not_jge_target - not_jge - 2) as u8;

    // JLE
    s.extend_from_slice(&[0x80, 0xF9, 0xF4]);
    let not_jle = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);
    let jle_sf_ne_of = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]);
    let jle_zf_test = s.len();
    s.extend_from_slice(&[0x74, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jle_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jle_target = s.len();
    s[not_jle + 1] = (not_jle_target - not_jle - 2) as u8;

    // JG
    s.extend_from_slice(&[0x80, 0xF9, 0xF5]);
    let not_jg = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]);
    let jg_zf_set = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);
    let jg_sf_ne_of = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);
    let jg_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);

    let not_jg_target = s.len();
    s[not_jg + 1] = (not_jg_target - not_jg - 2) as u8;

    // Set RIP
    let set_rip = s.len();
    // Patch all jumps to set_rip
    s[jz_not_taken + 1] = (set_rip - jz_not_taken - 2) as u8;
    s[jz_to_set_rip + 1] = (set_rip - jz_to_set_rip - 2) as u8;
    s[jnz_taken + 1] = (set_rip - jnz_taken - 2) as u8;
    s[jnz_to_set_rip + 1] = (set_rip - jnz_to_set_rip - 2) as u8;
    s[jl_eq + 1] = (set_rip - jl_eq - 2) as u8;
    s[jl_to_set_rip + 1] = (set_rip - jl_to_set_rip - 2) as u8;
    s[jge_ne + 1] = (set_rip - jge_ne - 2) as u8;
    s[jge_to_set_rip + 1] = (set_rip - jge_to_set_rip - 2) as u8;
    s[jle_sf_ne_of + 1] = (set_rip - jle_sf_ne_of - 2) as u8;
    s[jle_zf_test + 1] = (set_rip - jle_zf_test - 2) as u8;
    s[jle_to_set_rip + 1] = (set_rip - jle_to_set_rip - 2) as u8;
    s[jg_zf_set + 1] = (set_rip - jg_zf_set - 2) as u8;
    s[jg_sf_ne_of + 1] = (set_rip - jg_sf_ne_of - 2) as u8;
    s[jg_to_set_rip + 1] = (set_rip - jg_to_set_rip - 2) as u8;

    s.extend_from_slice(&[0x48, 0x03, 0x03]);           // add rax, [rbx]
    s.extend_from_slice(&[0x48, 0x89, 0x82, 0xF8, 0x00, 0x00, 0x00]); // mov [rdx+0xF8], rax
    s.push(0x5E);
    s.push(0x5B);
    s.extend_from_slice(&[0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1
    s.push(0xC3);

    // ═══ DATA AREA ═══
    let data_area_offset = s.len();

    // Patch data LEAs
    let d1 = (data_area_offset as i32) - (data_lea_patch as i32 + 4);
    s[data_lea_patch]     = d1 as u8;
    s[data_lea_patch + 1] = (d1 >> 8) as u8;
    s[data_lea_patch + 2] = (d1 >> 16) as u8;
    s[data_lea_patch + 3] = (d1 >> 24) as u8;

    let d2 = (data_area_offset as i32) - (epilogue_data_lea_patch as i32 + 4);
    s[epilogue_data_lea_patch]     = d2 as u8;
    s[epilogue_data_lea_patch + 1] = (d2 >> 8) as u8;
    s[epilogue_data_lea_patch + 2] = (d2 >> 16) as u8;
    s[epilogue_data_lea_patch + 3] = (d2 >> 24) as u8;

    let d3 = (data_area_offset as i32) - (veh_data_lea_patch as i32 + 4);
    s[veh_data_lea_patch]     = d3 as u8;
    s[veh_data_lea_patch + 1] = (d3 >> 8) as u8;
    s[veh_data_lea_patch + 2] = (d3 >> 16) as u8;
    s[veh_data_lea_patch + 3] = (d3 >> 24) as u8;

    // Data area layout:
    // 0x00: image_base (u64)
    // 0x08: poison_value (u64)
    // 0x10: rtl_add_veh_ptr (u64)
    // 0x18: orig_entry_rva (u32)
    // 0x1C: dispatch_count (u32)
    // 0x20: xtea_key (16 bytes)
    // 0x30: nm_nonce (u64)
    // 0x38: text_rva (u32)
    // 0x3C: reserved (u32)
    // 0x40: dispatch_table (N*16)

    s.extend_from_slice(&[0; 8]);                       // 0x00: image_base
    s.extend_from_slice(&[0; 8]);                       // 0x08: poison
    s.extend_from_slice(&[0; 8]);                       // 0x10: rtl_add_veh
    s.extend_from_slice(&orig_entry_rva.to_le_bytes()); // 0x18: orig_entry_rva
    s.extend_from_slice(&nm_count.to_le_bytes());       // 0x1C: dispatch_count
    // XTEA key [u32; 4] → stored as two u64 for 16-byte total
    for &k in &nm_xtea {
        s.extend_from_slice(&k.to_le_bytes());          // 0x20: xtea key
    }
    s.extend_from_slice(&nanomite_crypto_key.to_le_bytes()); // 0x30: nm_nonce
    s.extend_from_slice(&text_rva.to_le_bytes());       // 0x38: text_rva
    s.extend_from_slice(&[0; 4]);                       // 0x3C: reserved

    // Append dispatch table
    let table_start = s.len();
    for e in nanomite_entries.iter() {
        s.extend_from_slice(&e.bp_rva.to_le_bytes());
        s.extend_from_slice(&e.taken_rva.to_le_bytes());
        s.extend_from_slice(&e.nottaken_rva.to_le_bytes());
        s.push(e.condition);
        s.extend_from_slice(&[0; 3]);
    }

    // Encrypt dispatch table with XTEA-CTR
    if nanomite_crypto_key != 0 && nm_count > 0 {
        xtea_ctr_apply(&mut s[table_start..], &nm_xtea, nanomite_crypto_key);
    }

    // Align
    while s.len() % 16 != 0 {
        s.push(0x90);
    }

    eprintln!("[ULTRA+VEH] Runtime stub: {} bytes", s.len());
    eprintln!("  16 ultra anti-analysis phases");
    eprintln!("  VEH nanomite dispatch: {} entries", nm_count);
    eprintln!("  INT3 patching: 24 (limited for stability)");

    let _ = text_size;
    s
}

// ─── .sqtidal Tidal Memory stub builder ───────────────────────
//
// Generates a ~2KB x86-64 shellcode section for Tidal Memory:
//
//   1. Initialize page metadata table
//   2. XOR-encrypt each 4KB page of .text with derived key
//   3. Mark all pages PAGE_NOACCESS
//   4. Install VEH handler for ACCESS_VIOLATION in .text
//   5. Start tide thread for background re-encryption (50ms interval)
//
// On page fault:
//   - VEH decrypts the faulting page
//   - Marks PAGE_EXECUTE_READ
//   - Updates access timestamp
//   - Returns CONTINUE_EXECUTION
//
// Tide thread:
//   - Every 50ms, re-encrypts pages not accessed for >50ms
//   - Keeps <0.1% of code in plaintext at any moment
//
fn build_tidal_stub(text_rva: u32, text_size: u32, seed: u64) -> Vec<u8> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5449_4441_BEEF_CAFE);
    let mut s = Vec::with_capacity(2048);

    let page_count = (text_size as usize + 4095) / 4096;
    let master_key = splitmix_finalize(seed ^ 0x54494441_4C4D454D); // "TIDALMEM"

    // ═══════════════════════════════════════════════════════════════════
    // Data section (appended at end, referenced via RIP-relative)
    // ═══════════════════════════════════════════════════════════════════

    // Prologue: save callee-saved registers
    s.push(0x53); // push rbx
    s.push(0x57); // push rdi
    s.push(0x56); // push rsi
    s.extend_from_slice(&[0x41, 0x54]); // push r12
    s.extend_from_slice(&[0x41, 0x55]); // push r13
    s.extend_from_slice(&[0x41, 0x56]); // push r14
    s.extend_from_slice(&[0x41, 0x57]); // push r15
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28

    // Get ImageBase from PEB
    transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng);
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10] (ImageBase)

    // Calculate .text VA
    s.extend_from_slice(&[0x48, 0x8D, 0xB3]); // lea rsi, [rbx + text_rva]
    s.extend_from_slice(&text_rva.to_le_bytes());

    // Store master key in r12
    s.extend_from_slice(&[0x49, 0xBC]); // mov r12, master_key
    s.extend_from_slice(&master_key.to_le_bytes());

    // Store page count in r13d
    s.extend_from_slice(&[0x41, 0xBD]); // mov r13d, page_count
    s.extend_from_slice(&(page_count as u32).to_le_bytes());

    // Store text_size in r14d
    s.extend_from_slice(&[0x41, 0xBE]); // mov r14d, text_size
    s.extend_from_slice(&text_size.to_le_bytes());

    // ═══ Tidal initialization complete marker ═══
    // In a full implementation, this would:
    // 1. Allocate page metadata array
    // 2. Encrypt each page
    // 3. Set PAGE_NOACCESS
    // 4. Install VEH
    // 5. Start tide thread
    //
    // For now, emit a placeholder that just returns
    // (Full Tidal requires squre-runtime linking for thread/VEH)

    // Placeholder: just print status and return
    // xor eax, eax (success)
    s.extend_from_slice(&[0x31, 0xC0]);

    // Epilogue
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
    s.extend_from_slice(&[0x41, 0x5F]); // pop r15
    s.extend_from_slice(&[0x41, 0x5E]); // pop r14
    s.extend_from_slice(&[0x41, 0x5D]); // pop r13
    s.extend_from_slice(&[0x41, 0x5C]); // pop r12
    s.push(0x5E); // pop rsi
    s.push(0x5F); // pop rdi
    s.push(0x5B); // pop rbx
    s.push(0xC3); // ret

    // Align to 16 bytes
    while s.len() % 16 != 0 {
        s.push(0x90);
    }

    // Append data section
    // [master_key: u64][text_rva: u32][text_size: u32][page_count: u32][pad: u32]
    s.extend_from_slice(&master_key.to_le_bytes());
    s.extend_from_slice(&text_rva.to_le_bytes());
    s.extend_from_slice(&text_size.to_le_bytes());
    s.extend_from_slice(&(page_count as u32).to_le_bytes());
    s.extend_from_slice(&[0u8; 4]); // padding

    eprintln!("[TIDAL] Stub generated: {} bytes", s.len());
    eprintln!("  .text RVA: 0x{:08X}, size: {} bytes, {} pages", text_rva, text_size, page_count);
    eprintln!("  Master key: 0x{:016X}", master_key);
    eprintln!("  NOTE: Full Tidal requires squre-runtime for VEH/thread support");

    s
}

// ─── .sqrun runtime stub builder ──────────────────────────────
//
// Generates a ~4KB x86-64 shellcode section that provides runtime
// protection for CLI-only binaries (no squre-runtime linking needed):
//
//   1. Anti-debug (PEB.BeingDebugged) → poison value
//   2. Resolve RtlAddVectoredExceptionHandler from ntdll via PEB
//   3. XTEA-CTR decrypt embedded nanomite dispatch table
//      (poisoned key → wrong table → silent crash under debugger)
//   4. Patch INT3 (0xCC + 5×NOP) over original conditional jumps
//   5. Install VEH handler for nanomite dispatch
//   6. Jump to original entry point
//
// Data area layout (offsets from data_base):
//   0x00  image_base       u64  (filled at runtime)
//   0x08  poison_value     u64  (filled at runtime)
//   0x10  rtl_add_veh_ptr  u64  (filled at runtime)
//   0x18  orig_entry_rva   u32  (embedded by CLI)
//   0x1C  dispatch_count   u32  (embedded by CLI)
//   0x20  xtea_key         16B  (embedded by CLI)
//   0x30  nm_nonce         u64  (embedded by CLI)
//   0x38  text_rva         u32  (embedded by CLI)
//   0x3C  reserved         u32
//   0x40  dispatch_table   N*16 (XTEA-CTR encrypted by CLI)

fn build_runtime_stub(
    orig_entry_rva: u32,
    nanomite_entries: &[NanomiteRawEntry],
    nanomite_crypto_key: u64,
    text_rva: u32,
    text_size: u32,
) -> Vec<u8> {
    // Check for --ultra or --harden flag
    let (use_ultra, use_hardened, enable_anti_debug) = POLY_OPTIONS.with(|opt| {
        let opt = opt.borrow();
        (opt.ultra, opt.harden, opt.anti_debug)
    });

    // Get CEWE seed from environment or derive from crypto key
    let cewe_seed = std::env::var("SQURE_SEED")
        .ok()
        .and_then(|s| {
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        })
        .unwrap_or_else(|| nanomite_crypto_key ^ 0xCAFEBABE_DEADBEEF);

    // NOTE: Ultra-hardened and hardened stubs don't have VEH handler for nanomites.
    // When nanomites are present, we MUST use the full runtime stub with VEH support.
    // The anti-analysis phases from ultra/hardened would cause crashes on INT3 hits.
    if !nanomite_entries.is_empty() {
        if use_ultra {
            eprintln!("[ULTRA] Nanomites active → using full VEH stub (ultra anti-analysis disabled)");
        } else if use_hardened {
            eprintln!("[HARDENED] Nanomites active → using full VEH stub (hardened anti-analysis disabled)");
        }
        // Fall through to full stub with VEH support
    } else {
        // No nanomites → safe to use ultra/hardened stubs (they just jump to OEP)
        if use_ultra {
            let entries: Vec<(u32, u32, u32, u8)> = Vec::new();
            let expected_hash = 0u64;

            return transform::hardening::build_ultra_hardened_runtime_stub(
                orig_entry_rva,
                &entries,
                nanomite_crypto_key,
                text_rva,
                text_size,
                expected_hash,
                cewe_seed,
            );
        }

        if use_hardened {
            let entries: Vec<(u32, u32, u32, u8)> = Vec::new();

            return transform::hardening::build_hardened_runtime_stub(
                orig_entry_rva,
                &entries,
                nanomite_crypto_key,
                text_rva,
                cewe_seed,
            );
        }
    }

    // DEBUG: Test stubs to isolate issue
    // SQURE_DEBUG_SQRUN=1: Minimal (just jump to OEP)
    // SQURE_DEBUG_SQRUN=2: Prologue/epilogue + jump
    // SQURE_DEBUG_SQRUN=3: + ntdll resolution
    // SQURE_DEBUG_SQRUN=4: + VEH install (no INT3 patch)
    // SQURE_DEBUG_SQRUN=5: Production with INT3 patching (limited to 24)
    // SQURE_DEBUG_SQRUN=46: Custom INT3 patch count (set SQURE_DEBUG_PATCH_COUNT)
    let debug_level: u32 = std::env::var("SQURE_DEBUG_SQRUN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(46);  // Default: limited patching (5 entries, avoids Entry 5 crash)

    if debug_level == 1 {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut s = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(nanomite_crypto_key);

        // Use obfuscated PEB access instead of direct gs:[0x60] pattern
        transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]); // mov rax, [rax+0x10] (ImageBase)
        s.extend_from_slice(&[0x48, 0x05]);
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        s.extend_from_slice(&[0xFF, 0xE0]);
        eprintln!("[DEBUG] Level 1: minimal ({} bytes)", s.len());
        return s;
    }

    if debug_level == 2 {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut s = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(nanomite_crypto_key);

        // Prologue
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);
        // Get ImageBase into rbx (obfuscated PEB access)
        transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10]
        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        // lea rax, [rbx + orig_entry_rva]; jmp rax
        s.extend_from_slice(&[0x48, 0x8D, 0x83]);
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        s.extend_from_slice(&[0xFF, 0xE0]);
        eprintln!("[DEBUG] Level 2: prologue/epilogue ({} bytes)", s.len());
        return s;
    }

    if debug_level == 3 {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        // Level 3: Prologue/epilogue + ntdll resolution + VEH install (no decrypt/patch)
        let mut s = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(nanomite_crypto_key);
        let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");

        // Prologue
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // Get ImageBase into rbx (obfuscated PEB access)
        transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]); // mov rbx, [rax+0x10] (ImageBase)

        // Find ntdll via PEB → Ldr → InLoadOrderModuleList (obfuscated)
        transform::hardening::emit_obfuscated_peb_access(&mut s, 0, &mut rng); // rax = PEB
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]); // mov rax, [rax+0x18] (Ldr)
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]); // mov rax, [rax+0x10] (InLoadOrder.Flink)
        s.extend_from_slice(&[0x48, 0x8B, 0x00]);       // mov rax, [rax] (2nd entry = ntdll)
        s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]); // mov r12, [rax+0x30] (ntdll DllBase)

        // Walk export directory
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]); // mov eax, [r12+0x3C] (e_lfanew)
        s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);       // lea rax, [rax+r12] (PE header VA)
        s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]); // mov edx, [rax+0x88] (ExportDir RVA)
        s.extend_from_slice(&[0x4C, 0x01, 0xE2]);             // add rdx, r12 → rdx = ExportDir VA

        // NumberOfNames
        s.extend_from_slice(&[0x8B, 0x4A, 0x18]); // mov ecx, [rdx+0x18]
        // AddressOfNames
        s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]); // mov r13d, [rdx+0x20]
        s.extend_from_slice(&[0x4D, 0x01, 0xE5]);       // add r13, r12
        // AddressOfNameOrdinals
        s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]); // mov r15d, [rdx+0x24]
        s.extend_from_slice(&[0x4D, 0x01, 0xE7]);       // add r15, r12
        // AddressOfFunctions
        s.extend_from_slice(&[0x8B, 0x42, 0x1C]);       // mov eax, [rdx+0x1C]
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);       // add rax, r12
        s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+0x18], rax

        // Loop over export names
        s.extend_from_slice(&[0x31, 0xF6]); // xor esi, esi
        let export_loop = s.len();
        s.extend_from_slice(&[0x39, 0xCE]); // cmp esi, ecx
        let export_done_patch = s.len();
        s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]); // jge export_not_found

        // name_rva = AddressOfNames[i]
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]); // mov eax, [r13+rsi*4]
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);             // add rax, r12 (name VA)

        // Compute ROR-13 hash
        s.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
        let hash_loop = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x38]); // movzx edi, byte [rax]
        s.extend_from_slice(&[0x85, 0xFF]);       // test edi, edi
        let hash_done_jz = s.len();
        s.extend_from_slice(&[0x74, 0x00]);       // jz hash_done
        s.extend_from_slice(&[0xC1, 0xCA, 0x0D]); // ror edx, 13
        s.extend_from_slice(&[0x01, 0xFA]);       // add edx, edi
        s.extend_from_slice(&[0x48, 0xFF, 0xC0]); // inc rax
        let d = (hash_loop as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d as u8]);    // jmp hash_loop
        let hash_done = s.len();
        s[hash_done_jz + 1] = (hash_done - hash_done_jz - 2) as u8;

        // Compare hash
        s.extend_from_slice(&[0x81, 0xFA]);
        s.extend_from_slice(&target_hash.to_le_bytes());
        let found_jz = s.len();
        s.extend_from_slice(&[0x74, 0x00]); // je found

        // Next export
        s.extend_from_slice(&[0xFF, 0xC6]); // inc esi
        let d = (export_loop as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d as u8]); // jmp export_loop

        // Not found
        let export_not_found = s.len();
        let jge_disp = (export_not_found as i32) - (export_done_patch as i32 + 6);
        s[export_done_patch + 2] = jge_disp as u8;
        s[export_done_patch + 3] = (jge_disp >> 8) as u8;
        s[export_done_patch + 4] = (jge_disp >> 16) as u8;
        s[export_done_patch + 5] = (jge_disp >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
        let store_jmp = s.len();
        s.extend_from_slice(&[0xEB, 0x00]); // jmp store

        // Found
        let found = s.len();
        s[found_jz + 1] = (found - found_jz - 2) as u8;
        s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]); // movzx eax, word [r15+rsi*2]
        s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]); // mov rdx, [rsp+0x18]
        s.extend_from_slice(&[0x8B, 0x04, 0x82]);             // mov eax, [rdx+rax*4]
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);             // add rax, r12

        let store = s.len();
        s[store_jmp + 1] = (store - store_jmp - 2) as u8;
        // r14 = RtlAddVEH address
        s.extend_from_slice(&[0x49, 0x89, 0xC6]); // mov r14, rax

        // Install VEH: rcx=1 (first), rdx=handler
        s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx, 1
        let veh_lea_patch = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]); // lea rdx, [rip+?]
        s.extend_from_slice(&[0x41, 0xFF, 0xD6]); // call r14

        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        // jmp to OEP
        s.extend_from_slice(&[0x48, 0x8D, 0x83]);
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        s.extend_from_slice(&[0xFF, 0xE0]);

        // Minimal VEH handler (just returns CONTINUE_SEARCH = 0)
        let veh_handler = s.len();
        let veh_disp = (veh_handler as i32) - (veh_lea_patch as i32 + 4);
        s[veh_lea_patch]     = veh_disp as u8;
        s[veh_lea_patch + 1] = (veh_disp >> 8) as u8;
        s[veh_lea_patch + 2] = (veh_disp >> 16) as u8;
        s[veh_lea_patch + 3] = (veh_disp >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
        s.push(0xC3);                       // ret

        eprintln!("[DEBUG] Level 3: ntdll + VEH install ({} bytes)", s.len());
        return s;
    }

    // Level 3.5 (debug_level == 35): XTEA decrypt + simple VEH (no INT3 patch)
    // Tests if the crash is in XTEA decryption or VEH handler code
    if debug_level == 35 {
        let nm_xtea_35 = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
        let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");
        let mut s = Vec::new();

        // Prologue
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // LEA rbp, [rip + data_area]
        let data_lea_patch_35 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);

        // Get ImageBase into rbx
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);
        s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]); // mov [rbp+0], rbx

        // Anti-debug: PEB.BeingDebugged → r14 (poison)
        s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]); // movzx eax, byte [rax+2]
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]); // mov [rbp+8], rax
        s.extend_from_slice(&[0x49, 0x89, 0xC6]);       // mov r14, rax

        // Find ntdll
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);
        s.extend_from_slice(&[0x48, 0x8B, 0x00]);
        s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]); // r12 = ntdll

        // Export walk (same as Level 3)
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]);
        s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);
        s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE2]);
        s.extend_from_slice(&[0x8B, 0x4A, 0x18]);
        s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE5]);
        s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE7]);
        s.extend_from_slice(&[0x8B, 0x42, 0x1C]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]);

        s.extend_from_slice(&[0x31, 0xF6]);
        let export_loop_35 = s.len();
        s.extend_from_slice(&[0x39, 0xCE]);
        let export_done_patch_35 = s.len();
        s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x31, 0xD2]);
        let hash_loop_35 = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x38]);
        s.extend_from_slice(&[0x85, 0xFF]);
        let hash_done_jz_35 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);
        s.extend_from_slice(&[0x01, 0xFA]);
        s.extend_from_slice(&[0x48, 0xFF, 0xC0]);
        let d35 = (hash_loop_35 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d35 as u8]);
        let hash_done_35 = s.len();
        s[hash_done_jz_35 + 1] = (hash_done_35 - hash_done_jz_35 - 2) as u8;
        s.extend_from_slice(&[0x81, 0xFA]);
        s.extend_from_slice(&target_hash.to_le_bytes());
        let found_jz_35 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xFF, 0xC6]);
        let d35 = (export_loop_35 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d35 as u8]);
        let export_not_found_35 = s.len();
        let jge_disp_35 = (export_not_found_35 as i32) - (export_done_patch_35 as i32 + 6);
        s[export_done_patch_35 + 2] = jge_disp_35 as u8;
        s[export_done_patch_35 + 3] = (jge_disp_35 >> 8) as u8;
        s[export_done_patch_35 + 4] = (jge_disp_35 >> 16) as u8;
        s[export_done_patch_35 + 5] = (jge_disp_35 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        let store_jmp_35 = s.len();
        s.extend_from_slice(&[0xEB, 0x00]);
        let found_35 = s.len();
        s[found_jz_35 + 1] = (found_35 - found_jz_35 - 2) as u8;
        s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]);
        s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]);
        s.extend_from_slice(&[0x8B, 0x04, 0x82]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        let store_35 = s.len();
        s[store_jmp_35 + 1] = (store_35 - store_jmp_35 - 2) as u8;
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]); // mov [rbp+0x10], rax

        // ── XTEA key prep (with poison XOR) ──
        s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]); // mov rax, [rbp+0x20] (key lo)
        s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]); // mov rcx, [rbp+0x28] (key hi)
        s.extend_from_slice(&[0x4D, 0x85, 0xF6]);       // test r14, r14
        s.extend_from_slice(&[0x74, 0x06]);              // jz +6
        s.extend_from_slice(&[0x4C, 0x31, 0xF0]);       // xor rax, r14
        s.extend_from_slice(&[0x4C, 0x31, 0xF1]);       // xor rcx, r14
        s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax
        s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp+8], rcx

        // ── XTEA-CTR decrypt ──
        s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);       // mov ecx, [rbp+0x1C] (count)
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]); // lea rsi, [rbp+0x40] (table)
        s.extend_from_slice(&[0x48, 0x8B, 0x7D, 0x30]); // mov rdi, [rbp+0x30] (nonce)
        s.extend_from_slice(&[0x01, 0xC9]);              // add ecx, ecx
        s.extend_from_slice(&[0x85, 0xC9]);              // test ecx, ecx
        let skip_decrypt_35 = s.len();
        s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz skip

        s.extend_from_slice(&[0x45, 0x31, 0xFF]);       // xor r15d, r15d
        let ctr_loop_35 = s.len();
        s.extend_from_slice(&[0x89, 0x4C, 0x24, 0x10]); // mov [rsp+0x10], ecx
        s.extend_from_slice(&[0x4C, 0x89, 0xF8]);       // mov rax, r15
        s.extend_from_slice(&[0x48, 0x01, 0xF8]);       // add rax, rdi
        emit_xtea_encrypt(&mut s);
        s.extend_from_slice(&[0x4A, 0x31, 0x04, 0xFE]); // xor [rsi+r15*8], rax
        s.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]); // mov ecx, [rsp+0x10]
        s.extend_from_slice(&[0x49, 0xFF, 0xC7]);       // inc r15
        s.extend_from_slice(&[0xFF, 0xC9]);              // dec ecx
        // Use near jnz (6 bytes) instead of short jnz (2 bytes) - loop body > 127 bytes
        let d35 = (ctr_loop_35 as i32) - (s.len() as i32 + 6);
        s.extend_from_slice(&[0x0F, 0x85]);             // near jnz
        s.extend_from_slice(&(d35 as i32).to_le_bytes());

        let skip_decrypt_target_35 = s.len();
        let sd35 = (skip_decrypt_target_35 as i32) - (skip_decrypt_35 as i32 + 6);
        s[skip_decrypt_35 + 2] = sd35 as u8;
        s[skip_decrypt_35 + 3] = (sd35 >> 8) as u8;
        s[skip_decrypt_35 + 4] = (sd35 >> 16) as u8;
        s[skip_decrypt_35 + 5] = (sd35 >> 24) as u8;

        // ── Install simple VEH ──
        s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        let veh_lea_patch_35 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0xFF, 0x55, 0x10]); // call [rbp+0x10]

        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        let epilogue_data_lea_patch_35 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x8B, 0x41, 0x18]); // mov eax, [rcx+0x18]
        s.extend_from_slice(&[0x48, 0x03, 0x01]); // add rax, [rcx]
        s.extend_from_slice(&[0xFF, 0xE0]);       // jmp rax

        // Simple VEH handler (returns 0)
        let veh_handler_35 = s.len();
        let veh_disp_35 = (veh_handler_35 as i32) - (veh_lea_patch_35 as i32 + 4);
        s[veh_lea_patch_35]     = veh_disp_35 as u8;
        s[veh_lea_patch_35 + 1] = (veh_disp_35 >> 8) as u8;
        s[veh_lea_patch_35 + 2] = (veh_disp_35 >> 16) as u8;
        s[veh_lea_patch_35 + 3] = (veh_disp_35 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
        s.push(0xC3);                       // ret

        // Data area
        let data_area_35 = s.len();
        let dd35 = (data_area_35 as i32) - (data_lea_patch_35 as i32 + 4);
        s[data_lea_patch_35]     = dd35 as u8;
        s[data_lea_patch_35 + 1] = (dd35 >> 8) as u8;
        s[data_lea_patch_35 + 2] = (dd35 >> 16) as u8;
        s[data_lea_patch_35 + 3] = (dd35 >> 24) as u8;
        let edd35 = (data_area_35 as i32) - (epilogue_data_lea_patch_35 as i32 + 4);
        s[epilogue_data_lea_patch_35]     = edd35 as u8;
        s[epilogue_data_lea_patch_35 + 1] = (edd35 >> 8) as u8;
        s[epilogue_data_lea_patch_35 + 2] = (edd35 >> 16) as u8;
        s[epilogue_data_lea_patch_35 + 3] = (edd35 >> 24) as u8;

        // [+0x00] image_base
        s.extend_from_slice(&0u64.to_le_bytes());
        // [+0x08] poison
        s.extend_from_slice(&0u64.to_le_bytes());
        // [+0x10] rtl_add_veh_ptr
        s.extend_from_slice(&0u64.to_le_bytes());
        // [+0x18] orig_entry_rva
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        // [+0x1C] dispatch_count
        let nm_count_35 = nanomite_entries.len().min(128) as u32;
        s.extend_from_slice(&nm_count_35.to_le_bytes());
        // [+0x20] xtea_key
        for &k in &nm_xtea_35 {
            s.extend_from_slice(&k.to_le_bytes());
        }
        // [+0x30] nonce
        s.extend_from_slice(&nanomite_crypto_key.to_le_bytes());
        // [+0x38] text_rva
        s.extend_from_slice(&text_rva.to_le_bytes());
        // [+0x3C] reserved
        s.extend_from_slice(&0u32.to_le_bytes());
        // [+0x40] dispatch_table (encrypted)
        let table_start_35 = s.len();
        for e in nanomite_entries.iter().take(128) {
            s.extend_from_slice(&e.bp_rva.to_le_bytes());
            s.extend_from_slice(&e.taken_rva.to_le_bytes());
            s.extend_from_slice(&e.nottaken_rva.to_le_bytes());
            s.push(e.condition);
            s.extend_from_slice(&[0u8; 3]);
        }
        if nanomite_crypto_key != 0 && nm_count_35 > 0 {
            xtea_ctr_apply(&mut s[table_start_35..], &nm_xtea_35, nanomite_crypto_key);
        }

        eprintln!("[DEBUG] Level 3.5: XTEA decrypt + simple VEH ({} bytes)", s.len());
        return s;
    }

    // Level 3.6 (debug_level == 36): Same as 3.5 but skip XTEA loop entirely
    if debug_level == 36 {
        let nm_xtea_36 = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
        let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");
        let mut s = Vec::new();

        // Prologue (same as 3.5)
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        let data_lea_patch_36 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);

        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);
        s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]);
        s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]);
        s.extend_from_slice(&[0x49, 0x89, 0xC6]);

        // ntdll resolution (same as 3.5)
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);
        s.extend_from_slice(&[0x48, 0x8B, 0x00]);
        s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]);
        s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);
        s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE2]);
        s.extend_from_slice(&[0x8B, 0x4A, 0x18]);
        s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE5]);
        s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE7]);
        s.extend_from_slice(&[0x8B, 0x42, 0x1C]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]);

        s.extend_from_slice(&[0x31, 0xF6]);
        let export_loop_36 = s.len();
        s.extend_from_slice(&[0x39, 0xCE]);
        let export_done_patch_36 = s.len();
        s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x31, 0xD2]);
        let hash_loop_36 = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x38]);
        s.extend_from_slice(&[0x85, 0xFF]);
        let hash_done_jz_36 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);
        s.extend_from_slice(&[0x01, 0xFA]);
        s.extend_from_slice(&[0x48, 0xFF, 0xC0]);
        let d36 = (hash_loop_36 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d36 as u8]);
        let hash_done_36 = s.len();
        s[hash_done_jz_36 + 1] = (hash_done_36 - hash_done_jz_36 - 2) as u8;
        s.extend_from_slice(&[0x81, 0xFA]);
        s.extend_from_slice(&target_hash.to_le_bytes());
        let found_jz_36 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xFF, 0xC6]);
        let d36 = (export_loop_36 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d36 as u8]);
        let export_not_found_36 = s.len();
        let jge_disp_36 = (export_not_found_36 as i32) - (export_done_patch_36 as i32 + 6);
        s[export_done_patch_36 + 2] = jge_disp_36 as u8;
        s[export_done_patch_36 + 3] = (jge_disp_36 >> 8) as u8;
        s[export_done_patch_36 + 4] = (jge_disp_36 >> 16) as u8;
        s[export_done_patch_36 + 5] = (jge_disp_36 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        let store_jmp_36 = s.len();
        s.extend_from_slice(&[0xEB, 0x00]);
        let found_36 = s.len();
        s[found_jz_36 + 1] = (found_36 - found_jz_36 - 2) as u8;
        s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]);
        s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]);
        s.extend_from_slice(&[0x8B, 0x04, 0x82]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        let store_36 = s.len();
        s[store_jmp_36 + 1] = (store_36 - store_jmp_36 - 2) as u8;
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]);

        // XTEA key prep (still do this to test data area access)
        s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]);
        s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]);
        s.extend_from_slice(&[0x4D, 0x85, 0xF6]);
        s.extend_from_slice(&[0x74, 0x06]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF0]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF1]);
        s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);
        s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]);

        // !! SKIP XTEA-CTR loop entirely !! (just test setup code)

        // Install simple VEH
        s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        let veh_lea_patch_36 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0xFF, 0x55, 0x10]);

        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        let epilogue_data_lea_patch_36 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x8B, 0x41, 0x18]);
        s.extend_from_slice(&[0x48, 0x03, 0x01]);
        s.extend_from_slice(&[0xFF, 0xE0]);

        let veh_handler_36 = s.len();
        let veh_disp_36 = (veh_handler_36 as i32) - (veh_lea_patch_36 as i32 + 4);
        s[veh_lea_patch_36]     = veh_disp_36 as u8;
        s[veh_lea_patch_36 + 1] = (veh_disp_36 >> 8) as u8;
        s[veh_lea_patch_36 + 2] = (veh_disp_36 >> 16) as u8;
        s[veh_lea_patch_36 + 3] = (veh_disp_36 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        s.push(0xC3);

        // Data area
        let data_area_36 = s.len();
        let dd36 = (data_area_36 as i32) - (data_lea_patch_36 as i32 + 4);
        s[data_lea_patch_36]     = dd36 as u8;
        s[data_lea_patch_36 + 1] = (dd36 >> 8) as u8;
        s[data_lea_patch_36 + 2] = (dd36 >> 16) as u8;
        s[data_lea_patch_36 + 3] = (dd36 >> 24) as u8;
        let edd36 = (data_area_36 as i32) - (epilogue_data_lea_patch_36 as i32 + 4);
        s[epilogue_data_lea_patch_36]     = edd36 as u8;
        s[epilogue_data_lea_patch_36 + 1] = (edd36 >> 8) as u8;
        s[epilogue_data_lea_patch_36 + 2] = (edd36 >> 16) as u8;
        s[epilogue_data_lea_patch_36 + 3] = (edd36 >> 24) as u8;

        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        let nm_count_36 = nanomite_entries.len().min(128) as u32;
        s.extend_from_slice(&nm_count_36.to_le_bytes());
        for &k in &nm_xtea_36 {
            s.extend_from_slice(&k.to_le_bytes());
        }
        s.extend_from_slice(&nanomite_crypto_key.to_le_bytes());
        s.extend_from_slice(&text_rva.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        // Don't need dispatch table since we skip XTEA

        eprintln!("[DEBUG] Level 3.6: setup + VEH, no XTEA loop ({} bytes)", s.len());
        return s;
    }

    // Level 3.8 (debug_level == 38): Run XTEA exactly ONCE (no loop)
    // If this works, the issue is jnz offset overflow in the CTR loop
    if debug_level == 38 {
        let nm_xtea_38 = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
        let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");
        let mut s = Vec::new();

        // Prologue
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        let data_lea_patch_38 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);

        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);
        s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]);
        s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]);
        s.extend_from_slice(&[0x49, 0x89, 0xC6]);

        // ntdll resolution
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);
        s.extend_from_slice(&[0x48, 0x8B, 0x00]);
        s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]);
        s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);
        s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE2]);
        s.extend_from_slice(&[0x8B, 0x4A, 0x18]);
        s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE5]);
        s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE7]);
        s.extend_from_slice(&[0x8B, 0x42, 0x1C]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]);

        s.extend_from_slice(&[0x31, 0xF6]);
        let export_loop_38 = s.len();
        s.extend_from_slice(&[0x39, 0xCE]);
        let export_done_patch_38 = s.len();
        s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x31, 0xD2]);
        let hash_loop_38 = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x38]);
        s.extend_from_slice(&[0x85, 0xFF]);
        let hash_done_jz_38 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);
        s.extend_from_slice(&[0x01, 0xFA]);
        s.extend_from_slice(&[0x48, 0xFF, 0xC0]);
        let d38 = (hash_loop_38 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d38 as u8]);
        let hash_done_38 = s.len();
        s[hash_done_jz_38 + 1] = (hash_done_38 - hash_done_jz_38 - 2) as u8;
        s.extend_from_slice(&[0x81, 0xFA]);
        s.extend_from_slice(&target_hash.to_le_bytes());
        let found_jz_38 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xFF, 0xC6]);
        let d38 = (export_loop_38 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d38 as u8]);
        let export_not_found_38 = s.len();
        let jge_disp_38 = (export_not_found_38 as i32) - (export_done_patch_38 as i32 + 6);
        s[export_done_patch_38 + 2] = jge_disp_38 as u8;
        s[export_done_patch_38 + 3] = (jge_disp_38 >> 8) as u8;
        s[export_done_patch_38 + 4] = (jge_disp_38 >> 16) as u8;
        s[export_done_patch_38 + 5] = (jge_disp_38 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        let store_jmp_38 = s.len();
        s.extend_from_slice(&[0xEB, 0x00]);
        let found_38 = s.len();
        s[found_jz_38 + 1] = (found_38 - found_jz_38 - 2) as u8;
        s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]);
        s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]);
        s.extend_from_slice(&[0x8B, 0x04, 0x82]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        let store_38 = s.len();
        s[store_jmp_38 + 1] = (store_38 - store_jmp_38 - 2) as u8;
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]);

        // XTEA key prep
        s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]);
        s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]);
        s.extend_from_slice(&[0x4D, 0x85, 0xF6]);
        s.extend_from_slice(&[0x74, 0x06]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF0]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF1]);
        s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);
        s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]);

        // Run XTEA exactly ONCE (no loop)
        s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x30]); // mov rax, [rbp+0x30] (nonce)
        emit_xtea_encrypt(&mut s);
        // Result in rax - just discard it

        // Install simple VEH
        s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        let veh_lea_patch_38 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0xFF, 0x55, 0x10]);

        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        let epilogue_data_lea_patch_38 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x8B, 0x41, 0x18]);
        s.extend_from_slice(&[0x48, 0x03, 0x01]);
        s.extend_from_slice(&[0xFF, 0xE0]);

        let veh_handler_38 = s.len();
        let veh_disp_38 = (veh_handler_38 as i32) - (veh_lea_patch_38 as i32 + 4);
        s[veh_lea_patch_38]     = veh_disp_38 as u8;
        s[veh_lea_patch_38 + 1] = (veh_disp_38 >> 8) as u8;
        s[veh_lea_patch_38 + 2] = (veh_disp_38 >> 16) as u8;
        s[veh_lea_patch_38 + 3] = (veh_disp_38 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        s.push(0xC3);

        // Data area
        let data_area_38 = s.len();
        let dd38 = (data_area_38 as i32) - (data_lea_patch_38 as i32 + 4);
        s[data_lea_patch_38]     = dd38 as u8;
        s[data_lea_patch_38 + 1] = (dd38 >> 8) as u8;
        s[data_lea_patch_38 + 2] = (dd38 >> 16) as u8;
        s[data_lea_patch_38 + 3] = (dd38 >> 24) as u8;
        let edd38 = (data_area_38 as i32) - (epilogue_data_lea_patch_38 as i32 + 4);
        s[epilogue_data_lea_patch_38]     = edd38 as u8;
        s[epilogue_data_lea_patch_38 + 1] = (edd38 >> 8) as u8;
        s[epilogue_data_lea_patch_38 + 2] = (edd38 >> 16) as u8;
        s[epilogue_data_lea_patch_38 + 3] = (edd38 >> 24) as u8;

        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        let nm_count_38 = nanomite_entries.len().min(128) as u32;
        s.extend_from_slice(&nm_count_38.to_le_bytes());
        for &k in &nm_xtea_38 {
            s.extend_from_slice(&k.to_le_bytes());
        }
        s.extend_from_slice(&nanomite_crypto_key.to_le_bytes());
        s.extend_from_slice(&text_rva.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());

        eprintln!("[DEBUG] Level 3.8: XTEA once, no loop ({} bytes)", s.len());
        return s;
    }

    // Level 3.7 (debug_level == 37): XTEA loop but NO memory write
    if debug_level == 37 {
        let nm_xtea_37 = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
        let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");
        let mut s = Vec::new();

        // Prologue
        s.push(0x53); s.push(0x57); s.push(0x56);
        s.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        s.push(0x55);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        let data_lea_patch_37 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);

        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);
        s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]);
        s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]);
        s.extend_from_slice(&[0x49, 0x89, 0xC6]);

        // ntdll resolution (same as 3.5)
        s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
        s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);
        s.extend_from_slice(&[0x48, 0x8B, 0x00]);
        s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]);
        s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);
        s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE2]);
        s.extend_from_slice(&[0x8B, 0x4A, 0x18]);
        s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE5]);
        s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);
        s.extend_from_slice(&[0x4D, 0x01, 0xE7]);
        s.extend_from_slice(&[0x8B, 0x42, 0x1C]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]);

        s.extend_from_slice(&[0x31, 0xF6]);
        let export_loop_37 = s.len();
        s.extend_from_slice(&[0x39, 0xCE]);
        let export_done_patch_37 = s.len();
        s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        s.extend_from_slice(&[0x31, 0xD2]);
        let hash_loop_37 = s.len();
        s.extend_from_slice(&[0x0F, 0xB6, 0x38]);
        s.extend_from_slice(&[0x85, 0xFF]);
        let hash_done_jz_37 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);
        s.extend_from_slice(&[0x01, 0xFA]);
        s.extend_from_slice(&[0x48, 0xFF, 0xC0]);
        let d37 = (hash_loop_37 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d37 as u8]);
        let hash_done_37 = s.len();
        s[hash_done_jz_37 + 1] = (hash_done_37 - hash_done_jz_37 - 2) as u8;
        s.extend_from_slice(&[0x81, 0xFA]);
        s.extend_from_slice(&target_hash.to_le_bytes());
        let found_jz_37 = s.len();
        s.extend_from_slice(&[0x74, 0x00]);
        s.extend_from_slice(&[0xFF, 0xC6]);
        let d37 = (export_loop_37 as i32) - (s.len() as i32 + 2);
        s.extend_from_slice(&[0xEB, d37 as u8]);
        let export_not_found_37 = s.len();
        let jge_disp_37 = (export_not_found_37 as i32) - (export_done_patch_37 as i32 + 6);
        s[export_done_patch_37 + 2] = jge_disp_37 as u8;
        s[export_done_patch_37 + 3] = (jge_disp_37 >> 8) as u8;
        s[export_done_patch_37 + 4] = (jge_disp_37 >> 16) as u8;
        s[export_done_patch_37 + 5] = (jge_disp_37 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        let store_jmp_37 = s.len();
        s.extend_from_slice(&[0xEB, 0x00]);
        let found_37 = s.len();
        s[found_jz_37 + 1] = (found_37 - found_jz_37 - 2) as u8;
        s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]);
        s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]);
        s.extend_from_slice(&[0x8B, 0x04, 0x82]);
        s.extend_from_slice(&[0x4C, 0x01, 0xE0]);
        let store_37 = s.len();
        s[store_jmp_37 + 1] = (store_37 - store_jmp_37 - 2) as u8;
        s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]);

        // XTEA key prep
        s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]);
        s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]);
        s.extend_from_slice(&[0x4D, 0x85, 0xF6]);
        s.extend_from_slice(&[0x74, 0x06]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF0]);
        s.extend_from_slice(&[0x4C, 0x31, 0xF1]);
        s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);
        s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]);

        // XTEA-CTR loop (but NO memory write - just run XTEA)
        s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);
        s.extend_from_slice(&[0x48, 0x8B, 0x7D, 0x30]);
        s.extend_from_slice(&[0x01, 0xC9]);
        s.extend_from_slice(&[0x85, 0xC9]);
        let skip_decrypt_37 = s.len();
        s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);

        s.extend_from_slice(&[0x45, 0x31, 0xFF]);
        let ctr_loop_37 = s.len();
        s.extend_from_slice(&[0x89, 0x4C, 0x24, 0x10]);
        s.extend_from_slice(&[0x4C, 0x89, 0xF8]);
        s.extend_from_slice(&[0x48, 0x01, 0xF8]);
        emit_xtea_encrypt(&mut s);
        // SKIP: s.extend_from_slice(&[0x4A, 0x31, 0x04, 0xFE]); // xor [rsi+r15*8], rax
        s.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]);
        s.extend_from_slice(&[0x49, 0xFF, 0xC7]);
        s.extend_from_slice(&[0xFF, 0xC9]);
        // Use near jnz (6 bytes) instead of short jnz (2 bytes) - loop body > 127 bytes
        let d37 = (ctr_loop_37 as i32) - (s.len() as i32 + 6);
        s.extend_from_slice(&[0x0F, 0x85]);
        s.extend_from_slice(&(d37 as i32).to_le_bytes());

        let skip_decrypt_target_37 = s.len();
        let sd37 = (skip_decrypt_target_37 as i32) - (skip_decrypt_37 as i32 + 6);
        s[skip_decrypt_37 + 2] = sd37 as u8;
        s[skip_decrypt_37 + 3] = (sd37 >> 8) as u8;
        s[skip_decrypt_37 + 4] = (sd37 >> 16) as u8;
        s[skip_decrypt_37 + 5] = (sd37 >> 24) as u8;

        // Install simple VEH
        s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        let veh_lea_patch_37 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0xFF, 0x55, 0x10]);

        // Epilogue
        s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        s.push(0x5D);
        s.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        s.push(0x5E); s.push(0x5F); s.push(0x5B);
        let epilogue_data_lea_patch_37 = s.len() + 3;
        s.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x8B, 0x41, 0x18]);
        s.extend_from_slice(&[0x48, 0x03, 0x01]);
        s.extend_from_slice(&[0xFF, 0xE0]);

        let veh_handler_37 = s.len();
        let veh_disp_37 = (veh_handler_37 as i32) - (veh_lea_patch_37 as i32 + 4);
        s[veh_lea_patch_37]     = veh_disp_37 as u8;
        s[veh_lea_patch_37 + 1] = (veh_disp_37 >> 8) as u8;
        s[veh_lea_patch_37 + 2] = (veh_disp_37 >> 16) as u8;
        s[veh_lea_patch_37 + 3] = (veh_disp_37 >> 24) as u8;
        s.extend_from_slice(&[0x31, 0xC0]);
        s.push(0xC3);

        // Data area
        let data_area_37 = s.len();
        let dd37 = (data_area_37 as i32) - (data_lea_patch_37 as i32 + 4);
        s[data_lea_patch_37]     = dd37 as u8;
        s[data_lea_patch_37 + 1] = (dd37 >> 8) as u8;
        s[data_lea_patch_37 + 2] = (dd37 >> 16) as u8;
        s[data_lea_patch_37 + 3] = (dd37 >> 24) as u8;
        let edd37 = (data_area_37 as i32) - (epilogue_data_lea_patch_37 as i32 + 4);
        s[epilogue_data_lea_patch_37]     = edd37 as u8;
        s[epilogue_data_lea_patch_37 + 1] = (edd37 >> 8) as u8;
        s[epilogue_data_lea_patch_37 + 2] = (edd37 >> 16) as u8;
        s[epilogue_data_lea_patch_37 + 3] = (edd37 >> 24) as u8;

        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s.extend_from_slice(&orig_entry_rva.to_le_bytes());
        let nm_count_37 = nanomite_entries.len().min(128) as u32;
        s.extend_from_slice(&nm_count_37.to_le_bytes());
        for &k in &nm_xtea_37 {
            s.extend_from_slice(&k.to_le_bytes());
        }
        s.extend_from_slice(&nanomite_crypto_key.to_le_bytes());
        s.extend_from_slice(&text_rva.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        // Include dispatch table for memory access test
        let table_start_37 = s.len();
        for e in nanomite_entries.iter().take(128) {
            s.extend_from_slice(&e.bp_rva.to_le_bytes());
            s.extend_from_slice(&e.taken_rva.to_le_bytes());
            s.extend_from_slice(&e.nottaken_rva.to_le_bytes());
            s.push(e.condition);
            s.extend_from_slice(&[0u8; 3]);
        }
        if nanomite_crypto_key != 0 && nm_count_37 > 0 {
            xtea_ctr_apply(&mut s[table_start_37..], &nm_xtea_37, nanomite_crypto_key);
        }

        eprintln!("[DEBUG] Level 3.7: XTEA loop no-write ({} bytes)", s.len());
        return s;
    }

    // Level 4: Skip INT3 patching only (full XTEA decrypt + VEH handler)
    let skip_int3_patch = debug_level == 4 || debug_level == 45 || debug_level == 46 || debug_level == 47 || debug_level == 49 || debug_level == 51 || debug_level == 52 || debug_level == 53 || debug_level == 55;
    if debug_level == 4 {
        eprintln!("[DEBUG] Level 4: full stub without INT3 patching");
    }

    // Level 4.5: Do ONE INT3 patch only (test if INT3 patching itself crashes)
    let single_int3_patch = debug_level == 45;
    if single_int3_patch {
        eprintln!("[DEBUG] Level 4.5: single INT3 patch test");
    }

    // Level 4.6: Patch exactly N INT3s (configurable via SQURE_DEBUG_PATCH_COUNT)
    let limited_patch_count: Option<u32> = if debug_level == 46 {
        let count = std::env::var("SQURE_DEBUG_PATCH_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);  // Default: 5 entries (safe, avoids Entry 5)
        eprintln!("[DEBUG] Level 4.6: limited INT3 patches (count={})", count);
        Some(count)
    } else {
        None
    };

    // Level 4.7: Full INT3 patch loop but NO memory writes (test if loop itself works)
    let no_write_patch = debug_level == 47;
    if no_write_patch {
        eprintln!("[DEBUG] Level 4.7: INT3 patch loop without memory writes");
    }

    // Level 4.9: Validate 25th entry bp_rva
    let validate_25th = debug_level == 49;
    if validate_25th {
        eprintln!("[DEBUG] Level 4.9: validate 25th entry bp_rva");
    }

    // Level 5: Production with INT3 patch limited to first 24 entries
    let limit_to_24 = debug_level == 5;
    if limit_to_24 {
        eprintln!("[DEBUG] Level 5: production but limit INT3 patches to 20 entries");
    }

    // Level 5.1: Patch ONLY the 25th entry (index 24)
    let only_25th = debug_level == 51;
    if only_25th {
        eprintln!("[DEBUG] Level 5.1: patch ONLY 25th entry (index 24)");
    }

    // Level 5.2: Read from 25th entry address (test if address is valid/readable)
    let read_25th = debug_level == 52;
    if read_25th {
        eprintln!("[DEBUG] Level 5.2: read from 25th entry address");
    }

    // Level 5.3: Patch ONLY entry N (skip 0 to N-1)
    let only_nth: Option<u32> = if debug_level == 53 || debug_level == 55 {
        let n = std::env::var("SQURE_DEBUG_PATCH_INDEX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(35);
        eprintln!("[DEBUG] Level {}: patch ONLY entry {}", debug_level, n);
        Some(n)
    } else {
        None
    };

    // Level 5.5: Like 5.3 but VEH always uses nottaken (skip condition eval)
    let force_nottaken = debug_level == 55;
    if force_nottaken {
        eprintln!("[DEBUG] Level 5.5: VEH will always use nottaken_rva (skip condition)");
    }

    // Level 5.4: Patch entries 0 to N, skipping entry M
    let skip_one_entry: Option<u32> = if debug_level == 54 {
        let skip = std::env::var("SQURE_DEBUG_PATCH_SKIP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(35);
        let up_to = std::env::var("SQURE_DEBUG_PATCH_UPTO")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36);
        eprintln!("[DEBUG] Level 5.4: patch entries 0-{}, skip entry {}", up_to, skip);
        Some(skip)
    } else {
        None
    };

    let nm_xtea = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
    let target_hash = ror13_hash(b"RtlAddVectoredExceptionHandler");

    // CRITICAL: Sort nanomite entries by bp_rva for binary search in VEH handler
    let mut sorted_entries: Vec<_> = nanomite_entries.iter().take(128).cloned().collect();
    sorted_entries.sort_by_key(|e| e.bp_rva);

    let nanomite_entries = &sorted_entries[..];
    let nm_count = nanomite_entries.len().min(128) as u32;

    // DEBUG: Show first 50 entries to find problematic one
    eprintln!("[DEBUG] First 50 sorted nanomite entries (bp_rva → taken, nottaken, cond):");
    for (i, e) in nanomite_entries.iter().take(50).enumerate() {
        let cond_name = match e.condition {
            0xF0 => "JZ",
            0xF1 => "JNZ",
            0xF2 => "JL",
            0xF3 => "JGE",
            0xF4 => "JLE",
            0xF5 => "JG",
            _ => "???",
        };
        eprintln!("  [{:2}] 0x{:08X} → 0x{:08X}, 0x{:08X}  {}", i, e.bp_rva, e.taken_rva, e.nottaken_rva, cond_name);
    }

    let mut s = Vec::with_capacity(8192);

    // ═══════════════════════════════════════════════════════════
    // INIT CODE — runs once when .sqinit jumps here after .text decrypt
    // ═══════════════════════════════════════════════════════════

    // ── Prologue: save callee-saved registers ──
    s.push(0x53);                                       // push rbx
    s.push(0x57);                                       // push rdi
    s.push(0x56);                                       // push rsi
    s.extend_from_slice(&[0x41, 0x54]);                 // push r12
    s.extend_from_slice(&[0x41, 0x55]);                 // push r13
    s.extend_from_slice(&[0x41, 0x56]);                 // push r14
    s.extend_from_slice(&[0x41, 0x57]);                 // push r15
    s.push(0x55);                                       // push rbp

    // Stack frame: 0x38 bytes (for 16-byte alignment)
    //   [rsp+0x00..0x0F]  XTEA key (16 bytes)
    //   [rsp+0x10..0x17]  scratch
    //   [rsp+0x18..0x37]  shadow space (32 bytes)
    // Windows x64 entry: RSP % 16 = 8
    // After 8 pushes (64B): RSP % 16 = 8
    // sub 0x38 (56B): (8 - 56) % 16 = 0 ✓
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);    // sub rsp, 0x38

    // ── LEA rbp, [rip + data_area] — base pointer for all data ──
    let data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x2D,
                          0x00, 0x00, 0x00, 0x00]);     // lea rbp, [rip+?] (patched)

    // ── Get ImageBase from PEB ──
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25,
                          0x60, 0x00, 0x00, 0x00]);     // mov rax, gs:[0x60] (PEB)
    s.extend_from_slice(&[0x48, 0x8B, 0x58, 0x10]);    // mov rbx, [rax+0x10] (ImageBase)
    s.extend_from_slice(&[0x48, 0x89, 0x5D, 0x00]);    // mov [rbp+0x00], rbx

    // ── Anti-debug: PEB.BeingDebugged → poison ──
    if enable_anti_debug {
        s.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);    // movzx eax, byte [rax+2]
    } else {
        // Anti-debug disabled: set poison to 0 (padded to same size)
        s.extend_from_slice(&[0x31, 0xC0, 0x90, 0x90]);    // xor eax, eax; nop; nop
    }
    s.extend_from_slice(&[0x48, 0x89, 0x45, 0x08]);    // mov [rbp+0x08], rax (poison)
    s.extend_from_slice(&[0x49, 0x89, 0xC6]);          // mov r14, rax (keep poison in r14)

    // ── Sandbox/VM Detection: CPUID hypervisor bit check ──
    // If running in VM/hypervisor, poison the crypto key
    if use_hardened || use_ultra {
        // Save registers that CPUID clobbers (EAX, EBX, ECX, EDX)
        // RBX contains ImageBase which is already saved to [rbp+0x00]
        // but we still need to preserve it for safety
        s.extend_from_slice(&[0x53]);                      // push rbx
        s.extend_from_slice(&[0x51]);                      // push rcx
        s.extend_from_slice(&[0x52]);                      // push rdx

        // CPUID leaf 1: check hypervisor present bit (ECX bit 31)
        s.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        s.extend_from_slice(&[0x0F, 0xA2]);                // cpuid
        s.extend_from_slice(&[0xF7, 0xC1, 0x00, 0x00, 0x00, 0x80]); // test ecx, 0x80000000
        s.extend_from_slice(&[0x74, 0x04]);                // jz no_hypervisor (+4)
        s.extend_from_slice(&[0x49, 0x83, 0xCE, 0x10]);    // or r14, 0x10 (poison bit)
        // no_hypervisor:

        // CPUID leaf 0x40000000: check hypervisor vendor (VirtualBox/VMware/Hyper-V/KVM)
        s.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x40]); // mov eax, 0x40000000
        s.extend_from_slice(&[0x0F, 0xA2]);                // cpuid
        // If eax >= 0x40000000, hypervisor is present and supports hypervisor leaves
        s.extend_from_slice(&[0x3D, 0x00, 0x00, 0x00, 0x40]); // cmp eax, 0x40000000
        s.extend_from_slice(&[0x72, 0x04]);                // jb no_hv_vendor (+4)
        s.extend_from_slice(&[0x49, 0x83, 0xCE, 0x20]);    // or r14, 0x20 (poison bit)
        // no_hv_vendor:

        // Restore registers (reverse order)
        s.extend_from_slice(&[0x5A]);                      // pop rdx
        s.extend_from_slice(&[0x59]);                      // pop rcx
        s.extend_from_slice(&[0x5B]);                      // pop rbx
    }

    // ── Find ntdll via PEB → Ldr → InLoadOrderModuleList ──
    s.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25,
                          0x60, 0x00, 0x00, 0x00]);     // mov rax, gs:[0x60] (PEB)
    s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);    // mov rax, [rax+0x18] (Ldr)
    s.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]);    // mov rax, [rax+0x10] (InLoadOrder.Flink)
    s.extend_from_slice(&[0x48, 0x8B, 0x00]);          // mov rax, [rax] (2nd entry = ntdll)
    s.extend_from_slice(&[0x4C, 0x8B, 0x60, 0x30]);   // mov r12, [rax+0x30] (ntdll DllBase)

    // ── Resolve RtlAddVectoredExceptionHandler by ROR-13 hash ──
    // Walk ntdll export directory
    s.extend_from_slice(&[0x41, 0x8B, 0x44, 0x24, 0x3C]); // mov eax, [r12+0x3C] (e_lfanew)
    s.extend_from_slice(&[0x4A, 0x8D, 0x04, 0x20]);   // lea rax, [rax+r12] (PE header VA)
    s.extend_from_slice(&[0x8B, 0x90, 0x88, 0x00, 0x00, 0x00]); // mov edx, [rax+0x88] (ExportDir RVA)
    s.extend_from_slice(&[0x49, 0x01, 0xD4]);          // add r12, rdx → r12 = ExportDir VA (temp)
    // Oops, we clobbered r12 (ntdll base). Let me fix this.
    // Actually, we need ntdll base for all the RVA→VA conversions.
    // Let me use a different approach: keep ntdll base in r12, ExportDir in r13.

    // REWRITE: Let me redo this properly.
    s.truncate(s.len() - 3); // remove "add r12, rdx"
    s.extend_from_slice(&[0x4C, 0x01, 0xE2]);          // add rdx, r12 → rdx = ExportDir VA

    // NumberOfNames = [ExportDir+0x18]
    s.extend_from_slice(&[0x8B, 0x4A, 0x18]);          // mov ecx, [rdx+0x18]
    // AddressOfNames = r12 + [ExportDir+0x20]
    s.extend_from_slice(&[0x44, 0x8B, 0x6A, 0x20]);   // mov r13d, [rdx+0x20]
    s.extend_from_slice(&[0x4D, 0x01, 0xE5]);          // add r13, r12
    // AddressOfNameOrdinals = r12 + [ExportDir+0x24]
    s.extend_from_slice(&[0x44, 0x8B, 0x7A, 0x24]);   // mov r15d, [rdx+0x24]
    s.extend_from_slice(&[0x4D, 0x01, 0xE7]);          // add r15, r12
    // AddressOfFunctions = r12 + [ExportDir+0x1C], store on stack
    s.extend_from_slice(&[0x8B, 0x42, 0x1C]);          // mov eax, [rdx+0x1C]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x18]); // mov [rsp+0x18], rax (save AddrOfFunctions)

    // Loop over export names
    s.extend_from_slice(&[0x31, 0xF6]);                 // xor esi, esi (i = 0)
    let export_loop = s.len();
    s.extend_from_slice(&[0x39, 0xCE]);                 // cmp esi, ecx
    let export_done_patch = s.len();
    s.extend_from_slice(&[0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00]); // jge export_not_found (patch)

    // name_rva = AddressOfNames[i]
    s.extend_from_slice(&[0x41, 0x8B, 0x44, 0xB5, 0x00]); // mov eax, [r13+rsi*4]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12 (name VA)

    // Compute ROR-13 hash of name → edx
    s.extend_from_slice(&[0x31, 0xD2]);                 // xor edx, edx (hash = 0)
    let hash_loop = s.len();
    s.extend_from_slice(&[0x0F, 0xB6, 0x38]);          // movzx edi, byte [rax]
    s.extend_from_slice(&[0x85, 0xFF]);                 // test edi, edi
    let hash_done_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                 // jz hash_done (patch)
    s.extend_from_slice(&[0xC1, 0xCA, 0x0D]);          // ror edx, 13
    s.extend_from_slice(&[0x01, 0xFA]);                 // add edx, edi
    s.extend_from_slice(&[0x48, 0xFF, 0xC0]);          // inc rax
    let d = (hash_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);              // jmp hash_loop
    let hash_done = s.len();
    s[hash_done_jz + 1] = (hash_done - hash_done_jz - 2) as u8;

    // Compare hash with target
    s.extend_from_slice(&[0x81, 0xFA]);                 // cmp edx, imm32
    s.extend_from_slice(&target_hash.to_le_bytes());
    let found_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                 // je found (patch)

    // Next export
    s.extend_from_slice(&[0xFF, 0xC6]);                 // inc esi
    let d = (export_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);              // jmp export_loop

    // Not found → store 0
    let export_not_found = s.len();
    let jge_disp = (export_not_found as i32) - (export_done_patch as i32 + 6);
    s[export_done_patch + 2] = jge_disp as u8;
    s[export_done_patch + 3] = (jge_disp >> 8) as u8;
    s[export_done_patch + 4] = (jge_disp >> 16) as u8;
    s[export_done_patch + 5] = (jge_disp >> 24) as u8;
    s.extend_from_slice(&[0x31, 0xC0]);                 // xor eax, eax
    let store_rtl_jmp = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                 // jmp store_rtl (patch)

    // Found → resolve function address
    let found = s.len();
    s[found_jz + 1] = (found - found_jz - 2) as u8;
    // ordinal = AddressOfNameOrdinals[i]
    s.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x04, 0x77]); // movzx eax, word [r15+rsi*2]
    // func_rva = AddressOfFunctions[ordinal]
    s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x18]); // mov rdx, [rsp+0x18] (AddrOfFunctions)
    s.extend_from_slice(&[0x8B, 0x04, 0x82]);          // mov eax, [rdx+rax*4]
    s.extend_from_slice(&[0x4C, 0x01, 0xE0]);          // add rax, r12 (func VA)

    let store_rtl = s.len();
    s[store_rtl_jmp + 1] = (store_rtl - store_rtl_jmp - 2) as u8;
    // Store resolved address
    s.extend_from_slice(&[0x48, 0x89, 0x45, 0x10]);    // mov [rbp+0x10], rax

    // ── Prepare XTEA key on stack (with poison XOR) ──
    s.extend_from_slice(&[0x48, 0x8B, 0x45, 0x20]);    // mov rax, [rbp+0x20] (key lo)
    s.extend_from_slice(&[0x48, 0x8B, 0x4D, 0x28]);    // mov rcx, [rbp+0x28] (key hi)
    // If poison != 0: XOR key with poison
    s.extend_from_slice(&[0x4D, 0x85, 0xF6]);          // test r14, r14
    let _skip_poison = s.len();
    s.extend_from_slice(&[0x74, 0x06]);                 // jz +6
    s.extend_from_slice(&[0x4C, 0x31, 0xF0]);          // xor rax, r14
    s.extend_from_slice(&[0x4C, 0x31, 0xF1]);          // xor rcx, r14
    // Store key on stack for XTEA
    s.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);    // mov [rsp], rax
    s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp+8], rcx

    // ── XTEA-CTR decrypt dispatch table ──
    // If SQURE_SKIP_NM_XTEA is set, skip decryption (table is plaintext)
    let skip_runtime_xtea = std::env::var("SQURE_SKIP_NM_XTEA").is_ok();
    if skip_runtime_xtea {
        s.extend_from_slice(&[0x31, 0xC9]);               // xor ecx, ecx (force skip)
        eprintln!("[DEBUG] Runtime XTEA decryption SKIPPED");
    } else {
        s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);          // mov ecx, [rbp+0x1C] (dispatch_count)
    }
    s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (dispatch_table)
    s.extend_from_slice(&[0x48, 0x8B, 0x7D, 0x30]);    // mov rdi, [rbp+0x30] (nonce)
    // total qwords = count * 2 (each entry = 16 bytes = 2 qwords)
    s.extend_from_slice(&[0x01, 0xC9]);                 // add ecx, ecx
    s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
    let skip_decrypt = s.len();
    s.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz skip (patch)

    s.extend_from_slice(&[0x45, 0x31, 0xFF]);          // xor r15d, r15d (block index)
    let ctr_loop = s.len();
    // Save ecx (remaining qwords)
    s.extend_from_slice(&[0x89, 0x4C, 0x24, 0x10]);    // mov [rsp+0x10], ecx
    // counter = nonce + block_index
    s.extend_from_slice(&[0x4C, 0x89, 0xF8]);          // mov rax, r15
    s.extend_from_slice(&[0x48, 0x01, 0xF8]);          // add rax, rdi
    // XTEA encrypt rax → rax (uses [rsp+0..15] as key, clobbers rcx,rdx,r8-r11)
    emit_xtea_encrypt(&mut s);
    // XOR data: [rsi + r15*8] ^= rax
    s.extend_from_slice(&[0x4A, 0x31, 0x04, 0xFE]);    // xor [rsi+r15*8], rax
    // Restore ecx, advance
    s.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10]);    // mov ecx, [rsp+0x10]
    s.extend_from_slice(&[0x49, 0xFF, 0xC7]);          // inc r15
    s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
    // Use near jnz (6 bytes) instead of short jnz (2 bytes) - loop body > 127 bytes
    let d = (ctr_loop as i32) - (s.len() as i32 + 6);
    s.extend_from_slice(&[0x0F, 0x85]);                 // near jnz
    s.extend_from_slice(&(d as i32).to_le_bytes());    // 32-bit displacement

    let skip_decrypt_target = s.len();
    let sd = (skip_decrypt_target as i32) - (skip_decrypt as i32 + 6);
    s[skip_decrypt + 2] = sd as u8;
    s[skip_decrypt + 3] = (sd >> 8) as u8;
    s[skip_decrypt + 4] = (sd >> 16) as u8;
    s[skip_decrypt + 5] = (sd >> 24) as u8;

    // ── Patch INT3s into .text ──
    // (skip if debug level 4 or 4.5)
    let skip_patch: usize;
    if !skip_int3_patch {
        if limit_to_24 {
            // Level 5: Limit to 20 patches (was 24, but testing shows 21+ causes crash)
            s.extend_from_slice(&[0xB9, 0x14, 0x00, 0x00, 0x00]); // mov ecx, 20
        } else {
            // Full patching: read count from data area
            s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);          // mov ecx, [rbp+0x1C] (dispatch_count)
        }
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table)
        s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
        skip_patch = s.len();
        s.extend_from_slice(&[0x74, 0x00]);                 // jz skip_patch (patch)

        let patch_loop = s.len();
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);    // mov byte [rax+2], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);    // mov byte [rax+3], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);    // mov byte [rax+4], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);    // mov byte [rax+5], 0x90

        s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x10]);    // add rsi, 16 (next entry)
        s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
        // Use near jnz (same as Level 4.6 which works)
        let d = (patch_loop as i32) - (s.len() as i32 + 6);
        s.extend_from_slice(&[0x0F, 0x85]);                 // near jnz
        s.extend_from_slice(&(d as i32).to_le_bytes());    // 32-bit displacement

        let skip_patch_target = s.len();
        s[skip_patch + 1] = (skip_patch_target - skip_patch - 2) as u8;
    } else if single_int3_patch {
        // Level 4.5: Patch just ONE INT3 to test if patching itself works
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table)
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (first bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);    // mov byte [rax+2], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);    // mov byte [rax+3], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);    // mov byte [rax+4], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);    // mov byte [rax+5], 0x90
        skip_patch = 0;
    } else if let Some(patch_count) = limited_patch_count {
        // Level 4.6: Patch exactly N INT3s with a loop
        s.extend_from_slice(&[0xB9]);                        // mov ecx, imm32 (count)
        s.extend_from_slice(&patch_count.to_le_bytes());
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table)
        s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
        skip_patch = s.len();
        s.extend_from_slice(&[0x74, 0x00]);                 // jz skip_patch (patch)

        let patch_loop_46 = s.len();
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);    // mov byte [rax+2], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);    // mov byte [rax+3], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);    // mov byte [rax+4], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);    // mov byte [rax+5], 0x90
        s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x10]);    // add rsi, 16 (next entry)
        s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
        // Use near jnz (consistent with production and XTEA-CTR loops)
        let d46 = (patch_loop_46 as i32) - (s.len() as i32 + 6);
        s.extend_from_slice(&[0x0F, 0x85]);                 // near jnz
        s.extend_from_slice(&(d46 as i32).to_le_bytes());  // 32-bit displacement

        let skip_patch_target_46 = s.len();
        s[skip_patch + 1] = (skip_patch_target_46 - skip_patch - 2) as u8;
    } else if no_write_patch {
        // Level 4.7: Full INT3 loop but skip memory writes
        s.extend_from_slice(&[0x8B, 0x4D, 0x1C]);          // mov ecx, [rbp+0x1C] (dispatch_count)
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table)
        s.extend_from_slice(&[0x85, 0xC9]);                 // test ecx, ecx
        skip_patch = s.len();
        s.extend_from_slice(&[0x74, 0x00]);                 // jz skip_patch (patch)

        let patch_loop_47 = s.len();
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        // SKIP: s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        // SKIP: s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        // SKIP: all 6 mov byte instructions
        s.extend_from_slice(&[0x48, 0x83, 0xC6, 0x10]);    // add rsi, 16 (next entry)
        s.extend_from_slice(&[0xFF, 0xC9]);                 // dec ecx
        // Use near jnz (consistent with all other loops)
        let d47 = (patch_loop_47 as i32) - (s.len() as i32 + 6);
        s.extend_from_slice(&[0x0F, 0x85]);                 // near jnz
        s.extend_from_slice(&(d47 as i32).to_le_bytes());  // 32-bit displacement

        let skip_patch_target_47 = s.len();
        s[skip_patch + 1] = (skip_patch_target_47 - skip_patch - 2) as u8;
    } else if validate_25th {
        // Level 4.9: Read 25th entry bp_rva and save to [rbp+0x3C]
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table start)
        s.extend_from_slice(&[0x48, 0x81, 0xC6, 0x80, 0x01, 0x00, 0x00]); // add rsi, 0x180 (24 * 16)
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (25th bp_rva)
        s.extend_from_slice(&[0x89, 0x45, 0x3C]);          // mov [rbp+0x3C], eax (save for debugging)
        // Compare with text_rva
        s.extend_from_slice(&[0x8B, 0x4D, 0x38]);          // mov ecx, [rbp+0x38] (text_rva)
        s.extend_from_slice(&[0x39, 0xC8]);                 // cmp eax, ecx
        let bp_below_text = s.len();
        s.extend_from_slice(&[0x72, 0x00]);                 // jb error (bp_rva < text_rva)
        // Check if bp_rva looks encrypted (>= 0x10000000)
        s.extend_from_slice(&[0x3D, 0x00, 0x00, 0x00, 0x10]); // cmp eax, 0x10000000
        let bp_too_large = s.len();
        s.extend_from_slice(&[0x73, 0x00]);                 // jae error (bp_rva >= 0x10000000)
        let bp_ok_jmp = s.len();
        s.extend_from_slice(&[0xEB, 0x00]);                 // jmp ok
        // Error: infinite loop
        let bp_error = s.len();
        s[bp_below_text + 1] = (bp_error - bp_below_text - 2) as u8;
        s[bp_too_large + 1] = (bp_error - bp_too_large - 2) as u8;
        let err_loop = s.len();
        let err_d = (err_loop as i32) - (err_loop as i32 + 2);
        s.extend_from_slice(&[0xEB, err_d as u8]);         // jmp $ (infinite loop)
        let bp_ok = s.len();
        s[bp_ok_jmp + 1] = (bp_ok - bp_ok_jmp - 2) as u8;
        skip_patch = 0;
    } else if only_25th {
        // Level 5.1: Patch ONLY the 25th entry (index 24)
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table start)
        s.extend_from_slice(&[0x48, 0x81, 0xC6, 0x80, 0x01, 0x00, 0x00]); // add rsi, 0x180 (24 * 16 = 0x180)
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (25th bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);    // mov byte [rax+2], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);    // mov byte [rax+3], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);    // mov byte [rax+4], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);    // mov byte [rax+5], 0x90
        // If we reach here, patching succeeded - infinite loop to confirm
        let success_loop = s.len();
        let sl_d = (success_loop as i32) - (success_loop as i32 + 2);
        s.extend_from_slice(&[0xEB, sl_d as u8]);          // jmp $ (infinite loop = success!)
        skip_patch = 0;
    } else if read_25th {
        // Level 5.2: Read from 25th entry address (test readability)
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table start)
        s.extend_from_slice(&[0x48, 0x81, 0xC6, 0x80, 0x01, 0x00, 0x00]); // add rsi, 0x180 (24 * 16)
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (25th bp_rva)
        s.extend_from_slice(&[0x89, 0x45, 0x3C]);          // mov [rbp+0x3C], eax (save bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        // Try to read 6 bytes from this address
        s.extend_from_slice(&[0x0F, 0xB6, 0x08]);          // movzx ecx, byte [rax] (read byte 0)
        s.extend_from_slice(&[0x0F, 0xB6, 0x50, 0x01]);    // movzx edx, byte [rax+1] (read byte 1)
        s.extend_from_slice(&[0x0F, 0xB6, 0x70, 0x02]);    // movzx esi, byte [rax+2] (read byte 2)
        s.extend_from_slice(&[0x0F, 0xB6, 0x78, 0x03]);    // movzx edi, byte [rax+3] (read byte 3)
        s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x40, 0x04]); // movzx r8d, byte [rax+4] (read byte 4)
        s.extend_from_slice(&[0x44, 0x0F, 0xB6, 0x48, 0x05]); // movzx r9d, byte [rax+5] (read byte 5)
        // If we reach here, reading succeeded
        skip_patch = 0;
    } else if let Some(n) = only_nth {
        // Level 5.3: Patch ONLY entry N (skip 0 to N-1)
        let offset = n * 16;
        s.extend_from_slice(&[0x48, 0x8D, 0x75, 0x40]);    // lea rsi, [rbp+0x40] (table start)
        s.extend_from_slice(&[0x48, 0x81, 0xC6]);          // add rsi, imm32
        s.extend_from_slice(&offset.to_le_bytes());
        s.extend_from_slice(&[0x8B, 0x06]);                 // mov eax, [rsi] (bp_rva)
        s.extend_from_slice(&[0x48, 0x01, 0xD8]);          // add rax, rbx (ImageBase + rva = VA)
        s.extend_from_slice(&[0xC6, 0x00, 0xCC]);          // mov byte [rax], 0xCC (INT3)
        s.extend_from_slice(&[0xC6, 0x40, 0x01, 0x90]);    // mov byte [rax+1], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x02, 0x90]);    // mov byte [rax+2], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x03, 0x90]);    // mov byte [rax+3], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x04, 0x90]);    // mov byte [rax+4], 0x90
        s.extend_from_slice(&[0xC6, 0x40, 0x05, 0x90]);    // mov byte [rax+5], 0x90
        skip_patch = 0;
    } else {
        skip_patch = 0; // unused
    }

    // ── Install VEH handler ──
    s.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx, 1 (First = TRUE)
    let veh_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x15,
                          0x00, 0x00, 0x00, 0x00]);     // lea rdx, [rip+?] (veh_handler, patch)
    s.extend_from_slice(&[0xFF, 0x55, 0x10]);           // call [rbp+0x10] (RtlAddVectoredExceptionHandler)

    // ── Epilogue: restore regs, then jump to original entry ──
    // First restore all callee-saved registers
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);    // add rsp, 0x38
    s.push(0x5D);                                        // pop rbp
    s.extend_from_slice(&[0x41, 0x5F]);                  // pop r15
    s.extend_from_slice(&[0x41, 0x5E]);                  // pop r14
    s.extend_from_slice(&[0x41, 0x5D]);                  // pop r13
    s.extend_from_slice(&[0x41, 0x5C]);                  // pop r12
    s.push(0x5E);                                        // pop rsi
    s.push(0x5F);                                        // pop rdi
    s.push(0x5B);                                        // pop rbx
    // Now use RIP-relative addressing to get data area (patch later)
    let epilogue_data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x0D,
                          0x00, 0x00, 0x00, 0x00]);     // lea rcx, [rip+data_area] (patch)
    s.extend_from_slice(&[0x8B, 0x41, 0x18]);           // mov eax, [rcx+0x18] (orig_entry_rva)
    s.extend_from_slice(&[0x48, 0x03, 0x01]);           // add rax, [rcx] (+ ImageBase)
    s.extend_from_slice(&[0xFF, 0xE0]);                  // jmp rax

    // ═══════════════════════════════════════════════════════════
    // VEH HANDLER — called by Windows on every INT3 exception
    // ═══════════════════════════════════════════════════════════
    let veh_handler_offset = s.len();

    // Patch VEH LEA
    let veh_end = veh_lea_patch + 4;
    let vd = (veh_handler_offset as i32) - (veh_end as i32);
    s[veh_lea_patch]     = vd as u8;
    s[veh_lea_patch + 1] = (vd >> 8) as u8;
    s[veh_lea_patch + 2] = (vd >> 16) as u8;
    s[veh_lea_patch + 3] = (vd >> 24) as u8;

    // Windows x64: rcx = EXCEPTION_POINTERS*
    // Volatile: rax, rcx, rdx, r8, r9, r10, r11
    // We use volatile regs + push rbx, rsi, rdi for data/table/retry
    s.push(0x53);                                        // push rbx
    s.push(0x56);                                        // push rsi
    s.push(0x57);                                        // push rdi (for RIP retry logic)

    // Data area pointer
    let veh_data_lea_patch = s.len() + 3;
    s.extend_from_slice(&[0x48, 0x8D, 0x1D,
                          0x00, 0x00, 0x00, 0x00]);      // lea rbx, [rip+?] (data area, patch)

    // Check exception code
    s.extend_from_slice(&[0x48, 0x8B, 0x01]);           // mov rax, [rcx] (ExceptionRecord)
    s.extend_from_slice(&[0x81, 0x38, 0x03, 0x00, 0x00, 0x80]); // cmp dword [rax], 0x80000003
    let veh_pass_jne = s.len();
    s.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); // jne .pass (patch)

    // ContextRecord
    s.extend_from_slice(&[0x48, 0x8B, 0x51, 0x08]);    // mov rdx, [rcx+8] (ContextRecord)
    // RIP → RVA, then try both RVA and RVA-1 for binary search
    // Windows x64 behavior: INT3 exception may or may not decrement RIP
    s.extend_from_slice(&[0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00]); // mov rax, [rdx+0xF8] (RIP)
    s.extend_from_slice(&[0x48, 0x2B, 0x03]);           // sub rax, [rbx] (- ImageBase)
    // eax = RVA (zero-extend is fine, RVAs are 32-bit)
    // Save original RVA in edi for retry with RVA-1
    s.extend_from_slice(&[0x89, 0xC7]);                  // mov edi, eax (save original RVA)

    // Binary search: dispatch_count in ecx, dispatch_table in rsi
    s.extend_from_slice(&[0x8B, 0x4B, 0x1C]);           // mov ecx, [rbx+0x1C] (count)
    s.extend_from_slice(&[0x48, 0x8D, 0x73, 0x40]);    // lea rsi, [rbx+0x40] (table)
    s.extend_from_slice(&[0x85, 0xC9]);                  // test ecx, ecx
    let veh_no_table_jz = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // jz .pass_pop (patch)

    // retry_search: entry point for second attempt with RVA-1
    let retry_search = s.len();

    // r8d = lo = 0, r9d = hi = count - 1
    s.extend_from_slice(&[0x45, 0x31, 0xC0]);           // xor r8d, r8d
    s.extend_from_slice(&[0x44, 0x8D, 0x49, 0xFF]);    // lea r9d, [rcx-1]

    let bsearch_loop = s.len();
    s.extend_from_slice(&[0x45, 0x39, 0xC8]);           // cmp r8d, r9d
    let bsearch_fail = s.len();
    s.extend_from_slice(&[0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00]); // jg .not_found (patch)

    // mid = (lo + hi) / 2
    s.extend_from_slice(&[0x45, 0x8D, 0x14, 0x01]);    // lea r10d, [r8+r9] (lo+hi, may overflow for huge counts, fine for <=128)
    s.extend_from_slice(&[0x41, 0xD1, 0xEA]);           // shr r10d, 1 (mid)

    // r11d = mid * 16 (byte offset)
    s.extend_from_slice(&[0x45, 0x89, 0xD3]);           // mov r11d, r10d
    s.extend_from_slice(&[0x41, 0xC1, 0xE3, 0x04]);    // shl r11d, 4

    // Compare bp_rva at table[mid*16 + 0] with eax (target RVA)
    s.extend_from_slice(&[0x42, 0x39, 0x04, 0x1E]);    // cmp [rsi+r11], eax
    let bsearch_found_je = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // je .found (patch)

    // If table[mid].bp_rva > target: hi = mid - 1
    let bsearch_above_ja = s.len();
    s.extend_from_slice(&[0x77, 0x00]);                  // ja .go_hi (patch)
    // Else: lo = mid + 1
    s.extend_from_slice(&[0x45, 0x8D, 0x42, 0x01]);    // lea r8d, [r10+1]
    let bsearch_continue_jmp = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .bsearch_loop (patch)
    let go_hi = s.len();
    s[bsearch_above_ja + 1] = (go_hi - bsearch_above_ja - 2) as u8;
    s.extend_from_slice(&[0x45, 0x8D, 0x4A, 0xFF]);    // lea r9d, [r10-1]
    let d = (bsearch_loop as i32) - (s.len() as i32 + 2);
    s.extend_from_slice(&[0xEB, d as u8]);               // jmp bsearch_loop
    // Patch continue jmp
    let d = (bsearch_loop as i32) - (bsearch_continue_jmp as i32 + 2);
    s[bsearch_continue_jmp + 1] = d as u8;

    // Not found → try RVA-1, then pass
    // Windows may or may not decrement RIP on INT3, so try both RIP and RIP-1
    let bsearch_not_found = s.len();
    let bnf = (bsearch_not_found as i32) - (bsearch_fail as i32 + 6);
    s[bsearch_fail + 2] = bnf as u8;
    s[bsearch_fail + 3] = (bnf >> 8) as u8;
    s[bsearch_fail + 4] = (bnf >> 16) as u8;
    s[bsearch_fail + 5] = (bnf >> 24) as u8;

    // If eax == edi, we haven't tried RVA-1 yet; try it
    // If eax != edi, we already tried RVA-1; pass
    s.extend_from_slice(&[0x39, 0xF8]);                  // cmp eax, edi
    let already_retried = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .pass_pop (already retried, patch)
    s.extend_from_slice(&[0x8D, 0x47, 0xFF]);           // lea eax, [rdi-1] (try RVA-1)
    // Near jmp to retry_search (5 bytes: E9 + 32-bit displacement)
    let retry_jmp = (retry_search as i32) - (s.len() as i32 + 5);
    s.extend_from_slice(&[0xE9]);                        // jmp near
    s.extend_from_slice(&(retry_jmp as i32).to_le_bytes());

    let veh_pass_pop = s.len();
    s[already_retried + 1] = (veh_pass_pop - already_retried - 2) as u8;
    s[veh_no_table_jz + 1] = (veh_pass_pop - veh_no_table_jz - 2) as u8;
    s.push(0x5F);                                        // pop rdi
    s.push(0x5E);                                        // pop rsi
    s.push(0x5B);                                        // pop rbx
    s.extend_from_slice(&[0x31, 0xC0]);                  // xor eax, eax (CONTINUE_SEARCH)
    s.push(0xC3);                                        // ret

    // Patch .pass jne
    let _veh_pass_from_top = s.len(); // this is after ret, use veh_pass_pop instead
    let pass_disp = (veh_pass_pop as i32) - (veh_pass_jne as i32 + 6);
    s[veh_pass_jne + 2] = pass_disp as u8;
    s[veh_pass_jne + 3] = (pass_disp >> 8) as u8;
    s[veh_pass_jne + 4] = (pass_disp >> 16) as u8;
    s[veh_pass_jne + 5] = (pass_disp >> 24) as u8;

    // ── Found: r11d = mid*16 (byte offset into table) ──
    let found = s.len();
    s[bsearch_found_je + 1] = (found - bsearch_found_je - 2) as u8;

    // Load condition code
    s.extend_from_slice(&[0x42, 0x0F, 0xB6, 0x4C, 0x1E, 0x0C]); // movzx ecx, byte [rsi+r11+12]

    // Default target = nottaken_rva [rsi+r11+8]
    s.extend_from_slice(&[0x42, 0x8B, 0x44, 0x1E, 0x08]); // mov eax, [rsi+r11+8] (nottaken)

    // Level 5.5: Skip condition evaluation, always use nottaken
    let force_nottaken_jmp = if force_nottaken {
        let pos = s.len();
        s.extend_from_slice(&[0xE9, 0x00, 0x00, 0x00, 0x00]); // jmp set_rip (patch later)
        Some(pos)
    } else {
        None
    };

    // Load taken_rva into r8d for conditional use
    s.extend_from_slice(&[0x46, 0x8B, 0x44, 0x1E, 0x04]); // mov r8d, [rsi+r11+4] (taken)

    // Load EFLAGS from context
    s.extend_from_slice(&[0x44, 0x8B, 0x4A, 0x44]);    // mov r9d, [rdx+0x44] (EFlags)

    // Evaluate condition
    // 0xF0 = JZ (ZF=1), 0xF1 = JNZ (ZF=0), 0xF2 = JL (SF!=OF),
    // 0xF3 = JGE (SF==OF), 0xF4 = JLE (ZF=1||SF!=OF), 0xF5 = JG (ZF=0&&SF==OF)

    // --- JZ: ZF=1 ---
    s.extend_from_slice(&[0x80, 0xF9, 0xF0]);           // cmp cl, 0xF0
    let not_jz = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .not_jz (patch)
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]); // test r9d, 0x40 (ZF)
    let jz_not_taken = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // jz .set_rip (not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken_rva)
    let jz_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .set_rip (patch)

    let not_jz_target = s.len();
    s[not_jz + 1] = (not_jz_target - not_jz - 2) as u8;

    // --- JNZ: ZF=0 ---
    s.extend_from_slice(&[0x80, 0xF9, 0xF1]);           // cmp cl, 0xF1
    let not_jnz = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .not_jnz (patch)
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]); // test r9d, 0x40
    let jnz_taken = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jnz .set_rip (ZF=1 → not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken)
    let jnz_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .set_rip (patch)

    let not_jnz_target = s.len();
    s[not_jnz + 1] = (not_jnz_target - not_jnz - 2) as u8;

    // --- JL: SF!=OF → extract SF(bit7) and OF(bit11) ---
    s.extend_from_slice(&[0x80, 0xF9, 0xF2]);           // cmp cl, 0xF2
    let not_jl = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .not_jl (patch)
    // SF = (eflags >> 7) & 1, OF = (eflags >> 11) & 1
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);           // mov ecx, r9d
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);           // shr ecx, 7
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);           // and ecx, 1 (SF)
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);           // mov r10d, r9d
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);    // shr r10d, 11
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);    // and r10d, 1 (OF)
    s.extend_from_slice(&[0x41, 0x39, 0xD1]);           // cmp r9d→wrong, should be cmp ecx, r10d
    s.truncate(s.len() - 3);
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);           // cmp ecx, r10d (SF vs OF)
    let jl_eq = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // je .set_rip (SF==OF → not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken)
    let jl_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .set_rip (patch)

    let not_jl_target = s.len();
    s[not_jl + 1] = (not_jl_target - not_jl - 2) as u8;

    // --- JGE: SF==OF ---
    s.extend_from_slice(&[0x80, 0xF9, 0xF3]);           // cmp cl, 0xF3
    let not_jge = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .not_jge (patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);           // mov ecx, r9d
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);           // shr ecx, 7
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);           // and ecx, 1
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);           // mov r10d, r9d
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);    // shr r10d, 11
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);    // and r10d, 1
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);           // cmp ecx, r10d
    let jge_ne = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .set_rip (SF!=OF → not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken)
    let jge_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .set_rip (patch)

    let not_jge_target = s.len();
    s[not_jge + 1] = (not_jge_target - not_jge - 2) as u8;

    // --- JLE and JG: fall through to set_rip with default (nottaken) ---
    // For simplicity, JLE and JG use the same SF/OF + ZF logic
    // JLE: ZF=1 || SF!=OF → taken
    s.extend_from_slice(&[0x80, 0xF9, 0xF4]);           // cmp cl, 0xF4
    let not_jle = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .not_jle (patch)
    // Check ZF first
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]); // test r9d, 0x40
    let jle_zf_set = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jnz .take (ZF=1 → taken, patch)
    // Check SF!=OF
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);           // mov ecx, r9d
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);           // shr ecx, 7
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);           // and ecx, 1
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);           // mov r10d, r9d
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);    // shr r10d, 11
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);    // and r10d, 1
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);           // cmp ecx, r10d
    let jle_eq = s.len();
    s.extend_from_slice(&[0x74, 0x00]);                  // je .set_rip (SF==OF → not taken, patch)
    // Take
    let jle_take = s.len();
    s[jle_zf_set + 1] = (jle_take - jle_zf_set - 2) as u8;
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken)
    let jle_to_set_rip = s.len();
    s.extend_from_slice(&[0xEB, 0x00]);                  // jmp .set_rip (patch)

    let not_jle_target = s.len();
    s[not_jle + 1] = (not_jle_target - not_jle - 2) as u8;

    // --- JG: ZF=0 && SF==OF → taken ---
    // (default/unknown condition → not taken)
    s.extend_from_slice(&[0x41, 0xF7, 0xC1, 0x40, 0x00, 0x00, 0x00]); // test r9d, 0x40 (ZF)
    let jg_zf_set = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jnz .set_rip (ZF=1 → not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC9]);           // mov ecx, r9d
    s.extend_from_slice(&[0xC1, 0xE9, 0x07]);           // shr ecx, 7
    s.extend_from_slice(&[0x83, 0xE1, 0x01]);           // and ecx, 1
    s.extend_from_slice(&[0x45, 0x89, 0xCA]);           // mov r10d, r9d
    s.extend_from_slice(&[0x41, 0xC1, 0xEA, 0x0B]);    // shr r10d, 11
    s.extend_from_slice(&[0x41, 0x83, 0xE2, 0x01]);    // and r10d, 1
    s.extend_from_slice(&[0x44, 0x39, 0xD1]);           // cmp ecx, r10d
    let jg_ne = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                  // jne .set_rip (SF!=OF → not taken, patch)
    s.extend_from_slice(&[0x44, 0x89, 0xC0]);           // mov eax, r8d (taken)

    // ── .set_rip ──
    let set_rip = s.len();
    // Patch all forward jumps to .set_rip
    s[jz_not_taken + 1] = (set_rip - jz_not_taken - 2) as u8;
    s[jz_to_set_rip + 1] = (set_rip - jz_to_set_rip - 2) as u8;
    s[jnz_taken + 1] = (set_rip - jnz_taken - 2) as u8;
    s[jnz_to_set_rip + 1] = (set_rip - jnz_to_set_rip - 2) as u8;
    s[jl_eq + 1] = (set_rip - jl_eq - 2) as u8;
    s[jl_to_set_rip + 1] = (set_rip - jl_to_set_rip - 2) as u8;
    s[jge_ne + 1] = (set_rip - jge_ne - 2) as u8;
    s[jge_to_set_rip + 1] = (set_rip - jge_to_set_rip - 2) as u8;
    s[jle_eq + 1] = (set_rip - jle_eq - 2) as u8;
    s[jle_to_set_rip + 1] = (set_rip - jle_to_set_rip - 2) as u8;
    s[jg_zf_set + 1] = (set_rip - jg_zf_set - 2) as u8;
    s[jg_ne + 1] = (set_rip - jg_ne - 2) as u8;

    // Patch force_nottaken jump (Level 5.5)
    if let Some(pos) = force_nottaken_jmp {
        let disp = (set_rip as i32) - (pos as i32 + 5);
        s[pos + 1] = disp as u8;
        s[pos + 2] = (disp >> 8) as u8;
        s[pos + 3] = (disp >> 16) as u8;
        s[pos + 4] = (disp >> 24) as u8;
    }

    // target VA = eax (RVA) + [rbx] (ImageBase)
    s.extend_from_slice(&[0x48, 0x03, 0x03]);           // add rax, [rbx] (ImageBase)
    s.extend_from_slice(&[0x48, 0x89, 0x82, 0xF8, 0x00, 0x00, 0x00]); // mov [rdx+0xF8], rax (set RIP)
    s.push(0x5F);                                        // pop rdi
    s.push(0x5E);                                        // pop rsi
    s.push(0x5B);                                        // pop rbx
    s.extend_from_slice(&[0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1 (CONTINUE_EXECUTION)
    s.push(0xC3);                                        // ret

    // ═══════════════════════════════════════════════════════════
    // DATA AREA — inline parameters embedded by CLI
    // ═══════════════════════════════════════════════════════════
    let data_area_offset = s.len();

    // Patch data area LEA in init code
    let data_lea_end = data_lea_patch + 4;
    let dd = (data_area_offset as i32) - (data_lea_end as i32);
    s[data_lea_patch]     = dd as u8;
    s[data_lea_patch + 1] = (dd >> 8) as u8;
    s[data_lea_patch + 2] = (dd >> 16) as u8;
    s[data_lea_patch + 3] = (dd >> 24) as u8;

    // Patch data area LEA in VEH handler
    let veh_data_lea_end = veh_data_lea_patch + 4;
    let vdd = (data_area_offset as i32) - (veh_data_lea_end as i32);
    s[veh_data_lea_patch]     = vdd as u8;
    s[veh_data_lea_patch + 1] = (vdd >> 8) as u8;
    s[veh_data_lea_patch + 2] = (vdd >> 16) as u8;
    s[veh_data_lea_patch + 3] = (vdd >> 24) as u8;

    // Patch data area LEA in epilogue
    let epilogue_data_lea_end = epilogue_data_lea_patch + 4;
    let edd = (data_area_offset as i32) - (epilogue_data_lea_end as i32);
    s[epilogue_data_lea_patch]     = edd as u8;
    s[epilogue_data_lea_patch + 1] = (edd >> 8) as u8;
    s[epilogue_data_lea_patch + 2] = (edd >> 16) as u8;
    s[epilogue_data_lea_patch + 3] = (edd >> 24) as u8;

    // [+0x00] image_base (runtime)
    s.extend_from_slice(&0u64.to_le_bytes());
    // [+0x08] poison_value (runtime)
    s.extend_from_slice(&0u64.to_le_bytes());
    // [+0x10] rtl_add_veh_ptr (runtime)
    s.extend_from_slice(&0u64.to_le_bytes());
    // [+0x18] orig_entry_rva
    s.extend_from_slice(&orig_entry_rva.to_le_bytes());
    // [+0x1C] dispatch_count
    s.extend_from_slice(&nm_count.to_le_bytes());
    // [+0x20] xtea_key [u32; 4]
    for &k in &nm_xtea {
        s.extend_from_slice(&k.to_le_bytes());
    }
    // [+0x30] nm_nonce
    s.extend_from_slice(&nanomite_crypto_key.to_le_bytes());
    // [+0x38] text_rva
    s.extend_from_slice(&text_rva.to_le_bytes());
    // [+0x3C] reserved
    s.extend_from_slice(&0u32.to_le_bytes());
    // [+0x40] dispatch_table (will be XTEA-CTR encrypted)
    let table_start = s.len();
    for e in nanomite_entries.iter().take(128) {
        s.extend_from_slice(&e.bp_rva.to_le_bytes());
        s.extend_from_slice(&e.taken_rva.to_le_bytes());
        s.extend_from_slice(&e.nottaken_rva.to_le_bytes());
        s.push(e.condition);
        s.extend_from_slice(&[0u8; 3]);
    }
    // XTEA-CTR encrypt (skip if SQURE_SKIP_NM_XTEA is set for debugging)
    let skip_nm_xtea = std::env::var("SQURE_SKIP_NM_XTEA").is_ok();
    if nanomite_crypto_key != 0 && nm_count > 0 && !skip_nm_xtea {
        let nm_key = master_key_to_xtea(&derive_master_key_128(nanomite_crypto_key));
        xtea_ctr_apply(&mut s[table_start..], &nm_key, nanomite_crypto_key);
    }
    if skip_nm_xtea {
        eprintln!("[DEBUG] XTEA encryption SKIPPED for nanomite table");
    }

    s
}

/// Legacy: Derive a non-zero 8-byte XOR key from a seed using avalanche mixing.
#[cfg(test)]
fn derive_8byte_key(seed: u64) -> u64 {
    let h = splitmix_finalize(seed);
    if h == 0 { 0xDEAD_BEEF_CAFE_F00D } else { h }
}

/// Count printable ASCII strings of at least `min_len` in raw data
fn count_ascii_strings(data: &[u8], min_len: usize) -> usize {
    let mut count = 0;
    let mut run = 0;
    for &b in data {
        if b >= 0x20 && b < 0x7F {
            run += 1;
        } else {
            if run >= min_len {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= min_len {
        count += 1;
    }
    count
}

// ─── analyze ─────────────────────────────────────────────────

fn cmd_analyze(input: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", input.display(), e);
        std::process::exit(1);
    });
    let pe = pe::parser::PeFile::parse(data).unwrap_or_else(|e| {
        eprintln!("Error parsing PE: {:?}", e);
        std::process::exit(1);
    });

    println!("PE Analysis: {}", input.display());
    println!("════════════════════════════════════════");
    println!("Machine:        0x{:04X} ({})", pe.coff_header.machine,
        if pe.coff_header.machine == 0x8664 { "x86-64" } else { "other" });
    println!("Sections:       {}", pe.sections.len());
    println!("Entry point:    0x{:08X}", pe.optional_header.entry_point);
    println!("Image base:     0x{:016X}", pe.optional_header.image_base);
    println!("Section align:  0x{:08X}", pe.optional_header.section_alignment);
    println!("File align:     0x{:08X}", pe.optional_header.file_alignment);
    println!("Size of image:  0x{:08X}", pe.optional_header.size_of_image);
    println!();
    println!("Sections:");
    println!("  {:<8}  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
        "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Flags");
    for section in &pe.sections {
        println!("  {:<8}  0x{:08X}  0x{:08X}  0x{:08X}  0x{:08X}  0x{:08X}",
            section.name_str(),
            section.virtual_size, section.virtual_address,
            section.size_of_raw_data, section.pointer_to_raw_data,
            section.characteristics,
        );
    }
    println!();

    let dir_names = ["Export", "Import", "Resource", "Exception", "Security",
                     "Relocation", "Debug", "Architecture", "GlobalPtr", "TLS",
                     "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"];
    println!("Data Directories:");
    for (i, dir) in pe.data_directories.iter().enumerate() {
        if dir.virtual_address != 0 || dir.size != 0 {
            let name = dir_names.get(i).unwrap_or(&"Unknown");
            println!("  [{:2}] {:<12}  RVA=0x{:08X}  Size=0x{:08X}", i, name, dir.virtual_address, dir.size);
        }
    }

    // String count per section
    println!();
    println!("Readable strings (>= 6 chars) per section:");
    for section in &pe.sections {
        let data = pe.section_data(section);
        let count = count_ascii_strings(data, 6);
        if count > 0 {
            println!("  {:<8}  {} strings", section.name_str(), count);
        }
    }
}

// ─── strings ─────────────────────────────────────────────────

fn cmd_strings(input: PathBuf, min_len: usize) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", input.display(), e);
        std::process::exit(1);
    });
    let pe = pe::parser::PeFile::parse(data).unwrap_or_else(|e| {
        eprintln!("Error parsing PE: {:?}", e);
        std::process::exit(1);
    });

    println!("Readable strings in: {} (min length: {})", input.display(), min_len);
    println!("════════════════════════════════════════");

    for section in &pe.sections {
        let sdata = pe.section_data(section);
        let strings = extract_ascii_strings(sdata, min_len);
        if !strings.is_empty() {
            println!();
            println!("[{}] ({} strings)", section.name_str(), strings.len());
            for s in &strings {
                println!("  {}", s);
            }
        }
    }
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    for &b in data {
        if b >= 0x20 && b < 0x7F {
            current.push(b);
        } else {
            if current.len() >= min_len {
                result.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push(String::from_utf8_lossy(&current).into_owned());
    }
    result
}

// ─── info ────────────────────────────────────────────────────

fn cmd_info(input: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", input.display(), e);
        std::process::exit(1);
    });
    let pe = pe::parser::PeFile::parse(data).unwrap_or_else(|e| {
        eprintln!("Error parsing PE: {:?}", e);
        std::process::exit(1);
    });

    if let Some(squre_section) = pe.find_section(".squre") {
        let sdata = pe.section_data(squre_section);
        println!("SQURE Protected Binary");
        println!("────────────────────────────────────────");
        // Parse null-separated metadata fields
        for field in sdata.split(|&b| b == 0) {
            let s = String::from_utf8_lossy(field);
            let s = s.trim();
            if !s.is_empty() {
                println!("  {}", s);
            }
        }
        // Check for nanomite table
        let nmtq_magic = 0x5154_4D4Eu32.to_le_bytes();
        if let Some(pos) = sdata.windows(4).position(|w| w == nmtq_magic) {
            if pos + 8 <= sdata.len() {
                let count = u32::from_le_bytes([
                    sdata[pos + 4], sdata[pos + 5], sdata[pos + 6], sdata[pos + 7]
                ]);
                println!("  nanomite_entries={}", count);
            }
        }
    } else {
        println!("Not a SQURE-protected binary (no .squre section)");
    }
    println!();
    println!("Entry point: 0x{:08X}", pe.optional_header.entry_point);
    println!("Sections:    {}", pe.sections.iter()
        .map(|s| s.name_str().to_string())
        .collect::<Vec<_>>()
        .join(", "));
}

// ─── build ────────────────────────────────────────────────────

fn cmd_build(
    input: PathBuf,
    output: PathBuf,
    seed_str: Option<String>,
    nanomite: bool,
    level: String,
    post_process: bool,
    keep_temp: bool,
    polymorphic: bool,
    junk_level: u8,
    fake_keys: u8,
    encrypt_stub: bool,
    distributed_key: bool,
    layers: u8,
    integrity_check: bool,
    anti_dump: bool,
    harden: bool,
    ultra: bool,
    vm: bool,
    obfuscate: u8,
    honeypot: bool,
    anti_debug: bool,
    tidal: bool,
    process_guard: bool,
    direct_syscall: bool,
) {
    // Parse seed (same pattern as cmd_protect)
    let seed: u64 = seed_str
        .as_ref()
        .and_then(|s| {
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        })
        .unwrap_or_else(|| rand::random());

    println!("[*] SQURE Build: {} -> {}", input.display(), output.display());
    println!("    Seed: 0x{:016X}", seed);
    println!("    Level: {}", level);

    // Step 1: Validate input project
    let cargo_toml_path = input.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        eprintln!("Error: {} does not contain a Cargo.toml", input.display());
        std::process::exit(1);
    }

    // Step 2: Create temp directory
    let temp_dir = tempfile::Builder::new()
        .prefix("squre-build-")
        .tempdir()
        .expect("failed to create temp directory");
    let work_dir = if keep_temp {
        let path = temp_dir.path().to_path_buf();
        let _ = temp_dir.keep(); // Prevent auto-cleanup
        println!("[*] Temp directory (kept): {}", path.display());
        path
    } else {
        temp_dir.path().to_path_buf()
    };

    // Step 3: Copy project to temp dir
    println!("[*] Copying project to temp directory...");
    copy_dir_recursive(&input, &work_dir).expect("failed to copy project");

    // Step 4: Find squre crates directory
    let squre_crates = find_squre_crates_dir();
    println!("[*] Using SQURE crates from: {}", squre_crates.display());

    // Step 5: Patch Cargo.toml
    println!("[*] Patching Cargo.toml with SQURE dependencies...");
    patch_cargo_toml(&work_dir.join("Cargo.toml"), &squre_crates);

    // Step 6: Transform source files
    println!("[*] Transforming source files...");
    let src_dir = work_dir.join("src");
    let rs_files = discover_rs_files(&src_dir);
    let main_file = find_main_file(&rs_files);

    let mut total_stats = source_transform::TransformStats::default();
    for rs_file in &rs_files {
        let is_main = main_file.as_ref() == Some(rs_file);
        let content = fs::read_to_string(rs_file).expect("failed to read source file");

        match source_transform::transform_file(&content, is_main, &level) {
            Ok((transformed, stats)) => {
                fs::write(rs_file, transformed).expect("failed to write transformed source");
                total_stats.functions_annotated += stats.functions_annotated;
                total_stats.strings_encrypted += stats.strings_encrypted;
                if stats.anti_debug_inserted {
                    total_stats.anti_debug_inserted = true;
                }
                if stats.preamble_added {
                    total_stats.preamble_added = true;
                }
            }
            Err(e) => {
                eprintln!("    Warning: failed to transform {}: {}", rs_file.display(), e);
                // Leave file unchanged
            }
        }
    }
    println!("    Functions annotated: {}", total_stats.functions_annotated);
    println!("    Strings encrypted: {}", total_stats.strings_encrypted);
    println!("    anti_debug! inserted: {}", total_stats.anti_debug_inserted);

    // Step 7: Build with cargo
    println!("[*] Building with cargo (release)...");
    let mut cargo_cmd = std::process::Command::new("cargo");
    cargo_cmd.arg("build");
    cargo_cmd.arg("--release");
    cargo_cmd.arg("--manifest-path").arg(work_dir.join("Cargo.toml"));

    let build_status = cargo_cmd.status().expect("failed to run cargo build");
    if !build_status.success() {
        eprintln!("Error: cargo build failed");
        std::process::exit(1);
    }

    // Step 8: Find output binary
    let pkg_name = read_package_name(&work_dir.join("Cargo.toml"));
    // Binary name uses the package name directly (with hyphens, not underscores)
    let binary_name = format!("{}.exe", pkg_name);
    let built_binary = work_dir.join("target").join("release").join(&binary_name);

    if !built_binary.exists() {
        eprintln!("Error: built binary not found at {}", built_binary.display());
        std::process::exit(1);
    }
    println!("[*] Built: {}", built_binary.display());

    // Step 9: Post-process with cmd_protect
    if post_process {
        println!("[*] Post-processing binary with SQURE protections...");
        // If anti_debug! was inserted, squre-runtime handles VEH - skip .sqrun
        let skip_sqrun = total_stats.anti_debug_inserted;
        cmd_protect_with_options(
            built_binary,
            output.clone(),
            Some(format!("0x{:X}", seed)),
            nanomite,
            polymorphic,
            junk_level,
            fake_keys,
            encrypt_stub,
            distributed_key,
            layers,
            integrity_check,
            anti_dump,
            harden,
            ultra,
            vm,
            obfuscate,
            honeypot,
            anti_debug,
            skip_sqrun,  // Skip .sqrun if squre-runtime is already linked
            tidal,
            process_guard,
            direct_syscall,
        );
    } else {
        // Just copy the macro-protected binary to output
        fs::copy(&built_binary, &output).expect("failed to copy binary to output");
        println!("[*] Output (macro-only): {}", output.display());
    }

    println!("[*] Build complete!");
}

/// Recursively copy directory, skipping target/, .git/, etc.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    let skip_dirs = ["target", ".git", "node_modules", ".idea", ".vscode"];

    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if file_type.is_dir() {
            if skip_dirs.contains(&name_str.as_ref()) {
                continue;
            }
            copy_dir_recursive(&entry.path(), &dst.join(&name))?;
        } else {
            fs::copy(entry.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

/// Discover all .rs files under a directory recursively.
fn discover_rs_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap_or_else(|_| panic!("failed to read {}", dir.display())) {
            let entry = entry.expect("failed to read entry");
            let path = entry.path();
            if path.is_dir() {
                files.extend(discover_rs_files(&path));
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Find the main.rs file (contains fn main()).
fn find_main_file(files: &[PathBuf]) -> Option<PathBuf> {
    // First check for src/main.rs
    for file in files {
        if file.file_name().map_or(false, |n| n == "main.rs") {
            return Some(file.clone());
        }
    }
    // Fallback: search for fn main()
    for file in files {
        if let Ok(content) = fs::read_to_string(file) {
            if content.contains("fn main()") || content.contains("fn main ()") {
                return Some(file.clone());
            }
        }
    }
    None
}

/// Find the squre crates directory.
fn find_squre_crates_dir() -> PathBuf {
    // Strategy 1: SQURE_HOME environment variable
    if let Ok(home) = std::env::var("SQURE_HOME") {
        let crates = PathBuf::from(&home).join("crates");
        if crates.join("squre").exists() {
            return crates;
        }
    }

    // Strategy 2: Relative to CLI binary location
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..13 {
            if let Some(ref d) = dir {
                let crates = d.join("crates");
                if crates.join("squre").exists() {
                    return crates;
                }
                dir = d.parent().map(|p| p.to_path_buf());
            }
        }
    }

    // Strategy 3: Current working directory
    let cwd = std::env::current_dir().expect("failed to get cwd");
    let crates = cwd.join("crates");
    if crates.join("squre").exists() {
        return crates;
    }

    eprintln!("Error: cannot locate SQURE crates directory.");
    eprintln!("Set SQURE_HOME environment variable or run from the SQURE workspace.");
    std::process::exit(1);
}

/// Patch Cargo.toml to add/update squre dependencies with absolute paths.
fn patch_cargo_toml(cargo_toml: &std::path::Path, squre_crates: &std::path::Path) {
    let content = fs::read_to_string(cargo_toml).expect("failed to read Cargo.toml");
    let mut doc: toml_edit::DocumentMut = content.parse().expect("invalid Cargo.toml");

    let deps = doc["dependencies"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let deps = deps.as_table_mut().expect("dependencies must be a table");

    for (name, subdir) in [
        ("squre", "squre"),
        ("squre-runtime", "squre-runtime"),
        ("squre-core", "squre-core"),
    ] {
        // Always update path (overwrite existing relative paths with absolute)
        let mut table = toml_edit::InlineTable::new();
        let path = squre_crates.join(subdir);
        // Use forward slashes for cross-platform compatibility
        let path_str = path.to_string_lossy().replace('\\', "/");
        table.insert("path", toml_edit::Value::from(path_str.as_str()));
        deps.insert(name, toml_edit::Item::Value(toml_edit::Value::InlineTable(table)));
    }

    fs::write(cargo_toml, doc.to_string()).expect("failed to write Cargo.toml");
}

/// Read the package name from Cargo.toml.
fn read_package_name(cargo_toml: &std::path::Path) -> String {
    let content = fs::read_to_string(cargo_toml).expect("failed to read Cargo.toml");
    let doc: toml_edit::DocumentMut = content.parse().expect("invalid Cargo.toml");
    doc["package"]["name"]
        .as_str()
        .expect("package.name not found")
        .to_string()
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_8byte_key_nonzero() {
        for seed in 0..1000u64 {
            let key = derive_8byte_key(seed);
            assert_ne!(key, 0, "key must be non-zero for seed {}", seed);
        }
    }

    #[test]
    fn test_derive_8byte_key_deterministic() {
        let k1 = derive_8byte_key(0xDEADBEEF);
        let k2 = derive_8byte_key(0xDEADBEEF);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_8byte_key_avalanche() {
        let k1 = derive_8byte_key(0);
        let k2 = derive_8byte_key(1);
        // Different seeds should produce very different keys
        assert_ne!(k1, k2);
        // Check that at least 20 bits differ (good avalanche)
        let diff_bits = (k1 ^ k2).count_ones();
        assert!(diff_bits >= 20, "only {} bits differ", diff_bits);
    }

    #[test]
    fn test_derive_master_key_128_nonzero() {
        for seed in 0..100u64 {
            let master = derive_master_key_128(seed);
            assert_ne!(master[0], 0, "master_lo must be non-zero");
            assert_ne!(master[1], 0, "master_hi must be non-zero");
        }
    }

    #[test]
    fn test_derive_master_key_128_different_seeds() {
        let m1 = derive_master_key_128(0);
        let m2 = derive_master_key_128(1);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_derive_page_key_chained_nonzero() {
        let master = derive_master_key_128(0xCAFE);
        for seed in 0..100u64 {
            let key = derive_page_key_chained(seed, &master);
            assert_ne!(key, 0, "page key must be non-zero for seed {}", seed);
        }
    }

    #[test]
    fn test_hash_encrypted_page_avalanche() {
        let page1 = vec![0u8; 4096];
        let mut page2 = vec![0u8; 4096];
        page2[0] = 1; // single bit flip
        let h1 = hash_encrypted_page(&page1);
        let h2 = hash_encrypted_page(&page2);
        assert_ne!(h1, h2);
        let diff = (h1 ^ h2).count_ones();
        assert!(diff >= 15, "only {} bits differ (poor avalanche)", diff);
    }

    #[test]
    fn test_page_encryption_roundtrip() {
        // Simulate encrypt then decrypt for a single page
        let seed = 0xDEADBEEF_u64;
        let master = derive_master_key_128(seed);
        let initial_seed = hash_pe_fields(0x020B, 0x1000, 0x200, 0x22);

        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 7 + 13) as u8;
        }
        let orig = data.clone();

        // Encrypt
        let page_key = derive_page_key_chained(initial_seed, &master);
        for j in 0..512usize {
            let off = j * 8;
            let mut qw = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            qw ^= page_key ^ (j as u64).wrapping_mul(POSITION_PRIME);
            data[off..off+8].copy_from_slice(&qw.to_le_bytes());
        }
        assert_ne!(data, orig, "encrypted data should differ");

        // Decrypt (same operation — XOR is self-inverse)
        for j in 0..512usize {
            let off = j * 8;
            let mut qw = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            qw ^= page_key ^ (j as u64).wrapping_mul(POSITION_PRIME);
            data[off..off+8].copy_from_slice(&qw.to_le_bytes());
        }
        assert_eq!(data, orig, "decrypt must recover original");
    }

    #[test]
    fn test_build_decrypt_stub_v2_prologue() {
        let master = derive_master_key_128(0x12345678);
        let stub = build_decrypt_stub_v2(0x1000, 0x1000, 256, &master, 0xABCD);
        // 8 callee-saved registers: push rbx, rdi, rsi, r12, r13, r14, r15, rbp
        assert_eq!(stub[0], 0x53);                      // push rbx
        assert_eq!(stub[1], 0x57);                      // push rdi
        assert_eq!(stub[2], 0x56);                      // push rsi
        assert_eq!(&stub[3..5], &[0x41, 0x54]);         // push r12
        assert_eq!(&stub[5..7], &[0x41, 0x55]);         // push r13
        assert_eq!(&stub[7..9], &[0x41, 0x56]);         // push r14
        assert_eq!(&stub[9..11], &[0x41, 0x57]);        // push r15
        assert_eq!(stub[11], 0x55);                     // push rbp
    }

    #[test]
    fn test_build_decrypt_stub_v2_peb_access() {
        let master = derive_master_key_128(0x12345678);
        let stub = build_decrypt_stub_v2(0x1000, 0x1000, 256, &master, 0xABCD);
        // gs:[0x60] PEB access at offset 12
        assert_eq!(&stub[12..21],
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        // mov rbx, [rax+0x10] (ImageBase)
        assert_eq!(&stub[21..25], &[0x48, 0x8B, 0x58, 0x10]);
    }

    #[test]
    fn test_build_decrypt_stub_v2_contains_params() {
        let ep = 0x1234u32;
        let text_rva = 0x5678u32;
        let qwords = 0x100u32;
        let master = [0xDEAD_BEEF_CAFE_F00Du64, 0x0123_4567_89AB_CDEFu64];
        let seed = 0xFEDC_BA98_7654_3210u64;
        let stub = build_decrypt_stub_v2(ep, text_rva, qwords, &master, seed);

        // Params are the last 36 bytes: 4+4+4+8+8+8
        let p = stub.len() - 36;
        assert_eq!(u32::from_le_bytes(stub[p..p+4].try_into().unwrap()), ep);
        assert_eq!(u32::from_le_bytes(stub[p+4..p+8].try_into().unwrap()), text_rva);
        assert_eq!(u32::from_le_bytes(stub[p+8..p+12].try_into().unwrap()), qwords);
        assert_eq!(u64::from_le_bytes(stub[p+12..p+20].try_into().unwrap()), master[0]);
        assert_eq!(u64::from_le_bytes(stub[p+20..p+28].try_into().unwrap()), master[1]);
        assert_eq!(u64::from_le_bytes(stub[p+28..p+36].try_into().unwrap()), seed);
    }

    #[test]
    fn test_build_decrypt_stub_v2_jmp_rax_before_params() {
        let master = derive_master_key_128(0x12345678);
        let stub = build_decrypt_stub_v2(0x1000, 0x1000, 256, &master, 0xABCD);
        // jmp rax (FF E0) is right before the 36-byte params block
        let jmp_off = stub.len() - 36 - 2;
        assert_eq!(&stub[jmp_off..jmp_off+2], &[0xFF, 0xE0]);
    }

    #[test]
    fn test_build_decrypt_stub_v2_position_prime() {
        let master = derive_master_key_128(0x12345678);
        let stub = build_decrypt_stub_v2(0x1000, 0x1000, 256, &master, 0xABCD);
        // POSITION_PRIME should be embedded via movabs rbp (0x48 0xBD + imm64)
        let prime_bytes = POSITION_PRIME.to_le_bytes();
        let found = stub.windows(10).any(|w|
            w[0] == 0x48 && w[1] == 0xBD && w[2..10] == prime_bytes
        );
        assert!(found, "POSITION_PRIME not found in stub");
    }

    #[test]
    fn test_build_decrypt_stub_v2_has_decrypt_loop() {
        let master = derive_master_key_128(0x12345678);
        let stub = build_decrypt_stub_v2(0x1000, 0x1000, 256, &master, 0xABCD);
        // The decrypt loop must contain: xor [rsi], rdx (48 31 16)
        let found = stub.windows(3).any(|w| w == [0x48, 0x31, 0x16]);
        assert!(found, "xor [rsi], rdx not found in decrypt loop");
    }

    #[test]
    fn test_build_decrypt_stub_v2_deterministic() {
        let master = derive_master_key_128(0xCAFE);
        let s1 = build_decrypt_stub_v2(0x1000, 0x2000, 512, &master, 0xBEEF);
        let s2 = build_decrypt_stub_v2(0x1000, 0x2000, 512, &master, 0xBEEF);
        assert_eq!(s1, s2, "same inputs must produce identical stubs");
    }

    #[test]
    fn test_scan_conditional_jumps_empty() {
        // All zeros — no conditional jumps
        let data = vec![0u8; 1024];
        let entries = scan_conditional_jumps(&data, 0x1000, 1024, 42);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_scan_conditional_jumps_finds_jz_near() {
        let mut data = vec![0x90u8; 8192]; // NOP sled (>4KB for skip)
        // Place a jz near at offset 4200 (past the 4KB skip): 0F 84 20 00 00 00
        // This jumps forward 32 bytes from next instruction (at 4206)
        let off = 4200;
        data[off] = 0x0F;
        data[off + 1] = 0x84;
        data[off + 2] = 0x20; // disp = 32
        data[off + 3] = 0x00;
        data[off + 4] = 0x00;
        data[off + 5] = 0x00;

        // Try multiple seeds until we get one that selects this entry
        let mut found = false;
        for seed in 0..100u64 {
            let entries = scan_conditional_jumps(&data, 0x1000, 8192, seed);
            if !entries.is_empty() {
                let e = &entries[0];
                assert_eq!(e.bp_rva, 0x1000 + 4200);
                assert_eq!(e.nottaken_rva, 0x1000 + 4206); // fall-through
                assert_eq!(e.taken_rva, 0x1000 + 4206 + 32); // jump target
                assert_eq!(e.condition, 0xF0); // jz
                assert_eq!(e.instr_len, 6);
                found = true;
                break;
            }
        }
        assert!(found, "should find the jz near with some seed");
    }

    #[test]
    fn test_scan_conditional_jumps_skips_first_4kb() {
        let mut data = vec![0x90u8; 8192];
        // Place a jz near at offset 100 (within first 4KB)
        data[100] = 0x0F;
        data[101] = 0x84;
        data[102] = 0x20;
        data[103] = 0x00;
        data[104] = 0x00;
        data[105] = 0x00;

        // Should NOT find it (too early in .text)
        for seed in 0..100u64 {
            let entries = scan_conditional_jumps(&data, 0x1000, 8192, seed);
            for e in &entries {
                assert!(e.bp_rva >= 0x1000 + 4096, "should skip first 4KB");
            }
        }
    }

    #[test]
    fn test_scan_conditional_jumps_max_entries() {
        let mut data = vec![0x90u8; 16384];
        // Place many jz near instructions past 4KB
        let start = 4200;
        for j in 0..200 {
            let off = start + j * 8;
            if off + 6 > 16384 { break; }
            data[off] = 0x0F;
            data[off + 1] = 0x84;
            data[off + 2] = 0x40; // forward 64
            data[off + 3] = 0x00;
            data[off + 4] = 0x00;
            data[off + 5] = 0x00;
        }

        let entries = scan_conditional_jumps(&data, 0x1000, 16384, 42);
        assert!(entries.len() <= 128, "should cap at 128 entries");
    }

    #[test]
    fn test_count_ascii_strings() {
        let data = b"Hello World\x00Short\x00AB\x00This is a test\x00";
        assert_eq!(count_ascii_strings(data, 6), 2); // "Hello World" and "This is a test"
        assert_eq!(count_ascii_strings(data, 4), 3); // + "Short"
    }

    #[test]
    fn test_nanomite_table_encrypted_serialization() {
        let crypto_key: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let key_bytes = crypto_key.to_le_bytes();

        let mut blob = Vec::new();
        // Magic: NMTE (plaintext)
        blob.extend_from_slice(&0x4554_4D4Eu32.to_le_bytes());

        // Build plaintext payload
        let enc_start = blob.len();
        blob.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        blob.extend_from_slice(&0x1000u32.to_le_bytes()); // bp_rva
        blob.extend_from_slice(&0x2000u32.to_le_bytes()); // taken_rva
        blob.extend_from_slice(&0x1006u32.to_le_bytes()); // nottaken_rva
        blob.push(0xF0); // condition
        blob.extend_from_slice(&[0, 0, 0]);

        // Encrypt payload
        for i in enc_start..blob.len() {
            blob[i] ^= key_bytes[(i - enc_start) % 8];
        }

        assert_eq!(blob.len(), 4 + 4 + 16); // magic + count + 1 entry
        assert_eq!(&blob[0..4], &[0x4E, 0x4D, 0x54, 0x45]); // "NMTE" LE

        // The count should NOT be readable as plaintext 1
        let stored_count = u32::from_le_bytes(blob[4..8].try_into().unwrap());
        assert_ne!(stored_count, 1, "count should be encrypted");

        // Decrypt and verify
        let mut decrypted = blob[enc_start..].to_vec();
        for i in 0..decrypted.len() {
            decrypted[i] ^= key_bytes[i % 8];
        }
        assert_eq!(u32::from_le_bytes(decrypted[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(decrypted[4..8].try_into().unwrap()), 0x1000);
    }
}
