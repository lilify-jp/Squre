//! SQURE Phase 3: Full Protection Demo
//!
//! Demonstrates all obfuscation layers working together:
//! - MBA (linear + GF(2^64))
//! - String encryption
//! - VM execution with EDF
//! - White-Box key schedule
//! - Cascade integrity chain
//! - Nanomite table dispatch
//! - Process guard structures
//! - Direct syscall resolution

use squre::prelude::*;
use squre_core::mba::galois;
use squre_core::crypto::white_box::{WhiteBoxTables, WhiteBoxKeySchedule};
use squre_core::integrity::cascade;
use squre_runtime::nanomite::{NanomiteTable, NanomiteEntry};
use squre_runtime::process_guard;
use squre_runtime::syscall;
use std::collections::HashMap;

fn main() {
    println!("=== SQURE Phase 3: Full Protection Demo ===\n");

    test_gf_mba();
    test_cascade_integrity();
    test_whitebox_multiround();
    test_vm_with_gf_const();
    test_nanomite_table();
    test_process_guard_crypto();
    test_syscall_hashing();
    test_combined_pipeline();

    println!("\n=== All SQURE Phase 3 tests passed! ===");
}

/// Test GF(2^64) MBA addition obfuscation
fn test_gf_mba() {
    print!("[GF MBA]       ");

    let expr = galois::generate_gf_mba_add(42, 6);

    let a: u64 = 0xDEADBEEF_CAFEBABE;
    let b: u64 = 0x12345678_9ABCDEF0;
    let result = galois::eval_gf_mba_add(&expr, a, b);
    let expected = a.wrapping_add(b);
    assert_eq!(result, expected, "GF MBA add failed");

    // Test with many pseudo-random values
    let mut all_correct = true;
    for i in 0..1000u64 {
        let x = i.wrapping_mul(0x9E3779B97F4A7C15);
        let y = i.wrapping_mul(0x6C62272E07BB0142);
        if galois::eval_gf_mba_add(&expr, x, y) != x.wrapping_add(y) {
            all_correct = false;
            break;
        }
    }
    assert!(all_correct, "GF MBA add failed for some values");

    // Test GF constant encoding
    let target = 0xCAFEBABE_DEADBEEF_u64;
    let pairs = galois::generate_gf_const(target, 123, 5);
    let reconstructed = galois::eval_gf_const(&pairs);
    assert_eq!(reconstructed, target, "GF const reconstruction failed");

    println!("GF(2^64) MBA addition + constant encoding OK");
}

/// Test cascade integrity chain
fn test_cascade_integrity() {
    print!("[Cascade]      ");

    let data = b"This is protected code section data for cascade integrity verification";
    let chain = cascade::build_chain(data, 8, 42);

    // Verify decryption succeeds
    let decrypted = cascade::verify_and_decrypt(&chain).expect("Cascade decryption failed");
    assert_eq!(&decrypted, data, "Cascade roundtrip failed");

    // Verify tamper detection: modify a chunk's ciphertext
    let mut tampered = chain.clone();
    if !tampered.chunks.is_empty() {
        tampered.chunks[0][0] ^= 0xFF;
    }
    assert!(cascade::verify_and_decrypt(&tampered).is_err(), "Tamper not detected");

    println!("Cascade integrity chain (8 chunks) OK");
}

/// Test White-Box multi-round key schedule
fn test_whitebox_multiround() {
    print!("[WhiteBox]     ");

    let ks = WhiteBoxKeySchedule::generate(42, 4);

    // Deterministic
    let r1 = ks.evaluate(0x12345678);
    let r2 = ks.evaluate(0x12345678);
    assert_eq!(r1, r2, "WhiteBox not deterministic");

    // Different inputs produce different outputs (mostly)
    let mut outputs = std::collections::HashSet::new();
    for i in 0..500u32 {
        outputs.insert(ks.evaluate(i));
    }
    assert!(outputs.len() > 50, "WhiteBox output diversity too low: {}", outputs.len());

    // Handler index dispatch
    let wb = WhiteBoxTables::generate(99);
    for h in 0..16 {
        for op in 0..=255u8 {
            let idx = wb.next_handler_index(h, op, 0, 16);
            assert!(idx < 16, "Handler index out of range");
        }
    }

    println!("WhiteBox 4-round schedule + handler dispatch OK");
}

/// Test VM execution with GF(2^64) constant encoding
fn test_vm_with_gf_const() {
    print!("[VM+GF]        ");

    // Use GF constant encoding to hide a value, then use it in VM
    let secret_value: u64 = 42007;
    let gf_pairs = galois::generate_gf_const(secret_value, 777, 4);
    let recovered = galois::eval_gf_const(&gf_pairs);
    assert_eq!(recovered, secret_value);

    // Now run the recovered value through VM computation
    let x: u64 = recovered;
    let y: u64 = 993;
    let vm_result: u64 = vm_protect!(|x: u64, y: u64| -> u64 { x + y });
    assert_eq!(vm_result, 43000, "VM+GF computation failed");

    println!("VM execution with GF-encoded constants = {} OK", vm_result);
}

/// Test nanomite table setup and dispatch logic
fn test_nanomite_table() {
    print!("[Nanomite]     ");

    let mut entries = HashMap::new();
    entries.insert(0x401000usize, NanomiteEntry {
        target_zero: 0x401100,
        target_nonzero: 0x401200,
        condition_reg: 0,
    });
    entries.insert(0x402000usize, NanomiteEntry {
        target_zero: 0x402100,
        target_nonzero: 0x402200,
        condition_reg: 1,
    });
    entries.insert(0x403000usize, NanomiteEntry {
        target_zero: 0x403100,
        target_nonzero: 0x403200,
        condition_reg: 2,
    });

    let table = NanomiteTable { entries };
    assert_eq!(table.entries.len(), 3);

    let entry = table.entries.get(&0x401000).unwrap();
    assert_eq!(entry.target_zero, 0x401100);
    assert_eq!(entry.target_nonzero, 0x401200);

    println!("Nanomite table (3 entries) dispatch logic OK");
}

/// Test process guard challenge-response cryptography
fn test_process_guard_crypto() {
    print!("[ProcessGuard] ");

    let secret: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    let challenge = 0x12345678_9ABCDEF0_u64;

    let response = process_guard::compute_response(challenge, &secret);
    assert!(process_guard::verify_response(challenge, response, &secret),
        "Challenge-response verification failed");

    // Wrong secret should fail
    let mut wrong_secret = secret;
    wrong_secret[0] ^= 1;
    assert!(!process_guard::verify_response(challenge, response, &wrong_secret),
        "Wrong secret should not verify");

    // Different challenges produce different responses
    let response2 = process_guard::compute_response(challenge + 1, &secret);
    assert_ne!(response, response2, "Different challenges should give different responses");

    println!("Challenge-response crypto OK");
}

/// Test syscall function name hashing
fn test_syscall_hashing() {
    print!("[Syscall]      ");

    let h1 = syscall::hash_function_name(b"NtCreateFile");
    let h2 = syscall::hash_function_name(b"NtCreateFile");
    assert_eq!(h1, h2, "Hash should be deterministic");

    let h3 = syscall::hash_function_name(b"NtOpenProcess");
    assert_ne!(h1, h3, "Different names should hash differently");

    let h4 = syscall::hash_function_name(b"NtAllocateVirtualMemory");
    assert_ne!(h1, h4);
    assert_ne!(h3, h4);

    println!("Syscall hash: NtCreateFile=0x{:08X}, NtOpenProcess=0x{:08X} OK", h1, h3);
}

/// Test the full combined pipeline:
/// encrypt_string -> GF MBA -> VM -> cascade -> verify
fn test_combined_pipeline() {
    print!("[Pipeline]     ");

    // Step 1: Encrypt a string
    let secret = encrypt_string!("SQURE-FULL-PROTECTION-2024");

    // Step 2: Use GF MBA to compute x + 0 = x (identity through obfuscation)
    let expected_len: u64 = 26; // "SQURE-FULL-PROTECTION-2024".len()
    let gf_expr = galois::generate_gf_mba_add(555, 6);
    let obfuscated_len = galois::eval_gf_mba_add(&gf_expr, expected_len, 0);
    assert_eq!(obfuscated_len, expected_len, "GF MBA identity failed");

    // Step 3: VM computation on the length
    let x: u64 = obfuscated_len;
    let y: u64 = 0;
    let computed: u64 = vm_protect!(|x: u64, y: u64| -> u64 { x + y });
    assert_eq!(computed, 26, "Pipeline length check failed");

    // Step 4: Cascade integrity on the secret bytes
    let chain = cascade::build_chain(secret.as_bytes(), 4, 42);
    let recovered = cascade::verify_and_decrypt(&chain).expect("Cascade failed in pipeline");
    let recovered_str = String::from_utf8(recovered).expect("Invalid UTF-8");
    assert_eq!(recovered_str, "SQURE-FULL-PROTECTION-2024", "Pipeline roundtrip failed");

    // Step 5: White-Box evaluation as a fingerprint
    let wb = WhiteBoxTables::generate(42);
    let fingerprint = wb.evaluate(computed as u32);

    println!("Full pipeline (encrypt->GF->VM->cascade->WB) OK, fingerprint=0x{:02X}", fingerprint);
}
