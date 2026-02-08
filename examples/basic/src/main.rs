extern crate squre_runtime;

use squre::prelude::*;

#[obfuscate]
fn validate_license(key: &str) -> bool {
    let secret = encrypt_string!("SQURE-LICENSE-2024-VALID");
    key == secret
}

#[obfuscate]
fn compute_magic(x: u64) -> u64 {
    let a = 12345u64;
    let b = 67890u64;
    x.wrapping_add(a).wrapping_mul(b)
}

fn main() {
    // Anti-debug check
    anti_debug!();

    // Test encrypt_string
    let secret = encrypt_string!("Hello from SQURE!");
    println!("[encrypt_string] Decrypted: {}", secret);

    // Test obfuscate_const
    let magic: u64 = obfuscate_const!(42u64);
    println!("[obfuscate_const] Value: {} (expected 42)", magic);

    // Test #[obfuscate] on function
    let valid = validate_license("SQURE-LICENSE-2024-VALID");
    println!("[obfuscate fn] License valid: {} (expected true)", valid);

    let invalid = validate_license("WRONG-KEY");
    println!("[obfuscate fn] License valid: {} (expected false)", invalid);

    // Test obfuscated computation
    let result = compute_magic(100);
    let expected = 100u64.wrapping_add(12345).wrapping_mul(67890);
    println!("[obfuscate fn] compute_magic(100) = {} (expected {})", result, expected);
    assert_eq!(result, expected, "Computation mismatch!");

    println!("\n=== All SQURE Phase 1 tests passed! ===");
}
