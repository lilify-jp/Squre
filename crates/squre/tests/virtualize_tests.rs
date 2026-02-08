//! Integration tests for `#[virtualize]` — Phase 5C.
//!
//! These tests verify that full function virtualization produces
//! correct results across various constructs: arithmetic, branches,
//! loops, comparisons, and complex algorithms.

extern crate squre_runtime;

#[squre::virtualize]
fn vm_add(a: u64, b: u64) -> u64 {
    a + b
}

#[squre::virtualize]
fn vm_sub(a: u64, b: u64) -> u64 {
    a - b
}

#[squre::virtualize]
fn vm_mul(a: u64, b: u64) -> u64 {
    a * b
}

#[squre::virtualize]
fn vm_div(a: u64, b: u64) -> u64 {
    a / b
}

#[squre::virtualize]
fn vm_mod(a: u64, b: u64) -> u64 {
    a % b
}

#[squre::virtualize]
fn vm_xor(a: u64, b: u64) -> u64 {
    a ^ b
}

#[squre::virtualize]
fn vm_and(a: u64, b: u64) -> u64 {
    a & b
}

#[squre::virtualize]
fn vm_or(a: u64, b: u64) -> u64 {
    a | b
}

#[squre::virtualize]
fn vm_max(a: u64, b: u64) -> u64 {
    if a > b {
        return a;
    }
    b
}

#[squre::virtualize]
fn vm_min(a: u64, b: u64) -> u64 {
    if a < b {
        return a;
    }
    b
}

#[squre::virtualize]
fn vm_abs_diff(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        b - a
    }
}

#[squre::virtualize]
fn vm_sum_1_to_n(n: u64) -> u64 {
    let mut sum = 0u64;
    let mut i = 1u64;
    while i <= n {
        sum = sum + i;
        i = i + 1u64;
    }
    sum
}

#[squre::virtualize]
fn vm_factorial(n: u64) -> u64 {
    let mut result = 1u64;
    let mut i = 2u64;
    while i <= n {
        result = result * i;
        i = i + 1u64;
    }
    result
}

#[squre::virtualize]
fn vm_hash(seed: u64, key: u64) -> u64 {
    let mut h = seed;
    let mut i = 0u64;
    while i < 8u64 {
        h = h.wrapping_mul(31u64).wrapping_add(key);
        h = h ^ (h >> 7u64);
        i = i + 1u64;
    }
    h
}

#[squre::virtualize]
fn vm_classify(x: u64) -> u64 {
    if x == 0u64 {
        return 0u64;
    }
    if x < 10u64 {
        return 1u64;
    }
    2u64
}

#[squre::virtualize]
fn vm_collatz_steps(mut n: u64) -> u64 {
    let mut steps = 0u64;
    while n > 1u64 {
        if n % 2u64 == 0u64 {
            n = n / 2u64;
        } else {
            n = n * 3u64 + 1u64;
        }
        steps = steps + 1u64;
    }
    steps
}

#[squre::virtualize]
fn vm_gcd(mut a: u64, mut b: u64) -> u64 {
    while b > 0u64 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

// ═══ Reference implementations for verification ═══

fn ref_hash(seed: u64, key: u64) -> u64 {
    let mut h = seed;
    for _ in 0..8 {
        h = h.wrapping_mul(31).wrapping_add(key);
        h ^= h >> 7;
    }
    h
}

// ═══ Nested VM functions (Phase 5D) ═══

#[squre::virtualize(nested)]
fn nested_add(a: u64, b: u64) -> u64 {
    a + b
}

#[squre::virtualize(nested)]
fn nested_sum(n: u64) -> u64 {
    let mut sum = 0u64;
    let mut i = 1u64;
    while i <= n {
        sum = sum + i;
        i = i + 1u64;
    }
    sum
}

#[squre::virtualize(nested)]
fn nested_max(a: u64, b: u64) -> u64 {
    if a > b {
        return a;
    }
    b
}

#[squre::virtualize(nested)]
fn nested_hash(seed: u64, key: u64) -> u64 {
    let mut h = seed;
    let mut i = 0u64;
    while i < 8u64 {
        h = h.wrapping_mul(31u64).wrapping_add(key);
        h = h ^ (h >> 7u64);
        i = i + 1u64;
    }
    h
}

#[squre::virtualize(nested)]
fn nested_fibonacci(n: u64) -> u64 {
    if n == 0u64 {
        return 0u64;
    }
    let mut a = 0u64;
    let mut b = 1u64;
    let mut i = 1u64;
    while i < n {
        let next = a + b;
        a = b;
        b = next;
        i = i + 1u64;
    }
    b
}

fn ref_collatz_steps(mut n: u64) -> u64 {
    let mut steps = 0u64;
    while n > 1 {
        if n % 2 == 0 { n /= 2; } else { n = n * 3 + 1; }
        steps += 1;
    }
    steps
}

// ═══ Tests ═══

#[test]
fn test_virtualize_add() {
    assert_eq!(vm_add(100, 200), 300);
    assert_eq!(vm_add(0, 0), 0);
    assert_eq!(vm_add(u64::MAX, 1), 0); // wrapping
}

#[test]
fn test_virtualize_sub() {
    assert_eq!(vm_sub(100, 37), 63);
    assert_eq!(vm_sub(0, 1), u64::MAX); // wrapping
}

#[test]
fn test_virtualize_mul() {
    assert_eq!(vm_mul(12345, 67890), 12345u64.wrapping_mul(67890));
}

#[test]
fn test_virtualize_div_mod() {
    assert_eq!(vm_div(100, 7), 14);
    assert_eq!(vm_mod(100, 7), 2);
}

#[test]
fn test_virtualize_bitwise() {
    assert_eq!(vm_xor(0xAAAA, 0x5555), 0xAAAA ^ 0x5555);
    assert_eq!(vm_and(0xFF00, 0x0FF0), 0x0F00);
    assert_eq!(vm_or(0xFF00, 0x00FF), 0xFFFF);
}

#[test]
fn test_virtualize_if_else() {
    assert_eq!(vm_max(10, 20), 20);
    assert_eq!(vm_max(99, 42), 99);
    assert_eq!(vm_max(5, 5), 5);
    assert_eq!(vm_min(10, 20), 10);
    assert_eq!(vm_min(99, 42), 42);
}

#[test]
fn test_virtualize_abs_diff() {
    assert_eq!(vm_abs_diff(100, 37), 63);
    assert_eq!(vm_abs_diff(37, 100), 63);
    assert_eq!(vm_abs_diff(42, 42), 0);
}

#[test]
fn test_virtualize_while_loop() {
    assert_eq!(vm_sum_1_to_n(0), 0);
    assert_eq!(vm_sum_1_to_n(1), 1);
    assert_eq!(vm_sum_1_to_n(10), 55);
    assert_eq!(vm_sum_1_to_n(100), 5050);
}

#[test]
fn test_virtualize_factorial() {
    assert_eq!(vm_factorial(0), 1);
    assert_eq!(vm_factorial(1), 1);
    assert_eq!(vm_factorial(5), 120);
    assert_eq!(vm_factorial(10), 3628800);
}

#[test]
fn test_virtualize_hash() {
    for seed in [0u64, 42, 0xCAFEBABE, 0xDEADBEEF, u64::MAX] {
        for key in [0u64, 1, 42, 12345, 0xFF] {
            assert_eq!(
                vm_hash(seed, key),
                ref_hash(seed, key),
                "hash mismatch: seed={seed}, key={key}"
            );
        }
    }
}

#[test]
fn test_virtualize_classify() {
    assert_eq!(vm_classify(0), 0);
    assert_eq!(vm_classify(1), 1);
    assert_eq!(vm_classify(9), 1);
    assert_eq!(vm_classify(10), 2);
    assert_eq!(vm_classify(100), 2);
}

#[test]
fn test_virtualize_collatz() {
    assert_eq!(vm_collatz_steps(1), 0);
    assert_eq!(vm_collatz_steps(2), ref_collatz_steps(2));
    assert_eq!(vm_collatz_steps(7), ref_collatz_steps(7));
    assert_eq!(vm_collatz_steps(27), ref_collatz_steps(27));
}

#[test]
fn test_virtualize_gcd() {
    assert_eq!(vm_gcd(12, 8), 4);
    assert_eq!(vm_gcd(100, 75), 25);
    assert_eq!(vm_gcd(7, 13), 1);
    assert_eq!(vm_gcd(0, 42), 42);
}

// ═══ Nested VM Tests (Phase 5D) ═══

#[test]
fn test_nested_add() {
    assert_eq!(nested_add(100, 200), 300);
    assert_eq!(nested_add(0, 0), 0);
    assert_eq!(nested_add(u64::MAX, 1), 0); // wrapping
}

#[test]
fn test_nested_sum() {
    assert_eq!(nested_sum(0), 0);
    assert_eq!(nested_sum(1), 1);
    assert_eq!(nested_sum(10), 55);
    assert_eq!(nested_sum(100), 5050);
}

#[test]
fn test_nested_max() {
    assert_eq!(nested_max(10, 20), 20);
    assert_eq!(nested_max(99, 42), 99);
    assert_eq!(nested_max(5, 5), 5);
}

#[test]
fn test_nested_hash() {
    for seed in [0u64, 42, 0xCAFEBABE, 0xDEADBEEF, u64::MAX] {
        for key in [0u64, 1, 42, 12345, 0xFF] {
            assert_eq!(
                nested_hash(seed, key),
                ref_hash(seed, key),
                "nested hash mismatch: seed={seed}, key={key}"
            );
        }
    }
}

#[test]
fn test_nested_fibonacci() {
    assert_eq!(nested_fibonacci(0), 0);
    assert_eq!(nested_fibonacci(1), 1);
    assert_eq!(nested_fibonacci(2), 1);
    assert_eq!(nested_fibonacci(10), 55);
    assert_eq!(nested_fibonacci(20), 6765);
}

#[test]
fn test_nested_matches_single_layer() {
    // Verify nested VM produces the same results as single-layer
    for a in [0u64, 1, 42, 100, 0xCAFEBABE] {
        for b in [0u64, 1, 37, 200, 0xDEADBEEF] {
            assert_eq!(
                nested_add(a, b), vm_add(a, b),
                "nested vs single mismatch: add({a}, {b})"
            );
        }
    }
    for n in [0u64, 1, 5, 10, 20, 50, 100] {
        assert_eq!(
            nested_sum(n), vm_sum_1_to_n(n),
            "nested vs single mismatch: sum({n})"
        );
    }
}
