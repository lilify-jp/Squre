//! Integration tests for `#[obfuscate(cff)]` — Phase 5F.
//!
//! These tests verify that Control Flow Flattening produces
//! correct results: the state machine preserves the original
//! function semantics across arithmetic, branches, loops, and returns.

extern crate squre_runtime;

// ═══ Simple arithmetic ═══

#[squre::obfuscate(cff)]
fn cff_add(a: u64, b: u64) -> u64 {
    let x: u64 = a;
    let y: u64 = b;
    x + y
}

// ═══ If/else branching with early return ═══

#[squre::obfuscate(cff)]
fn cff_max(a: u64, b: u64) -> u64 {
    if a > b {
        return a;
    }
    b
}

#[squre::obfuscate(cff)]
fn cff_classify(x: u64) -> u64 {
    if x < 10 {
        return 0;
    }
    if x < 20 {
        return 1;
    }
    2
}

// ═══ While loop ═══

#[squre::obfuscate(cff)]
fn cff_sum_1_to_n(n: u64) -> u64 {
    let mut total: u64 = 0;
    let mut i: u64 = 1;
    while i <= n {
        total += i;
        i += 1;
    }
    total
}

// ═══ Multiple variables ═══

#[squre::obfuscate(cff)]
fn cff_multi_var(x: u64, y: u64) -> u64 {
    let a: u64 = x + 1;
    let b: u64 = y * 2;
    let c: u64 = a - b;
    c * 3 + 1
}

// ═══ Early return + fallthrough ═══

#[squre::obfuscate(cff)]
fn cff_early_return(x: u64) -> u64 {
    if x == 0 {
        return 999;
    }
    let doubled: u64 = x * 2;
    doubled
}

// ═══ Abs diff (if/else expression) ═══

#[squre::obfuscate(cff)]
fn cff_abs_diff(a: u64, b: u64) -> u64 {
    if a >= b {
        return a - b;
    }
    b - a
}

// ═══ GCD via while loop ═══

#[squre::obfuscate(cff)]
fn cff_gcd(mut a: u64, mut b: u64) -> u64 {
    while b > 0 {
        let t: u64 = b;
        b = a % b;
        a = t;
    }
    a
}

// ═══ Tests ═══

#[test]
fn test_cff_add() {
    assert_eq!(cff_add(100, 200), 300);
    assert_eq!(cff_add(0, 0), 0);
    assert_eq!(cff_add(1, 2), 3);
}

#[test]
fn test_cff_max() {
    assert_eq!(cff_max(10, 20), 20);
    assert_eq!(cff_max(99, 42), 99);
    assert_eq!(cff_max(5, 5), 5);
}

#[test]
fn test_cff_classify() {
    assert_eq!(cff_classify(0), 0);
    assert_eq!(cff_classify(5), 0);
    assert_eq!(cff_classify(9), 0);
    assert_eq!(cff_classify(10), 1);
    assert_eq!(cff_classify(19), 1);
    assert_eq!(cff_classify(20), 2);
    assert_eq!(cff_classify(100), 2);
}

#[test]
fn test_cff_sum_1_to_n() {
    assert_eq!(cff_sum_1_to_n(0), 0);
    assert_eq!(cff_sum_1_to_n(1), 1);
    assert_eq!(cff_sum_1_to_n(10), 55);
    assert_eq!(cff_sum_1_to_n(100), 5050);
}

#[test]
fn test_cff_multi_var() {
    // (7+1) - (3*2) = 8 - 6 = 2; 2*3+1 = 7
    assert_eq!(cff_multi_var(7, 3), 7);
    // (0+1) - (0*2) = 1; 1*3+1 = 4
    assert_eq!(cff_multi_var(0, 0), 4);
}

#[test]
fn test_cff_early_return() {
    assert_eq!(cff_early_return(0), 999);
    assert_eq!(cff_early_return(5), 10);
    assert_eq!(cff_early_return(100), 200);
}

#[test]
fn test_cff_abs_diff() {
    assert_eq!(cff_abs_diff(100, 37), 63);
    assert_eq!(cff_abs_diff(37, 100), 63);
    assert_eq!(cff_abs_diff(42, 42), 0);
}

#[test]
fn test_cff_gcd() {
    assert_eq!(cff_gcd(12, 8), 4);
    assert_eq!(cff_gcd(100, 75), 25);
    assert_eq!(cff_gcd(7, 13), 1);
    assert_eq!(cff_gcd(0, 42), 42);
}
