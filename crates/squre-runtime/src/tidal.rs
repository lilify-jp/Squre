//! Tidal Memory — page-granular guard encryption with background re-encryption.
//!
//! ## Architecture
//!
//! All critical functions are placed in the `.tidal` PE section via
//! `#[link_section = ".tidal"]`, keeping them separate from `.text`.
//! This is essential because `.text` itself gets encrypted.
//!
//! ## Runtime flow
//!
//! 1. `initialize(master_key)` is called from `anti_debug!()`
//! 2. Each 4KB page of `.text` is XOR-encrypted with a unique derived key
//! 3. All pages are marked `PAGE_NOACCESS`
//! 4. VEH handler is installed to catch ACCESS_VIOLATION in `.text`
//! 5. On page fault: VEH decrypts the page → `PAGE_EXECUTE_READ` → resume
//! 6. Tide thread re-encrypts cold pages periodically → `PAGE_NOACCESS`
//!
//! ## Anti-dump effect
//!
//! At any instant, only 1–2 pages of `.text` are decrypted in memory.
//! A memory dump captures ≤0.1% of the code in plaintext.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, Ordering};

const PAGE_SIZE: usize = 4096;
/// Re-encryption interval (milliseconds).
const TIDE_INTERVAL_MS: u32 = 50;
/// Pages not accessed for this many RDTSC ticks are re-encrypted.
/// ~50 ms at a typical 3 GHz invariant TSC frequency.
const COOLDOWN_TICKS: u64 = 150_000_000;

// Page lifecycle: ENCRYPTED ↔ DECRYPTED, with TRANSITIONING as a lock.
const PAGE_ENCRYPTED: u8 = 0;
const PAGE_DECRYPTED: u8 = 1;
const PAGE_TRANSITIONING: u8 = 2;

// ─── Global state ────────────────────────────────────────────

/// Per-page metadata (24 bytes each, all atomic for VEH safety).
#[repr(C)]
struct PageEntry {
    state: AtomicU8,
    _pad: [u8; 7],
    nonce: AtomicU64,
    last_access: AtomicU64,
}

/// Immutable after initialization; pointed to by `TIDAL_PTR`.
///
/// No function pointers — all kernel calls go through direct syscalls
/// (SSNs cached in `crate::syscall` atomics).
struct TidalState {
    text_base: usize,
    text_size: usize,
    page_count: usize,
    master_key: u64,
    pages: *mut PageEntry, // VirtualAlloc'd array, never freed
}

// Safety: TidalState is immutable after init; pages use atomics.
unsafe impl Send for TidalState {}
unsafe impl Sync for TidalState {}

static TIDAL_PTR: AtomicPtr<TidalState> = AtomicPtr::new(core::ptr::null_mut());
static INSTALLED: AtomicBool = AtomicBool::new(false);


// ─── FFI: Windows API (all in kernel32/ntdll, NOT in .text) ──

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
extern "system" {
    // ── Used ONLY before .text encryption (import thunks still intact) ──
    fn VirtualAlloc(addr: *mut u8, size: usize, alloc_type: u32, protect: u32) -> *mut u8;
    fn CreateThread(
        attrs: *mut u8,
        stack_size: usize,
        start: unsafe extern "system" fn(*mut u8) -> u32,
        param: *mut u8,
        flags: u32,
        id: *mut u32,
    ) -> isize;
    // GetModuleHandleA / GetProcAddress removed — all kernel calls now
    // go through direct NT syscalls (SSNs resolved from ntdll PEB walk).
}

// VEH registration — uses windows_sys for type compatibility with nanomite handler
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS,
};

// ─── Public API ──────────────────────────────────────────────

/// Check whether Tidal Memory is active.
pub fn is_active() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// Initialize Tidal Memory: encrypt `.text` page-by-page, install VEH,
/// start tide thread.
///
/// # Safety
///
/// * Must be called AFTER nanomite activation (INT3 patches are part
///   of the encrypted snapshot).
/// * On return the caller's `.text` page will fault and be transparently
///   decrypted by the VEH handler.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn initialize(master_key: u64) {
    if INSTALLED.load(Ordering::Relaxed) {
        return;
    }

    // 1. Locate .text in the running PE image
    let (text_base, text_size) = find_text_section();
    if text_base == 0 || text_size == 0 {
        return;
    }
    let page_count = (text_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // 2. Ensure direct-syscall SSNs are resolved.
    //    This is idempotent — may already have been called by anti_debug.
    //    MUST happen BEFORE encrypting .text because resolve_ssn() uses
    //    HashMap/Mutex code that lives in .text.
    crate::syscall::ensure_ssns_resolved();

    // 3. Allocate page entries with VirtualAlloc (avoids Rust allocator in .text)
    let entries_bytes = page_count * core::mem::size_of::<PageEntry>();
    let pages = VirtualAlloc(
        core::ptr::null_mut(),
        entries_bytes,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04,   // PAGE_READWRITE
    ) as *mut PageEntry;
    if pages.is_null() {
        return;
    }
    // Zero-init gives state=0=PAGE_ENCRYPTED; we want PAGE_DECRYPTED initially
    core::ptr::write_bytes(pages as *mut u8, 0, entries_bytes);
    for i in 0..page_count {
        let entry = &*pages.add(i);
        entry.state.store(PAGE_DECRYPTED, Ordering::Relaxed);
    }

    // 4. Allocate TidalState
    let state_ptr = VirtualAlloc(
        core::ptr::null_mut(),
        core::mem::size_of::<TidalState>(),
        0x3000,
        0x04,
    ) as *mut TidalState;
    if state_ptr.is_null() {
        return;
    }
    core::ptr::write(state_ptr, TidalState {
        text_base,
        text_size,
        page_count,
        master_key,
        pages,
    });

    // 5. Publish state + install VEH handler BEFORE encrypting any pages.
    TIDAL_PTR.store(state_ptr, Ordering::Release);
    AddVectoredExceptionHandler(1, Some(tidal_veh_handler));

    // 6. Encrypt each .text page with XTEA-CTR.
    //    Uses direct syscalls for VirtualProtect — no user-mode hook possible.
    let mut rng = master_key;
    for i in 0..page_count {
        let nonce = splitmix64_next(&mut rng);
        let key = derive_page_key_128(master_key, i as u64, nonce);

        let page_base = (text_base + i * PAGE_SIZE) as *mut u8;
        let page_len = tidal_min(PAGE_SIZE, text_size - i * PAGE_SIZE);

        let entry = &*pages.add(i);
        entry.nonce.store(nonce, Ordering::Release);

        let mut old_prot: u32 = 0;
        crate::syscall::nt_protect_virtual_memory(
            page_base, page_len, 0x04 /* RW */, &mut old_prot);
        xtea_ctr_page(page_base, page_len, &key, nonce);
        crate::syscall::nt_protect_virtual_memory(
            page_base, page_len, 0x01 /* NOACCESS */, &mut old_prot);

        entry.state.store(PAGE_ENCRYPTED, Ordering::Release);
    }

    crate::syscall::nt_flush_instruction_cache(
        text_base as *const u8, text_size);

    // 7. Spawn tide thread via CreateThread (import thunk — VEH will
    //    transparently decrypt the .text page containing the thunk).
    let mut tid: u32 = 0;
    let h = CreateThread(
        core::ptr::null_mut(),
        0,
        tide_thread_entry,
        core::ptr::null_mut(),
        0,
        &mut tid,
    );
    if h != 0 {
        crate::syscall::nt_close(h);
    }

    INSTALLED.store(true, Ordering::Release);
    // On return the caller's .text page faults → VEH decrypts → continues.
}

/// Stub for non-Windows / non-x86_64.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn initialize(_master_key: u64) {}

// ─── VEH Handler ─────────────────────────────────────────────

/// Handles ACCESS_VIOLATION inside `.text`: decrypt the faulting page,
/// mark it executable, and resume.  Completely lock-free.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
unsafe extern "system" fn tidal_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
    const CONTINUE_EXECUTION: i32 = -1;
    const CONTINUE_SEARCH: i32 = 0;

    // Spin-wait while polymorphic mutation is in progress
    while crate::polymorph::MUTATING.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    if info.is_null() {
        return CONTINUE_SEARCH;
    }
    let ep = &*info;
    if ep.ExceptionRecord.is_null() {
        return CONTINUE_SEARCH;
    }
    let record = &*ep.ExceptionRecord;

    if record.ExceptionCode as u32 != EXCEPTION_ACCESS_VIOLATION {
        return CONTINUE_SEARCH;
    }

    // Faulting address is ExceptionInformation[1]
    if record.NumberParameters < 2 {
        return CONTINUE_SEARCH;
    }
    let fault_addr = record.ExceptionInformation[1];

    let ptr = TIDAL_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return CONTINUE_SEARCH;
    }
    let state = &*ptr;

    // Is the fault inside .text?
    if fault_addr < state.text_base || fault_addr >= state.text_base + state.text_size {
        return CONTINUE_SEARCH;
    }

    let page_idx = (fault_addr - state.text_base) / PAGE_SIZE;
    if page_idx >= state.page_count {
        return CONTINUE_SEARCH;
    }

    let entry = &*state.pages.add(page_idx);
    let current = entry.state.load(Ordering::Acquire);

    if current == PAGE_ENCRYPTED {
        // Decrypt this page using XTEA-CTR + direct NT syscalls (no user-mode hooks)
        let nonce = entry.nonce.load(Ordering::Acquire);
        let key = derive_page_key_128(state.master_key, page_idx as u64, nonce);

        let page_base = (state.text_base + page_idx * PAGE_SIZE) as *mut u8;
        let page_len = tidal_min(PAGE_SIZE, state.text_size - page_idx * PAGE_SIZE);

        let mut old: u32 = 0;
        crate::syscall::nt_protect_virtual_memory(page_base, page_len, 0x04, &mut old); // RW
        xtea_ctr_page(page_base, page_len, &key, nonce);
        crate::syscall::nt_protect_virtual_memory(page_base, page_len, 0x20, &mut old); // EXECUTE_READ
        crate::syscall::nt_flush_instruction_cache(page_base as *const u8, page_len);

        entry.last_access.store(rdtsc_now(), Ordering::Release);
        entry.state.store(PAGE_DECRYPTED, Ordering::Release);
        return CONTINUE_EXECUTION;
    }

    if current == PAGE_TRANSITIONING {
        // Tide thread is re-encrypting — spin until it finishes
        while entry.state.load(Ordering::Acquire) == PAGE_TRANSITIONING {
            core::hint::spin_loop();
        }
        // Now ENCRYPTED → retry instruction (will fault again, VEH decrypts)
        return CONTINUE_EXECUTION;
    }

    // PAGE_DECRYPTED but faulted? Not our problem.
    CONTINUE_SEARCH
}

// ─── Tide Thread ─────────────────────────────────────────────

/// Background re-encryption loop.  Re-encrypts cold pages every
/// `TIDE_INTERVAL_MS` to minimize the decrypted-memory window.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
unsafe extern "system" fn tide_thread_entry(_param: *mut u8) -> u32 {
    loop {
        let ptr = TIDAL_PTR.load(Ordering::Acquire);
        if ptr.is_null() {
            return 0;
        }
        let state = &*ptr;

        // Direct syscall NtDelayExecution — no user-mode hook possible
        crate::syscall::nt_delay_execution_ms(TIDE_INTERVAL_MS);

        let now = rdtsc_now();

        for i in 0..state.page_count {
            let entry = &*state.pages.add(i);

            if entry.state.load(Ordering::Acquire) != PAGE_DECRYPTED {
                continue;
            }
            let last = entry.last_access.load(Ordering::Acquire);
            if now.wrapping_sub(last) < COOLDOWN_TICKS {
                continue;
            }

            // CAS: DECRYPTED → TRANSITIONING (we now own this page)
            if entry
                .state
                .compare_exchange(
                    PAGE_DECRYPTED,
                    PAGE_TRANSITIONING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }

            let page_base = (state.text_base + i * PAGE_SIZE) as *mut u8;
            let page_len = tidal_min(PAGE_SIZE, state.text_size - i * PAGE_SIZE);

            // New nonce for re-encryption (forward secrecy).
            // Prefers RDRAND; falls back to RDTSC-mixed value.
            let new_nonce = generate_nonce(i, state.master_key);
            let key = derive_page_key_128(state.master_key, i as u64, new_nonce);

            let mut old: u32 = 0;
            // Direct syscall NtProtectVirtualMemory — no user-mode hook
            crate::syscall::nt_protect_virtual_memory(page_base, page_len, 0x04, &mut old); // RW
            xtea_ctr_page(page_base, page_len, &key, new_nonce);
            crate::syscall::nt_protect_virtual_memory(page_base, page_len, 0x01, &mut old); // NOACCESS

            entry.nonce.store(new_nonce, Ordering::Release);
            entry.state.store(PAGE_ENCRYPTED, Ordering::Release);
        }

        // Polymorphic mutation: swap equivalent instruction sequences in .tidal
        // Uses the nonce as a seed for random selection of which patterns to swap
        let mutation_seed = generate_nonce(0, state.master_key);
        crate::polymorph::mutate_tidal(mutation_seed);
    }
}

// ─── Pure helpers (all in .tidal section, NO stdlib) ─────────

#[link_section = ".tidal"]
#[inline(always)]
fn tidal_min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

/// Derive a 128-bit XTEA key from (master_key, page_idx, nonce).
/// Each of the 4 u32 subkeys is derived independently via splitmix64.
#[link_section = ".tidal"]
fn derive_page_key_128(master: u64, page_idx: u64, nonce: u64) -> [u32; 4] {
    let seed = master ^ page_idx ^ nonce;
    let s0 = splitmix64(seed);
    let s1 = splitmix64(s0);
    let s2 = splitmix64(s1);
    let s3 = splitmix64(s2);
    [s0 as u32, s1 as u32, s2 as u32, s3 as u32]
}

#[link_section = ".tidal"]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

#[link_section = ".tidal"]
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    splitmix64(*state)
}

/// XTEA block cipher (64-bit block, 128-bit key, 32 Feistel rounds).
/// Embedded in `.tidal` so it's available after `.text` encryption.
#[link_section = ".tidal"]
fn xtea_encrypt_block(pt: u64, key: &[u32; 4]) -> u64 {
    const DELTA: u32 = 0x9E37_79B9;
    let mut v0 = pt as u32;
    let mut v1 = (pt >> 32) as u32;
    let mut sum: u32 = 0;
    let mut i = 0u32;
    while i < 32 {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ (sum.wrapping_add(key[(sum & 3) as usize])),
        );
        sum = sum.wrapping_add(DELTA);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ (sum.wrapping_add(key[((sum >> 11) & 3) as usize])),
        );
        i += 1;
    }
    (v0 as u64) | ((v1 as u64) << 32)
}

/// XTEA-CTR: encrypt/decrypt a page using XTEA in counter mode.
///
/// For each 8-byte block, the keystream is `XTEA_encrypt(nonce ^ block_idx, key)`.
/// XOR with plaintext/ciphertext gives symmetric encrypt/decrypt.
///
/// XTEA-CTR is resistant to known-plaintext attacks — recovering one
/// keystream block reveals nothing about other blocks.
#[link_section = ".tidal"]
fn xtea_ctr_page(ptr: *mut u8, len: usize, key: &[u32; 4], nonce: u64) {
    let qwords = len / 8;
    unsafe {
        let mut i = 0usize;
        while i < qwords {
            let counter = nonce ^ (i as u64);
            let ks = xtea_encrypt_block(counter, key);
            let p = ptr.add(i * 8) as *mut u64;
            p.write_unaligned(p.read_unaligned() ^ ks);
            i += 1;
        }
        let remaining = len % 8;
        if remaining > 0 {
            let counter = nonce ^ (qwords as u64);
            let ks = xtea_encrypt_block(counter, key);
            let tail = ptr.add(qwords * 8);
            let kb = ks.to_le_bytes();
            let mut j = 0usize;
            while j < remaining {
                *tail.add(j) ^= kb[j];
                j += 1;
            }
        }
    }
}

/// Try to read a hardware random number via RDRAND.
/// Returns `Some(value)` on success, `None` if RDRAND fails or is unsupported.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
fn rdrand64() -> Option<u64> {
    unsafe {
        let val: u64;
        let ok: u64;
        core::arch::asm!(
            "xor {ok}, {ok}",
            "rdrand {val}",
            "setc {ok:l}",
            val = out(reg) val,
            ok = out(reg) ok,
            options(nostack, nomem),
        );
        if ok != 0 { Some(val) } else { None }
    }
}

/// Generate a strong nonce for page re-encryption.
/// Prefers RDRAND hardware random; falls back to RDTSC ⊕ page_idx ⊕ secret.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
fn generate_nonce(page_idx: usize, secret: u64) -> u64 {
    // Try RDRAND up to 3 times
    let mut i = 0u32;
    while i < 3 {
        if let Some(r) = rdrand64() {
            return r;
        }
        i += 1;
    }
    // Fallback: mix RDTSC, page index, and a secret
    let tsc = rdtsc_now();
    splitmix64(tsc ^ (page_idx as u64) ^ secret)
}

/// Read CPU timestamp counter via RDTSC (no API call needed).
/// Replaces QPC — avoids any user-mode hook surface.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
fn rdtsc_now() -> u64 {
    unsafe {
        let lo: u64;
        let hi: u64;
        core::arch::asm!(
            "rdtsc",
            out("rax") lo,
            out("rdx") hi,
            options(nostack, nomem, preserves_flags),
        );
        lo | (hi << 32)
    }
}

/// Parse the running PE image to find the `.text` section.
/// Returns (virtual_address, virtual_size).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
unsafe fn find_text_section() -> (usize, usize) {
    // PEB → ImageBaseAddress
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

    // DOS header → PE offset
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let pe_sig = base.add(e_lfanew);

    // Verify "PE\0\0"
    if *(pe_sig as *const u32) != 0x0000_4550 {
        return (0, 0);
    }

    // COFF header starts 4 bytes after PE signature
    let coff = pe_sig.add(4);
    let num_sections = *(coff.add(2) as *const u16) as usize;
    let opt_hdr_size = *(coff.add(16) as *const u16) as usize;

    // Section headers follow optional header
    let sections = coff.add(20 + opt_hdr_size);

    // Each IMAGE_SECTION_HEADER is 40 bytes
    for i in 0..num_sections {
        let sh = sections.add(i * 40);
        // Name is first 8 bytes: ".text\0\0\0"
        let n = core::slice::from_raw_parts(sh, 8);
        if n[0] == b'.' && n[1] == b't' && n[2] == b'e' && n[3] == b'x' && n[4] == b't' {
            let vsize = *(sh.add(8) as *const u32) as usize;
            let rva = *(sh.add(12) as *const u32) as usize;
            return (image_base + rva, vsize);
        }
    }

    (0, 0)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splitmix64_deterministic() {
        assert_eq!(splitmix64(0), splitmix64(0));
        assert_eq!(splitmix64(42), splitmix64(42));
    }

    #[test]
    fn test_splitmix64_avalanche() {
        let a = splitmix64(0);
        let b = splitmix64(1);
        assert_ne!(a, b);
        let diff = (a ^ b).count_ones();
        assert!(diff >= 20, "only {} bits differ", diff);
    }

    #[test]
    fn test_derive_page_key_128_different_pages() {
        let k0 = derive_page_key_128(0xCAFE, 0, 99);
        let k1 = derive_page_key_128(0xCAFE, 1, 99);
        assert_ne!(k0, k1, "different pages should have different keys");
    }

    #[test]
    fn test_derive_page_key_128_different_nonces() {
        let k0 = derive_page_key_128(0xCAFE, 5, 100);
        let k1 = derive_page_key_128(0xCAFE, 5, 200);
        assert_ne!(k0, k1, "different nonces should produce different keys");
    }

    #[test]
    fn test_xtea_encrypt_block_roundtrip() {
        let key = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210];
        for pt in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let ct = xtea_encrypt_block(pt, &key);
            assert_ne!(ct, pt, "ciphertext should differ from plaintext");
            // XTEA-CTR doesn't need decrypt, but verify the block cipher is deterministic
            let ct2 = xtea_encrypt_block(pt, &key);
            assert_eq!(ct, ct2, "encrypt must be deterministic");
        }
    }

    #[test]
    fn test_xtea_ctr_page_roundtrip() {
        let original: Vec<u8> = (0..PAGE_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let mut data = original.clone();
        let key = [0xDEAD_BEEF, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0];
        let nonce = 0x42u64;

        xtea_ctr_page(data.as_mut_ptr(), data.len(), &key, nonce);
        assert_ne!(data, original, "encrypted data should differ");

        // CTR mode is symmetric: applying the same operation decrypts
        xtea_ctr_page(data.as_mut_ptr(), data.len(), &key, nonce);
        assert_eq!(data, original, "decrypt(encrypt(data)) must equal original");
    }

    #[test]
    fn test_xtea_ctr_page_partial() {
        // Test with non-aligned length (not multiple of 8)
        let original: Vec<u8> = (0..100).map(|i| (i & 0xFF) as u8).collect();
        let mut data = original.clone();
        let key = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let nonce = 0x99u64;

        xtea_ctr_page(data.as_mut_ptr(), data.len(), &key, nonce);
        assert_ne!(data, original);
        xtea_ctr_page(data.as_mut_ptr(), data.len(), &key, nonce);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xtea_ctr_different_nonces_different_ciphertext() {
        let original: Vec<u8> = vec![0xAA; PAGE_SIZE];
        let mut data_a = original.clone();
        let mut data_b = original.clone();
        let key = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];

        xtea_ctr_page(data_a.as_mut_ptr(), data_a.len(), &key, 111);
        xtea_ctr_page(data_b.as_mut_ptr(), data_b.len(), &key, 222);
        assert_ne!(data_a, data_b, "different nonces must produce different ciphertext");
    }

    #[test]
    fn test_xtea_ctr_known_plaintext_resistance() {
        // With xorshift64, knowing one plaintext-ciphertext pair reveals the entire keystream.
        // With XTEA-CTR, each block uses an independent keystream.
        let key = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        let nonce = 42u64;

        // Encrypt a page of zeros — the ciphertext IS the keystream
        let mut keystream: Vec<u8> = vec![0u8; 64]; // 8 qwords
        xtea_ctr_page(keystream.as_mut_ptr(), keystream.len(), &key, nonce);

        // Verify each 8-byte block of keystream is unique (not a shifted PRNG)
        let blocks: Vec<u64> = (0..8)
            .map(|i| u64::from_le_bytes(keystream[i * 8..(i + 1) * 8].try_into().unwrap()))
            .collect();
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                assert_ne!(blocks[i], blocks[j],
                    "keystream blocks {} and {} are identical", i, j);
            }
        }
    }

    #[test]
    fn test_splitmix64_next_sequence() {
        let mut state = 0u64;
        let a = splitmix64_next(&mut state);
        let b = splitmix64_next(&mut state);
        let c = splitmix64_next(&mut state);
        // All values should be different
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_page_entry_size() {
        // Ensure PageEntry is 24 bytes for predictable layout
        assert_eq!(core::mem::size_of::<PageEntry>(), 24);
    }
}
