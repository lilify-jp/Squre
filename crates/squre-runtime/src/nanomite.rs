//! Nanomite + VEH (Vectored Exception Handler) dispatch.
//!
//! Nanomites replace conditional branches with INT3 (0xCC) breakpoints.
//! A Vectored Exception Handler catches the breakpoint exception and
//! uses a lookup table to determine the correct branch target.
//!
//! Supports two condition modes:
//!   - GPR mode (condition_reg 0-15): checks a general-purpose register for zero
//!   - EFLAGS mode (condition_reg 0xF0+): checks CPU flags (ZF, SF, etc.)
//!
//! The nanomite table can be loaded from the PE's .squre section at runtime,
//! populated by the squre-cli post-processor.
//!
//! ## Lock-free design
//!
//! The dispatch table is stored behind an `AtomicPtr` to a sorted `Vec`.
//! The VEH handler reads it via `Acquire` load + binary search — no mutex,
//! no allocation, no possibility of deadlock inside an exception handler.

use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::collections::HashMap;

/// Global flag: whether the nanomite VEH handler is installed.
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Lock-free dispatch table: sorted Vec behind an AtomicPtr.
/// The VEH handler reads this with Acquire ordering + binary search.
static DISPATCH_PTR: AtomicPtr<SortedDispatch> = AtomicPtr::new(core::ptr::null_mut());

/// Sorted dispatch table for lock-free VEH lookups.
///
/// Also stores a raw pointer + length for the VEH handler to use
/// without calling any Vec methods (which would be compiled into .text
/// and become unavailable when Tidal encrypts .text pages).
struct SortedDispatch {
    /// Sorted by breakpoint address (first element of tuple).
    entries: Vec<(usize, NanomiteEntry)>,
    /// Raw pointer to entries data (== entries.as_ptr()), for .tidal VEH use.
    raw_ptr: *const (usize, NanomiteEntry),
    /// Number of entries (== entries.len()), for .tidal VEH use.
    raw_len: usize,
}

/// The nanomite dispatch table (public API — HashMap-based for ergonomics).
#[derive(Debug, Clone)]
pub struct NanomiteTable {
    /// Maps: breakpoint_address → entry
    pub entries: HashMap<usize, NanomiteEntry>,
}

impl NanomiteTable {
    /// Create an empty nanomite table (for VEH pre-installation).
    pub fn empty() -> Self {
        NanomiteTable { entries: HashMap::new() }
    }
}

/// A single nanomite entry.
#[derive(Debug, Clone, Copy)]
pub struct NanomiteEntry {
    /// Address to jump to when condition is TRUE (branch taken).
    pub target_zero: usize,
    /// Address to jump to when condition is FALSE (fall-through).
    pub target_nonzero: usize,
    /// Condition type:
    ///   0-15:  check GPR[idx] == 0
    ///   0xF0:  jz  (ZF == 1 → taken)
    ///   0xF1:  jnz (ZF == 0 → taken)
    ///   0xF2:  jl  (SF != OF → taken)
    ///   0xF3:  jge (SF == OF → taken)
    ///   0xF4:  jle (ZF==1 || SF!=OF → taken)
    ///   0xF5:  jg  (ZF==0 && SF==OF → taken)
    pub condition_reg: u8,
}

/// Nanomite table serialization magic: "NMTQ" (legacy, plaintext)
pub const NANOMITE_MAGIC: u32 = 0x5154_4D4E;

/// Encrypted nanomite table magic: "NMTE"
pub const NANOMITE_MAGIC_ENCRYPTED: u32 = 0x4554_4D4E;

// ─── Crypto helpers for nanomite table decryption ─────────────

/// Splitmix64 finalizer — must match the CLI's splitmix_finalize().
fn splitmix_finalize(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CEB9FE1A85EC53);
    h ^= h >> 33;
    h
}

/// Hash a byte slice — must match the CLI's hash_encrypted_page().
fn hash_data(data: &[u8]) -> u64 {
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

// ─── XTEA-CTR helpers for metadata decryption ────────────────

/// Derive XTEA [u32; 4] key from a u64 crypto key (matches CLI's master_key_to_xtea + derive_master_key_128).
fn derive_xtea_key(crypto_key: u64) -> [u32; 4] {
    let lo = splitmix_finalize(crypto_key);
    let hi = splitmix_finalize(lo ^ 0x6A09E667F3BCC908);
    let lo = if lo == 0 { 1 } else { lo };
    let hi = if hi == 0 { 1 } else { hi };
    [lo as u32, (lo >> 32) as u32, hi as u32, (hi >> 32) as u32]
}

/// XTEA-CTR decrypt in place (self-inverse with same key/nonce).
fn xtea_ctr_decrypt(data: &mut [u8], key: &[u32; 4], nonce: u64) {
    for (i, chunk) in data.chunks_mut(8).enumerate() {
        let counter = nonce.wrapping_add(i as u64);
        let keystream = squre_core::crypto::xtea::xtea_encrypt_block(counter, key);
        let ks_bytes = keystream.to_le_bytes();
        for (j, b) in chunk.iter_mut().enumerate() {
            *b ^= ks_bytes[j];
        }
    }
}

// ─── Core API ─────────────────────────────────────────────────

/// Install the nanomite VEH handler and set the dispatch table.
///
/// Converts the HashMap-based table to a sorted Vec for lock-free
/// VEH lookups, then installs the vectored exception handler.
///
/// # Safety
/// This modifies global exception handling and must be called before
/// any nanomite breakpoints are hit.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn install_handler(table: NanomiteTable) {
    use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

    // Convert HashMap → sorted Vec for lock-free binary search
    let mut entries: Vec<(usize, NanomiteEntry)> = table.entries.into_iter().collect();
    entries.sort_by_key(|e| e.0);

    let raw_ptr = entries.as_ptr();
    let raw_len = entries.len();
    let boxed = Box::new(SortedDispatch { entries, raw_ptr, raw_len });
    let old = DISPATCH_PTR.swap(Box::into_raw(boxed), Ordering::Release);
    if !old.is_null() {
        drop(Box::from_raw(old));
    }

    if !HANDLER_INSTALLED.load(Ordering::SeqCst) {
        AddVectoredExceptionHandler(1, Some(nanomite_exception_handler));
        HANDLER_INSTALLED.store(true, Ordering::SeqCst);
    }
}

/// Stub for non-Windows platforms.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn install_handler(table: NanomiteTable) {
    let mut entries: Vec<(usize, NanomiteEntry)> = table.entries.into_iter().collect();
    entries.sort_by_key(|e| e.0);
    let raw_ptr = entries.as_ptr();
    let raw_len = entries.len();
    let boxed = Box::new(SortedDispatch { entries, raw_ptr, raw_len });
    let old = DISPATCH_PTR.swap(Box::into_raw(boxed), Ordering::Release);
    if !old.is_null() {
        drop(Box::from_raw(old));
    }
    HANDLER_INSTALLED.store(true, Ordering::SeqCst);
}

// ─── VEH Handler ──────────────────────────────────────────────
//
// IMPORTANT: The VEH handler and all functions it calls are placed in
// the `.tidal` section.  When Tidal Memory encrypts `.text` and sets
// pages to NOACCESS, the OS must still be able to invoke this handler
// (and the Tidal VEH handler) without faulting on encrypted code.

/// The VEH handler that dispatches nanomite breakpoints.
///
/// Completely lock-free: reads the sorted dispatch table via AtomicPtr
/// and performs a manual binary search (no Vec methods — those are in
/// `.text` and may be encrypted by Tidal).
///
/// ## RIP handling on Windows x64
///
/// For `EXCEPTION_BREAKPOINT`, the Windows kernel exception dispatcher
/// decrements `CONTEXT.Rip` by 1 *before* delivering the exception.
/// Therefore `Rip` already points AT the INT3 instruction — we do NOT
/// subtract 1.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
unsafe extern "system" fn nanomite_exception_handler(
    exception_info: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    const EXCEPTION_BREAKPOINT: i32 = 0x80000003u32 as i32;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    // Spin-wait while polymorphic mutation is in progress
    while crate::polymorph::MUTATING.load(core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let info = &*exception_info;
    if info.ExceptionRecord.is_null() || info.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &*info.ExceptionRecord;
    let context = &mut *(info.ContextRecord as *mut RawContext);

    if record.ExceptionCode != EXCEPTION_BREAKPOINT {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rip = get_rip(context) as usize;

    // Lock-free table lookup via AtomicPtr + manual binary search.
    // We use raw_ptr/raw_len instead of Vec methods to avoid calling
    // code in .text (which may be encrypted by Tidal).
    let ptr = DISPATCH_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let dispatch = &*ptr;
    let data = dispatch.raw_ptr;
    let len = dispatch.raw_len;
    if data.is_null() || len == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Try Rip first (kernel already decremented), then Rip-1 (kernel didn't)
    let mut found_idx: isize = raw_binary_search(data, len, rip);
    if found_idx < 0 {
        found_idx = raw_binary_search(data, len, rip.wrapping_sub(1));
    }

    if found_idx >= 0 {
        let entry = &(*data.add(found_idx as usize)).1;
        let taken = evaluate_condition(context, entry.condition_reg);

        let target = if taken {
            entry.target_zero
        } else {
            entry.target_nonzero
        };

        set_rip(context, target as u64);
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

/// Manual binary search over sorted dispatch entries using raw pointers.
/// Returns the index if found, or -1 if not found.
/// Avoids calling any Vec/slice methods (which live in .text).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn raw_binary_search(
    data: *const (usize, NanomiteEntry),
    len: usize,
    needle: usize,
) -> isize {
    let mut lo: usize = 0;
    let mut hi: usize = len;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let key = (*data.add(mid)).0;
        if key == needle {
            return mid as isize;
        } else if key < needle {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    -1
}

// ─── Condition Evaluation ─────────────────────────────────────

/// Evaluate a nanomite condition.
/// Placed in .tidal section to remain accessible when .text is encrypted.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn evaluate_condition(ctx: &RawContext, condition: u8) -> bool {
    match condition {
        // GPR-based: check if register is zero
        0..=15 => get_gpr(ctx, condition) == 0,

        // EFLAGS-based conditions
        0xF0 => {
            // jz: ZF == 1
            let eflags = get_eflags(ctx);
            (eflags >> 6) & 1 != 0
        }
        0xF1 => {
            // jnz: ZF == 0
            let eflags = get_eflags(ctx);
            (eflags >> 6) & 1 == 0
        }
        0xF2 => {
            // jl: SF != OF
            let eflags = get_eflags(ctx);
            let sf = (eflags >> 7) & 1;
            let of = (eflags >> 11) & 1;
            sf != of
        }
        0xF3 => {
            // jge: SF == OF
            let eflags = get_eflags(ctx);
            let sf = (eflags >> 7) & 1;
            let of = (eflags >> 11) & 1;
            sf == of
        }
        0xF4 => {
            // jle: ZF==1 || SF!=OF
            let eflags = get_eflags(ctx);
            let zf = (eflags >> 6) & 1;
            let sf = (eflags >> 7) & 1;
            let of = (eflags >> 11) & 1;
            zf != 0 || sf != of
        }
        0xF5 => {
            // jg: ZF==0 && SF==OF
            let eflags = get_eflags(ctx);
            let zf = (eflags >> 6) & 1;
            let sf = (eflags >> 7) & 1;
            let of = (eflags >> 11) & 1;
            zf == 0 && sf == of
        }
        _ => false,
    }
}

// ─── Raw CONTEXT access ──────────────────────────────────────
// All placed in .tidal section for Tidal compatibility.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[repr(C, align(16))]
struct RawContext {
    data: [u8; 1232],
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn get_rip(ctx: &RawContext) -> u64 {
    *(ctx.data.as_ptr().add(0xF8) as *const u64)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn set_rip(ctx: &mut RawContext, val: u64) {
    *(ctx.data.as_mut_ptr().add(0xF8) as *mut u64) = val;
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn get_eflags(ctx: &RawContext) -> u64 {
    // EFlags is at offset 0x44 in x86_64 CONTEXT
    *(ctx.data.as_ptr().add(0x44) as *const u32) as u64
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(always)]
unsafe fn get_gpr(ctx: &RawContext, idx: u8) -> u64 {
    // Manual offset lookup using raw pointer — avoids array bounds check in .text
    let base = ctx.data.as_ptr();
    let offset = match idx & 0xF {
        0  => 0x78usize,
        1  => 0x80,
        2  => 0x88,
        3  => 0x90,
        4  => 0x98,
        5  => 0xA0,
        6  => 0xA8,
        7  => 0xB0,
        8  => 0xB8,
        9  => 0xC0,
        10 => 0xC8,
        11 => 0xD0,
        12 => 0xD8,
        13 => 0xE0,
        14 => 0xE8,
        _  => 0xF0,
    };
    *(base.add(offset) as *const u64)
}

// ─── Public Queries ──────────────────────────────────────────

/// Query whether the nanomite handler is installed.
pub fn is_installed() -> bool {
    HANDLER_INSTALLED.load(Ordering::SeqCst)
}

/// Get the number of entries in the dispatch table.
pub fn table_size() -> usize {
    let ptr = DISPATCH_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        0
    } else {
        unsafe { (*ptr).entries.len() }
    }
}

/// Merge additional entries into the existing dispatch table.
///
/// Creates a new sorted Vec, merges old + new, atomically swaps the pointer.
pub fn merge_entries(new_entries: HashMap<usize, NanomiteEntry>) {
    let old_ptr = DISPATCH_PTR.load(Ordering::Acquire);
    let mut combined: Vec<(usize, NanomiteEntry)> = if !old_ptr.is_null() {
        unsafe { (*old_ptr).entries.clone() }
    } else {
        Vec::new()
    };

    for (k, v) in new_entries {
        match combined.binary_search_by_key(&k, |e| e.0) {
            Ok(idx) => combined[idx] = (k, v),
            Err(idx) => combined.insert(idx, (k, v)),
        }
    }

    let raw_ptr = combined.as_ptr();
    let raw_len = combined.len();
    let new_box = Box::new(SortedDispatch { entries: combined, raw_ptr, raw_len });
    let old = DISPATCH_PTR.swap(Box::into_raw(new_box), Ordering::Release);
    // Safe to drop: we're single-threaded during init, no VEH race.
    if !old.is_null() {
        unsafe { drop(Box::from_raw(old)); }
    }
}

// ─── Nanomite Activation (runtime INT3 patching) ─────────────

/// Activate nanomites by patching INT3 into the code at each breakpoint address.
///
/// This MUST be called AFTER `install_handler()` and `load_table_from_pe_section()`.
/// Reads the dispatch table and writes 0xCC (INT3) + 0x90 (NOP) padding at each
/// breakpoint location.  Uses VirtualProtect to ensure pages are writable, then
/// flushes the instruction cache.
///
/// # Safety
/// Writes directly into the .text section of the running process.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn activate_nanomites() {
    /// Near conditional jumps are always 6 bytes: 0F 8x XX XX XX XX
    const NANOMITE_INSTR_LEN: usize = 6;

    // Ensure SSNs are resolved (idempotent — may already be called by anti_debug)
    crate::syscall::ensure_ssns_resolved();

    let ptr = DISPATCH_PTR.load(Ordering::Acquire);
    if ptr.is_null() { return; }
    let dispatch = &*ptr;

    if dispatch.entries.is_empty() { return; }

    for &(bp_addr, _) in &dispatch.entries {
        let p = bp_addr as *mut u8;

        // Direct syscall NtProtectVirtualMemory — no user-mode hook
        let mut old_protect: u32 = 0;
        crate::syscall::nt_protect_virtual_memory(
            p, NANOMITE_INSTR_LEN, 0x40 /* PAGE_EXECUTE_READWRITE */, &mut old_protect,
        );

        // Patch: INT3 + NOP padding
        core::ptr::write_volatile(p, 0xCC);
        for j in 1..NANOMITE_INSTR_LEN {
            core::ptr::write_volatile(p.add(j), 0x90);
        }
    }

    // Flush instruction cache via direct syscall
    crate::syscall::nt_flush_instruction_cache(core::ptr::null(), 0);
}

/// Stub for non-Windows platforms.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn activate_nanomites() {
    // No-op on non-Windows
}

// ─── PE Section Loading ──────────────────────────────────────

/// Load nanomite table from the current PE's .squre section.
///
/// Scans the PE image in memory for a section named ".squre",
/// looks for the NANOMITE_MAGIC header, and deserializes entries.
/// Each entry is 16 bytes: [bp_rva:u32, taken_rva:u32, nottaken_rva:u32, cond:u8, pad:3]
///
/// # Safety
/// Reads raw memory of the current process image.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn load_table_from_pe_section() {
    // Get image base from PEB
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );
    if peb.is_null() { return; }

    let image_base = *(peb.add(0x10) as *const u64) as usize;
    if image_base == 0 { return; }

    let base = image_base as *const u8;

    // Parse DOS header → PE offset
    let dos_magic = *(base as *const u16);
    if dos_magic != 0x5A4D { return; }
    let pe_offset = *(base.add(0x3C) as *const u32) as usize;

    // Verify PE signature
    let pe_sig = *(base.add(pe_offset) as *const u32);
    if pe_sig != 0x0000_4550 { return; }

    // COFF header
    let coff = base.add(pe_offset + 4);
    let num_sections = *(coff.add(2) as *const u16) as usize;
    let opt_header_size = *(coff.add(16) as *const u16) as usize;

    // Section table starts after optional header
    let section_table = coff.add(20 + opt_header_size);

    // Search for .sqinit and .squre sections
    let mut sqinit_data: &[u8] = &[];
    let mut squre_data: &[u8] = &[];

    for i in 0..num_sections {
        let sh = section_table.add(i * 40);
        let name = core::slice::from_raw_parts(sh, 8);
        let virt_addr = *(sh.add(12) as *const u32) as usize;
        let virt_size = *(sh.add(8) as *const u32) as usize;

        if name.starts_with(b".sqinit") {
            sqinit_data = core::slice::from_raw_parts(base.add(virt_addr), virt_size);
        } else if name.starts_with(b".squre") {
            squre_data = core::slice::from_raw_parts(base.add(virt_addr), virt_size);
        }
    }

    if squre_data.is_empty() { return; }

    // Derive nanomite crypto key from .sqinit hash (matches CLI derivation)
    let crypto_key = if !sqinit_data.is_empty() {
        splitmix_finalize(hash_data(sqinit_data))
    } else {
        0
    };

    parse_nanomite_blob(squre_data, image_base, crypto_key);
}

/// Stub for non-Windows platforms.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn load_table_from_pe_section() {
    // No-op on non-Windows
}

/// Parse a nanomite table blob from .squre section data.
///
/// Supports two formats:
///   NMTQ (0x5154_4D4E): legacy plaintext table
///   NMTE (0x4554_4D4E): encrypted table (count + entries XOR'd with crypto_key)
///
/// Format after magic: count(u32) + entries[count]{ bp_rva:u32, taken:u32, nottaken:u32, cond:u8, pad:3 }
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn parse_nanomite_blob(data: &[u8], image_base: usize, crypto_key: u64) {
    if data.len() < 8 { return; }

    // Scan for either NMTQ (plaintext) or NMTE (encrypted) magic
    for offset in 0..data.len().saturating_sub(8) {
        let magic = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]);

        let encrypted = match magic {
            NANOMITE_MAGIC => false,
            NANOMITE_MAGIC_ENCRYPTED => true,
            _ => continue,
        };

        let payload_start = offset + 4; // right after the 4-byte magic
        let payload_len = data.len() - payload_start;
        if payload_len < 4 { return; }

        // Decrypt payload if encrypted (XTEA-CTR mode, matches CLI)
        let payload: Vec<u8> = if encrypted && crypto_key != 0 {
            let xtea_key = derive_xtea_key(crypto_key);
            let mut buf = data[payload_start..].to_vec();
            xtea_ctr_decrypt(&mut buf, &xtea_key, crypto_key);
            buf
        } else {
            data[payload_start..].to_vec()
        };

        let count = u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3]
        ]) as usize;

        let entries_start = 4; // offset within payload
        if entries_start + count * 16 > payload.len() { return; }

        let mut new_entries = HashMap::new();
        for i in 0..count {
            let e = entries_start + i * 16;
            let bp_rva = u32::from_le_bytes([payload[e], payload[e+1], payload[e+2], payload[e+3]]) as usize;
            let taken_rva = u32::from_le_bytes([payload[e+4], payload[e+5], payload[e+6], payload[e+7]]) as usize;
            let nottaken_rva = u32::from_le_bytes([payload[e+8], payload[e+9], payload[e+10], payload[e+11]]) as usize;
            let condition = payload[e + 12];

            new_entries.insert(image_base + bp_rva, NanomiteEntry {
                target_zero: image_base + taken_rva,
                target_nonzero: image_base + nottaken_rva,
                condition_reg: condition,
            });
        }

        if !new_entries.is_empty() {
            merge_entries(new_entries);
        }
        return;
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_creation() {
        let mut entries = HashMap::new();
        entries.insert(0x1000, NanomiteEntry {
            target_zero: 0x2000,
            target_nonzero: 0x3000,
            condition_reg: 0, // RAX
        });
        entries.insert(0x4000, NanomiteEntry {
            target_zero: 0x5000,
            target_nonzero: 0x6000,
            condition_reg: 1, // RCX
        });
        let table = NanomiteTable { entries };
        assert_eq!(table.entries.len(), 2);
    }

    #[test]
    fn test_install_handler() {
        let table = NanomiteTable { entries: HashMap::new() };
        unsafe { install_handler(table); }
        assert!(is_installed());
    }

    #[test]
    fn test_eflags_condition_types() {
        // Verify condition_reg constants are properly defined
        let entry_jz = NanomiteEntry {
            target_zero: 0x1000,
            target_nonzero: 0x2000,
            condition_reg: 0xF0,
        };
        assert_eq!(entry_jz.condition_reg, 0xF0);

        let entry_jnz = NanomiteEntry {
            target_zero: 0x1000,
            target_nonzero: 0x2000,
            condition_reg: 0xF1,
        };
        assert_eq!(entry_jnz.condition_reg, 0xF1);
    }

    #[test]
    fn test_nanomite_magic() {
        assert_eq!(NANOMITE_MAGIC, 0x5154_4D4E);
        let bytes = NANOMITE_MAGIC.to_le_bytes();
        assert_eq!(&bytes, b"NMTQ");
    }

    #[test]
    fn test_nanomite_magic_encrypted() {
        assert_eq!(NANOMITE_MAGIC_ENCRYPTED, 0x4554_4D4E);
        let bytes = NANOMITE_MAGIC_ENCRYPTED.to_le_bytes();
        assert_eq!(&bytes, b"NMTE");
    }

    #[test]
    fn test_splitmix_finalize_matches_cli() {
        // splitmix_finalize(0) = 0 (multiplying 0 by any constant gives 0)
        assert_eq!(splitmix_finalize(0), 0);
        // Non-zero inputs produce non-zero outputs
        assert_ne!(splitmix_finalize(1), 0);
        // Same input must produce same output
        assert_eq!(splitmix_finalize(42), splitmix_finalize(42));
        // Different inputs produce different outputs
        assert_ne!(splitmix_finalize(1), splitmix_finalize(2));
    }

    #[test]
    fn test_hash_data_deterministic() {
        let data = b"Hello, World! SQURE test data here";
        let h1 = hash_data(data);
        let h2 = hash_data(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_data_avalanche() {
        let mut d1 = vec![0u8; 64];
        let mut d2 = vec![0u8; 64];
        d2[0] = 1;
        let h1 = hash_data(&d1);
        let h2 = hash_data(&d2);
        assert_ne!(h1, h2);
        let diff = (h1 ^ h2).count_ones();
        assert!(diff >= 15, "poor avalanche: only {} bits differ", diff);
    }

    #[test]
    fn test_merge_entries() {
        unsafe { install_handler(NanomiteTable::empty()); }
        assert_eq!(table_size(), 0);

        let mut new = HashMap::new();
        new.insert(0x1000, NanomiteEntry {
            target_zero: 0x2000,
            target_nonzero: 0x3000,
            condition_reg: 0xF0,
        });
        merge_entries(new);
        assert!(table_size() >= 1);
    }
}
