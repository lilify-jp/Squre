//! Direct Syscall wrapper for Windows.
//!
//! Bypasses user-mode API hooks by resolving System Service Numbers (SSN)
//! dynamically from ntdll.dll and invoking the syscall instruction directly
//! via inline assembly.
//!
//! This defeats:
//! - API hooking (Detours, inline hooks)
//! - IAT hooking
//! - DLL injection-based monitoring
//!
//! The SSN is extracted from the native API function prologue:
//!   mov r10, rcx     (4C 8B D1)
//!   mov eax, <SSN>   (B8 xx xx 00 00)
//!   ...
//!   syscall

use std::sync::Mutex;
use std::collections::HashMap;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

/// Cache of resolved SSNs: function_hash → SSN
static SSN_CACHE: Mutex<Option<HashMap<u32, u16>>> = Mutex::new(None);

/// Hash a function name for lookup (avoids storing strings).
pub fn hash_function_name(name: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5; // FNV offset basis
    for &b in name {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV prime
    }
    hash
}

/// Resolve the SSN for a native API function by walking ntdll exports.
///
/// # Safety
/// Reads from ntdll.dll's memory space.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn resolve_ssn(fn_name_hash: u32) -> Option<u16> {
    // Check cache first
    {
        let cache = SSN_CACHE.lock().unwrap();
        if let Some(ref map) = *cache {
            if let Some(&ssn) = map.get(&fn_name_hash) {
                return Some(ssn);
            }
        }
    }

    // Get ntdll base address from PEB
    let ntdll_base = get_ntdll_base()?;

    // Parse PE headers to find the export directory
    let dos_header = ntdll_base as *const u8;
    let e_lfanew = *(dos_header.add(0x3C) as *const u32) as usize;
    let nt_headers = dos_header.add(e_lfanew);

    // Optional header starts at nt_headers + 0x18 (after signature + file header)
    // Export directory RVA is at optional_header + 0x70 (112) for x64
    let optional_header = nt_headers.add(0x18);
    let export_dir_rva = *(optional_header.add(0x70) as *const u32) as usize;

    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = dos_header.add(export_dir_rva);
    let num_functions = *(export_dir.add(0x14) as *const u32) as usize;
    let num_names = *(export_dir.add(0x18) as *const u32) as usize;
    let addr_of_functions_rva = *(export_dir.add(0x1C) as *const u32) as usize;
    let addr_of_names_rva = *(export_dir.add(0x20) as *const u32) as usize;
    let addr_of_ordinals_rva = *(export_dir.add(0x24) as *const u32) as usize;

    let addr_of_functions = dos_header.add(addr_of_functions_rva) as *const u32;
    let addr_of_names = dos_header.add(addr_of_names_rva) as *const u32;
    let addr_of_ordinals = dos_header.add(addr_of_ordinals_rva) as *const u16;

    // Walk exports to find our function
    for i in 0..num_names {
        let name_rva = *addr_of_names.add(i) as usize;
        let name_ptr = dos_header.add(name_rva);

        // Read null-terminated function name
        let mut name_buf = Vec::new();
        let mut j = 0;
        loop {
            let b = *name_ptr.add(j);
            if b == 0 { break; }
            name_buf.push(b);
            j += 1;
            if j > 256 { break; }
        }

        // Check hash match
        if hash_function_name(&name_buf) == fn_name_hash {
            let ordinal = *addr_of_ordinals.add(i) as usize;
            if ordinal >= num_functions { return None; }
            let func_rva = *addr_of_functions.add(ordinal) as usize;
            let func_addr = dos_header.add(func_rva);

            // Extract SSN from function prologue:
            //   4C 8B D1       mov r10, rcx
            //   B8 xx xx 00 00 mov eax, SSN
            if *func_addr == 0x4C
                && *func_addr.add(1) == 0x8B
                && *func_addr.add(2) == 0xD1
                && *func_addr.add(3) == 0xB8
            {
                let ssn = *(func_addr.add(4) as *const u16);

                // Cache it
                let mut cache = SSN_CACHE.lock().unwrap();
                if cache.is_none() {
                    *cache = Some(HashMap::new());
                }
                cache.as_mut().unwrap().insert(fn_name_hash, ssn);

                return Some(ssn);
            }
        }
    }

    None
}

/// Get ntdll.dll base address from PEB's InLoadOrderModuleList.
/// ntdll is always the second entry (after the main module).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn get_ntdll_base() -> Option<usize> {
    let peb: u64;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );

    if peb == 0 { return None; }

    // PEB.Ldr at offset 0x18 (pointer — read 8 bytes, not 1)
    let ldr = *((peb as *const u8).add(0x18) as *const usize) as *const u8;
    if ldr.is_null() { return None; }

    // InLoadOrderModuleList at Ldr + 0x10
    let list_head = ldr.add(0x10) as *const usize;
    let first_entry = *list_head as *const u8;
    if first_entry.is_null() { return None; }

    // First entry = main module. Second entry = ntdll.
    let second_entry = *(first_entry as *const usize) as *const u8;
    if second_entry.is_null() { return None; }

    // DllBase is at offset 0x30 in LDR_DATA_TABLE_ENTRY
    let dll_base = *(second_entry.add(0x30) as *const usize);
    if dll_base == 0 { return None; }

    Some(dll_base)
}

/// Execute a direct syscall with the given SSN and up to 4 arguments.
///
/// Placed in `.tidal` section so it remains callable after `.text` encryption.
///
/// # Safety
/// This performs a raw syscall. Incorrect SSN or arguments will crash.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(never)]
pub unsafe fn direct_syscall(ssn: u16, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let result: u64;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        ssn = in(reg) ssn as u64,
        // syscall clobbers RCX (saves RIP) and R11 (saves RFLAGS).
        // Must use inout to tell the compiler RCX is modified.
        inout("rcx") arg1 => _,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        out("rax") result,
        out("r10") _,
        out("r11") _,
        options(nostack),
    );
    result
}

/// Execute a direct syscall with 5 arguments.
///
/// Needed for NtProtectVirtualMemory which takes 5 parameters.
/// Allocates shadow space + 5th-arg slot on the stack before `syscall`.
///
/// # Safety
/// This performs a raw syscall. Incorrect SSN or arguments will crash.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
#[inline(never)]
pub unsafe fn direct_syscall_5(
    ssn: u16, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64,
) -> u64 {
    let result: u64;
    core::arch::asm!(
        "sub rsp, 0x30",
        "mov [rsp + 0x28], {arg5}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x30",
        ssn = in(reg) ssn as u64,
        arg5 = in(reg) arg5,
        // syscall clobbers RCX (saves RIP) and R11 (saves RFLAGS).
        // Must use inout to tell the compiler RCX is modified.
        inout("rcx") arg1 => _,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        out("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

/// Stub for non-Windows.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn resolve_ssn(_fn_name_hash: u32) -> Option<u16> {
    None
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn direct_syscall(_ssn: u16, _a1: u64, _a2: u64, _a3: u64, _a4: u64) -> u64 {
    0
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn direct_syscall_5(
    _ssn: u16, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64,
) -> u64 {
    0
}

// ─── Cached SSN statics (always accessible from .tidal) ──────

static SSN_NT_PROTECT_VM: AtomicU16 = AtomicU16::new(0);
static SSN_NT_FLUSH_ICACHE: AtomicU16 = AtomicU16::new(0);
static SSN_NT_DELAY_EXECUTION: AtomicU16 = AtomicU16::new(0);
static SSN_NT_CLOSE: AtomicU16 = AtomicU16::new(0);
static SSN_NT_GET_CONTEXT_THREAD: AtomicU16 = AtomicU16::new(0);
static SSN_NT_QUERY_INFO_PROCESS: AtomicU16 = AtomicU16::new(0);
static SSN_NT_QUERY_SYSTEM_INFO: AtomicU16 = AtomicU16::new(0);
static SSNS_RESOLVED: AtomicBool = AtomicBool::new(false);

/// Resolve and cache all SSNs we need.  Must be called from `.text`
/// (before encryption) because `resolve_ssn()` uses `HashMap`/`Mutex`.
///
/// Idempotent — subsequent calls are no-ops.
///
/// # Safety
/// Reads ntdll memory to extract SSNs.
pub unsafe fn ensure_ssns_resolved() {
    if SSNS_RESOLVED.load(Ordering::Acquire) {
        return;
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtProtectVirtualMemory")) {
            SSN_NT_PROTECT_VM.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtFlushInstructionCache")) {
            SSN_NT_FLUSH_ICACHE.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtDelayExecution")) {
            SSN_NT_DELAY_EXECUTION.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtClose")) {
            SSN_NT_CLOSE.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtGetContextThread")) {
            SSN_NT_GET_CONTEXT_THREAD.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtQueryInformationProcess")) {
            SSN_NT_QUERY_INFO_PROCESS.store(ssn, Ordering::Release);
        }
        if let Some(ssn) = resolve_ssn(hash_function_name(b"NtQuerySystemInformation")) {
            SSN_NT_QUERY_SYSTEM_INFO.store(ssn, Ordering::Release);
        }
    }

    SSNS_RESOLVED.store(true, Ordering::Release);
}

// ─── .tidal wrapper functions ────────────────────────────────
//
// These are safe to call from VEH handlers and tide threads
// after .text encryption because they live in `.tidal` and only
// use atomic loads + inline asm (no .text dependencies).

/// Direct syscall wrapper for NtProtectVirtualMemory.
///
/// NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
///
/// Note: takes **pointers** to BaseAddress and RegionSize (the kernel
/// may page-align them).
///
/// # Safety
/// Performs a raw NT syscall.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_protect_virtual_memory(
    base: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let ssn = SSN_NT_PROTECT_VM.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    let mut base_addr: u64 = base as u64;
    let mut region_size: u64 = size as u64;
    direct_syscall_5(
        ssn,
        (-1i64) as u64,                             // ProcessHandle (current)
        (&mut base_addr) as *mut u64 as u64,         // *BaseAddress
        (&mut region_size) as *mut u64 as u64,       // *RegionSize
        new_protect as u64,                          // NewProtect
        old_protect as u64,                          // *OldProtect
    ) as i32
}

/// Direct syscall wrapper for NtFlushInstructionCache.
///
/// NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
///
/// # Safety
/// Performs a raw NT syscall.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_flush_instruction_cache(base: *const u8, size: usize) -> i32 {
    let ssn = SSN_NT_FLUSH_ICACHE.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    direct_syscall(
        ssn,
        (-1i64) as u64,    // ProcessHandle (current)
        base as u64,        // BaseAddress
        size as u64,        // Length
        0,                  // unused arg4
    ) as i32
}

/// Direct syscall wrapper for NtDelayExecution (Sleep replacement).
///
/// Converts milliseconds to a relative LARGE_INTEGER (negative 100ns units).
///
/// # Safety
/// Performs a raw NT syscall.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_delay_execution_ms(ms: u32) {
    let ssn = SSN_NT_DELAY_EXECUTION.load(Ordering::Acquire);
    if ssn == 0 {
        return;
    }
    // Negative = relative time in 100ns units.
    // 1 ms = 10,000 × 100ns
    let interval: i64 = -((ms as i64) * 10_000);
    direct_syscall(
        ssn,
        0,                                  // Alertable = FALSE
        (&interval) as *const i64 as u64,   // *DelayInterval
        0,
        0,
    );
}

/// Direct syscall wrapper for NtClose.
///
/// # Safety
/// Performs a raw NT syscall.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_close(handle: isize) -> i32 {
    let ssn = SSN_NT_CLOSE.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    direct_syscall(ssn, handle as u64, 0, 0, 0) as i32
}

/// Direct syscall wrapper for NtGetContextThread.
///
/// # Safety
/// Performs a raw NT syscall. `context` must point to a valid CONTEXT buffer.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_get_context_thread(thread: isize, context: *mut u8) -> i32 {
    let ssn = SSN_NT_GET_CONTEXT_THREAD.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    direct_syscall(ssn, thread as u64, context as u64, 0, 0) as i32
}

/// Direct syscall wrapper for NtQueryInformationProcess.
///
/// NtQueryInformationProcess(ProcessHandle, InfoClass, Buffer, Length, *ReturnLength)
///
/// # Safety
/// Performs a raw NT syscall. `buffer` must be valid for `length` bytes.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_query_information_process(
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> i32 {
    let ssn = SSN_NT_QUERY_INFO_PROCESS.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    direct_syscall_5(
        ssn,
        (-1i64) as u64,              // ProcessHandle (current process)
        info_class as u64,            // ProcessInformationClass
        buffer as u64,                // ProcessInformation
        length as u64,                // ProcessInformationLength
        return_length as u64,         // ReturnLength
    ) as i32
}

/// Direct syscall wrapper for NtQuerySystemInformation.
///
/// NtQuerySystemInformation(InfoClass, Buffer, Length, *ReturnLength)
///
/// # Safety
/// Performs a raw NT syscall. `buffer` must be valid for `length` bytes.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[link_section = ".tidal"]
pub unsafe fn nt_query_system_information(
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> i32 {
    let ssn = SSN_NT_QUERY_SYSTEM_INFO.load(Ordering::Acquire);
    if ssn == 0 {
        return -1;
    }
    direct_syscall(
        ssn,
        info_class as u64,            // SystemInformationClass
        buffer as u64,                 // SystemInformation
        length as u64,                 // SystemInformationLength
        return_length as u64,          // ReturnLength
    ) as i32
}

// ─── Non-Windows stubs for wrappers ──────────────────────────

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_protect_virtual_memory(
    _base: *mut u8, _size: usize, _new_protect: u32, _old_protect: *mut u32,
) -> i32 { 0 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_flush_instruction_cache(_base: *const u8, _size: usize) -> i32 { 0 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_delay_execution_ms(_ms: u32) {}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_close(_handle: isize) -> i32 { 0 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_get_context_thread(_thread: isize, _context: *mut u8) -> i32 { 0 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_query_information_process(
    _info_class: u32, _buffer: *mut u8, _length: u32, _return_length: *mut u32,
) -> i32 { 0 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_query_system_information(
    _info_class: u32, _buffer: *mut u8, _length: u32, _return_length: *mut u32,
) -> i32 { 0 }

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_function_name() {
        let h1 = hash_function_name(b"NtCreateFile");
        let h2 = hash_function_name(b"NtReadFile");
        let h3 = hash_function_name(b"NtCreateFile");
        assert_eq!(h1, h3, "Same name should produce same hash");
        assert_ne!(h1, h2, "Different names should produce different hashes");
    }

    #[test]
    fn test_hash_deterministic() {
        for _ in 0..100 {
            let h = hash_function_name(b"NtQueryInformationProcess");
            assert_eq!(h, hash_function_name(b"NtQueryInformationProcess"));
        }
    }

    #[test]
    fn test_nt_function_hashes_unique() {
        let hashes = [
            hash_function_name(b"NtProtectVirtualMemory"),
            hash_function_name(b"NtFlushInstructionCache"),
            hash_function_name(b"NtDelayExecution"),
            hash_function_name(b"NtClose"),
            hash_function_name(b"NtGetContextThread"),
            hash_function_name(b"NtQueryInformationProcess"),
            hash_function_name(b"NtQuerySystemInformation"),
        ];
        // All hashes must be unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j],
                    "hash collision between NT functions {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_ensure_ssns_resolved_idempotent() {
        // Resolves SSNs from ntdll on Windows; no-op on other platforms.
        unsafe { ensure_ssns_resolved(); }
        unsafe { ensure_ssns_resolved(); }
        assert!(SSNS_RESOLVED.load(Ordering::Relaxed));
    }

    #[test]
    fn test_ssns_resolved_on_windows() {
        // After ensure_ssns_resolved, all SSNs should be non-zero on Windows.
        unsafe { ensure_ssns_resolved(); }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            assert_ne!(SSN_NT_PROTECT_VM.load(Ordering::Relaxed), 0,
                "NtProtectVirtualMemory SSN not resolved");
            assert_ne!(SSN_NT_FLUSH_ICACHE.load(Ordering::Relaxed), 0,
                "NtFlushInstructionCache SSN not resolved");
            assert_ne!(SSN_NT_DELAY_EXECUTION.load(Ordering::Relaxed), 0,
                "NtDelayExecution SSN not resolved");
            assert_ne!(SSN_NT_CLOSE.load(Ordering::Relaxed), 0,
                "NtClose SSN not resolved");
            assert_ne!(SSN_NT_GET_CONTEXT_THREAD.load(Ordering::Relaxed), 0,
                "NtGetContextThread SSN not resolved");
            assert_ne!(SSN_NT_QUERY_INFO_PROCESS.load(Ordering::Relaxed), 0,
                "NtQueryInformationProcess SSN not resolved");
            assert_ne!(SSN_NT_QUERY_SYSTEM_INFO.load(Ordering::Relaxed), 0,
                "NtQuerySystemInformation SSN not resolved");
        }
    }

    #[test]
    fn test_nt_flush_icache_with_resolved_ssn() {
        // After SSN resolution, flushing with null/0 should succeed (NTSTATUS >= 0)
        unsafe {
            ensure_ssns_resolved();
            let result = nt_flush_instruction_cache(core::ptr::null(), 0);
            // On Windows: should return STATUS_SUCCESS (0)
            // On non-Windows: stub returns 0
            assert_eq!(result, 0, "NtFlushInstructionCache(null, 0) failed: {result}");
        }
    }

    #[test]
    fn test_nt_protect_virtual_memory_roundtrip() {
        // Allocate a page, change protection RW→RX→RW, verify syscall works
        unsafe {
            ensure_ssns_resolved();

            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            {
                // Allocate a page with VirtualAlloc (RW)
                extern "system" {
                    fn VirtualAlloc(addr: *mut u8, size: usize, t: u32, p: u32) -> *mut u8;
                    fn VirtualFree(addr: *mut u8, size: usize, t: u32) -> i32;
                }
                let page = VirtualAlloc(
                    core::ptr::null_mut(), 4096, 0x3000, 0x04,
                );
                assert!(!page.is_null(), "VirtualAlloc failed");

                // Write a pattern
                core::ptr::write_bytes(page, 0xAA, 4096);

                // Change to PAGE_READONLY (0x02) via direct syscall
                let mut old_prot: u32 = 0;
                let status = nt_protect_virtual_memory(page, 4096, 0x02, &mut old_prot);
                assert_eq!(status, 0,
                    "NtProtectVirtualMemory → READONLY failed: NTSTATUS=0x{:08X}", status as u32);
                assert_eq!(old_prot, 0x04,
                    "old protect should be PAGE_READWRITE (0x04), got 0x{:08X}", old_prot);

                // Change back to PAGE_READWRITE (0x04)
                let mut old_prot2: u32 = 0;
                let status2 = nt_protect_virtual_memory(page, 4096, 0x04, &mut old_prot2);
                assert_eq!(status2, 0,
                    "NtProtectVirtualMemory → RW failed: NTSTATUS=0x{:08X}", status2 as u32);
                assert_eq!(old_prot2, 0x02,
                    "old protect should be PAGE_READONLY (0x02), got 0x{:08X}", old_prot2);

                // Verify we can still write
                core::ptr::write_bytes(page, 0xBB, 4096);
                assert_eq!(*page, 0xBB);

                VirtualFree(page, 0, 0x8000); // MEM_RELEASE
            }
        }
    }

    #[test]
    fn test_nt_query_information_process_basic_info() {
        // Query ProcessBasicInformation (class 0) — should always succeed
        unsafe {
            ensure_ssns_resolved();

            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            {
                // PROCESS_BASIC_INFORMATION is 48 bytes on x64
                let mut buf = [0u8; 48];
                let mut ret_len: u32 = 0;
                let status = nt_query_information_process(
                    0,  // ProcessBasicInformation
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut ret_len,
                );
                assert_eq!(status, 0,
                    "NtQueryInformationProcess(BasicInfo) failed: NTSTATUS=0x{:08X}", status as u32);
                assert!(ret_len > 0, "ReturnLength should be > 0");
            }
        }
    }

    #[test]
    fn test_nt_query_system_information_basic() {
        // Query SystemBasicInformation (class 0) — should always succeed
        unsafe {
            ensure_ssns_resolved();

            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            {
                let mut buf = [0u8; 64];
                let mut ret_len: u32 = 0;
                let status = nt_query_system_information(
                    0,  // SystemBasicInformation
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut ret_len,
                );
                assert_eq!(status, 0,
                    "NtQuerySystemInformation(BasicInfo) failed: NTSTATUS=0x{:08X}", status as u32);
            }
        }
    }
}
