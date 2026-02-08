//! Anti-debugging checks for Windows.
//!
//! These checks detect common debugging techniques and return a "poison"
//! value. Instead of crashing (which reveals the check), the poison is
//! mixed into MBA calculations to produce subtly wrong results.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global poison value. Non-zero when a debugger is detected.
/// Mixed into MBA calculations to corrupt results silently.
pub static ANTI_DEBUG_POISON: AtomicU64 = AtomicU64::new(0);

/// Run all anti-debug checks. Returns the combined poison value.
/// The return value is 0 if clean, non-zero if debugger detected.
#[inline(always)]
pub fn run_all_checks() -> u64 {
    // Ensure direct-syscall SSNs are resolved (idempotent).
    // Must happen from .text before encryption.
    unsafe { crate::syscall::ensure_ssns_resolved(); }

    let mut poison: u64 = 0;

    poison |= check_peb_debugger();
    poison |= check_timing();
    poison |= check_hardware_breakpoints();
    poison |= check_process_debug_port();
    poison |= check_debug_object_handle();
    poison |= check_system_kernel_debugger();
    poison |= check_peb_ntglobalflag();
    poison |= check_heap_flags();
    poison |= check_process_debug_flags();

    ANTI_DEBUG_POISON.store(poison, Ordering::Relaxed);
    poison
}

/// Check PEB.BeingDebugged flag directly via TEB.
/// Does NOT call IsDebuggerPresent (avoids API hooking).
#[inline(always)]
pub fn check_peb_debugger() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let peb_addr: u64;
            let being_debugged: u64;
            std::arch::asm!(
                "mov {peb}, gs:[0x60]",
                "movzx {out}, byte ptr [{peb} + 0x02]",
                peb = out(reg) peb_addr,
                out = out(reg) being_debugged,
                options(nostack, preserves_flags),
            );
            let _ = peb_addr;
            if being_debugged != 0 {
                return 0xDEAD_0001_u64;
            }
        }
    }
    0
}

/// Timing-based debugger detection.
/// Measures execution time of a tight loop. Under a debugger with
/// single-stepping, this takes orders of magnitude longer.
#[inline(always)]
pub fn check_timing() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let start: u64;
            let end: u64;
            let _rdx1: u64;
            let _rdx2: u64;
            std::arch::asm!(
                "rdtsc",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") start,
                out("rdx") _rdx1,
                options(nostack, nomem),
            );

            // Dummy computation (should take < 1000 cycles normally)
            let mut dummy: u64 = 0;
            for i in 0..100u64 {
                dummy = dummy.wrapping_add(i).wrapping_mul(7);
            }
            std::hint::black_box(dummy);

            std::arch::asm!(
                "rdtsc",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") end,
                out("rdx") _rdx2,
                options(nostack, nomem),
            );

            let elapsed = end.wrapping_sub(start);
            // Normal: < 10,000 cycles. Debugger step: >> 100,000 cycles.
            if elapsed > 100_000 {
                return 0xDEAD_0002_u64;
            }
        }
    }
    0
}

/// Check for hardware breakpoints via debug registers.
/// Uses NtGetContextThread direct syscall — no LoadLibrary/GetProcAddress needed.
#[inline(always)]
pub fn check_hardware_breakpoints() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        // x86_64 CONTEXT layout:
        //   ContextFlags at offset 0x30 (48)
        //   Dr0 at offset 0x68 (104), Dr1 at 0x70, Dr2 at 0x78, Dr3 at 0x80
        // CONTEXT_DEBUG_REGISTERS on x86_64 = 0x00100010
        const CTX_DEBUG_REGS: u32 = 0x0010_0010;
        const CTX_SIZE: usize = 1232;

        unsafe {
            #[repr(C, align(16))]
            struct RawContext {
                data: [u8; CTX_SIZE],
            }

            let mut ctx = RawContext { data: [0u8; CTX_SIZE] };

            // Set ContextFlags at offset 0x30
            let flags_ptr = ctx.data.as_mut_ptr().add(0x30) as *mut u32;
            *flags_ptr = CTX_DEBUG_REGS;

            // Direct syscall NtGetContextThread — bypasses any API hooks.
            // GetCurrentThread() pseudo-handle = -2.
            let status = crate::syscall::nt_get_context_thread(
                -2isize,
                ctx.data.as_mut_ptr(),
            );
            if status == 0 {
                let dr0 = *(ctx.data.as_ptr().add(0x68) as *const u64);
                let dr1 = *(ctx.data.as_ptr().add(0x70) as *const u64);
                let dr2 = *(ctx.data.as_ptr().add(0x78) as *const u64);
                let dr3 = *(ctx.data.as_ptr().add(0x80) as *const u64);

                if dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 {
                    return 0xDEAD_0003_u64;
                }
            }
        }
    }
    0
}

/// Check ProcessDebugPort via NtQueryInformationProcess(7).
/// The kernel sets this to a non-zero value when a debugger is attached.
/// Unlike PEB.BeingDebugged, this cannot be patched from user mode.
#[inline(always)]
pub fn check_process_debug_port() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let mut debug_port: u64 = 0;
            let mut ret_len: u32 = 0;
            let status = crate::syscall::nt_query_information_process(
                7,  // ProcessDebugPort
                (&mut debug_port) as *mut u64 as *mut u8,
                core::mem::size_of::<u64>() as u32,
                &mut ret_len,
            );
            // STATUS_SUCCESS and debug_port != 0 → debugger attached
            if status == 0 && debug_port != 0 {
                return 0xDEAD_0004_u64;
            }
        }
    }
    0
}

/// Check DebugObjectHandle via NtQueryInformationProcess(0x1E).
/// When a debugger is attached, a debug object handle exists.
/// Returns STATUS_PORT_NOT_SET (0xC0000353) if no debugger.
#[inline(always)]
pub fn check_debug_object_handle() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let mut debug_handle: u64 = 0;
            let mut ret_len: u32 = 0;
            let status = crate::syscall::nt_query_information_process(
                0x1E,  // ProcessDebugObjectHandle
                (&mut debug_handle) as *mut u64 as *mut u8,
                core::mem::size_of::<u64>() as u32,
                &mut ret_len,
            );
            // STATUS_SUCCESS means a debug object exists → debugger attached
            // STATUS_PORT_NOT_SET (0xC0000353) means no debugger — that's clean
            if status == 0 {
                return 0xDEAD_0005_u64;
            }
        }
    }
    0
}

/// Check SystemKernelDebuggerInformation via NtQuerySystemInformation(0x23).
/// Detects if a kernel debugger (WinDbg, etc.) is connected to the system.
#[inline(always)]
pub fn check_system_kernel_debugger() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            // SYSTEM_KERNEL_DEBUGGER_INFORMATION: { DebuggerEnabled: u8, DebuggerNotPresent: u8 }
            let mut info = [0u8; 2];
            let mut ret_len: u32 = 0;
            let status = crate::syscall::nt_query_system_information(
                0x23,  // SystemKernelDebuggerInformation
                info.as_mut_ptr(),
                info.len() as u32,
                &mut ret_len,
            );
            if status == 0 {
                let debugger_enabled = info[0];
                let debugger_not_present = info[1];
                // Poison if debugger is enabled AND present
                if debugger_enabled != 0 && debugger_not_present == 0 {
                    return 0xDEAD_0006_u64;
                }
            }
        }
    }
    0
}

/// Check PEB.NtGlobalFlag at offset 0xBC (x64).
/// When a process is created under a debugger, the OS sets heap debug flags:
///   FLG_HEAP_ENABLE_TAIL_CHECK  (0x10)
///   FLG_HEAP_ENABLE_FREE_CHECK  (0x20)
///   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
/// Combined = 0x70
#[inline(always)]
pub fn check_peb_ntglobalflag() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let peb: u64;
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, preserves_flags),
            );
            if peb != 0 {
                // NtGlobalFlag is at PEB + 0xBC on x64
                let nt_global_flag = *((peb as *const u8).add(0xBC) as *const u32);
                if nt_global_flag & 0x70 != 0 {
                    return 0xDEAD_0007_u64;
                }
            }
        }
    }
    0
}

/// Check process heap flags for debugger artifacts.
/// When started under a debugger, the default heap has:
///   Flags |= HEAP_TAIL_CHECKING_ENABLED (0x20) | HEAP_FREE_CHECKING_ENABLED (0x40)
///   ForceFlags |= same
/// Heap base is at PEB+0x30 (ProcessHeap pointer on x64).
/// Heap.Flags at +0x70, Heap.ForceFlags at +0x74 (Windows 10/11 ntdll heap).
#[inline(always)]
pub fn check_heap_flags() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let peb: u64;
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, preserves_flags),
            );
            if peb != 0 {
                // PEB+0x30 = ProcessHeap (pointer to default heap)
                let process_heap = *((peb as *const u8).add(0x30) as *const u64);
                if process_heap != 0 {
                    // On Windows 10/11 x64:
                    //   Heap.Flags at offset 0x70
                    //   Heap.ForceFlags at offset 0x74
                    let flags = *((process_heap as *const u8).add(0x70) as *const u32);
                    let force_flags = *((process_heap as *const u8).add(0x74) as *const u32);

                    // Normal process: Flags = 0x02 (HEAP_GROWABLE), ForceFlags = 0
                    // Under debugger: Flags |= 0x60, ForceFlags |= 0x60
                    if force_flags != 0 {
                        return 0xDEAD_0008_u64;
                    }
                    // Also check Flags for the debug-specific bits
                    if flags & 0x60 != 0 {
                        return 0xDEAD_0008_u64;
                    }
                }
            }
        }
    }
    0
}

/// Check ProcessDebugFlags via NtQueryInformationProcess(0x1F).
/// When a process is created under a debugger, the NoDebugInherit flag is 0.
/// Normal process: returns non-zero. Under debugger: returns 0.
/// This is a kernel-level check — cannot be patched from user mode.
#[inline(always)]
pub fn check_process_debug_flags() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        unsafe {
            let mut debug_flags: u32 = 0;
            let mut ret_len: u32 = 0;
            let status = crate::syscall::nt_query_information_process(
                0x1F,  // ProcessDebugFlags
                (&mut debug_flags) as *mut u32 as *mut u8,
                core::mem::size_of::<u32>() as u32,
                &mut ret_len,
            );
            // STATUS_SUCCESS and debug_flags == 0 → debugger attached
            if status == 0 && debug_flags == 0 {
                return 0xDEAD_0009_u64;
            }
        }
    }
    0
}

/// Get the current poison value (for mixing into MBA calculations).
#[inline(always)]
pub fn get_poison() -> u64 {
    ANTI_DEBUG_POISON.load(Ordering::Relaxed)
}
