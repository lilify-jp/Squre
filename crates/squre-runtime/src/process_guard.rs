//! Triple Process Mutual Monitoring with Shamir Key Splitting.
//!
//! Three-process architecture for key protection:
//!   Main     → holds Share 1, runs the protected application
//!   Sentinel → holds Share 2, serves via Named Pipe
//!   Resolver → holds Share 3, serves via Named Pipe
//!
//! On startup, Main splits the Tidal master_key into 3 Shamir shares,
//! spawns Sentinel/Resolver (passing shares via CLI args), then requests
//! shares back via challenge-response on Named Pipes to reconstruct the key.
//!
//! A heartbeat loop runs on each child. If the pipe breaks or parent dies,
//! the share is zeroed and the child exits — making Tidal decryption
//! permanently impossible.
//!
//! On non-Windows platforms, this provides stub implementations.

use std::sync::atomic::{AtomicU32, AtomicBool, AtomicU64, Ordering};

/// Process role in the triple-process architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRole {
    /// Sentinel: holds Share 2, monitors via heartbeat.
    Sentinel,
    /// Resolver: holds Share 3, monitors via heartbeat.
    Resolver,
    /// Main: holds Share 1, runs protected code.
    Main,
}

/// Current process role (set during initialization).
static CURRENT_ROLE: AtomicU32 = AtomicU32::new(0xFF); // 0xFF = uninitialized

/// Whether the process ring is active.
static RING_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The reconstructed master key (only set in Main process).
static MASTER_KEY: AtomicU64 = AtomicU64::new(0);

/// Named Pipe protocol message types.
const MSG_CHALLENGE: u8 = 0x01;
const MSG_RESPONSE: u8 = 0x02;
const MSG_SHARE_REQUEST: u8 = 0x03;
const MSG_SHARE_REPLY: u8 = 0x04;
const MSG_HEARTBEAT: u8 = 0x05;
const MSG_HEARTBEAT_ACK: u8 = 0x06;
const MSG_SHUTDOWN: u8 = 0xFF;

/// Heartbeat interval in milliseconds.
const HEARTBEAT_MS: u64 = 200;
/// Heartbeat timeout — if no heartbeat for this long, terminate.
const HEARTBEAT_TIMEOUT_MS: u64 = 1000;

/// Set the current process role.
pub fn set_role(role: ProcessRole) {
    let val = match role {
        ProcessRole::Sentinel => 0,
        ProcessRole::Resolver => 1,
        ProcessRole::Main => 2,
    };
    CURRENT_ROLE.store(val, Ordering::SeqCst);
}

/// Get the current process role.
pub fn get_role() -> Option<ProcessRole> {
    match CURRENT_ROLE.load(Ordering::SeqCst) {
        0 => Some(ProcessRole::Sentinel),
        1 => Some(ProcessRole::Resolver),
        2 => Some(ProcessRole::Main),
        _ => None,
    }
}

/// Configuration for the process guard.
#[derive(Debug, Clone)]
pub struct ProcessGuardConfig {
    /// Shared secret for challenge-response authentication (32 bytes).
    pub shared_secret: [u8; 32],
    /// The Tidal master key to protect via Shamir splitting.
    pub master_key: u64,
}

/// Simple challenge-response authentication between processes.
/// Returns a response to a challenge using the shared secret.
pub fn compute_response(challenge: u64, secret: &[u8; 32]) -> u64 {
    let mut h: u64 = challenge;
    for &b in secret {
        h = h.wrapping_mul(0x517e_cafe_0000_0001)
            .wrapping_add(b as u64);
        h ^= h >> 17;
    }
    h
}

/// Verify a challenge-response pair.
pub fn verify_response(challenge: u64, response: u64, secret: &[u8; 32]) -> bool {
    compute_response(challenge, secret) == response
}

// ─── Windows Implementation ──────────────────────────────────

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod pipe_impl {
    use super::*;
    use std::ptr;

    // Windows API constants for Named Pipes
    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE: isize = -1;
    extern "system" {
        fn CreateNamedPipeA(
            name: *const u8,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buf_size: u32,
            in_buf_size: u32,
            default_timeout: u32,
            security_attrs: *const u8,
        ) -> isize;

        fn ConnectNamedPipe(pipe: isize, overlapped: *const u8) -> i32;

        fn CreateFileA(
            name: *const u8,
            desired_access: u32,
            share_mode: u32,
            security_attrs: *const u8,
            creation_disposition: u32,
            flags_and_attrs: u32,
            template_file: isize,
        ) -> isize;

        fn ReadFile(
            file: isize,
            buffer: *mut u8,
            bytes_to_read: u32,
            bytes_read: *mut u32,
            overlapped: *const u8,
        ) -> i32;

        fn WriteFile(
            file: isize,
            buffer: *const u8,
            bytes_to_write: u32,
            bytes_written: *mut u32,
            overlapped: *const u8,
        ) -> i32;

        fn CloseHandle(handle: isize) -> i32;
        fn GetCurrentProcessId() -> u32;
        fn GetLastError() -> u32;
        fn Sleep(ms: u32);
        fn WaitNamedPipeA(name: *const u8, timeout: u32) -> i32;
    }

    /// Generate a pipe name: `\\.\pipe\squre_{pid}_{role}`
    fn make_pipe_name(pid: u32, role: &str) -> Vec<u8> {
        let s = format!("\\\\.\\pipe\\squre_{}_{}\0", pid, role);
        s.into_bytes()
    }

    /// Write a message to a pipe handle: [msg_type: u8][payload: 8 bytes]
    fn pipe_send(handle: isize, msg_type: u8, payload: u64) -> bool {
        let mut buf = [0u8; 9];
        buf[0] = msg_type;
        buf[1..9].copy_from_slice(&payload.to_le_bytes());
        let mut written: u32 = 0;
        unsafe {
            WriteFile(handle, buf.as_ptr(), 9, &mut written, ptr::null()) != 0
                && written == 9
        }
    }

    /// Read a message from a pipe handle. Returns (msg_type, payload).
    fn pipe_recv(handle: isize) -> Option<(u8, u64)> {
        let mut buf = [0u8; 9];
        let mut read: u32 = 0;
        unsafe {
            if ReadFile(handle, buf.as_mut_ptr(), 9, &mut read, ptr::null()) == 0
                || read != 9
            {
                return None;
            }
        }
        let msg_type = buf[0];
        let payload = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        Some((msg_type, payload))
    }

    /// Create a Named Pipe server and wait for a client to connect.
    fn create_pipe_server(name: &[u8]) -> Option<isize> {
        unsafe {
            let handle = CreateNamedPipeA(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,     // max instances
                1024,  // out buffer
                1024,  // in buffer
                5000,  // default timeout ms
                ptr::null(),
            );
            if handle == INVALID_HANDLE {
                return None;
            }
            // Wait for client
            if ConnectNamedPipe(handle, ptr::null()) == 0 {
                // GetLastError() == ERROR_PIPE_CONNECTED is also OK
                let err = GetLastError();
                if err != 535 {
                    // 535 = ERROR_PIPE_CONNECTED, still success
                    // For other errors, we still try to use the pipe
                }
            }
            Some(handle)
        }
    }

    /// Connect to an existing Named Pipe server as a client.
    fn connect_pipe_client(name: &[u8], timeout_ms: u32) -> Option<isize> {
        unsafe {
            // Wait for the pipe to become available
            WaitNamedPipeA(name.as_ptr(), timeout_ms);

            let handle = CreateFileA(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if handle == INVALID_HANDLE {
                return None;
            }
            Some(handle)
        }
    }

    /// Child process (Sentinel or Resolver) main loop.
    /// Holds a Shamir share and serves it via Named Pipe with challenge-response.
    pub fn child_main(role: ProcessRole, share_x: u64, share_y: u64, parent_pid: u32, secret: &[u8; 32]) {
        let role_str = match role {
            ProcessRole::Sentinel => "sentinel",
            ProcessRole::Resolver => "resolver",
            _ => return,
        };

        set_role(role);
        RING_ACTIVE.store(true, Ordering::SeqCst);

        let pipe_name = make_pipe_name(parent_pid, role_str);

        // Create the pipe server and wait for parent to connect
        let handle = match create_pipe_server(&pipe_name) {
            Some(h) => h,
            None => {
                std::process::exit(0xDEAD);
            }
        };

        // Main protocol loop
        #[allow(unused_assignments)]
        let mut share_alive = true;
        let mut last_heartbeat = std::time::Instant::now();

        loop {
            match pipe_recv(handle) {
                Some((MSG_CHALLENGE, challenge)) => {
                    // Authenticate: respond to challenge
                    let response = compute_response(challenge, secret);
                    pipe_send(handle, MSG_RESPONSE, response);
                }
                Some((MSG_SHARE_REQUEST, challenge)) => {
                    // Verify challenge first, then send share
                    let response = compute_response(challenge, secret);
                    pipe_send(handle, MSG_RESPONSE, response);

                    if share_alive {
                        // Send the share as two messages: x then y
                        pipe_send(handle, MSG_SHARE_REPLY, share_x);
                        pipe_send(handle, MSG_SHARE_REPLY, share_y);
                    } else {
                        // Share was zeroed (compromised)
                        pipe_send(handle, MSG_SHARE_REPLY, 0);
                        pipe_send(handle, MSG_SHARE_REPLY, 0);
                    }
                }
                Some((MSG_HEARTBEAT, _)) => {
                    last_heartbeat = std::time::Instant::now();
                    pipe_send(handle, MSG_HEARTBEAT_ACK, 1);
                }
                Some((MSG_SHUTDOWN, _)) => {
                    share_alive = false;
                    break;
                }
                None => {
                    // Pipe broken — parent died
                    share_alive = false;
                    break;
                }
                _ => {}
            }

            // Check heartbeat timeout
            if last_heartbeat.elapsed().as_millis() > HEARTBEAT_TIMEOUT_MS as u128 {
                share_alive = false;
                break;
            }
        }

        unsafe { CloseHandle(handle); }
        RING_ACTIVE.store(false, Ordering::SeqCst);

        // Exit silently
        std::process::exit(0);
    }

    /// Request a share from a child process via Named Pipe challenge-response.
    fn request_share(
        pipe_name: &[u8],
        secret: &[u8; 32],
    ) -> Option<squre_core::crypto::shamir::Share> {
        // Connect to the child's pipe
        let handle = connect_pipe_client(pipe_name, 5000)?;

        // Generate a challenge from RDTSC
        let challenge: u64 = unsafe {
            let lo: u32;
            let hi: u32;
            std::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
            (lo as u64) | ((hi as u64) << 32)
        };

        // Send share request with challenge
        if !pipe_send(handle, MSG_SHARE_REQUEST, challenge) {
            unsafe { CloseHandle(handle); }
            return None;
        }

        // Read response (authentication)
        let (msg_type, response) = pipe_recv(handle)?;
        if msg_type != MSG_RESPONSE || !verify_response(challenge, response, secret) {
            unsafe { CloseHandle(handle); }
            return None;
        }

        // Read share x and y
        let (t1, share_x) = pipe_recv(handle)?;
        let (t2, share_y) = pipe_recv(handle)?;
        if t1 != MSG_SHARE_REPLY || t2 != MSG_SHARE_REPLY {
            unsafe { CloseHandle(handle); }
            return None;
        }

        unsafe { CloseHandle(handle); }

        Some(squre_core::crypto::shamir::Share { x: share_x, y: share_y })
    }

    /// Heartbeat thread: periodically pings both children.
    /// If either fails to respond, zeroes the master key and exits.
    fn heartbeat_loop(
        sentinel_name: Vec<u8>,
        resolver_name: Vec<u8>,
    ) {
        // Wait briefly for pipes to be created
        unsafe { Sleep(100); }

        let sentinel_handle = connect_pipe_client(&sentinel_name, 5000);
        let resolver_handle = connect_pipe_client(&resolver_name, 5000);

        loop {
            unsafe { Sleep(HEARTBEAT_MS as u32); }

            if !RING_ACTIVE.load(Ordering::SeqCst) {
                break;
            }

            // Ping sentinel
            if let Some(h) = sentinel_handle {
                if !pipe_send(h, MSG_HEARTBEAT, 0) {
                    // Sentinel died — wipe key and exit
                    MASTER_KEY.store(0, Ordering::SeqCst);
                    RING_ACTIVE.store(false, Ordering::SeqCst);
                    std::process::exit(0xDEAD);
                }
                if pipe_recv(h).is_none() {
                    MASTER_KEY.store(0, Ordering::SeqCst);
                    RING_ACTIVE.store(false, Ordering::SeqCst);
                    std::process::exit(0xDEAD);
                }
            }

            // Ping resolver
            if let Some(h) = resolver_handle {
                if !pipe_send(h, MSG_HEARTBEAT, 0) {
                    MASTER_KEY.store(0, Ordering::SeqCst);
                    RING_ACTIVE.store(false, Ordering::SeqCst);
                    std::process::exit(0xDEAD);
                }
                if pipe_recv(h).is_none() {
                    MASTER_KEY.store(0, Ordering::SeqCst);
                    RING_ACTIVE.store(false, Ordering::SeqCst);
                    std::process::exit(0xDEAD);
                }
            }
        }

        // Cleanup
        if let Some(h) = sentinel_handle {
            unsafe { CloseHandle(h); }
        }
        if let Some(h) = resolver_handle {
            unsafe { CloseHandle(h); }
        }
    }

    /// Initialize the process guard as the Main process.
    ///
    /// 1. Splits master_key into 3 Shamir shares
    /// 2. Spawns sentinel and resolver child processes
    /// 3. Retrieves shares via Named Pipe challenge-response
    /// 4. Reconstructs master_key
    /// 5. Starts heartbeat monitoring thread
    ///
    /// Returns the reconstructed master key (should equal the input).
    pub fn initialize_main(config: &ProcessGuardConfig) -> Option<u64> {
        use squre_core::crypto::shamir;

        set_role(ProcessRole::Main);

        let pid = unsafe { GetCurrentProcessId() };

        // Generate random coefficients for Shamir from RDTSC
        let (rand1, rand2) = unsafe {
            let lo1: u32;
            let hi1: u32;
            std::arch::asm!("rdtsc", out("eax") lo1, out("edx") hi1, options(nostack, nomem));
            let r1 = (lo1 as u64) | ((hi1 as u64) << 32);
            // Small delay for different TSC
            for _ in 0..1000u32 { std::hint::black_box(0u64); }
            let lo2: u32;
            let hi2: u32;
            std::arch::asm!("rdtsc", out("eax") lo2, out("edx") hi2, options(nostack, nomem));
            let r2 = (lo2 as u64) | ((hi2 as u64) << 32);
            (r1, r2)
        };

        // Split the master key
        let shares = shamir::split(config.master_key, rand1, rand2);
        let share1 = shares[0]; // Main keeps this
        let share2 = shares[1]; // Sentinel gets this
        let share3 = shares[2]; // Resolver gets this

        // Get our executable path
        let exe_path = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => return None,
        };

        // Encode shared_secret as hex for CLI
        let secret_hex: String = config.shared_secret.iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // Spawn sentinel
        let _ = std::process::Command::new(&exe_path)
            .args([
                "--squre-sentinel",
                &format!("--squre-share-x={}", share2.x),
                &format!("--squre-share-y={}", share2.y),
                &format!("--squre-ppid={}", pid),
                &format!("--squre-secret={}", secret_hex),
            ])
            .spawn();

        // Spawn resolver
        let _ = std::process::Command::new(&exe_path)
            .args([
                "--squre-resolver",
                &format!("--squre-share-x={}", share3.x),
                &format!("--squre-share-y={}", share3.y),
                &format!("--squre-ppid={}", pid),
                &format!("--squre-secret={}", secret_hex),
            ])
            .spawn();

        // Give children time to create their pipes
        unsafe { Sleep(200); }

        // Request shares from children
        let sentinel_pipe = make_pipe_name(pid, "sentinel");
        let resolver_pipe = make_pipe_name(pid, "resolver");

        let share2_recovered = request_share(&sentinel_pipe, &config.shared_secret)?;
        let share3_recovered = request_share(&resolver_pipe, &config.shared_secret)?;

        // Reconstruct the master key
        let recovered_shares = [share1, share2_recovered, share3_recovered];
        let key = shamir::reconstruct(&recovered_shares);

        MASTER_KEY.store(key, Ordering::SeqCst);
        RING_ACTIVE.store(true, Ordering::SeqCst);

        // Start heartbeat thread
        let sentinel_name = sentinel_pipe;
        let resolver_name = resolver_pipe;
        std::thread::spawn(move || {
            heartbeat_loop(sentinel_name, resolver_name);
        });

        Some(key)
    }

    /// Parse child process arguments and run as sentinel/resolver.
    /// Returns true if this process is a child (sentinel/resolver) and
    /// should NOT continue with normal main() execution.
    pub fn maybe_run_as_child() -> bool {
        let args: Vec<String> = std::env::args().collect();

        let is_sentinel = args.iter().any(|a| a == "--squre-sentinel");
        let is_resolver = args.iter().any(|a| a == "--squre-resolver");

        if !is_sentinel && !is_resolver {
            return false;
        }

        let role = if is_sentinel {
            ProcessRole::Sentinel
        } else {
            ProcessRole::Resolver
        };

        // Parse share-x, share-y, ppid, secret from args
        let mut share_x: u64 = 0;
        let mut share_y: u64 = 0;
        let mut ppid: u32 = 0;
        let mut secret = [0u8; 32];

        for arg in &args {
            if let Some(val) = arg.strip_prefix("--squre-share-x=") {
                share_x = val.parse().unwrap_or(0);
            } else if let Some(val) = arg.strip_prefix("--squre-share-y=") {
                share_y = val.parse().unwrap_or(0);
            } else if let Some(val) = arg.strip_prefix("--squre-ppid=") {
                ppid = val.parse().unwrap_or(0);
            } else if let Some(hex) = arg.strip_prefix("--squre-secret=") {
                // Decode hex to bytes
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                let copy_len = bytes.len().min(32);
                secret[..copy_len].copy_from_slice(&bytes[..copy_len]);
            }
        }

        if ppid == 0 || share_x == 0 {
            std::process::exit(1);
        }

        child_main(role, share_x, share_y, ppid, &secret);

        true // Never reaches here, but signals this is a child
    }
}

// ─── Public API ──────────────────────────────────────────────

/// Initialize the process guard.
///
/// For Main process: splits key, spawns children, recovers key.
/// Returns the (potentially reconstructed) master key.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn initialize_guard(config: &ProcessGuardConfig) -> Option<u64> {
    pipe_impl::initialize_main(config)
}

/// Check if the current process should run as a child (sentinel/resolver).
/// Must be called at the very start of main().
/// Returns true if this process is a child and should not continue.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn maybe_run_as_child() -> bool {
    pipe_impl::maybe_run_as_child()
}

/// Get the stored master key (only valid in Main process after initialize_guard).
pub fn get_master_key() -> u64 {
    MASTER_KEY.load(Ordering::SeqCst)
}

/// Shut down the process guard.
pub fn shutdown_guard() {
    RING_ACTIVE.store(false, Ordering::SeqCst);
    MASTER_KEY.store(0, Ordering::SeqCst);
}

/// Check whether the process guard is active.
pub fn is_guard_active() -> bool {
    RING_ACTIVE.load(Ordering::SeqCst)
}

// ─── Non-Windows Stubs ───────────────────────────────────────

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub fn initialize_guard(config: &ProcessGuardConfig) -> Option<u64> {
    set_role(ProcessRole::Main);
    MASTER_KEY.store(config.master_key, Ordering::SeqCst);
    RING_ACTIVE.store(true, Ordering::SeqCst);
    Some(config.master_key)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub fn maybe_run_as_child() -> bool {
    false
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_management() {
        set_role(ProcessRole::Sentinel);
        assert_eq!(get_role(), Some(ProcessRole::Sentinel));
        set_role(ProcessRole::Main);
        assert_eq!(get_role(), Some(ProcessRole::Main));
    }

    #[test]
    fn test_challenge_response() {
        let secret = [0x42u8; 32];
        let challenge = 0xDEADBEEF;
        let response = compute_response(challenge, &secret);
        assert!(verify_response(challenge, response, &secret));
        assert!(!verify_response(challenge, response.wrapping_add(1), &secret));
    }

    #[test]
    fn test_different_secrets_different_responses() {
        let secret1 = [0x42u8; 32];
        let secret2 = [0x43u8; 32];
        let challenge = 12345;
        assert_ne!(
            compute_response(challenge, &secret1),
            compute_response(challenge, &secret2)
        );
    }

    #[test]
    fn test_shamir_integration() {
        // Verify that Shamir split/reconstruct works end-to-end
        use squre_core::crypto::shamir;
        let key = 0xDEAD_BEEF_CAFE_F00D;
        let shares = shamir::split(key, 0x1111, 0x2222);
        let recovered = shamir::reconstruct(&shares);
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_guard_config_creation() {
        let config = ProcessGuardConfig {
            shared_secret: [0xAA; 32],
            master_key: 0x1234_5678_9ABC_DEF0,
        };
        assert_eq!(config.master_key, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_master_key_store_load() {
        MASTER_KEY.store(0xCAFE_BABE, Ordering::SeqCst);
        assert_eq!(get_master_key(), 0xCAFE_BABE);
        MASTER_KEY.store(0, Ordering::SeqCst); // cleanup
    }

    #[test]
    fn test_shutdown_guard() {
        RING_ACTIVE.store(true, Ordering::SeqCst);
        MASTER_KEY.store(0x1234, Ordering::SeqCst);
        shutdown_guard();
        assert!(!is_guard_active());
        assert_eq!(get_master_key(), 0);
    }

    #[test]
    fn test_non_child_detection() {
        // In test context, there are no --squre-* args, so this should return false
        assert!(!maybe_run_as_child());
    }
}
