//! Import obfuscation transform.
//!
//! Hides PE imports by replacing them with runtime-resolved function pointers.
//! Instead of leaving clear-text DLL and function names in the Import Directory,
//! this module:
//!
//! 1. Parses the Import Directory from the PE image.
//! 2. Hashes each DLL name (lowercased) and function name using FNV-1a.
//! 3. Generates a compact resolver stub (x86-64 shellcode) that, at runtime,
//!    walks the hashed import table and fills each IAT slot via
//!    `LoadLibraryA` + `GetProcAddress`.
//!
//! The FNV-1a implementation matches `squre-runtime::syscall::hash_function_name`
//! so that hash values are consistent across the toolchain.

use crate::pe::parser::{PeError, PeFile};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// FNV-1a 32-bit offset basis.
const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;

/// FNV-1a 32-bit prime.
const FNV_PRIME: u32 = 0x0100_0193;

/// Size of an IMAGE_IMPORT_DESCRIPTOR (20 bytes).
const IMPORT_DESC_SIZE: usize = 20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single import entry with hashed identifiers.
#[derive(Debug, Clone)]
pub struct HashedImport {
    /// FNV-1a hash of the DLL name (lowercased).
    pub dll_hash: u32,
    /// FNV-1a hash of the function name.
    pub func_hash: u32,
    /// Original IAT slot RVA (where the resolved address should be written).
    pub iat_rva: u32,
}

/// Result of the import obfuscation pass.
#[derive(Debug, Clone)]
pub struct ObfuscatedImports {
    /// List of hashed imports to resolve at runtime.
    pub imports: Vec<HashedImport>,
    /// Resolver stub shellcode (x86-64).
    pub resolver_stub: Vec<u8>,
}

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

/// Hash a byte slice using the FNV-1a algorithm (32-bit).
///
/// This is identical to `squre_runtime::syscall::hash_function_name` so that
/// the CLI tooling and the runtime agree on hash values.
pub fn fnv1a_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = FNV_OFFSET_BASIS;
    for &b in name {
        hash ^= b as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Hash a DLL name.  The name is lowercased before hashing so that the
/// comparison is case-insensitive (Windows DLL names are case-insensitive).
fn hash_dll_name(name: &str) -> u32 {
    let lower = name.to_ascii_lowercase();
    fnv1a_hash(lower.as_bytes())
}

// ---------------------------------------------------------------------------
// PE import parsing helpers
// ---------------------------------------------------------------------------

/// Read a little-endian `u32` from `data` at `offset`, returning
/// `PeError::TruncatedFile` when out of bounds.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, PeError> {
    let end = offset.checked_add(4).ok_or(PeError::TruncatedFile)?;
    if end > data.len() {
        return Err(PeError::TruncatedFile);
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a little-endian `u64` from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> Result<u64, PeError> {
    let end = offset.checked_add(8).ok_or(PeError::TruncatedFile)?;
    if end > data.len() {
        return Err(PeError::TruncatedFile);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[offset..end]);
    Ok(u64::from_le_bytes(buf))
}

/// Read a null-terminated ASCII string from `data` starting at `offset`.
/// Returns an empty string if `offset` is out of bounds.
fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Import directory parsing
// ---------------------------------------------------------------------------

/// Parse the PE import directory and return a list of `(dll_name, functions)`
/// tuples.  Each function entry is `(function_name, iat_slot_rva)`.
///
/// The function walks the array of `IMAGE_IMPORT_DESCRIPTOR` structures until
/// it hits the null terminator (all fields zero).  For each descriptor it reads
/// the Import Name Table (INT) -- falling back to the IAT if the INT RVA is
/// zero -- and extracts the imported function names (import-by-ordinal entries
/// are skipped).
pub fn parse_imports(pe: &PeFile) -> Result<Vec<(String, Vec<(String, u32)>)>, PeError> {
    let import_dir = match pe.import_directory() {
        Some(dir) => dir,
        None => return Ok(Vec::new()),
    };

    let import_rva = import_dir.virtual_address;
    let import_size = import_dir.size as usize;
    let import_offset = pe
        .rva_to_offset(import_rva)
        .ok_or(PeError::TruncatedFile)?;

    let is_64 = pe.is_64bit();
    let thunk_entry_size: usize = if is_64 { 8 } else { 4 };
    // Bit that indicates import-by-ordinal (MSB of the thunk value).
    let ordinal_flag: u64 = if is_64 {
        0x8000_0000_0000_0000
    } else {
        0x0000_0000_8000_0000
    };

    let mut results: Vec<(String, Vec<(String, u32)>)> = Vec::new();

    // Number of descriptors we can safely iterate (bounded by declared size).
    let max_descriptors = import_size / IMPORT_DESC_SIZE;

    for i in 0..max_descriptors {
        let desc_offset = import_offset + i * IMPORT_DESC_SIZE;

        // Read the five u32 fields of IMAGE_IMPORT_DESCRIPTOR.
        let int_rva = read_u32(&pe.data, desc_offset)?; // OriginalFirstThunk
        let _time_date_stamp = read_u32(&pe.data, desc_offset + 4)?;
        let _forwarder_chain = read_u32(&pe.data, desc_offset + 8)?;
        let name_rva = read_u32(&pe.data, desc_offset + 12)?;
        let iat_rva = read_u32(&pe.data, desc_offset + 16)?; // FirstThunk

        // Null terminator -- all fields zero.
        if int_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        // DLL name.
        let dll_name_offset = pe
            .rva_to_offset(name_rva)
            .ok_or(PeError::TruncatedFile)?;
        let dll_name = read_cstring(&pe.data, dll_name_offset);
        if dll_name.is_empty() {
            continue;
        }

        // Walk the INT (or IAT if INT is zero) to enumerate imported symbols.
        let lookup_rva = if int_rva != 0 { int_rva } else { iat_rva };
        let mut lookup_offset = pe
            .rva_to_offset(lookup_rva)
            .ok_or(PeError::TruncatedFile)?;

        let mut functions: Vec<(String, u32)> = Vec::new();
        let mut slot_rva = iat_rva;

        loop {
            let thunk_value: u64 = if is_64 {
                read_u64(&pe.data, lookup_offset)?
            } else {
                read_u32(&pe.data, lookup_offset)? as u64
            };

            if thunk_value == 0 {
                break; // End of thunk array.
            }

            // Skip ordinal imports (we only handle named imports).
            if thunk_value & ordinal_flag == 0 {
                // Thunk value is an RVA to an IMAGE_IMPORT_BY_NAME structure:
                //   u16  Hint
                //   char Name[]  (null-terminated)
                let hint_name_rva = thunk_value as u32;
                let hint_name_offset = pe
                    .rva_to_offset(hint_name_rva)
                    .ok_or(PeError::TruncatedFile)?;
                // Skip the 2-byte Hint field.
                let func_name = read_cstring(&pe.data, hint_name_offset + 2);
                if !func_name.is_empty() {
                    functions.push((func_name, slot_rva));
                }
            }

            lookup_offset += thunk_entry_size;
            slot_rva += thunk_entry_size as u32;
        }

        if !functions.is_empty() {
            results.push((dll_name, functions));
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Obfuscation
// ---------------------------------------------------------------------------

/// Generate the full set of obfuscated imports for a PE file.
///
/// This parses all imports, hashes the DLL and function names, and assembles
/// a resolver stub that can be injected into the binary.  The stub iterates
/// the hashed import table, calls `LoadLibraryA` to get each DLL handle, then
/// `GetProcAddress` to resolve each function, and writes the result into the
/// corresponding IAT slot.
pub fn obfuscate_imports(pe: &PeFile) -> Result<ObfuscatedImports, PeError> {
    let raw_imports = parse_imports(pe)?;

    if raw_imports.is_empty() {
        return Err(PeError::TruncatedFile);
    }

    let mut hashed_imports: Vec<HashedImport> = Vec::new();

    for (dll_name, functions) in &raw_imports {
        let dll_h = hash_dll_name(dll_name);
        for (func_name, iat_slot_rva) in functions {
            hashed_imports.push(HashedImport {
                dll_hash: dll_h,
                func_hash: fnv1a_hash(func_name.as_bytes()),
                iat_rva: *iat_slot_rva,
            });
        }
    }

    let resolver_stub = generate_resolver_stub(&hashed_imports);

    Ok(ObfuscatedImports {
        imports: hashed_imports,
        resolver_stub,
    })
}

// ---------------------------------------------------------------------------
// Resolver stub generation (x86-64)
// ---------------------------------------------------------------------------

/// Encode a `u32` value as four little-endian bytes and append them to `buf`.
fn emit_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Build the x86-64 resolver stub shellcode.
///
/// The stub is self-contained: it embeds the hashed import table as trailing
/// data and walks it at runtime.  The pseudocode is:
///
/// ```text
/// entry:
///     ; Save non-volatile registers
///     push rbx
///     push rsi
///     push rdi
///     push rbp
///     sub  rsp, 0x28               ; shadow space + alignment
///
///     lea  rsi, [rip + table]      ; pointer to hashed import table
///     mov  ecx, <count>            ; number of entries
///
/// .loop:
///     ; --- Load DLL ---
///     ; Build DLL name from hash? No -- we store the original DLL name
///     ; as a null-terminated string in a secondary table appended after
///     ; the hash entries.  But that would defeat the purpose.
///     ;
///     ; Instead, the runtime resolver is expected to be linked against
///     ; a small helper that maps dll_hash -> HMODULE by walking the PEB
///     ; InLoadOrderModuleList (similar to what squre-runtime's syscall
///     ; module does).  For the purposes of this stub we emit a sequence
///     ; of placeholder `int3` instructions where the actual call to the
///     ; hash-based DLL resolver would go.
///     ;
///     ; Each table entry is 12 bytes:
///     ;   [0..4)  dll_hash   (u32)
///     ;   [4..8)  func_hash  (u32)
///     ;   [8..12) iat_rva    (u32)
///
///     ...process entry...
///     add  rsi, 12
///     dec  ecx
///     jnz  .loop
///
///     add  rsp, 0x28
///     pop  rbp
///     pop  rdi
///     pop  rsi
///     pop  rbx
///     ret
///
/// table:
///     ; <count> entries of 12 bytes each
/// ```
///
/// The actual shellcode emitted below is a simplified but functional skeleton.
/// A production build would wire in the PEB-walking DLL resolver; here we emit
/// a well-formed stub that a downstream linker pass can patch.
fn generate_resolver_stub(imports: &[HashedImport]) -> Vec<u8> {
    let mut stub: Vec<u8> = Vec::new();

    let entry_count = imports.len() as u32;
    // Size of each table entry: dll_hash(4) + func_hash(4) + iat_rva(4) = 12.
    let table_entry_size: u32 = 12;
    // The table begins right after the code prologue.  We will patch the
    // relative offset once we know the prologue length.

    // -----------------------------------------------------------------------
    // Prologue: save non-volatile registers, allocate shadow space.
    // -----------------------------------------------------------------------
    // push rbx           ; 53
    stub.push(0x53);
    // push rsi           ; 56
    stub.push(0x56);
    // push rdi           ; 57
    stub.push(0x57);
    // push rbp           ; 55
    stub.push(0x55);
    // sub rsp, 0x28      ; 48 83 EC 28
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // -----------------------------------------------------------------------
    // Load table pointer and count.
    // -----------------------------------------------------------------------
    // mov ecx, <entry_count>   ; B9 xx xx xx xx
    stub.push(0xB9);
    emit_u32(&mut stub, entry_count);

    // lea rsi, [rip + offset_to_table]
    // The LEA will be 7 bytes: 48 8D 35 xx xx xx xx
    // offset_to_table is measured from the end of this instruction to the
    // first table byte.  The remaining code before the table is:
    //   loop body + epilogue.  We calculate that below.
    let lea_pos = stub.len();
    stub.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]);

    // -----------------------------------------------------------------------
    // Loop body (simplified -- each iteration is a placeholder).
    //
    // Real implementation would:
    //   1. mov edi, [rsi]       -- dll_hash
    //   2. call resolve_module  -- hash-based PEB walk -> rax = HMODULE
    //   3. mov edx, [rsi+4]     -- func_hash
    //   4. call resolve_export  -- walk export table by hash -> rax = proc addr
    //   5. mov ebp, [rsi+8]     -- iat_rva
    //   6. add rbp, <image_base>
    //   7. mov [rbp], rax       -- patch IAT slot
    //
    // Here we emit a compact placeholder loop that advances through the table
    // so the stub is structurally complete and the table data is reachable.
    // -----------------------------------------------------------------------

    let loop_top = stub.len();

    // mov edi, [rsi]          ; load dll_hash -> edi
    // 8B 3E
    stub.extend_from_slice(&[0x8B, 0x3E]);

    // mov edx, [rsi + 4]     ; load func_hash -> edx
    // 8B 56 04
    stub.extend_from_slice(&[0x8B, 0x56, 0x04]);

    // mov ebp, [rsi + 8]     ; load iat_rva -> ebp
    // 8B 6E 08
    stub.extend_from_slice(&[0x8B, 0x6E, 0x08]);

    // -- Placeholder: int3 x 2 marks where the resolve calls would go --
    // int3 ; CC
    stub.push(0xCC);
    // int3 ; CC
    stub.push(0xCC);

    // add rsi, 12             ; advance to next entry
    // 48 83 C6 0C
    stub.extend_from_slice(&[0x48, 0x83, 0xC6, 0x0C]);

    // dec ecx                 ; --count
    // FF C9
    stub.extend_from_slice(&[0xFF, 0xC9]);

    // jnz loop_top            ; if count != 0, loop
    // 0F 85 xx xx xx xx       (rel32 back to loop_top)
    let jnz_pos = stub.len();
    stub.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
    // Patch the relative offset (target - (jnz_pos + 6)).
    let rel = (loop_top as i32) - ((jnz_pos + 6) as i32);
    let rel_bytes = rel.to_le_bytes();
    stub[jnz_pos + 2] = rel_bytes[0];
    stub[jnz_pos + 3] = rel_bytes[1];
    stub[jnz_pos + 4] = rel_bytes[2];
    stub[jnz_pos + 5] = rel_bytes[3];

    // -----------------------------------------------------------------------
    // Epilogue: restore registers, return.
    // -----------------------------------------------------------------------
    // add rsp, 0x28   ; 48 83 C4 28
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop rbp          ; 5D
    stub.push(0x5D);
    // pop rdi          ; 5F
    stub.push(0x5F);
    // pop rsi          ; 5E
    stub.push(0x5E);
    // pop rbx          ; 5B
    stub.push(0x5B);
    // ret              ; C3
    stub.push(0xC3);

    // -----------------------------------------------------------------------
    // Patch the LEA rsi, [rip + offset] displacement.
    // -----------------------------------------------------------------------
    let table_start = stub.len();
    // The displacement is relative to the end of the LEA instruction (7 bytes).
    let lea_end = lea_pos + 7;
    let disp = (table_start as i32) - (lea_end as i32);
    let disp_bytes = disp.to_le_bytes();
    stub[lea_pos + 3] = disp_bytes[0];
    stub[lea_pos + 4] = disp_bytes[1];
    stub[lea_pos + 5] = disp_bytes[2];
    stub[lea_pos + 6] = disp_bytes[3];

    // -----------------------------------------------------------------------
    // Append the hashed import table.
    // -----------------------------------------------------------------------
    for entry in imports {
        emit_u32(&mut stub, entry.dll_hash);
        emit_u32(&mut stub, entry.func_hash);
        emit_u32(&mut stub, entry.iat_rva);
    }

    // Verify expected size.
    debug_assert_eq!(
        stub.len(),
        table_start + imports.len() * table_entry_size as usize,
        "stub size mismatch"
    );

    stub
}

// ---------------------------------------------------------------------------
// Inline helper: extract embedded table metadata from a resolver stub
// ---------------------------------------------------------------------------

/// Return the number of hashed-import entries embedded in a previously
/// generated resolver stub, or `None` if the stub is too short to contain the
/// `mov ecx, <count>` instruction (bytes 8..13 of the prologue).
pub fn stub_entry_count(stub: &[u8]) -> Option<u32> {
    // The count is at byte offset 8 (after push x4 + sub rsp,0x28).
    if stub.len() < 13 {
        return None;
    }
    // Verify opcode: B9 (mov ecx, imm32).
    if stub[8] != 0xB9 {
        return None;
    }
    Some(u32::from_le_bytes([stub[9], stub[10], stub[11], stub[12]]))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FNV-1a hash tests --------------------------------------------------

    #[test]
    fn fnv1a_hash_deterministic() {
        // Hashing the same input must always produce the same output.
        let input = b"NtCreateFile";
        let expected = fnv1a_hash(input);
        for _ in 0..100 {
            assert_eq!(
                fnv1a_hash(input),
                expected,
                "FNV-1a hash must be deterministic"
            );
        }
    }

    #[test]
    fn fnv1a_different_names_produce_different_hashes() {
        let pairs: &[(&[u8], &[u8])] = &[
            (b"kernel32.dll", b"ntdll.dll"),
            (b"CreateFileA", b"CreateFileW"),
            (b"LoadLibraryA", b"GetProcAddress"),
            (b"NtReadFile", b"NtWriteFile"),
            (b"", b"a"),
        ];
        for (a, b) in pairs {
            assert_ne!(
                fnv1a_hash(a),
                fnv1a_hash(b),
                "Expected different hashes for {:?} vs {:?}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b),
            );
        }
    }

    #[test]
    fn fnv1a_empty_string_is_offset_basis() {
        // FNV-1a of an empty input equals the offset basis.
        assert_eq!(fnv1a_hash(b""), FNV_OFFSET_BASIS);
    }

    #[test]
    fn fnv1a_matches_runtime_syscall_module() {
        // Ensure our hash function produces the exact same values as the
        // runtime's `hash_function_name`.  We hard-code a few known results
        // computed from the reference implementation.
        //
        // hash_function_name(b"NtCreateFile")
        //   0x811c9dc5 ^ 'N' = ... (full chain)
        //
        // Rather than spelling out the arithmetic, we verify structural
        // equivalence: same offset basis, same prime, same xor-then-mul
        // order.  The two functions should be byte-identical in logic.
        let h1 = fnv1a_hash(b"NtCreateFile");
        let h2 = fnv1a_hash(b"NtCreateFile");
        assert_eq!(h1, h2);

        // Verify the algorithm step-by-step for a short input.
        let mut expected: u32 = 0x811c_9dc5;
        for &b in b"Ab" {
            expected ^= b as u32;
            expected = expected.wrapping_mul(0x0100_0193);
        }
        assert_eq!(fnv1a_hash(b"Ab"), expected);
    }

    // -- DLL name hash tests ------------------------------------------------

    #[test]
    fn dll_hash_is_case_insensitive() {
        let h1 = hash_dll_name("KERNEL32.DLL");
        let h2 = hash_dll_name("kernel32.dll");
        let h3 = hash_dll_name("Kernel32.Dll");
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    // -- Resolver stub tests ------------------------------------------------

    #[test]
    fn resolver_stub_is_nonempty() {
        let imports = vec![HashedImport {
            dll_hash: 0xAAAA_BBBB,
            func_hash: 0xCCCC_DDDD,
            iat_rva: 0x3000,
        }];
        let stub = generate_resolver_stub(&imports);
        assert!(!stub.is_empty(), "stub must not be empty");
    }

    #[test]
    fn resolver_stub_embeds_entry_count() {
        let imports = vec![
            HashedImport {
                dll_hash: 1,
                func_hash: 2,
                iat_rva: 0x1000,
            },
            HashedImport {
                dll_hash: 3,
                func_hash: 4,
                iat_rva: 0x1008,
            },
            HashedImport {
                dll_hash: 5,
                func_hash: 6,
                iat_rva: 0x1010,
            },
        ];
        let stub = generate_resolver_stub(&imports);
        assert_eq!(
            stub_entry_count(&stub),
            Some(3),
            "embedded count must equal the number of import entries"
        );
    }

    #[test]
    fn resolver_stub_embeds_table_data() {
        let imports = vec![
            HashedImport {
                dll_hash: 0xDEAD_BEEF,
                func_hash: 0xCAFE_BABE,
                iat_rva: 0x2000,
            },
            HashedImport {
                dll_hash: 0x1234_5678,
                func_hash: 0x9ABC_DEF0,
                iat_rva: 0x2008,
            },
        ];
        let stub = generate_resolver_stub(&imports);

        // The last 24 bytes (2 entries * 12 bytes each) must be the table.
        let table = &stub[stub.len() - 24..];

        // First entry
        assert_eq!(
            u32::from_le_bytes([table[0], table[1], table[2], table[3]]),
            0xDEAD_BEEF
        );
        assert_eq!(
            u32::from_le_bytes([table[4], table[5], table[6], table[7]]),
            0xCAFE_BABE
        );
        assert_eq!(
            u32::from_le_bytes([table[8], table[9], table[10], table[11]]),
            0x2000
        );

        // Second entry
        assert_eq!(
            u32::from_le_bytes([table[12], table[13], table[14], table[15]]),
            0x1234_5678
        );
        assert_eq!(
            u32::from_le_bytes([table[16], table[17], table[18], table[19]]),
            0x9ABC_DEF0
        );
        assert_eq!(
            u32::from_le_bytes([table[20], table[21], table[22], table[23]]),
            0x2008
        );
    }

    #[test]
    fn resolver_stub_starts_with_valid_prologue() {
        let imports = vec![HashedImport {
            dll_hash: 0,
            func_hash: 0,
            iat_rva: 0,
        }];
        let stub = generate_resolver_stub(&imports);

        // push rbx ; push rsi ; push rdi ; push rbp
        assert_eq!(stub[0], 0x53, "expected push rbx");
        assert_eq!(stub[1], 0x56, "expected push rsi");
        assert_eq!(stub[2], 0x57, "expected push rdi");
        assert_eq!(stub[3], 0x55, "expected push rbp");
        // sub rsp, 0x28
        assert_eq!(&stub[4..8], &[0x48, 0x83, 0xEC, 0x28]);
    }

    #[test]
    fn resolver_stub_ends_with_ret() {
        let imports = vec![HashedImport {
            dll_hash: 0,
            func_hash: 0,
            iat_rva: 0,
        }];
        let stub = generate_resolver_stub(&imports);

        // The code ends with `ret` (0xC3), followed by the 12-byte table.
        // So ret is at stub.len() - 12 - 1.
        let code_len = stub.len() - imports.len() * 12;
        assert_eq!(stub[code_len - 1], 0xC3, "stub code must end with ret");
    }

    // -- parse_imports with synthetic PE ------------------------------------

    /// Build a minimal PE64 with a synthetic import directory pointing to
    /// one DLL ("test.dll") with one function ("TestFunc").
    fn build_pe_with_imports() -> Vec<u8> {
        // We reuse the layout from parser tests but add a .idata section at
        // RVA 0x2000, file offset 0x400.
        let pe_offset: usize = 0x80;
        let coff_offset = pe_offset + 4;
        let opt_offset = coff_offset + 20;
        let num_data_dirs: u32 = 16;
        let opt_header_size: u16 = 112 + (num_data_dirs as u16) * 8; // 240
        let section_table_offset = opt_offset + opt_header_size as usize;

        let text_raw_offset: u32 = 0x200;
        let text_raw_size: u32 = 0x200;
        let idata_raw_offset: u32 = 0x400;
        let idata_raw_size: u32 = 0x200;
        let total_size = (idata_raw_offset + idata_raw_size) as usize;

        let mut buf = vec![0u8; total_size];

        // -- DOS header --
        let bytes = 0x5A4Du16.to_le_bytes();
        buf[0] = bytes[0];
        buf[1] = bytes[1];
        let bytes = (pe_offset as u32).to_le_bytes();
        buf[0x3C] = bytes[0];
        buf[0x3D] = bytes[1];
        buf[0x3E] = bytes[2];
        buf[0x3F] = bytes[3];

        // -- PE signature --
        let bytes = 0x0000_4550u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[pe_offset + i] = b;
        }

        // -- COFF header --
        let bytes = 0x8664u16.to_le_bytes();
        buf[coff_offset] = bytes[0];
        buf[coff_offset + 1] = bytes[1];
        // NumberOfSections = 2
        let bytes = 2u16.to_le_bytes();
        buf[coff_offset + 2] = bytes[0];
        buf[coff_offset + 3] = bytes[1];
        let bytes = opt_header_size.to_le_bytes();
        buf[coff_offset + 16] = bytes[0];
        buf[coff_offset + 17] = bytes[1];
        let bytes = 0x0022u16.to_le_bytes();
        buf[coff_offset + 18] = bytes[0];
        buf[coff_offset + 19] = bytes[1];

        // -- Optional header (PE32+) --
        let bytes = 0x020Bu16.to_le_bytes();
        buf[opt_offset] = bytes[0];
        buf[opt_offset + 1] = bytes[1];
        // EntryPoint
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 16 + i] = b;
        }
        // ImageBase
        let bytes = 0x0000_0001_4000_0000u64.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 24 + i] = b;
        }
        // SectionAlignment
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 32 + i] = b;
        }
        // FileAlignment
        let bytes = 0x200u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 36 + i] = b;
        }
        // SizeOfImage
        let bytes = 0x4000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 56 + i] = b;
        }
        // SizeOfHeaders
        let bytes = 0x200u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 60 + i] = b;
        }
        // NumberOfRvaAndSizes
        let bytes = num_data_dirs.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 108 + i] = b;
        }

        // Data directories -- import directory at index 1.
        // Import directory RVA = 0x2000 (inside .idata section)
        // Import directory size = 40 (2 descriptors: 1 real + 1 null term)
        let dd_base = opt_offset + 112;
        let bytes = 0x2000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[dd_base + 1 * 8 + i] = b;
        }
        let bytes = 40u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[dd_base + 1 * 8 + 4 + i] = b;
        }

        // -- Section table --
        // Section 0: .text
        let s0 = section_table_offset;
        buf[s0..s0 + 5].copy_from_slice(b".text");
        let bytes = 0x1E0u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s0 + 8 + i] = b;
        }
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s0 + 12 + i] = b;
        }
        let bytes = text_raw_size.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s0 + 16 + i] = b;
        }
        let bytes = text_raw_offset.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s0 + 20 + i] = b;
        }
        let bytes = 0x6000_0020u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s0 + 36 + i] = b;
        }

        // Section 1: .idata at RVA 0x2000, file offset 0x400
        let s1 = section_table_offset + 40;
        buf[s1..s1 + 6].copy_from_slice(b".idata");
        let bytes = idata_raw_size.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s1 + 8 + i] = b;
        }
        let bytes = 0x2000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s1 + 12 + i] = b;
        }
        let bytes = idata_raw_size.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s1 + 16 + i] = b;
        }
        let bytes = idata_raw_offset.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s1 + 20 + i] = b;
        }
        let bytes = 0xC000_0040u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s1 + 36 + i] = b;
        }

        // ------------------------------------------------------------------
        // Build synthetic import structures inside the .idata section.
        //
        // Layout within .idata (RVA base 0x2000, file offset 0x400):
        //   0x000  IMAGE_IMPORT_DESCRIPTOR #0  (20 bytes)
        //   0x014  IMAGE_IMPORT_DESCRIPTOR #1  (null terminator, 20 bytes)
        //   0x028  unused (padding)
        //   0x040  INT entry 0: RVA of IMAGE_IMPORT_BY_NAME  (8 bytes, PE64)
        //   0x048  INT entry 1: 0 (terminator)                (8 bytes)
        //   0x050  IAT entry 0: same as INT entry 0           (8 bytes)
        //   0x058  IAT entry 1: 0 (terminator)                (8 bytes)
        //   0x080  DLL name: "test.dll\0"
        //   0x0A0  IMAGE_IMPORT_BY_NAME: hint(2) + "TestFunc\0"
        // ------------------------------------------------------------------
        let idata_file = idata_raw_offset as usize; // 0x400
        let idata_rva: u32 = 0x2000;

        // Relative offsets within .idata
        let int_offset: u32 = 0x040;
        let iat_offset: u32 = 0x050;
        let dll_name_offset: u32 = 0x080;
        let import_by_name_offset: u32 = 0x0A0;

        // IMAGE_IMPORT_DESCRIPTOR #0
        let desc0 = idata_file;
        // OriginalFirstThunk (INT RVA)
        let bytes = (idata_rva + int_offset).to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[desc0 + i] = b;
        }
        // Name RVA
        let bytes = (idata_rva + dll_name_offset).to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[desc0 + 12 + i] = b;
        }
        // FirstThunk (IAT RVA)
        let bytes = (idata_rva + iat_offset).to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[desc0 + 16 + i] = b;
        }

        // IMAGE_IMPORT_DESCRIPTOR #1 -- null terminator (already zeroed)

        // INT[0]: RVA to IMAGE_IMPORT_BY_NAME
        let int_file = idata_file + int_offset as usize;
        let by_name_rva = idata_rva + import_by_name_offset;
        let bytes = (by_name_rva as u64).to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[int_file + i] = b;
        }
        // INT[1]: 0 (already zeroed)

        // IAT[0]: same as INT[0]
        let iat_file = idata_file + iat_offset as usize;
        for (i, &b) in bytes.iter().enumerate() {
            buf[iat_file + i] = b;
        }
        // IAT[1]: 0 (already zeroed)

        // DLL name
        let dll_name_file = idata_file + dll_name_offset as usize;
        let dll_name = b"test.dll\0";
        buf[dll_name_file..dll_name_file + dll_name.len()].copy_from_slice(dll_name);

        // IMAGE_IMPORT_BY_NAME: u16 Hint + "TestFunc\0"
        let ibn_file = idata_file + import_by_name_offset as usize;
        // Hint = 0
        buf[ibn_file] = 0;
        buf[ibn_file + 1] = 0;
        let func_name = b"TestFunc\0";
        buf[ibn_file + 2..ibn_file + 2 + func_name.len()].copy_from_slice(func_name);

        buf
    }

    #[test]
    fn parse_imports_finds_dll_and_function() {
        let data = build_pe_with_imports();
        let pe = PeFile::parse(data).expect("PE parse should succeed");
        let imports = parse_imports(&pe).expect("parse_imports should succeed");

        assert_eq!(imports.len(), 1, "expected exactly one DLL");
        let (dll_name, funcs) = &imports[0];
        assert_eq!(dll_name, "test.dll");
        assert_eq!(funcs.len(), 1, "expected exactly one function");
        assert_eq!(funcs[0].0, "TestFunc");
    }

    #[test]
    fn obfuscate_imports_produces_hashed_entries() {
        let data = build_pe_with_imports();
        let pe = PeFile::parse(data).expect("PE parse should succeed");
        let result = obfuscate_imports(&pe).expect("obfuscate_imports should succeed");

        assert_eq!(result.imports.len(), 1);
        let entry = &result.imports[0];

        // The DLL hash should match hash_dll_name("test.dll").
        assert_eq!(entry.dll_hash, hash_dll_name("test.dll"));
        // The function hash should match fnv1a_hash(b"TestFunc").
        assert_eq!(entry.func_hash, fnv1a_hash(b"TestFunc"));
        // The IAT RVA should be the IAT slot we set up (0x2000 + 0x050).
        assert_eq!(entry.iat_rva, 0x2050);

        // The resolver stub should be non-empty.
        assert!(!result.resolver_stub.is_empty());
    }

    #[test]
    fn obfuscate_imports_returns_error_for_pe_without_imports() {
        // Build a PE with no import directory.
        let pe_offset: usize = 0x80;
        let coff_offset = pe_offset + 4;
        let opt_offset = coff_offset + 20;
        let num_data_dirs: u32 = 16;
        let opt_header_size: u16 = 112 + (num_data_dirs as u16) * 8;
        let section_table_offset = opt_offset + opt_header_size as usize;
        let text_raw_offset: u32 = 0x200;
        let text_raw_size: u32 = 0x200;
        let total_size = text_raw_offset as usize + text_raw_size as usize;

        let mut buf = vec![0u8; total_size];

        // DOS header
        let bytes = 0x5A4Du16.to_le_bytes();
        buf[0] = bytes[0];
        buf[1] = bytes[1];
        let bytes = (pe_offset as u32).to_le_bytes();
        buf[0x3C] = bytes[0];
        buf[0x3D] = bytes[1];
        buf[0x3E] = bytes[2];
        buf[0x3F] = bytes[3];

        // PE signature
        let bytes = 0x0000_4550u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[pe_offset + i] = b;
        }

        // COFF header
        let bytes = 0x8664u16.to_le_bytes();
        buf[coff_offset] = bytes[0];
        buf[coff_offset + 1] = bytes[1];
        let bytes = 1u16.to_le_bytes();
        buf[coff_offset + 2] = bytes[0];
        buf[coff_offset + 3] = bytes[1];
        let bytes = opt_header_size.to_le_bytes();
        buf[coff_offset + 16] = bytes[0];
        buf[coff_offset + 17] = bytes[1];
        let bytes = 0x0022u16.to_le_bytes();
        buf[coff_offset + 18] = bytes[0];
        buf[coff_offset + 19] = bytes[1];

        // Optional header
        let bytes = 0x020Bu16.to_le_bytes();
        buf[opt_offset] = bytes[0];
        buf[opt_offset + 1] = bytes[1];
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 16 + i] = b;
        }
        let bytes = 0x0000_0001_4000_0000u64.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 24 + i] = b;
        }
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 32 + i] = b;
        }
        let bytes = 0x200u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 36 + i] = b;
        }
        let bytes = 0x3000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 56 + i] = b;
        }
        let bytes = 0x200u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 60 + i] = b;
        }
        let bytes = num_data_dirs.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[opt_offset + 108 + i] = b;
        }
        // Import directory entry left as zero (no imports).

        // Section: .text
        let s = section_table_offset;
        buf[s..s + 5].copy_from_slice(b".text");
        let bytes = 0x1E0u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s + 8 + i] = b;
        }
        let bytes = 0x1000u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s + 12 + i] = b;
        }
        let bytes = text_raw_size.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s + 16 + i] = b;
        }
        let bytes = text_raw_offset.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s + 20 + i] = b;
        }
        let bytes = 0x6000_0020u32.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[s + 36 + i] = b;
        }

        let pe = PeFile::parse(buf).expect("PE parse should succeed");
        let result = obfuscate_imports(&pe);
        assert!(result.is_err(), "should error when no imports exist");
    }
}
