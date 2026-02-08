//! Minimal PE (Portable Executable) parser for Windows PE files.
//!
//! This module provides zero-dependency parsing of PE32 and PE32+ binaries,
//! reading only from a `Vec<u8>` buffer using little-endian helpers from the
//! standard library.  It is intentionally lean -- just enough structure to
//! support the obfuscation passes that need to read and rewrite sections,
//! relocations, imports, and TLS callbacks.

#![allow(dead_code)]

use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while parsing a PE file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// The first two bytes are not `MZ` (0x5A4D).
    InvalidDosSignature,
    /// The four bytes at `e_lfanew` are not `PE\0\0` (0x00004550).
    InvalidPeSignature,
    /// The input buffer is too short to contain a required structure.
    TruncatedFile,
    /// The `Machine` field in the COFF header is not a supported value.
    UnsupportedMachine(u16),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::InvalidDosSignature => {
                write!(f, "invalid DOS signature (expected 0x5A4D)")
            }
            PeError::InvalidPeSignature => {
                write!(f, "invalid PE signature (expected 0x00004550)")
            }
            PeError::TruncatedFile => write!(f, "file is truncated"),
            PeError::UnsupportedMachine(m) => {
                write!(f, "unsupported machine type: 0x{m:04X}")
            }
        }
    }
}

impl std::error::Error for PeError {}

// ---------------------------------------------------------------------------
// Little-endian read helpers
// ---------------------------------------------------------------------------

/// Read a `u16` at `offset` (little-endian).  Returns `TruncatedFile` if out
/// of bounds.
fn read_u16(data: &[u8], offset: usize) -> Result<u16, PeError> {
    let end = offset.checked_add(2).ok_or(PeError::TruncatedFile)?;
    if end > data.len() {
        return Err(PeError::TruncatedFile);
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a `u32` at `offset` (little-endian).
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

/// Read a `u64` at `offset` (little-endian).
fn read_u64(data: &[u8], offset: usize) -> Result<u64, PeError> {
    let end = offset.checked_add(8).ok_or(PeError::TruncatedFile)?;
    if end > data.len() {
        return Err(PeError::TruncatedFile);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[offset..end]);
    Ok(u64::from_le_bytes(buf))
}

// ---------------------------------------------------------------------------
// Well-known constants
// ---------------------------------------------------------------------------

/// `MZ` -- DOS header magic.
const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0` -- PE signature.
const PE_SIGNATURE: u32 = 0x0000_4550;

/// Optional-header magic for PE32 (32-bit).
pub const PE32_MAGIC: u16 = 0x010B;
/// Optional-header magic for PE32+ (64-bit).
pub const PE32PLUS_MAGIC: u16 = 0x020B;

/// IMAGE_FILE_MACHINE_I386
pub const MACHINE_I386: u16 = 0x014C;
/// IMAGE_FILE_MACHINE_AMD64
pub const MACHINE_AMD64: u16 = 0x8664;
/// IMAGE_FILE_MACHINE_ARM64
pub const MACHINE_ARM64: u16 = 0xAA64;

// Data directory indices.
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// The DOS header -- we only keep the two fields we actually need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosHeader {
    /// Must be `0x5A4D` (`MZ`).
    pub e_magic: u16,
    /// File offset to the PE signature.
    pub e_lfanew: u32,
}

/// COFF file header (20 bytes in the file, we store the interesting subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Combined optional header fields that are useful for obfuscation passes.
/// Works for both PE32 and PE32+ -- `image_base` is always stored as `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHeader {
    /// `0x010B` for PE32, `0x020B` for PE32+.
    pub magic: u16,
    pub entry_point: u32,
    /// Stored as `u64` regardless of format (PE32 zero-extends).
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_rva_and_sizes: u32,
}

/// A single entry in the data-directory table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// A single section header (40 bytes in the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    /// Raw 8-byte name (may or may not be null-terminated).
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Return the section name as a UTF-8 `&str`, trimming any trailing NUL
    /// bytes.  Section names are almost always pure ASCII, so this is safe in
    /// practice; if the name is somehow invalid UTF-8, the returned string
    /// will be `"<invalid>"`.
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        std::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

// ---------------------------------------------------------------------------
// PeFile
// ---------------------------------------------------------------------------

/// A parsed PE file held entirely in memory.
#[derive(Debug, Clone)]
pub struct PeFile {
    /// The raw bytes of the entire file.
    pub data: Vec<u8>,
    pub dos_header: DosHeader,
    /// Absolute file offset where the PE signature lives (`e_lfanew`).
    pub pe_offset: usize,
    pub coff_header: CoffHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub data_directories: Vec<DataDirectory>,
}

impl PeFile {
    // -- construction -------------------------------------------------------

    /// Parse a PE file from a raw byte buffer.
    ///
    /// The buffer is consumed and stored inside the returned `PeFile` so that
    /// later passes can read (and mutate) raw section data in-place.
    pub fn parse(data: Vec<u8>) -> Result<PeFile, PeError> {
        // --- DOS header ----------------------------------------------------
        let e_magic = read_u16(&data, 0)?;
        if e_magic != DOS_MAGIC {
            return Err(PeError::InvalidDosSignature);
        }
        let e_lfanew = read_u32(&data, 0x3C)?;
        let dos_header = DosHeader { e_magic, e_lfanew };

        let pe_offset = e_lfanew as usize;

        // --- PE signature --------------------------------------------------
        let pe_sig = read_u32(&data, pe_offset)?;
        if pe_sig != PE_SIGNATURE {
            return Err(PeError::InvalidPeSignature);
        }

        // --- COFF header (starts right after the 4-byte signature) ---------
        let coff_offset = pe_offset + 4;
        let machine = read_u16(&data, coff_offset)?;
        match machine {
            MACHINE_I386 | MACHINE_AMD64 | MACHINE_ARM64 => {}
            other => return Err(PeError::UnsupportedMachine(other)),
        }
        let number_of_sections = read_u16(&data, coff_offset + 2)?;
        let size_of_optional_header = read_u16(&data, coff_offset + 16)?;
        let characteristics = read_u16(&data, coff_offset + 18)?;
        let coff_header = CoffHeader {
            machine,
            number_of_sections,
            size_of_optional_header,
            characteristics,
        };

        // --- Optional header -----------------------------------------------
        let opt_offset = coff_offset + 20; // COFF header is always 20 bytes
        let magic = read_u16(&data, opt_offset)?;

        let (entry_point, image_base, section_alignment, file_alignment,
             size_of_image, size_of_headers, number_of_rva_and_sizes,
             data_dir_offset) = match magic {
            PE32_MAGIC => {
                let entry_point = read_u32(&data, opt_offset + 16)?;
                let image_base = read_u32(&data, opt_offset + 28)? as u64;
                let section_alignment = read_u32(&data, opt_offset + 32)?;
                let file_alignment = read_u32(&data, opt_offset + 36)?;
                let size_of_image = read_u32(&data, opt_offset + 56)?;
                let size_of_headers = read_u32(&data, opt_offset + 60)?;
                let number_of_rva_and_sizes = read_u32(&data, opt_offset + 92)?;
                let data_dir_offset = opt_offset + 96;
                (
                    entry_point,
                    image_base,
                    section_alignment,
                    file_alignment,
                    size_of_image,
                    size_of_headers,
                    number_of_rva_and_sizes,
                    data_dir_offset,
                )
            }
            PE32PLUS_MAGIC => {
                let entry_point = read_u32(&data, opt_offset + 16)?;
                let image_base = read_u64(&data, opt_offset + 24)?;
                let section_alignment = read_u32(&data, opt_offset + 32)?;
                let file_alignment = read_u32(&data, opt_offset + 36)?;
                let size_of_image = read_u32(&data, opt_offset + 56)?;
                let size_of_headers = read_u32(&data, opt_offset + 60)?;
                let number_of_rva_and_sizes = read_u32(&data, opt_offset + 108)?;
                let data_dir_offset = opt_offset + 112;
                (
                    entry_point,
                    image_base,
                    section_alignment,
                    file_alignment,
                    size_of_image,
                    size_of_headers,
                    number_of_rva_and_sizes,
                    data_dir_offset,
                )
            }
            _ => {
                // Treat unknown optional-header magic as an unsupported format.
                return Err(PeError::TruncatedFile);
            }
        };

        let optional_header = OptionalHeader {
            magic,
            entry_point,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            number_of_rva_and_sizes,
        };

        // --- Data directories ----------------------------------------------
        let num_dirs = number_of_rva_and_sizes as usize;
        let mut data_directories = Vec::with_capacity(num_dirs);
        for i in 0..num_dirs {
            let base = data_dir_offset + i * 8;
            let va = read_u32(&data, base)?;
            let sz = read_u32(&data, base + 4)?;
            data_directories.push(DataDirectory {
                virtual_address: va,
                size: sz,
            });
        }

        // --- Section headers -----------------------------------------------
        // Section table immediately follows the optional header.
        let section_table_offset = opt_offset + size_of_optional_header as usize;
        let num_sections = number_of_sections as usize;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let base = section_table_offset + i * 40;
            // Ensure we can read a full 40-byte entry.
            if base + 40 > data.len() {
                return Err(PeError::TruncatedFile);
            }

            let mut name = [0u8; 8];
            name.copy_from_slice(&data[base..base + 8]);

            let virtual_size = read_u32(&data, base + 8)?;
            let virtual_address = read_u32(&data, base + 12)?;
            let size_of_raw_data = read_u32(&data, base + 16)?;
            let pointer_to_raw_data = read_u32(&data, base + 20)?;
            let characteristics = read_u32(&data, base + 36)?;

            sections.push(SectionHeader {
                name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                characteristics,
            });
        }

        Ok(PeFile {
            data,
            dos_header,
            pe_offset,
            coff_header,
            optional_header,
            sections,
            data_directories,
        })
    }

    // -- helpers ------------------------------------------------------------

    /// Look up a section by its (ASCII) name, e.g. `".text"`.
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name_str() == name)
    }

    /// Convert a Relative Virtual Address to a raw file offset by finding the
    /// section that contains it and applying the delta between the section's
    /// virtual address and its raw-data pointer.
    ///
    /// Returns `None` if the RVA does not fall within any section.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let va_start = section.virtual_address;
            // Use the larger of virtual_size and size_of_raw_data so that we
            // cover both BSS-style sections and zero-padded raw sections.
            let extent = std::cmp::max(section.virtual_size, section.size_of_raw_data);
            let va_end = va_start.checked_add(extent)?;
            if rva >= va_start && rva < va_end {
                let delta = rva - va_start;
                return Some(section.pointer_to_raw_data as usize + delta as usize);
            }
        }
        None
    }

    /// Return a slice into the raw file data that corresponds to the given
    /// section's raw content.  If the section extends past the end of the
    /// file the slice is clamped to whatever bytes are actually available.
    pub fn section_data(&self, section: &SectionHeader) -> &[u8] {
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;
        let clamped_end = end.min(self.data.len());
        let clamped_start = start.min(clamped_end);
        &self.data[clamped_start..clamped_end]
    }

    /// Convenience: return the import data directory, if present and non-zero.
    pub fn import_directory(&self) -> Option<&DataDirectory> {
        self.data_directories
            .get(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .filter(|d| d.virtual_address != 0 && d.size != 0)
    }

    /// Convenience: return the base-relocation data directory, if present.
    pub fn relocation_directory(&self) -> Option<&DataDirectory> {
        self.data_directories
            .get(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .filter(|d| d.virtual_address != 0 && d.size != 0)
    }

    /// Convenience: return the TLS data directory, if present.
    pub fn tls_directory(&self) -> Option<&DataDirectory> {
        self.data_directories
            .get(IMAGE_DIRECTORY_ENTRY_TLS)
            .filter(|d| d.virtual_address != 0 && d.size != 0)
    }

    /// Returns `true` when the optional header indicates a PE32+ (64-bit)
    /// image.
    pub fn is_64bit(&self) -> bool {
        self.optional_header.magic == PE32PLUS_MAGIC
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers to build minimal synthetic PE images -----------------------

    /// Write a `u16` into `buf` at `offset` in little-endian order.
    fn put_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
    }

    /// Write a `u32` into `buf` at `offset` in little-endian order.
    fn put_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
        buf[offset + 2] = bytes[2];
        buf[offset + 3] = bytes[3];
    }

    /// Write a `u64` into `buf` at `offset` in little-endian order.
    fn put_u64(buf: &mut Vec<u8>, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[offset + i] = b;
        }
    }

    /// Build a minimal PE32+ (64-bit) image with one `.text` section and a
    /// handful of data directories.  The image is entirely synthetic but
    /// structurally valid enough for the parser.
    fn build_minimal_pe64() -> Vec<u8> {
        // Layout:
        //   0x0000  DOS header  (64 bytes minimum, e_lfanew at 0x3C)
        //   0x0080  PE signature (4 bytes)
        //   0x0084  COFF header  (20 bytes)
        //   0x0098  Optional header PE32+ (112 bytes fixed + 16*8 data dirs = 240)
        //   0x0188  Section table (1 entry, 40 bytes)
        //   0x01B0  ...padding to 0x0200 (file alignment)
        //   0x0200  .text raw data (512 bytes)
        let pe_offset: usize = 0x80;
        let coff_offset = pe_offset + 4;
        let opt_offset = coff_offset + 20;
        let num_data_dirs: u32 = 16;
        let opt_header_size: u16 = 112 + (num_data_dirs as u16) * 8; // 240
        let section_table_offset = opt_offset + opt_header_size as usize;
        let text_raw_offset: u32 = 0x200;
        let text_raw_size: u32 = 0x200;
        let total_size = text_raw_offset as usize + text_raw_size as usize;

        let mut buf = vec![0u8; total_size];

        // -- DOS header --
        put_u16(&mut buf, 0, DOS_MAGIC);       // e_magic
        put_u32(&mut buf, 0x3C, pe_offset as u32); // e_lfanew

        // -- PE signature --
        put_u32(&mut buf, pe_offset, PE_SIGNATURE);

        // -- COFF header --
        put_u16(&mut buf, coff_offset, MACHINE_AMD64);       // Machine
        put_u16(&mut buf, coff_offset + 2, 1);               // NumberOfSections
        // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols left as 0
        put_u16(&mut buf, coff_offset + 16, opt_header_size); // SizeOfOptionalHeader
        put_u16(&mut buf, coff_offset + 18, 0x0022);          // Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)

        // -- Optional header (PE32+) --
        put_u16(&mut buf, opt_offset, PE32PLUS_MAGIC);         // Magic
        put_u32(&mut buf, opt_offset + 16, 0x1000);            // AddressOfEntryPoint
        put_u64(&mut buf, opt_offset + 24, 0x0000_0001_4000_0000); // ImageBase
        put_u32(&mut buf, opt_offset + 32, 0x1000);            // SectionAlignment
        put_u32(&mut buf, opt_offset + 36, 0x200);             // FileAlignment
        put_u32(&mut buf, opt_offset + 56, 0x3000);            // SizeOfImage
        put_u32(&mut buf, opt_offset + 60, 0x200);             // SizeOfHeaders
        put_u32(&mut buf, opt_offset + 108, num_data_dirs);    // NumberOfRvaAndSizes

        // Data directories -- set import (index 1), reloc (index 5), TLS (index 9)
        let dd_base = opt_offset + 112;
        // Import directory
        put_u32(&mut buf, dd_base + 1 * 8, 0x2000);  // RVA
        put_u32(&mut buf, dd_base + 1 * 8 + 4, 0x80); // Size
        // Relocation directory
        put_u32(&mut buf, dd_base + 5 * 8, 0x2500);
        put_u32(&mut buf, dd_base + 5 * 8 + 4, 0x40);
        // TLS directory
        put_u32(&mut buf, dd_base + 9 * 8, 0x2600);
        put_u32(&mut buf, dd_base + 9 * 8 + 4, 0x28);

        // -- Section table: .text --
        let s = section_table_offset;
        buf[s..s + 5].copy_from_slice(b".text");
        put_u32(&mut buf, s + 8, 0x1E0);               // VirtualSize
        put_u32(&mut buf, s + 12, 0x1000);              // VirtualAddress
        put_u32(&mut buf, s + 16, text_raw_size);       // SizeOfRawData
        put_u32(&mut buf, s + 20, text_raw_offset);     // PointerToRawData
        put_u32(&mut buf, s + 36, 0x6000_0020);         // Characteristics (CODE|EXECUTE|READ)

        // Put a recognisable pattern in the .text section data.
        buf[text_raw_offset as usize] = 0xCC; // int3
        buf[text_raw_offset as usize + 1] = 0xC3; // ret

        buf
    }

    /// Build a minimal PE32 (32-bit) image with one `.text` section.
    fn build_minimal_pe32() -> Vec<u8> {
        let pe_offset: usize = 0x80;
        let coff_offset = pe_offset + 4;
        let opt_offset = coff_offset + 20;
        let num_data_dirs: u32 = 16;
        let opt_header_size: u16 = 96 + (num_data_dirs as u16) * 8; // 224
        let section_table_offset = opt_offset + opt_header_size as usize;
        let text_raw_offset: u32 = 0x200;
        let text_raw_size: u32 = 0x200;
        let total_size = text_raw_offset as usize + text_raw_size as usize;

        let mut buf = vec![0u8; total_size];

        // DOS header
        put_u16(&mut buf, 0, DOS_MAGIC);
        put_u32(&mut buf, 0x3C, pe_offset as u32);

        // PE signature
        put_u32(&mut buf, pe_offset, PE_SIGNATURE);

        // COFF header
        put_u16(&mut buf, coff_offset, MACHINE_I386);
        put_u16(&mut buf, coff_offset + 2, 1);
        put_u16(&mut buf, coff_offset + 16, opt_header_size);
        put_u16(&mut buf, coff_offset + 18, 0x0102); // EXECUTABLE | 32BIT

        // Optional header (PE32)
        put_u16(&mut buf, opt_offset, PE32_MAGIC);
        put_u32(&mut buf, opt_offset + 16, 0x1000);       // EntryPoint
        put_u32(&mut buf, opt_offset + 28, 0x0040_0000);  // ImageBase (32-bit)
        put_u32(&mut buf, opt_offset + 32, 0x1000);       // SectionAlignment
        put_u32(&mut buf, opt_offset + 36, 0x200);        // FileAlignment
        put_u32(&mut buf, opt_offset + 56, 0x3000);       // SizeOfImage
        put_u32(&mut buf, opt_offset + 60, 0x200);        // SizeOfHeaders
        put_u32(&mut buf, opt_offset + 92, num_data_dirs); // NumberOfRvaAndSizes

        // Section table: .text
        let s = section_table_offset;
        buf[s..s + 5].copy_from_slice(b".text");
        put_u32(&mut buf, s + 8, 0x100);
        put_u32(&mut buf, s + 12, 0x1000);
        put_u32(&mut buf, s + 16, text_raw_size);
        put_u32(&mut buf, s + 20, text_raw_offset);
        put_u32(&mut buf, s + 36, 0x6000_0020);

        buf
    }

    // -- tests --------------------------------------------------------------

    #[test]
    fn parse_pe64_dos_header() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.dos_header.e_magic, DOS_MAGIC);
        assert_eq!(pe.dos_header.e_lfanew, 0x80);
    }

    #[test]
    fn parse_pe64_coff_header() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.coff_header.machine, MACHINE_AMD64);
        assert_eq!(pe.coff_header.number_of_sections, 1);
        assert_eq!(pe.coff_header.characteristics, 0x0022);
    }

    #[test]
    fn parse_pe64_optional_header() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.optional_header.magic, PE32PLUS_MAGIC);
        assert_eq!(pe.optional_header.entry_point, 0x1000);
        assert_eq!(pe.optional_header.image_base, 0x0000_0001_4000_0000);
        assert_eq!(pe.optional_header.section_alignment, 0x1000);
        assert_eq!(pe.optional_header.file_alignment, 0x200);
        assert_eq!(pe.optional_header.size_of_image, 0x3000);
        assert_eq!(pe.optional_header.size_of_headers, 0x200);
        assert!(pe.is_64bit());
    }

    #[test]
    fn parse_pe64_sections() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.sections.len(), 1);

        let text = &pe.sections[0];
        assert_eq!(text.name_str(), ".text");
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.pointer_to_raw_data, 0x200);
        assert_eq!(text.characteristics, 0x6000_0020);
    }

    #[test]
    fn parse_pe64_data_directories() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.data_directories.len(), 16);

        let import = pe.import_directory().expect("import dir should exist");
        assert_eq!(import.virtual_address, 0x2000);
        assert_eq!(import.size, 0x80);

        let reloc = pe.relocation_directory().expect("reloc dir should exist");
        assert_eq!(reloc.virtual_address, 0x2500);
        assert_eq!(reloc.size, 0x40);

        let tls = pe.tls_directory().expect("tls dir should exist");
        assert_eq!(tls.virtual_address, 0x2600);
        assert_eq!(tls.size, 0x28);
    }

    #[test]
    fn parse_pe32_basic() {
        let data = build_minimal_pe32();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert_eq!(pe.optional_header.magic, PE32_MAGIC);
        assert_eq!(pe.optional_header.image_base, 0x0040_0000);
        assert_eq!(pe.coff_header.machine, MACHINE_I386);
        assert!(!pe.is_64bit());
    }

    #[test]
    fn find_section_by_name() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        assert!(pe.find_section(".text").is_some());
        assert!(pe.find_section(".data").is_none());
    }

    #[test]
    fn section_data_contains_expected_bytes() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        let text = pe.find_section(".text").unwrap();
        let raw = pe.section_data(text);
        assert_eq!(raw[0], 0xCC);
        assert_eq!(raw[1], 0xC3);
    }

    #[test]
    fn rva_to_offset_within_section() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse should succeed");
        // RVA 0x1000 is the start of .text whose raw data is at 0x200.
        assert_eq!(pe.rva_to_offset(0x1000), Some(0x200));
        // RVA 0x1010 -> offset 0x210
        assert_eq!(pe.rva_to_offset(0x1010), Some(0x210));
        // RVA outside any section
        assert_eq!(pe.rva_to_offset(0x5000), None);
    }

    #[test]
    fn invalid_dos_signature_rejected() {
        let mut data = build_minimal_pe64();
        data[0] = 0x00; // corrupt MZ
        let err = PeFile::parse(data).unwrap_err();
        assert_eq!(err, PeError::InvalidDosSignature);
    }

    #[test]
    fn invalid_pe_signature_rejected() {
        let mut data = build_minimal_pe64();
        let pe_off = 0x80usize;
        data[pe_off] = 0x00; // corrupt PE\0\0
        let err = PeFile::parse(data).unwrap_err();
        assert_eq!(err, PeError::InvalidPeSignature);
    }

    #[test]
    fn truncated_file_rejected() {
        let data = vec![0x4Du8, 0x5A]; // just "MZ", nothing else useful
        let err = PeFile::parse(data).unwrap_err();
        assert_eq!(err, PeError::TruncatedFile);
    }

    #[test]
    fn unsupported_machine_rejected() {
        let mut data = build_minimal_pe64();
        let coff_offset = 0x80 + 4;
        put_u16(&mut data, coff_offset, 0xBEEF); // bogus machine
        let err = PeFile::parse(data).unwrap_err();
        assert_eq!(err, PeError::UnsupportedMachine(0xBEEF));
    }

    #[test]
    fn section_name_with_full_8_bytes() {
        let header = SectionHeader {
            name: *b"longname",
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            characteristics: 0,
        };
        // All 8 bytes used, no NUL terminator -- should still work.
        assert_eq!(header.name_str(), "longname");
    }

    #[test]
    fn pe_error_display() {
        assert_eq!(
            PeError::InvalidDosSignature.to_string(),
            "invalid DOS signature (expected 0x5A4D)"
        );
        assert_eq!(
            PeError::InvalidPeSignature.to_string(),
            "invalid PE signature (expected 0x00004550)"
        );
        assert_eq!(PeError::TruncatedFile.to_string(), "file is truncated");
        assert_eq!(
            PeError::UnsupportedMachine(0x1234).to_string(),
            "unsupported machine type: 0x1234"
        );
    }
}
