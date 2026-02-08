//! PE writer module.
//!
//! This module takes a parsed [`PeFile`] (from [`super::parser`]) and can write
//! modifications back to bytes.  It supports serialising the entire PE, adding
//! new sections, changing the entry point, and updating section raw data.

#![allow(dead_code)]

use super::parser::{PeError, PeFile, SectionHeader, PE32PLUS_MAGIC, PE32_MAGIC};

// ---------------------------------------------------------------------------
// Section characteristic constants
// ---------------------------------------------------------------------------

/// IMAGE_SCN_MEM_READ
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// IMAGE_SCN_MEM_WRITE
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// IMAGE_SCN_MEM_EXECUTE
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// IMAGE_SCN_CNT_CODE
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// IMAGE_SCN_CNT_INITIALIZED_DATA
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;

// ---------------------------------------------------------------------------
// Little-endian write helpers
// ---------------------------------------------------------------------------

/// Write a `u16` at `offset` in little-endian order.
fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    buf[offset] = bytes[0];
    buf[offset + 1] = bytes[1];
}

/// Write a `u32` at `offset` in little-endian order.
fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[offset] = bytes[0];
    buf[offset + 1] = bytes[1];
    buf[offset + 2] = bytes[2];
    buf[offset + 3] = bytes[3];
}

/// Write a `u64` at `offset` in little-endian order.
fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        buf[offset + i] = b;
    }
}

// ---------------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------------

/// Round `value` up to the nearest multiple of `alignment`.
/// `alignment` must be a power of two.
fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialize a [`PeFile`] back to a byte vector.
///
/// This starts from the original raw data stored in `pe.data` and applies
/// all header modifications (COFF header, optional header, section table)
/// as well as any changes to section raw data.  New or updated sections are
/// written at their recorded `pointer_to_raw_data` offsets.
pub fn write_pe(pe: &PeFile) -> Vec<u8> {
    // Start from the original data -- this preserves the DOS stub, rich
    // header, debug info, overlay, etc.
    let mut buf = pe.data.clone();

    // Compute header offsets the same way the parser does.
    let pe_offset = pe.pe_offset;
    let coff_offset = pe_offset + 4;
    let opt_offset = coff_offset + 20;

    // --- Write COFF header fields we track --------------------------------
    put_u16(&mut buf, coff_offset, pe.coff_header.machine);
    put_u16(&mut buf, coff_offset + 2, pe.coff_header.number_of_sections);
    put_u16(&mut buf, coff_offset + 16, pe.coff_header.size_of_optional_header);
    put_u16(&mut buf, coff_offset + 18, pe.coff_header.characteristics);

    // --- Write optional header fields we track ----------------------------
    put_u16(&mut buf, opt_offset, pe.optional_header.magic);

    match pe.optional_header.magic {
        PE32_MAGIC => {
            put_u32(&mut buf, opt_offset + 16, pe.optional_header.entry_point);
            put_u32(&mut buf, opt_offset + 28, pe.optional_header.image_base as u32);
            put_u32(&mut buf, opt_offset + 32, pe.optional_header.section_alignment);
            put_u32(&mut buf, opt_offset + 36, pe.optional_header.file_alignment);
            put_u32(&mut buf, opt_offset + 56, pe.optional_header.size_of_image);
            put_u32(&mut buf, opt_offset + 60, pe.optional_header.size_of_headers);
            put_u32(&mut buf, opt_offset + 92, pe.optional_header.number_of_rva_and_sizes);
        }
        PE32PLUS_MAGIC => {
            put_u32(&mut buf, opt_offset + 16, pe.optional_header.entry_point);
            put_u64(&mut buf, opt_offset + 24, pe.optional_header.image_base);
            put_u32(&mut buf, opt_offset + 32, pe.optional_header.section_alignment);
            put_u32(&mut buf, opt_offset + 36, pe.optional_header.file_alignment);
            put_u32(&mut buf, opt_offset + 56, pe.optional_header.size_of_image);
            put_u32(&mut buf, opt_offset + 60, pe.optional_header.size_of_headers);
            put_u32(&mut buf, opt_offset + 108, pe.optional_header.number_of_rva_and_sizes);
        }
        _ => { /* unknown magic -- leave as-is */ }
    }

    // --- Write data directories -------------------------------------------
    let data_dir_offset = match pe.optional_header.magic {
        PE32_MAGIC => opt_offset + 96,
        PE32PLUS_MAGIC => opt_offset + 112,
        _ => opt_offset + 112, // fallback
    };
    for (i, dir) in pe.data_directories.iter().enumerate() {
        let base = data_dir_offset + i * 8;
        if base + 8 <= buf.len() {
            put_u32(&mut buf, base, dir.virtual_address);
            put_u32(&mut buf, base + 4, dir.size);
        }
    }

    // --- Write section headers --------------------------------------------
    let section_table_offset = opt_offset + pe.coff_header.size_of_optional_header as usize;
    for (i, section) in pe.sections.iter().enumerate() {
        let base = section_table_offset + i * 40;
        // Grow the buffer if the section table has grown beyond the original
        // file (e.g. after add_section).
        if base + 40 > buf.len() {
            buf.resize(base + 40, 0);
        }
        buf[base..base + 8].copy_from_slice(&section.name);
        put_u32(&mut buf, base + 8, section.virtual_size);
        put_u32(&mut buf, base + 12, section.virtual_address);
        put_u32(&mut buf, base + 16, section.size_of_raw_data);
        put_u32(&mut buf, base + 20, section.pointer_to_raw_data);
        // Bytes 24..36 (PointerToRelocations, PointerToLinenumbers,
        // NumberOfRelocations, NumberOfLinenumbers) are left as zero for new
        // sections; for existing sections the original data is preserved since
        // we started from a clone.
        put_u32(&mut buf, base + 36, section.characteristics);
    }

    // --- Ensure the buffer extends to cover all section data ---------------
    for section in &pe.sections {
        let end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
        if end > buf.len() {
            buf.resize(end, 0);
        }
    }

    buf
}

/// Add a new section to the PE.
///
/// The function:
/// 1. Checks if section table has room; if not, expands headers and shifts data.
/// 2. Increments `NumberOfSections` in the COFF header.
/// 3. Computes file-aligned and section-aligned values for the new section.
/// 4. Appends a [`SectionHeader`] to `pe.sections`.
/// 5. Copies `data` into `pe.data` at the computed raw offset.
/// 6. Updates `SizeOfImage` in the optional header.
///
/// Returns an error if `name` exceeds 8 bytes.
pub fn add_section(
    pe: &mut PeFile,
    name: &str,
    data: &[u8],
    characteristics: u32,
) -> Result<(), PeError> {
    if name.len() > 8 {
        return Err(PeError::TruncatedFile);
    }

    let file_alignment = pe.optional_header.file_alignment;
    let section_alignment = pe.optional_header.section_alignment;

    // --- Check if we need to expand headers to make room for new section ---
    let pe_offset = pe.pe_offset;
    let coff_offset = pe_offset + 4;
    let opt_offset = coff_offset + 20;
    let section_table_offset = opt_offset + pe.coff_header.size_of_optional_header as usize;
    let new_section_count = pe.coff_header.number_of_sections as usize + 1;
    let needed_table_end = section_table_offset + new_section_count * 40;
    let current_headers_size = pe.optional_header.size_of_headers as usize;

    if needed_table_end > current_headers_size {
        // Need to expand headers - add one file_alignment block
        let new_headers_size = align_up(needed_table_end as u32 + 40, file_alignment);
        let shift_amount = new_headers_size - pe.optional_header.size_of_headers;

        // Shift all section raw data forward
        let old_size = pe.data.len();
        pe.data.resize(old_size + shift_amount as usize, 0);

        // Build list of (section_index, old_offset, size) sorted by offset descending
        // We MUST process sections from highest offset to lowest to avoid overwriting
        let mut section_info: Vec<(usize, usize, usize)> = pe
            .sections
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.pointer_to_raw_data as usize, s.size_of_raw_data as usize))
            .collect();
        section_info.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by offset descending

        // Move data from old location to new location (highest offset first)
        for (_, old_offset, size) in &section_info {
            if *old_offset < old_size && *size > 0 {
                let new_offset = old_offset + shift_amount as usize;
                // Copy backwards within this section to handle potential overlap
                for i in (0..*size).rev() {
                    pe.data[new_offset + i] = pe.data[old_offset + i];
                }
            }
        }

        // Zero out the gap between headers and first section data
        let first_section_new_offset = pe.optional_header.size_of_headers as usize + shift_amount as usize;
        for i in new_headers_size as usize..first_section_new_offset.min(pe.data.len()) {
            pe.data[i] = 0;
        }

        // Update all section offsets
        for section in pe.sections.iter_mut() {
            section.pointer_to_raw_data += shift_amount;
        }

        pe.optional_header.size_of_headers = new_headers_size;
    }

    // --- Compute the raw file offset for the new section data -------------
    // Place it right after the end of the last section's raw data (aligned).
    let raw_offset = if let Some(last) = pe.sections.last() {
        align_up(
            last.pointer_to_raw_data + last.size_of_raw_data,
            file_alignment,
        )
    } else {
        align_up(pe.optional_header.size_of_headers, file_alignment)
    };

    let raw_size = align_up(data.len() as u32, file_alignment);

    // --- Compute the virtual address for the new section ------------------
    let virtual_address = if let Some(last) = pe.sections.last() {
        align_up(
            last.virtual_address + std::cmp::max(last.virtual_size, last.size_of_raw_data),
            section_alignment,
        )
    } else {
        align_up(pe.optional_header.size_of_headers, section_alignment)
    };

    let virtual_size = data.len() as u32;

    // --- Build the section name (zero-padded to 8 bytes) ------------------
    let mut section_name = [0u8; 8];
    let name_bytes = name.as_bytes();
    section_name[..name_bytes.len()].copy_from_slice(name_bytes);

    // --- Create the header ------------------------------------------------
    let new_section = SectionHeader {
        name: section_name,
        virtual_size,
        virtual_address,
        size_of_raw_data: raw_size,
        pointer_to_raw_data: raw_offset,
        characteristics,
    };

    // --- Update the in-memory PE ------------------------------------------
    pe.sections.push(new_section);
    pe.coff_header.number_of_sections += 1;

    // Update SizeOfImage to cover the new section (aligned to section
    // alignment).
    pe.optional_header.size_of_image =
        align_up(virtual_address + virtual_size, section_alignment);

    // --- Write section data into the raw buffer ---------------------------
    let end = raw_offset as usize + raw_size as usize;
    if pe.data.len() < end {
        pe.data.resize(end, 0);
    }
    pe.data[raw_offset as usize..raw_offset as usize + data.len()].copy_from_slice(data);
    // The rest (padding to file alignment) is already zeroed by resize.

    Ok(())
}

/// Change the entry point RVA of the PE.
pub fn set_entry_point(pe: &mut PeFile, rva: u32) {
    pe.optional_header.entry_point = rva;
}

/// Replace the raw data of an existing section.
///
/// The section at `section_index` has its raw data overwritten with
/// `new_data`.  The `size_of_raw_data` field is updated to the file-aligned
/// size of `new_data`, and `virtual_size` is updated to the unaligned
/// length.
///
/// **Note**: This function writes into `pe.data` in-place.  If `new_data` is
/// larger than the original raw size the buffer is grown (which may cause
/// overlaps with subsequent sections -- callers are responsible for ensuring
/// this is acceptable or for adjusting later sections).
pub fn update_section_data(
    pe: &mut PeFile,
    section_index: usize,
    new_data: &[u8],
) -> Result<(), PeError> {
    if section_index >= pe.sections.len() {
        return Err(PeError::TruncatedFile);
    }

    let file_alignment = pe.optional_header.file_alignment;
    let section = &mut pe.sections[section_index];

    let raw_offset = section.pointer_to_raw_data as usize;
    let new_raw_size = align_up(new_data.len() as u32, file_alignment);

    // Update the header.
    section.size_of_raw_data = new_raw_size;
    section.virtual_size = new_data.len() as u32;

    // Ensure the backing buffer is large enough.
    let end = raw_offset + new_raw_size as usize;
    if pe.data.len() < end {
        pe.data.resize(end, 0);
    }

    // Write the new data (and zero the alignment padding).
    pe.data[raw_offset..raw_offset + new_data.len()].copy_from_slice(new_data);
    // Zero padding between data end and aligned end.
    for b in &mut pe.data[raw_offset + new_data.len()..end] {
        *b = 0;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::parser::{
        PeFile, MACHINE_AMD64, MACHINE_I386, PE32PLUS_MAGIC, PE32_MAGIC,
    };

    // -- helpers to build synthetic PE images (mirrors parser tests) --------

    fn put_test_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
    }

    fn put_test_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
        buf[offset + 2] = bytes[2];
        buf[offset + 3] = bytes[3];
    }

    fn put_test_u64(buf: &mut Vec<u8>, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            buf[offset + i] = b;
        }
    }

    fn read_u16(buf: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([buf[offset], buf[offset + 1]])
    }

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    }

    fn read_u64(buf: &[u8], offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    }

    /// Build a minimal PE32+ (64-bit) image with one `.text` section.
    fn build_minimal_pe64() -> Vec<u8> {
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

        // DOS header
        put_test_u16(&mut buf, 0, 0x5A4D);
        put_test_u32(&mut buf, 0x3C, pe_offset as u32);

        // PE signature
        put_test_u32(&mut buf, pe_offset, 0x0000_4550);

        // COFF header
        put_test_u16(&mut buf, coff_offset, MACHINE_AMD64);
        put_test_u16(&mut buf, coff_offset + 2, 1); // 1 section
        put_test_u16(&mut buf, coff_offset + 16, opt_header_size);
        put_test_u16(&mut buf, coff_offset + 18, 0x0022);

        // Optional header (PE32+)
        put_test_u16(&mut buf, opt_offset, PE32PLUS_MAGIC);
        put_test_u32(&mut buf, opt_offset + 16, 0x1000); // EntryPoint
        put_test_u64(&mut buf, opt_offset + 24, 0x0000_0001_4000_0000); // ImageBase
        put_test_u32(&mut buf, opt_offset + 32, 0x1000); // SectionAlignment
        put_test_u32(&mut buf, opt_offset + 36, 0x200); // FileAlignment
        put_test_u32(&mut buf, opt_offset + 56, 0x3000); // SizeOfImage
        put_test_u32(&mut buf, opt_offset + 60, 0x200); // SizeOfHeaders
        put_test_u32(&mut buf, opt_offset + 108, num_data_dirs);

        // Data directories -- set import (index 1)
        let dd_base = opt_offset + 112;
        put_test_u32(&mut buf, dd_base + 1 * 8, 0x2000);
        put_test_u32(&mut buf, dd_base + 1 * 8 + 4, 0x80);

        // Section table: .text
        let s = section_table_offset;
        buf[s..s + 5].copy_from_slice(b".text");
        put_test_u32(&mut buf, s + 8, 0x1E0);  // VirtualSize
        put_test_u32(&mut buf, s + 12, 0x1000); // VirtualAddress
        put_test_u32(&mut buf, s + 16, text_raw_size);
        put_test_u32(&mut buf, s + 20, text_raw_offset);
        put_test_u32(&mut buf, s + 36, 0x6000_0020); // CODE|EXECUTE|READ

        // Recognisable pattern in .text
        buf[text_raw_offset as usize] = 0xCC;
        buf[text_raw_offset as usize + 1] = 0xC3;

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
        put_test_u16(&mut buf, 0, 0x5A4D);
        put_test_u32(&mut buf, 0x3C, pe_offset as u32);

        // PE signature
        put_test_u32(&mut buf, pe_offset, 0x0000_4550);

        // COFF header
        put_test_u16(&mut buf, coff_offset, MACHINE_I386);
        put_test_u16(&mut buf, coff_offset + 2, 1);
        put_test_u16(&mut buf, coff_offset + 16, opt_header_size);
        put_test_u16(&mut buf, coff_offset + 18, 0x0102);

        // Optional header (PE32)
        put_test_u16(&mut buf, opt_offset, PE32_MAGIC);
        put_test_u32(&mut buf, opt_offset + 16, 0x1000);
        put_test_u32(&mut buf, opt_offset + 28, 0x0040_0000);
        put_test_u32(&mut buf, opt_offset + 32, 0x1000);
        put_test_u32(&mut buf, opt_offset + 36, 0x200);
        put_test_u32(&mut buf, opt_offset + 56, 0x3000);
        put_test_u32(&mut buf, opt_offset + 60, 0x200);
        put_test_u32(&mut buf, opt_offset + 92, num_data_dirs);

        // Section table: .text
        let s = section_table_offset;
        buf[s..s + 5].copy_from_slice(b".text");
        put_test_u32(&mut buf, s + 8, 0x100);
        put_test_u32(&mut buf, s + 12, 0x1000);
        put_test_u32(&mut buf, s + 16, text_raw_size);
        put_test_u32(&mut buf, s + 20, text_raw_offset);
        put_test_u32(&mut buf, s + 36, 0x6000_0020);

        buf
    }

    // -- write_pe tests ----------------------------------------------------

    #[test]
    fn write_pe_roundtrip_preserves_original() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data.clone()).expect("parse");
        let output = write_pe(&pe);
        // The output should be byte-identical to the input since nothing
        // was modified.
        assert_eq!(output.len(), data.len());
        assert_eq!(output, data);
    }

    #[test]
    fn write_pe_roundtrip_pe32() {
        let data = build_minimal_pe32();
        let pe = PeFile::parse(data.clone()).expect("parse");
        let output = write_pe(&pe);
        assert_eq!(output, data);
    }

    #[test]
    fn write_pe_reflects_entry_point_change_pe64() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        set_entry_point(&mut pe, 0x2000);
        let output = write_pe(&pe);

        let opt_offset = pe.pe_offset + 4 + 20;
        let written_ep = read_u32(&output, opt_offset + 16);
        assert_eq!(written_ep, 0x2000);
    }

    #[test]
    fn write_pe_reflects_entry_point_change_pe32() {
        let data = build_minimal_pe32();
        let mut pe = PeFile::parse(data).expect("parse");
        set_entry_point(&mut pe, 0x3000);
        let output = write_pe(&pe);

        let opt_offset = pe.pe_offset + 4 + 20;
        let written_ep = read_u32(&output, opt_offset + 16);
        assert_eq!(written_ep, 0x3000);
    }

    #[test]
    fn write_pe_after_add_section_has_correct_header_count() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        add_section(
            &mut pe,
            ".new",
            &[0xAA; 64],
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        )
        .expect("add_section");

        let output = write_pe(&pe);

        let coff_offset = pe.pe_offset + 4;
        let num_sections = read_u16(&output, coff_offset + 2);
        assert_eq!(num_sections, 2);
    }

    // -- set_entry_point tests ---------------------------------------------

    #[test]
    fn set_entry_point_updates_optional_header() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        assert_eq!(pe.optional_header.entry_point, 0x1000);

        set_entry_point(&mut pe, 0xDEAD);
        assert_eq!(pe.optional_header.entry_point, 0xDEAD);
    }

    // -- add_section tests -------------------------------------------------

    #[test]
    fn add_section_increments_section_count() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        assert_eq!(pe.coff_header.number_of_sections, 1);
        assert_eq!(pe.sections.len(), 1);

        add_section(&mut pe, ".rsrc", &[0u8; 16], IMAGE_SCN_MEM_READ)
            .expect("add_section");

        assert_eq!(pe.coff_header.number_of_sections, 2);
        assert_eq!(pe.sections.len(), 2);
    }

    #[test]
    fn add_section_name_stored_correctly() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        add_section(&mut pe, ".squre", &[1, 2, 3], IMAGE_SCN_MEM_READ)
            .expect("add_section");

        let new_sec = pe.sections.last().unwrap();
        assert_eq!(new_sec.name_str(), ".squre");
    }

    #[test]
    fn add_section_aligns_raw_offset_to_file_alignment() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        // .text ends at 0x200 + 0x200 = 0x400 which is already aligned to
        // file_alignment (0x200), so the new section starts at 0x400.
        add_section(&mut pe, ".data", &[0xBB; 100], IMAGE_SCN_MEM_READ)
            .expect("add_section");

        let new_sec = &pe.sections[1];
        assert_eq!(new_sec.pointer_to_raw_data, 0x400);
        // raw size should be aligned to file_alignment
        assert_eq!(new_sec.size_of_raw_data % pe.optional_header.file_alignment, 0);
    }

    #[test]
    fn add_section_aligns_virtual_address_to_section_alignment() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        add_section(&mut pe, ".data", &[0xBB; 100], IMAGE_SCN_MEM_READ)
            .expect("add_section");

        let new_sec = &pe.sections[1];
        assert_eq!(
            new_sec.virtual_address % pe.optional_header.section_alignment,
            0
        );
        // .text VA=0x1000, virtual_size=0x1E0 -> aligned to 0x1000 -> 0x2000
        assert_eq!(new_sec.virtual_address, 0x2000);
    }

    #[test]
    fn add_section_updates_size_of_image() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        let old_size_of_image = pe.optional_header.size_of_image;

        add_section(
            &mut pe,
            ".extra",
            &[0xDD; 0x1001],
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )
        .expect("add_section");

        // SizeOfImage must have grown (data is large enough to push
        // beyond the original 0x3000).
        assert!(pe.optional_header.size_of_image > old_size_of_image);
        // Must be aligned to section alignment.
        assert_eq!(
            pe.optional_header.size_of_image % pe.optional_header.section_alignment,
            0
        );
    }

    #[test]
    fn add_section_stores_characteristics() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        add_section(&mut pe, ".hook", &[0x90; 32], chars).expect("add_section");

        assert_eq!(pe.sections.last().unwrap().characteristics, chars);
    }

    #[test]
    fn add_section_data_written_to_buffer() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");
        let payload = b"HELLO_SECTION";

        add_section(&mut pe, ".msg", payload, IMAGE_SCN_MEM_READ)
            .expect("add_section");

        let sec = pe.sections.last().unwrap();
        let offset = sec.pointer_to_raw_data as usize;
        assert_eq!(&pe.data[offset..offset + payload.len()], payload);
    }

    #[test]
    fn add_section_name_too_long_returns_error() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let result = add_section(&mut pe, ".toolongname", &[0], IMAGE_SCN_MEM_READ);
        assert!(result.is_err());
    }

    #[test]
    fn add_multiple_sections_in_sequence() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        add_section(&mut pe, ".sec1", &[1u8; 100], IMAGE_SCN_MEM_READ)
            .expect("add first");
        add_section(&mut pe, ".sec2", &[2u8; 200], IMAGE_SCN_MEM_READ)
            .expect("add second");

        assert_eq!(pe.sections.len(), 3);
        assert_eq!(pe.coff_header.number_of_sections, 3);

        // Sections should not overlap in virtual or raw space.
        let sec1 = &pe.sections[1];
        let sec2 = &pe.sections[2];
        assert!(sec2.virtual_address >= sec1.virtual_address + sec1.virtual_size);
        assert!(sec2.pointer_to_raw_data >= sec1.pointer_to_raw_data + sec1.size_of_raw_data);
    }

    #[test]
    fn add_section_roundtrip_through_write_and_reparse() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        add_section(
            &mut pe,
            ".test",
            &[0xFE; 48],
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        )
        .expect("add_section");

        let written = write_pe(&pe);
        let pe2 = PeFile::parse(written).expect("reparse");

        assert_eq!(pe2.sections.len(), 2);
        assert_eq!(pe2.coff_header.number_of_sections, 2);
        assert_eq!(pe2.sections[1].name_str(), ".test");
        assert_eq!(
            pe2.sections[1].characteristics,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
        );

        let sec_data = pe2.section_data(&pe2.sections[1]);
        assert!(sec_data.starts_with(&[0xFE; 48]));
    }

    // -- update_section_data tests -----------------------------------------

    #[test]
    fn update_section_data_replaces_content() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let new_data = vec![0x90u8; 64]; // NOP sled
        update_section_data(&mut pe, 0, &new_data).expect("update");

        let offset = pe.sections[0].pointer_to_raw_data as usize;
        assert_eq!(&pe.data[offset..offset + 64], &new_data[..]);
    }

    #[test]
    fn update_section_data_updates_virtual_size() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let new_data = vec![0x42u8; 128];
        update_section_data(&mut pe, 0, &new_data).expect("update");

        assert_eq!(pe.sections[0].virtual_size, 128);
    }

    #[test]
    fn update_section_data_aligns_raw_size() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        // 100 bytes -> should be aligned up to 0x200 (file alignment)
        let new_data = vec![0x42u8; 100];
        update_section_data(&mut pe, 0, &new_data).expect("update");

        assert_eq!(
            pe.sections[0].size_of_raw_data % pe.optional_header.file_alignment,
            0
        );
        assert_eq!(pe.sections[0].size_of_raw_data, 0x200);
    }

    #[test]
    fn update_section_data_pads_with_zeros() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let new_data = vec![0xAA; 10];
        update_section_data(&mut pe, 0, &new_data).expect("update");

        let offset = pe.sections[0].pointer_to_raw_data as usize;
        // Data should be there.
        assert_eq!(&pe.data[offset..offset + 10], &[0xAA; 10]);
        // Padding should be zero.
        assert_eq!(pe.data[offset + 10], 0x00);
    }

    #[test]
    fn update_section_data_invalid_index_returns_error() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let result = update_section_data(&mut pe, 99, &[0]);
        assert!(result.is_err());
    }

    #[test]
    fn update_section_data_roundtrip_through_write_and_reparse() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        let replacement = vec![0xDE; 80];
        update_section_data(&mut pe, 0, &replacement).expect("update");

        let written = write_pe(&pe);
        let pe2 = PeFile::parse(written).expect("reparse");

        let sec_data = pe2.section_data(&pe2.sections[0]);
        assert!(sec_data.starts_with(&[0xDE; 80]));
        assert_eq!(pe2.sections[0].virtual_size, 80);
    }

    // -- align_up tests ----------------------------------------------------

    #[test]
    fn align_up_already_aligned() {
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn align_up_rounds_correctly() {
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn align_up_zero_value() {
        assert_eq!(align_up(0, 0x200), 0);
    }

    #[test]
    fn align_up_zero_alignment() {
        assert_eq!(align_up(42, 0), 42);
    }

    // -- section characteristic constants ----------------------------------

    #[test]
    fn section_characteristic_values() {
        assert_eq!(IMAGE_SCN_MEM_READ, 0x4000_0000);
        assert_eq!(IMAGE_SCN_MEM_WRITE, 0x8000_0000);
        assert_eq!(IMAGE_SCN_MEM_EXECUTE, 0x2000_0000);
        assert_eq!(IMAGE_SCN_CNT_CODE, 0x0000_0020);
        assert_eq!(IMAGE_SCN_CNT_INITIALIZED_DATA, 0x0000_0040);
    }

    // -- combined workflow test --------------------------------------------

    #[test]
    fn full_workflow_modify_and_extend() {
        let data = build_minimal_pe64();
        let mut pe = PeFile::parse(data).expect("parse");

        // 1. Change entry point.
        set_entry_point(&mut pe, 0x2000);

        // 2. Update .text data.
        update_section_data(&mut pe, 0, &[0x48, 0x89, 0xE5]).expect("update .text");

        // 3. Add two new sections.
        add_section(
            &mut pe,
            ".rdata",
            b"Hello, world!\0",
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        )
        .expect("add .rdata");

        add_section(
            &mut pe,
            ".bss",
            &[0u8; 4096],
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )
        .expect("add .bss");

        // 4. Write and reparse.
        let output = write_pe(&pe);
        let pe2 = PeFile::parse(output).expect("reparse");

        assert_eq!(pe2.optional_header.entry_point, 0x2000);
        assert_eq!(pe2.sections.len(), 3);
        assert_eq!(pe2.sections[0].name_str(), ".text");
        assert_eq!(pe2.sections[1].name_str(), ".rdata");
        assert_eq!(pe2.sections[2].name_str(), ".bss");

        // .text starts with the bytes we wrote.
        let text_data = pe2.section_data(&pe2.sections[0]);
        assert_eq!(&text_data[..3], &[0x48, 0x89, 0xE5]);

        // .rdata contains our string.
        let rdata = pe2.section_data(&pe2.sections[1]);
        assert!(rdata.starts_with(b"Hello, world!\0"));

        // SizeOfImage covers all sections.
        let last = pe2.sections.last().unwrap();
        let last_end = last.virtual_address + last.virtual_size;
        assert!(pe2.optional_header.size_of_image >= last_end);
        assert_eq!(
            pe2.optional_header.size_of_image % pe2.optional_header.section_alignment,
            0
        );
    }

    #[test]
    fn write_pe_pe32_entry_point_and_image_base() {
        let data = build_minimal_pe32();
        let mut pe = PeFile::parse(data).expect("parse");

        set_entry_point(&mut pe, 0x5000);
        let output = write_pe(&pe);

        let opt_offset = pe.pe_offset + 4 + 20;
        assert_eq!(read_u32(&output, opt_offset + 16), 0x5000);
        assert_eq!(read_u32(&output, opt_offset + 28), 0x0040_0000);
    }

    #[test]
    fn write_pe_pe64_image_base() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(data).expect("parse");
        let output = write_pe(&pe);

        let opt_offset = pe.pe_offset + 4 + 20;
        assert_eq!(read_u64(&output, opt_offset + 24), 0x0000_0001_4000_0000);
    }
}
