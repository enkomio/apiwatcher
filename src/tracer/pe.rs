//! PE import/export table parsers.

#![allow(dead_code)]

use windows_sys::Win32::Foundation::HANDLE;

use super::process::{basename, read_cstr, read_u16, read_u32, read_u64};

pub struct Import {
    /// Resolved address of the function (read from the IAT after loader binding).
    pub addr: usize,
    pub dll: String,
    pub name: String,
}

/// Parse the import table of the module at `base` in process `proc`.
/// Returns one entry per imported symbol with its resolved runtime address.
pub fn parse_imports(proc: HANDLE, base: usize) -> Vec<Import> {
    let mut out = Vec::new();

    // DOS header → e_lfanew
    let e_lfanew = match read_u32(proc, base + 0x3C) {
        Some(v) => v as usize,
        None => return out,
    };

    // Verify PE signature "PE\0\0"
    if read_u32(proc, base + e_lfanew) != Some(0x0000_4550) {
        return out;
    }

    // Optional header at base + e_lfanew + 4 (sig) + 20 (COFF file header)
    let opt = base + e_lfanew + 24;
    let (import_dd_off, bits, iat_entry_sz) = match read_u16(proc, opt) {
        Some(0x020B) => (opt + 120, 64u32, 8usize), // PE32+
        Some(0x010B) => (opt + 104, 32u32, 4usize), // PE32
        _ => return out,
    };

    let import_rva = read_u32(proc, import_dd_off).unwrap_or(0) as usize;
    if import_rva == 0 {
        return out;
    }

    // Walk IMAGE_IMPORT_DESCRIPTOR chain (20 bytes each, zero-terminated)
    let import_base = base + import_rva;
    let mut desc = 0usize;
    loop {
        let ilt_rva = read_u32(proc, import_base + desc).unwrap_or(0) as usize;
        let name_rva = read_u32(proc, import_base + desc + 12).unwrap_or(0) as usize;
        let iat_rva = read_u32(proc, import_base + desc + 16).unwrap_or(0) as usize;

        if name_rva == 0 && iat_rva == 0 {
            break; // null terminator
        }

        let dll = read_cstr(proc, base + name_rva).to_ascii_lowercase();
        let ilt_base = base + if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let iat_base = base + iat_rva;

        let mut slot = 0usize;
        loop {
            // After loader binding the IAT slot IS the function address
            let func_addr = if bits == 64 {
                read_u64(proc, iat_base + slot).unwrap_or(0) as usize
            } else {
                read_u32(proc, iat_base + slot).unwrap_or(0) as usize
            };
            if func_addr == 0 {
                break;
            }

            let ilt_entry = if bits == 64 {
                read_u64(proc, ilt_base + slot).unwrap_or(0)
            } else {
                read_u32(proc, ilt_base + slot).unwrap_or(0) as u64
            };

            let ordinal_bit = if bits == 64 { 1u64 << 63 } else { 1u64 << 31 };
            let func_name = if ilt_entry & ordinal_bit != 0 {
                format!("#{}", ilt_entry & 0xFFFF)
            } else {
                // RVA to IMAGE_IMPORT_BY_NAME: [hint: u16][name: char*]
                read_cstr(proc, base + (ilt_entry & 0x7FFF_FFFF) as usize + 2)
            };

            out.push(Import { addr: func_addr, dll: dll.clone(), name: func_name });
            slot += iat_entry_sz;
        }

        desc += 20;
    }

    out
}

/// Read `SizeOfImage` from the optional header. Falls back to 0x1000.
pub fn get_module_size(proc: HANDLE, base: usize) -> usize {
    let e_lfanew = read_u32(proc, base + 0x3C).unwrap_or(0) as usize;
    let opt = base + e_lfanew + 24;
    match read_u16(proc, opt) {
        Some(0x020B) | Some(0x010B) => read_u32(proc, opt + 56).unwrap_or(0x1000) as usize,
        _ => 0x1000,
    }
}

/// Strip directory path, return just the file name.
pub fn dll_basename(dll: &str) -> &str {
    basename(dll)
}

/// Read `AddressOfEntryPoint` from the PE optional header and return the
/// absolute address in the target process.
///
/// Returns `None` when the field is zero (resource-only DLLs, etc.) or when
/// the PE header cannot be read.
pub fn get_entry_point(proc: HANDLE, base: usize) -> Option<usize> {
    let e_lfanew = read_u32(proc, base + 0x3C)? as usize;
    // PE signature "PE\0\0"
    if read_u32(proc, base + e_lfanew) != Some(0x0000_4550) {
        return None;
    }
    // Optional header starts right after the 4-byte signature and the 20-byte
    // COFF file header.
    let opt = base + e_lfanew + 24;
    match read_u16(proc, opt)? {
        0x020B | 0x010B => {
            // AddressOfEntryPoint is at offset +16 inside the optional header
            // for both PE32 and PE32+.
            let ep_rva = read_u32(proc, opt + 16)? as usize;
            if ep_rva == 0 { None } else { Some(base + ep_rva) }
        }
        _ => None,
    }
}

// ── Export table ──────────────────────────────────────────────────────────────

pub struct Export {
    /// Absolute address of the exported function in the target process.
    pub addr: usize,
    pub name: String,
}

/// Parse the Export Address Table (EAT) of the PE image mapped at `base`
/// inside the target process.
///
/// Returns one [`Export`] per *named* export whose RVA is not a forwarder
/// (i.e. does not fall inside the export directory itself).
pub fn parse_exports(proc: HANDLE, base: usize) -> Vec<Export> {
    let mut out = Vec::new();

    // ── DOS header → e_lfanew ─────────────────────────────────────────────────
    let e_lfanew = match read_u32(proc, base + 0x3C) {
        Some(v) => v as usize,
        None => return out,
    };

    // ── PE signature ──────────────────────────────────────────────────────────
    if read_u32(proc, base + e_lfanew) != Some(0x0000_4550) {
        return out;
    }

    // ── Optional header ───────────────────────────────────────────────────────
    let opt = base + e_lfanew + 24; // after 4-byte sig + 20-byte COFF header
    // DataDirectory[0] (Export) offset from the start of the optional header:
    //   PE32+: 112   PE32: 96
    let export_dd_off = match read_u16(proc, opt) {
        Some(0x020B) => opt + 112, // PE32+
        Some(0x010B) => opt + 96,  // PE32
        _ => return out,
    };

    let export_rva  = read_u32(proc, export_dd_off    ).unwrap_or(0) as usize;
    let export_size = read_u32(proc, export_dd_off + 4).unwrap_or(0) as usize;
    if export_rva == 0 {
        return out; // no export directory
    }

    // ── IMAGE_EXPORT_DIRECTORY ────────────────────────────────────────────────
    //   +0x14  NumberOfFunctions      (u32)
    //   +0x18  NumberOfNames          (u32)
    //   +0x1C  AddressOfFunctions     (RVA → u32[NumberOfFunctions])
    //   +0x20  AddressOfNames         (RVA → u32[NumberOfNames])
    //   +0x24  AddressOfNameOrdinals  (RVA → u16[NumberOfNames])
    let export_dir  = base + export_rva;
    let num_names   = read_u32(proc, export_dir + 0x18).unwrap_or(0) as usize;
    let rva_fns     = read_u32(proc, export_dir + 0x1C).unwrap_or(0) as usize;
    let rva_names   = read_u32(proc, export_dir + 0x20).unwrap_or(0) as usize;
    let rva_ords    = read_u32(proc, export_dir + 0x24).unwrap_or(0) as usize;

    if rva_fns == 0 || rva_names == 0 || rva_ords == 0 {
        return out;
    }

    out.reserve(num_names);
    for i in 0..num_names {
        // Name RVA → null-terminated ASCII name
        let name_rva = match read_u32(proc, base + rva_names + i * 4) {
            Some(v) => v as usize,
            None    => continue,
        };
        let name = read_cstr(proc, base + name_rva);
        if name.is_empty() {
            continue;
        }

        // Ordinal (relative, 0-based index into AddressOfFunctions)
        let ord = match read_u16(proc, base + rva_ords + i * 2) {
            Some(v) => v as usize,
            None    => continue,
        };

        // Function RVA
        let func_rva = match read_u32(proc, base + rva_fns + ord * 4) {
            Some(v) => v as usize,
            None    => continue,
        };

        // Skip null entries and forwarded exports (RVA points inside the
        // export directory section itself).
        if func_rva == 0 {
            continue;
        }
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue; // forwarder string, not a real code address
        }

        out.push(Export { addr: base + func_rva, name });
    }

    out
}
