//! Low-level process memory I/O wrappers.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};

/// Read `buf.len()` bytes from `addr` in the target process.
pub fn rpmem(proc: HANDLE, addr: usize, buf: &mut [u8]) -> bool {
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(proc, addr as *const _, buf.as_mut_ptr() as *mut _, buf.len(), &mut n)
            != 0
            && n == buf.len()
    }
}

pub fn read_u8(proc: HANDLE, addr: usize) -> Option<u8> {
    let mut b = [0u8; 1];
    rpmem(proc, addr, &mut b).then_some(b[0])
}

pub fn read_u16(proc: HANDLE, addr: usize) -> Option<u16> {
    let mut b = [0u8; 2];
    rpmem(proc, addr, &mut b).then_some(u16::from_le_bytes(b))
}

pub fn read_u32(proc: HANDLE, addr: usize) -> Option<u32> {
    let mut b = [0u8; 4];
    rpmem(proc, addr, &mut b).then_some(u32::from_le_bytes(b))
}

pub fn read_u64(proc: HANDLE, addr: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    rpmem(proc, addr, &mut b).then_some(u64::from_le_bytes(b))
}

/// Read a null-terminated ASCII string from the target process.
pub fn read_cstr(proc: HANDLE, addr: usize) -> String {
    let mut v = Vec::with_capacity(64);
    for i in 0..512usize {
        match read_u8(proc, addr + i) {
            Some(0) | None => break,
            Some(b) => v.push(b),
        }
    }
    String::from_utf8_lossy(&v).into_owned()
}

/// Read a null-terminated UTF-16 string from the target process.
pub fn read_wstr(proc: HANDLE, addr: usize) -> String {
    let mut units = Vec::new();
    for i in 0..256usize {
        match read_u16(proc, addr + i * 2) {
            Some(0) | None => break,
            Some(w) => units.push(w),
        }
    }
    OsString::from_wide(&units).to_string_lossy().into_owned()
}

/// Read up to `buf.len()` bytes from `addr`; returns how many were actually read.
/// Unlike `rpmem`, a partial read (e.g. near a page boundary) is acceptable.
pub fn read_bytes(proc: HANDLE, addr: usize, buf: &mut [u8]) -> usize {
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(proc, addr as *const _, buf.as_mut_ptr() as *mut _, buf.len(), &mut n);
    }
    n
}

/// Write a single byte to the target process.
pub fn write_byte(proc: HANDLE, addr: usize, byte: u8) -> bool {
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(proc, addr as *mut _, [byte].as_ptr() as *const _, 1, &mut written)
            != 0
            && written == 1
    }
}

/// Return the basename of a path (last component after `\` or `/`).
pub fn basename(path: &str) -> &str {
    path.rfind(['\\', '/']).map(|i| &path[i + 1..]).unwrap_or(path)
}
