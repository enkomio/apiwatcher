//! Simplified C header parser — public API.
//!
//! The pipeline for each `.h` file:
//!   1. `preprocessor::collect_macros` — scan `#define` lines, build macro table
//!   2. `lexer::tokenize_raw` — produce a raw token stream
//!   3. `preprocessor::expand_macros` — expand object-like macros in the stream
//!   4. `parser::Parser::new(toks).parse_file()` — extract typedefs & function decls

mod lexer;
mod parser;
mod preprocessor;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use lexer::tokenize_raw;
use parser::Parser;
use preprocessor::{collect_macros, expand_macros};

// ── Public types ──────────────────────────────────────────────────────────────

/// Simplified C type — enough to determine parameter size and display.
#[derive(Debug, Clone, PartialEq)]
pub enum CType {
    Void,
    Bool,
    I8,
    I16,
    /// `int` / `long` (32-bit on Windows x64)
    I32,
    /// `long long` / `__int64`
    I64,
    U8,
    U16,
    /// `unsigned int` / `DWORD` / `unsigned long`
    U32,
    /// `unsigned long long` / `SIZE_T` / `ULONGLONG`
    U64,
    Float,
    Double,
    /// Any pointer — always 8 bytes on x64.
    Pointer,
    /// `char*` / `const char*` — 8-byte pointer, printed as an ANSI string.
    CharPtr,
    /// `wchar_t*` / `const wchar_t*` — 8-byte pointer, printed as a UTF-16 string.
    WCharPtr,
    /// Function pointer — treated as Pointer.
    FnPtr,
    /// Unresolved typedef or struct tag; looked up at size-query time.
    Named(String),
}

impl CType {
    /// Size in bytes on Windows x64.
    pub fn size_x64(&self, typedefs: &HashMap<String, CType>) -> usize {
        match self {
            CType::Void => 0,
            CType::Bool | CType::I8 | CType::U8 => 1,
            CType::I16 | CType::U16 => 2,
            CType::I32 | CType::U32 | CType::Float => 4,
            CType::I64 | CType::U64 | CType::Double
            | CType::Pointer | CType::CharPtr | CType::WCharPtr | CType::FnPtr => 8,
            CType::Named(name) => typedefs
                .get(name)
                .map(|t| t.size_x64(typedefs))
                .unwrap_or(8),
        }
    }

}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: CType,
}

#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub ret: CType,
    pub params: Vec<Param>,
}

// ── HeaderDb ──────────────────────────────────────────────────────────────────

/// Database of parsed function definitions and type aliases.
pub struct HeaderDb {
    pub functions: HashMap<String, FunctionDef>,
    pub typedefs: HashMap<String, CType>,
}

impl Default for HeaderDb {
    fn default() -> Self { Self::new() }
}

impl HeaderDb {
    /// Create an empty database pre-populated with common Windows API types.
    ///
    /// These cover the types that Windows SDK headers define in `windef.h`,
    /// `basetsd.h`, `winnt.h`, etc. — files that are `#include`'d but not
    /// parsed by us. Having them here means `DWORD`, `LPVOID`, `SIZE_T`, etc.
    /// resolve to the correct sizes without any extra user-provided files.
    pub fn new() -> Self {
        let mut td: HashMap<String, CType> = HashMap::new();

        macro_rules! ins {
            ($name:expr, $ty:expr) => { td.insert($name.to_string(), $ty); };
        }

        // Boolean
        ins!("BOOL",    CType::Bool);
        ins!("WINBOOL", CType::Bool);
        ins!("BOOLEAN", CType::U8);

        // Integer aliases
        ins!("BYTE",   CType::U8);
        ins!("CHAR",   CType::I8);
        ins!("UCHAR",  CType::U8);
        ins!("WORD",   CType::U16);
        ins!("SHORT",  CType::I16);
        ins!("USHORT", CType::U16);
        ins!("WCHAR",  CType::U16);
        ins!("INT",    CType::I32);
        ins!("UINT",   CType::U32);
        ins!("LONG",   CType::I32);
        ins!("ULONG",  CType::U32);
        ins!("DWORD",  CType::U32);
        ins!("FLOAT",  CType::Float);
        ins!("LONGLONG",   CType::I64);
        ins!("ULONGLONG",  CType::U64);
        ins!("DWORDLONG",  CType::U64);
        ins!("DWORD32",    CType::U32);
        ins!("DWORD64",    CType::U64);
        ins!("INT32",  CType::I32);
        ins!("INT64",  CType::I64);
        ins!("UINT32", CType::U32);
        ins!("UINT64", CType::U64);

        // Pointer-sized integers (x64)
        ins!("SIZE_T",    CType::U64);
        ins!("SSIZE_T",   CType::I64);
        ins!("ULONG_PTR", CType::U64);
        ins!("LONG_PTR",  CType::I64);
        ins!("UINT_PTR",  CType::U64);
        ins!("INT_PTR",   CType::I64);
        ins!("DWORD_PTR", CType::U64);

        // Void / generic
        ins!("VOID",    CType::Void);
        ins!("PVOID",   CType::Pointer);
        ins!("LPVOID",  CType::Pointer);
        ins!("LPCVOID", CType::Pointer);

        // Handle types
        ins!("HANDLE",    CType::Pointer);
        ins!("HMODULE",   CType::Pointer);
        ins!("HINSTANCE", CType::Pointer);
        ins!("HKEY",      CType::Pointer);
        ins!("HWND",      CType::Pointer);
        ins!("HDC",       CType::Pointer);
        ins!("HBITMAP",   CType::Pointer);
        ins!("HGLOBAL",   CType::Pointer);
        ins!("HLOCAL",    CType::Pointer);
        ins!("HRSRC",     CType::Pointer);
        ins!("HFILE",     CType::Pointer);
        ins!("SC_HANDLE", CType::Pointer);

        // Narrow string pointer aliases → CharPtr (printed as ANSI strings)
        ins!("LPSTR",    CType::CharPtr);
        ins!("LPCSTR",   CType::CharPtr);
        ins!("PSTR",     CType::CharPtr);
        ins!("PCSTR",    CType::CharPtr);
        ins!("LPCCH",    CType::CharPtr);
        ins!("LPCH",     CType::CharPtr);

        // Wide string pointer aliases → WCharPtr (printed as UTF-16 strings)
        ins!("LPWSTR",   CType::WCharPtr);
        ins!("LPCWSTR",  CType::WCharPtr);
        ins!("PCWSTR",   CType::WCharPtr);
        ins!("PWSTR",    CType::WCharPtr);
        ins!("LPCOLESTR",CType::WCharPtr);
        ins!("LPOLESTR", CType::WCharPtr);

        // Common pointer-to-scalar aliases
        ins!("PBOOL",   CType::Pointer);
        ins!("PBYTE",   CType::Pointer);
        ins!("PCHAR",   CType::Pointer);
        ins!("PWORD",   CType::Pointer);
        ins!("PDWORD",  CType::Pointer);
        ins!("PULONG",  CType::Pointer);
        ins!("PLONG",   CType::Pointer);
        ins!("PULONG_PTR", CType::Pointer);
        ins!("PSIZE_T",    CType::Pointer);

        HeaderDb { functions: HashMap::new(), typedefs: td }
    }

    /// Scan `dir` for `.h` files and load each one into this database.
    pub fn load_dir(&mut self, dir: &Path) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[defs] cannot open '{}': {}", dir.display(), e);
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("h") {
                self.load_file(&path);
            }
        }
    }

    /// Parse one `.h` file and merge its definitions into this database.
    pub fn load_file(&mut self, path: &Path) {
        let src = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[defs] cannot read '{}': {}", path.display(), e);
                return;
            }
        };

        let macros = collect_macros(&src);
        let raw_toks = tokenize_raw(&src);
        let toks = expand_macros(raw_toks, &macros);

        let mut p = Parser::new(toks);
        p.parse_file();

        eprintln!(
            "[defs] {}: {} function(s), {} typedef(s), {} macro(s) expanded",
            path.file_name().unwrap_or_default().to_string_lossy(),
            p.functions.len(),
            p.typedefs.len(),
            macros.len(),
        );

        // Typedefs first so function parameter types can be resolved
        self.typedefs.extend(p.typedefs);
        self.functions.extend(p.functions);
    }
}
