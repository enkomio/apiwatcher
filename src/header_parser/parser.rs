//! Recursive-descent parser for a simplified subset of C declarations.
//! Receives a pre-processed (macro-expanded) token stream from the lexer.

use std::collections::HashMap;

use super::lexer::Tok;
use super::{CType, FunctionDef, Param};

// ── Modifier recognition ──────────────────────────────────────────────────────

/// Returns true for identifiers that should be silently skipped in any
/// declarator context: calling conventions, storage-class macros, SAL
/// annotations, and common compiler extension keywords.
///
/// After macro expansion, things like `WINBASEAPI` → `__declspec(dllimport)`
/// and `WINAPI` → `__stdcall` are handled here via the compiler keywords.
/// We also keep common Windows API names in the static list for headers
/// where the macros are defined in an #include'd file that we don't parse.
fn is_modifier(s: &str) -> bool {
    matches!(
        s,
        // Windows API storage-class macros (defined in system headers we don't parse)
        "WINBASEAPI" | "WINUSERAPI" | "NTSYSAPI" | "NTSYSCALLAPI" | "DECLSPEC_IMPORT"
        | "DECLSPEC_NOINLINE" | "DECLSPEC_NORETURN" | "DECLSPEC_SELECTANY"
        | "WINAPI_INLINE" | "FORCEINLINE"
        // Calling conventions
        | "WINAPI" | "APIENTRY" | "CALLBACK" | "PASCAL" | "NTAPI"
        | "STDAPICALLTYPE" | "STDMETHODCALLTYPE" | "CDECL" | "FASTCALL"
        | "__cdecl" | "__stdcall" | "__fastcall" | "__thiscall" | "__vectorcall"
        // 16-bit compatibility / winsock macros
        | "FAR" | "NEAR"
        // Linkage specifiers
        | "EXTERN_C" | "WINSOCK_API_LINKAGE"
        // Common SAL-free parameter qualifiers (older SDK / winsock headers)
        | "IN" | "OUT" | "OPTIONAL"
        // Inline / linkage
        | "__forceinline" | "__inline" | "inline" | "extern" | "static"
        | "auto" | "register" | "restrict" | "__restrict"
        | "__extension__" | "__volatile__" | "__const__"
    )
    // SAL annotations and double-underscore compiler extensions:
    // anything that starts with `_` AND contains a second `_`
    || s.starts_with('_') && s[1..].contains('_')
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    pub typedefs: HashMap<String, CType>,
    pub functions: HashMap<String, FunctionDef>,
}

impl Parser {
    /// Construct a parser from a pre-expanded token stream.
    pub fn new(toks: Vec<Tok>) -> Self {
        Parser { toks, pos: 0, typedefs: HashMap::new(), functions: HashMap::new() }
    }

    // ── Token primitives ──────────────────────────────────────────────────────

    fn peek(&self) -> &Tok { &self.toks[self.pos] }

    fn eat(&mut self) -> Tok {
        let t = self.toks[self.pos].clone();
        if self.pos + 1 < self.toks.len() { self.pos += 1; }
        t
    }

    fn at_eof(&self) -> bool { matches!(self.peek(), Tok::Eof) }

    fn expect_semi(&mut self) { if matches!(self.peek(), Tok::Semicolon) { self.eat(); } }

    /// Error recovery: consume to next `;` (inclusive) or unbalanced `}`.
    fn skip_to_semi(&mut self) {
        let mut depth = 0i32;
        loop {
            match self.peek() {
                Tok::Eof => break,
                Tok::LParen | Tok::LBrace | Tok::LBracket => { depth += 1; self.eat(); }
                Tok::RParen | Tok::RBracket if depth > 0 => { depth -= 1; self.eat(); }
                Tok::RBrace if depth > 0 => { depth -= 1; self.eat(); }
                Tok::RBrace => break,
                Tok::Semicolon if depth == 0 => { self.eat(); break; }
                _ => { self.eat(); }
            }
        }
    }

    /// Skip balanced `(…)` — call after consuming the opening `(`.
    fn skip_parens(&mut self) {
        let mut d = 1i32;
        loop {
            match self.peek() {
                Tok::Eof => break,
                Tok::LParen => { d += 1; self.eat(); }
                Tok::RParen => { d -= 1; self.eat(); if d == 0 { break; } }
                _ => { self.eat(); }
            }
        }
    }

    /// Skip balanced `{…}` — call after consuming the opening `{`.
    fn skip_braces(&mut self) {
        let mut d = 1i32;
        loop {
            match self.peek() {
                Tok::Eof => break,
                Tok::LBrace => { d += 1; self.eat(); }
                Tok::RBrace => { d -= 1; self.eat(); if d == 0 { break; } }
                _ => { self.eat(); }
            }
        }
    }

    // ── Modifier skipping ─────────────────────────────────────────────────────

    /// Consume calling conventions, SAL annotations, `__declspec(…)`, etc.
    fn skip_modifiers(&mut self) {
        loop {
            match self.peek().clone() {
                Tok::Ident(ref s) => {
                    let s = s.clone();
                    if s == "__declspec" || s == "__attribute__" || s == "__attribute" {
                        self.eat();
                        if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                    } else if is_modifier(&s) {
                        self.eat();
                        // SAL annotations can have arguments: _Post_writable_byte_size_(N),
                        // _Success_(expr), _Frees_ptr_opt_(p), etc. — skip them.
                        if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    // ── File-level dispatch ───────────────────────────────────────────────────

    pub fn parse_file(&mut self) {
        while !self.at_eof() {
            self.parse_top_level();
        }
    }

    fn parse_top_level(&mut self) {
        self.skip_modifiers();
        if self.at_eof() { return; }

        match self.peek().clone() {
            Tok::Semicolon => { self.eat(); }
            // Bare `{` (e.g. from `extern "C" {`) — just enter the block and
            // keep parsing. The matching `}` is handled by the RBrace arm.
            Tok::LBrace    => { self.eat(); }
            Tok::RBrace    => { self.eat(); }
            Tok::Ident(ref s) => {
                let s = s.clone();
                match s.as_str() {
                    "typedef" => { self.eat(); self.parse_typedef(); }
                    "struct" | "union" => {
                        self.parse_struct_or_union();
                        self.skip_modifiers();
                        if let Tok::Ident(_) = self.peek() { self.eat(); }
                        self.expect_semi();
                    }
                    "enum" => { self.skip_to_semi(); }
                    _ => { self.parse_decl(); }
                }
            }
            _ => { self.skip_to_semi(); }
        }
    }

    // ── Type specifier ────────────────────────────────────────────────────────

    /// Parse a type specifier (qualifiers + base type) and return the CType.
    fn parse_type_spec(&mut self) -> CType {
        let mut unsigned = false;
        let mut is_signed = false;
        let mut longs = 0u32;
        let mut base: Option<CType> = None;

        loop {
            match self.peek().clone() {
                Tok::Ident(ref s) => {
                    let s = s.clone();
                    match s.as_str() {
                        // Type qualifiers / storage class / calling-conv
                        "const" | "volatile" | "extern" | "static" | "auto" | "register"
                        | "inline" | "__inline" | "__forceinline"
                        | "restrict" | "__restrict" => { self.eat(); }

                        // Calling conventions
                        "WINAPI" | "APIENTRY" | "CALLBACK" | "PASCAL" | "NTAPI"
                        | "STDAPICALLTYPE" | "STDMETHODCALLTYPE"
                        | "__cdecl" | "__stdcall" | "__fastcall"
                        | "__thiscall" | "__vectorcall" => { self.eat(); }

                        // Windows storage-class macros (defined in system includes)
                        "WINBASEAPI" | "WINUSERAPI" | "NTSYSAPI" | "NTSYSCALLAPI" | "DECLSPEC_IMPORT"
                        | "DECLSPEC_NOINLINE" | "DECLSPEC_NORETURN" | "FORCEINLINE"
                        | "WINAPI_INLINE" => { self.eat(); }

                        // 16-bit compat / winsock / older SDK qualifiers
                        "FAR" | "NEAR" | "EXTERN_C" | "WINSOCK_API_LINKAGE"
                        | "IN" | "OUT" | "OPTIONAL" => { self.eat(); }

                        // Compiler attributes
                        "__declspec" | "__attribute__" | "__attribute" => {
                            self.eat();
                            if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                        }

                        // SAL annotations / underscore-prefixed extensions
                        s if s.starts_with('_') => {
                            self.eat();
                            if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                        }

                        "unsigned" => { self.eat(); unsigned = true; }
                        "signed"   => { self.eat(); is_signed = true; }
                        "long"     => { self.eat(); longs += 1; }
                        "short"    => {
                            self.eat();
                            base = Some(if unsigned { CType::U16 } else { CType::I16 });
                        }

                        "void"  => { self.eat(); base = Some(CType::Void); break; }
                        "bool" | "_Bool" | "BOOL" | "WINBOOL" => { self.eat(); base = Some(CType::Bool); break; }

                        "char" => {
                            self.eat();
                            base = Some(if unsigned { CType::U8 } else { CType::I8 });
                            break;
                        }
                        "int" => {
                            self.eat();
                            if longs == 0 {
                                base = Some(if unsigned { CType::U32 } else { CType::I32 });
                            }
                            longs = 0;
                            break;
                        }
                        "__int8"  => { self.eat(); base = Some(if unsigned { CType::U8  } else { CType::I8  }); break; }
                        "__int16" => { self.eat(); base = Some(if unsigned { CType::U16 } else { CType::I16 }); break; }
                        "__int32" => { self.eat(); base = Some(if unsigned { CType::U32 } else { CType::I32 }); break; }
                        "__int64" => { self.eat(); base = Some(if unsigned { CType::U64 } else { CType::I64 }); break; }
                        "float"  => { self.eat(); base = Some(CType::Float);  break; }
                        "double" => { self.eat(); base = Some(CType::Double); break; }

                        "struct" | "union" => { base = Some(self.parse_struct_or_union()); break; }
                        "enum" => {
                            self.eat();
                            if let Tok::Ident(_) = self.peek() { self.eat(); }
                            if matches!(self.peek(), Tok::LBrace) { self.eat(); self.skip_braces(); }
                            base = Some(CType::I32);
                            break;
                        }

                        // Any other identifier: named type (typedef, struct tag, …).
                        // BUT if we already have pending unsigned/signed/long qualifiers,
                        // stop WITHOUT consuming this token — it's the declarator name,
                        // not a type keyword. Example: `unsigned long DWORD` where DWORD
                        // is the typedef alias, not a base type.
                        _ => {
                            if unsigned || is_signed || longs > 0 {
                                break;
                            }
                            self.eat();
                            base = Some(CType::Named(s));
                            break;
                        }
                    }
                }
                _ => break,
            }
        }

        // Resolve pending `long` qualifiers
        if base.is_none() && longs > 0 {
            base = Some(match (longs, unsigned) {
                (1, false) => CType::I32, // `long` = 32-bit on Windows x64
                (1, true)  => CType::U32,
                (_, false) => CType::I64,
                (_, true)  => CType::U64,
            });
        }
        if base.is_none() && unsigned  { base = Some(CType::U32); }
        if base.is_none() && is_signed { base = Some(CType::I32); }

        base.unwrap_or(CType::I32)
    }

    /// Consume pointer stars (and cv-qualifiers / 16-bit compat keywords between them).
    ///
    /// When the first star is applied to a character base type the result is
    /// narrowed to a string-pointer variant so that the tracer can dereference
    /// and print the pointed-to text automatically:
    ///   - `char *` / `const char *`    → `CType::CharPtr`
    ///   - `wchar_t *` / `WCHAR *`      → `CType::WCharPtr`
    fn parse_ptr(&mut self, inner: CType) -> CType {
        let mut had_star = false;
        loop {
            match self.peek() {
                Tok::Star => { self.eat(); had_star = true; }
                Tok::Ident(s)
                    if matches!(
                        s.as_str(),
                        "const" | "volatile" | "__restrict" | "restrict"
                        // `FAR *` and `NEAR *` are common in winsock / win16-compat headers
                        | "FAR" | "NEAR"
                    ) =>
                {
                    self.eat();
                }
                _ => break,
            }
        }
        if had_star {
            match &inner {
                // char* / signed char*  →  narrow string pointer
                CType::I8 => CType::CharPtr,
                // wchar_t* / WCHAR*  →  wide string pointer
                CType::Named(n) if n == "wchar_t" || n == "WCHAR" => CType::WCharPtr,
                _ => CType::Pointer,
            }
        } else {
            inner
        }
    }

    /// Parse `struct`/`union` keyword + optional tag + optional body `{…}`.
    fn parse_struct_or_union(&mut self) -> CType {
        self.eat(); // consume 'struct' or 'union'
        let name = if let Tok::Ident(n) = self.peek().clone() { self.eat(); n } else { String::new() };
        if matches!(self.peek(), Tok::LBrace) { self.eat(); self.skip_braces(); }
        CType::Named(if name.is_empty() { "struct".into() } else { name })
    }

    // ── typedef ───────────────────────────────────────────────────────────────

    fn parse_typedef(&mut self) {
        self.skip_modifiers();
        let base = self.parse_type_spec();
        let ptr_ty = self.parse_ptr(base);
        self.skip_modifiers();

        // Function-pointer typedef: typedef ret (WINAPI *Name)(params);
        if matches!(self.peek(), Tok::LParen) {
            self.eat();
            self.skip_modifiers();
            if matches!(self.peek(), Tok::Star) {
                self.eat();
                self.skip_modifiers();
                let name =
                    if let Tok::Ident(n) = self.peek().clone() { self.eat(); n } else { String::new() };
                if matches!(self.peek(), Tok::RParen) { self.eat(); }
                if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                if !name.is_empty() { self.typedefs.insert(name, CType::FnPtr); }
            } else {
                self.skip_parens();
            }
            self.expect_semi();
            return;
        }

        // Simple alias: typedef BaseType [*] Alias [[]];
        let alias =
            if let Tok::Ident(n) = self.peek().clone() { self.eat(); n } else { String::new() };

        // typedef BYTE Name[N] — skip
        if matches!(self.peek(), Tok::LBracket) { self.skip_to_semi(); return; }

        if !alias.is_empty() { self.typedefs.insert(alias, ptr_ty); }
        self.expect_semi();
    }

    // ── Function / variable declaration ───────────────────────────────────────

    /// Try to interpret the current position as a *typed API macro* call:
    ///
    /// ```text
    /// MACRO_NAME ( ReturnType [, extra_args...] ) FunctionName (
    /// ```
    ///
    /// This covers Windows patterns such as:
    ///   `INTERNETAPI_(HINTERNET) InternetOpenA(`
    ///   `INTERNETAPIX(BOOL, _Success_(...)) InternetCloseHandle(`
    ///   `URLCACHEAPI_(DWORD) GetUrlCacheEntryInfoA(`
    ///
    /// **Call when `peek()` is `LParen`** (i.e. after the macro name has already
    /// been consumed as the "return type").
    ///
    /// On success, returns `(embedded_return_type, function_name)` with the
    /// parser positioned just before the function's opening `(`.
    /// On failure, the parser position is restored to where it was on entry.
    fn try_typed_api_macro(&mut self) -> Option<(CType, String)> {
        let saved = self.pos;

        // Consume the opening `(` of the macro argument list.
        debug_assert!(matches!(self.peek(), Tok::LParen));
        self.eat();

        // The first argument is the embedded return type.
        self.skip_modifiers();
        let ret = self.parse_type_spec();
        let ret = self.parse_ptr(ret);

        // Skip the rest of the macro arguments (any extra args, SAL, …) until
        // we close the matching `)`.  We already consumed the opening `(`, so
        // start at depth 1.
        let mut depth = 1i32;
        loop {
            match self.peek() {
                Tok::Eof => { self.pos = saved; return None; }
                Tok::LParen => { depth += 1; self.eat(); }
                Tok::RParen => {
                    depth -= 1;
                    self.eat();
                    if depth == 0 { break; }
                }
                _ => { self.eat(); }
            }
        }

        // Skip any calling-convention / linkage modifiers between `)` and the name.
        self.skip_modifiers();

        // The next token must be the actual function name.
        let func_name = match self.peek().clone() {
            Tok::Ident(n) => { self.eat(); n }
            _ => { self.pos = saved; return None; }
        };

        // …followed immediately by the function's parameter list `(`.
        if !matches!(self.peek(), Tok::LParen) {
            self.pos = saved;
            return None;
        }

        Some((ret, func_name))
    }

    fn parse_decl(&mut self) {
        let base = self.parse_type_spec();
        self.skip_modifiers();
        let mut ret_ty = self.parse_ptr(base);
        self.skip_modifiers();

        let name = match self.peek().clone() {
            Tok::Ident(n) => { self.eat(); n }
            // A `(` here can mean two things:
            //  (a) function-pointer return type  — skip and bail (no name available)
            //  (b) typed API macro call: MACRO(RetType) FuncName(…)  — try to recover
            Tok::LParen => {
                match self.try_typed_api_macro() {
                    Some((ty, n)) => { ret_ty = ty; n }
                    None => { self.skip_to_semi(); return; }
                }
            }
            _ => { self.skip_to_semi(); return; }
        };

        match self.peek() {
            Tok::LParen => {
                self.eat();
                let (params, variadic) = self.parse_param_list();
                self.skip_modifiers();
                if matches!(self.peek(), Tok::LBrace) {
                    self.eat(); self.skip_braces();
                } else {
                    self.expect_semi();
                }
                self.functions.insert(
                    name.clone(),
                    FunctionDef { name, ret: ret_ty, params, variadic },
                );
            }
            _ => { self.skip_to_semi(); }
        }
    }

    // ── Parameter list ────────────────────────────────────────────────────────

    fn parse_param_list(&mut self) -> (Vec<Param>, bool) {
        let mut params = Vec::new();
        let mut variadic = false;

        loop {
            self.skip_modifiers();
            match self.peek() {
                Tok::RParen  => { self.eat(); break; }
                Tok::Eof     => break,
                Tok::Ellipsis => {
                    self.eat();
                    variadic = true;
                    if matches!(self.peek(), Tok::RParen) { self.eat(); }
                    break;
                }
                _ => {}
            }

            let pbase = self.parse_type_spec();
            self.skip_modifiers();
            let pty = self.parse_ptr(pbase);
            self.skip_modifiers();

            // Function-pointer parameter: ret (*name)(params)
            if matches!(self.peek(), Tok::LParen) {
                self.eat(); self.skip_parens();
                if matches!(self.peek(), Tok::LParen) { self.eat(); self.skip_parens(); }
                params.push(Param { name: format!("param{}", params.len()), ty: CType::FnPtr });
            } else {
                let pname = match self.peek().clone() {
                    Tok::Ident(n) => { self.eat(); n }
                    _ => format!("param{}", params.len()),
                };
                // Array declarator
                if matches!(self.peek(), Tok::LBracket) {
                    self.eat();
                    while !matches!(self.peek(), Tok::RBracket | Tok::Eof) { self.eat(); }
                    if matches!(self.peek(), Tok::RBracket) { self.eat(); }
                }

                // `(void)` → empty parameter list
                if matches!(pty, CType::Void) && params.is_empty() {
                    if matches!(self.peek(), Tok::RParen) { self.eat(); return (params, variadic); }
                } else if !matches!(pty, CType::Void) || !params.is_empty() {
                    params.push(Param { name: pname, ty: pty });
                }
            }

            match self.peek() {
                Tok::Comma  => { self.eat(); }
                Tok::RParen => { self.eat(); break; }
                _ => break,
            }
        }

        (params, variadic)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_parser::lexer::tokenize_raw;
    use crate::header_parser::preprocessor::{collect_macros, expand_macros};

    fn parse(src: &str) -> Parser {
        let macros = collect_macros(src);
        let raw = tokenize_raw(src);
        let toks = expand_macros(raw, &macros);
        let mut p = Parser::new(toks);
        p.parse_file();
        p
    }

    #[test]
    fn test_simple_typedef() {
        let p = parse("typedef unsigned long DWORD;");
        assert_eq!(p.typedefs.get("DWORD"), Some(&CType::U32));
    }

    #[test]
    fn test_pointer_typedef() {
        let p = parse("typedef void* LPVOID;");
        assert_eq!(p.typedefs.get("LPVOID"), Some(&CType::Pointer));
    }

    #[test]
    fn test_winapi_decl() {
        let p = parse(
            "WINBASEAPI void* WINAPI VirtualAlloc(void* a, unsigned long long b, unsigned long c, unsigned long d);",
        );
        let f = p.functions.get("VirtualAlloc").unwrap();
        assert_eq!(f.params.len(), 4);
        assert_eq!(f.params[0].name, "a");
    }

    #[test]
    fn test_macro_define_expand() {
        let src = "\
#define MYAPI __declspec(dllimport)\n\
#define MYBOOL int\n\
MYAPI MYBOOL WINAPI Foo(unsigned long x);";
        let p = parse(src);
        assert!(p.functions.contains_key("Foo"), "Foo not found: {:?}", p.functions.keys().collect::<Vec<_>>());
    }

    #[test]
    fn test_void_param() {
        let p = parse("int GetCurrentProcess(void);");
        let f = p.functions.get("GetCurrentProcess").unwrap();
        assert_eq!(f.params.len(), 0);
    }

    #[test]
    fn test_sdk_libloaderapi_h() {
        let path = std::path::Path::new("defs/libloaderapi.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let found: Vec<_> = {
            let mut v: Vec<_> = db.functions.keys().cloned().collect();
            v.sort(); v
        };
        println!("libloaderapi functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        // Key functions that must be present
        for name in &["LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "FreeLibrary",
                       "GetModuleHandleA", "GetModuleFileNameA"] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
        // LoadStringA/W uses WINUSERAPI — check if present
        if !db.functions.contains_key("LoadStringA") {
            println!("NOTE: LoadStringA missing (WINUSERAPI not a modifier yet?)");
        }
    }

    #[test]
    fn test_sdk_ntifs_h() {
        let path = std::path::Path::new("defs/ntifs.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let found: Vec<_> = {
            let mut v: Vec<_> = db.functions.keys().cloned().collect();
            v.sort(); v
        };
        println!("ntifs functions ({}):", found.len());
        for n in found.iter().take(30) { println!("  {}", n); }
        if found.len() > 30 { println!("  ... and {} more", found.len() - 30); }

        assert!(!found.is_empty(), "no functions found in ntifs.h");
        for name in &["RtlCreateHeap", "RtlDestroyHeap", "RtlAllocateHeap", "RtlFreeHeap"] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found {} functions", name, found.len());
        }
    }

    #[test]
    fn test_sdk_memoryapi_h() {
        let path = std::path::Path::new("defs/memoryapi.h");
        if !path.exists() { return; } // skip if not present
        use crate::header_parser::{HeaderDb};
        let mut db = HeaderDb::new();
        db.load_file(path);
        let found: Vec<_> = db.functions.keys().cloned().collect();
        assert!(!found.is_empty(), "no functions found in memoryapi.h");
        assert!(db.functions.contains_key("VirtualAlloc"), "VirtualAlloc missing; found: {:?}", found);
        assert!(db.functions.contains_key("VirtualFree"),  "VirtualFree missing; found: {:?}", found);
        let va = db.functions.get("VirtualAlloc").unwrap();
        assert_eq!(va.params.len(), 4, "VirtualAlloc should have 4 params");
        assert_eq!(va.params[0].name, "lpAddress");
    }

    #[test]
    fn test_sdk_synchapi_h() {
        let path = std::path::Path::new("defs/synchapi.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let mut found: Vec<_> = db.functions.keys().cloned().collect();
        found.sort();
        println!("synchapi functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        for name in &[
            "CreateMutexA", "CreateMutexW",
            "CreateEventA", "CreateEventW",
            "OpenEventA", "OpenEventW",
            "WaitForSingleObject", "WaitForMultipleObjects",
            "ReleaseMutex", "SetEvent", "ResetEvent",
            "CreateSemaphoreW",   // no ANSI variant in this SDK version
            "ReleaseSemaphore",
            "Sleep", "SleepEx",
            "InitializeCriticalSection",
            "EnterCriticalSection", "LeaveCriticalSection",
            "DeleteCriticalSection",
        ] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
    }

    #[test]
    fn test_sdk_processthreadsapi_h() {
        let path = std::path::Path::new("defs/processthreadsapi.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let mut found: Vec<_> = db.functions.keys().cloned().collect();
        found.sort();
        println!("processthreadsapi functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        // Key functions that must be present
        for name in &[
            "CreateProcessA", "CreateProcessW",
            "OpenProcess", "TerminateProcess",
            "CreateThread", "GetCurrentThread", "GetCurrentProcess",
            "GetThreadContext", "SetThreadContext",
            "GetExitCodeProcess", "GetExitCodeThread",
        ] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
    }

    #[test]
    fn test_multiline_sal_decl() {
        // Reproduces the exact ntifs.h pattern for RtlDestroyHeap
        let src = "
NTSYSAPI
PVOID
NTAPI
RtlDestroyHeap(
    _In_ _Post_invalid_ PVOID HeapHandle
    );
";
        let p = parse(src);
        assert!(p.functions.contains_key("RtlDestroyHeap"),
            "RtlDestroyHeap missing; found: {:?}", p.functions.keys().collect::<Vec<_>>());
        assert_eq!(p.functions["RtlDestroyHeap"].params.len(), 1);
    }

    #[test]
    fn test_winbool_treated_as_type() {
        let p = parse("WINBASEAPI WINBOOL WINAPI VirtualFree(void* lpAddress, unsigned long long dwSize, unsigned long dwFreeType);");
        let f = p.functions.get("VirtualFree").unwrap();
        assert_eq!(f.params.len(), 3);
        assert_eq!(f.params[0].name, "lpAddress");
    }

    // ── winsock / winsock2 style (TYPE PASCAL FAR FuncName) ───────────────────

    #[test]
    fn test_far_calling_conv() {
        // winsock.h pattern: SOCKET PASCAL FAR accept(SOCKET, struct sockaddr FAR *, int FAR *);
        let p = parse("typedef unsigned int SOCKET; SOCKET PASCAL FAR accept(SOCKET s, int FAR * addr, int FAR * addrlen);");
        let f = p.functions.get("accept").expect("accept missing");
        assert_eq!(f.params.len(), 3);
        assert_eq!(f.params[0].name, "s");
    }

    #[test]
    fn test_far_pointer_param() {
        // char FAR * should resolve to CharPtr (not a generic Pointer)
        let p = parse("int PASCAL FAR recv(int s, char FAR * buf, int len, int flags);");
        let f = p.functions.get("recv").expect("recv missing");
        assert_eq!(f.params.len(), 4);
        assert_eq!(f.params[1].ty, CType::CharPtr); // char FAR * → CharPtr
    }

    #[test]
    fn test_char_ptr_variants() {
        // char*, const char*, char const* all → CharPtr
        let p = parse("int foo(char* a, const char* b, char const* c);");
        let f = p.functions.get("foo").expect("foo missing");
        assert_eq!(f.params[0].ty, CType::CharPtr, "char*");
        assert_eq!(f.params[1].ty, CType::CharPtr, "const char*");
        assert_eq!(f.params[2].ty, CType::CharPtr, "char const*");
    }

    #[test]
    fn test_wchar_ptr() {
        // wchar_t* → WCharPtr
        let p = parse("int bar(wchar_t* s, const wchar_t* t);");
        let f = p.functions.get("bar").expect("bar missing");
        assert_eq!(f.params[0].ty, CType::WCharPtr, "wchar_t*");
        assert_eq!(f.params[1].ty, CType::WCharPtr, "const wchar_t*");
    }

    #[test]
    fn test_winsock2_multiline() {
        // winsock2.h pattern: WINSOCK_API_LINKAGE expands to __declspec(dllimport),
        // WSAAPI expands to FAR PASCAL — both need to be modifiers.
        let src = "
#define WINSOCK_API_LINKAGE __declspec(dllimport)
#define WSAAPI FAR PASCAL
typedef unsigned int SOCKET;
WINSOCK_API_LINKAGE
SOCKET
WSAAPI
accept(
    SOCKET s,
    int FAR * addr,
    int FAR * addrlen
);
";
        let p = parse(src);
        let f = p.functions.get("accept").expect("accept missing");
        assert_eq!(f.params.len(), 3);
    }

    // ── WinInet typed-API-macro style (MACRO(RetType) FuncName) ──────────────

    #[test]
    fn test_typed_api_macro_simple() {
        // INTERNETAPI_(HINTERNET) InternetOpenA(...)
        // INTERNETAPI_ is function-like (skipped by preprocessor), stays as-is.
        let src = "typedef void* HINTERNET; INTERNETAPI_(HINTERNET) InternetOpenA(int a, int b);";
        let p = parse(src);
        let f = p.functions.get("InternetOpenA").expect("InternetOpenA missing");
        assert_eq!(f.params.len(), 2);
    }

    #[test]
    fn test_typed_api_macro_with_sal() {
        // BOOLAPI expands to INTERNETAPIX(BOOL, _Success_(return != FALSE))
        // — the extra SAL arg must be skipped gracefully.
        let src = "
#define BOOLAPI INTERNETAPIX(BOOL,_Success_(return != FALSE))
BOOLAPI InternetCloseHandle(int hInternet);
";
        let p = parse(src);
        let f = p.functions.get("InternetCloseHandle").expect("InternetCloseHandle missing");
        assert_eq!(f.params.len(), 1);
    }

    // ── Winsock / WinInet header integration tests ────────────────────────────

    #[test]
    fn test_sdk_winsock2_h() {
        let path = std::path::Path::new("defs/winsock2.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let mut found: Vec<_> = db.functions.keys().cloned().collect();
        found.sort();
        println!("winsock2 functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        for name in &["accept", "bind", "connect", "recv", "send", "socket",
                       "WSAStartup", "WSACleanup", "WSAGetLastError"] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
    }

    #[test]
    fn test_sdk_winsock_h() {
        let path = std::path::Path::new("defs/winsock.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let mut found: Vec<_> = db.functions.keys().cloned().collect();
        found.sort();
        println!("winsock functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        for name in &["accept", "bind", "connect", "recv", "send", "socket"] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
    }

    #[test]
    fn test_sdk_wininet_h() {
        let path = std::path::Path::new("defs/WinInet.h");
        if !path.exists() { return; }
        use crate::header_parser::HeaderDb;
        let mut db = HeaderDb::new();
        db.load_file(path);
        let mut found: Vec<_> = db.functions.keys().cloned().collect();
        found.sort();
        println!("WinInet functions ({}):", found.len());
        for n in &found { println!("  {}", n); }

        for name in &[
            "InternetOpenA", "InternetOpenW",
            "InternetConnectA", "InternetConnectW",
            "InternetCloseHandle",
            "HttpOpenRequestA", "HttpOpenRequestW",
            "HttpSendRequestA", "HttpSendRequestW",
            "InternetReadFile",
        ] {
            assert!(db.functions.contains_key(*name),
                "MISSING: {} — found: {:?}", name, found);
        }
    }
}
