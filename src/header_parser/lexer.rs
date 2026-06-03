//! C source tokenizer (no macro expansion — that is done in `preprocessor`).

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Star,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semicolon,
    Comma,
    Equals,
    Ellipsis,
    Eof,
}

/// Tokenize `src` into a raw token stream.
/// Skips comments, string/char literals, numbers, and `#` directive LINES
/// (the directive itself, not the code between `#if` … `#endif`).
pub fn tokenize_raw(src: &str) -> Vec<Tok> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();

    while i < b.len() {
        // Whitespace
        if b[i].is_ascii_whitespace() { i += 1; continue; }

        // Line comment //
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' { i += 1; }
            continue;
        }

        // Block comment /* … */
        if b[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < b.len() && !b[i..].starts_with(b"*/") { i += 1; }
            if i + 1 < b.len() { i += 2; }
            continue;
        }

        // Preprocessor directive — skip the directive LINE only.
        // Content between #if … #endif is tokenized normally (the #if line is
        // one line and gets skipped here; the body lines are not skipped).
        if b[i] == b'#' {
            loop {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\\' { i += 1; }
                if i >= b.len() { break; }
                if b[i] == b'\\' {
                    i += 1; // skip '\\'
                    // Handle both LF (\n) and CR+LF (\r\n) line endings.
                    // On Windows, the continuation sequence is '\\' + '\r' + '\n'.
                    if i < b.len() && b[i] == b'\r' { i += 1; } // skip optional '\r'
                    if i < b.len() && b[i] == b'\n' { i += 1; } // skip '\n'
                    continue; // go on to skip the continuation line too
                }
                i += 1; // skip '\n'
                break;
            }
            continue;
        }

        // String literal — skip
        if b[i] == b'"' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' { i += 2; continue; }
                if b[i] == b'"' { i += 1; break; }
                i += 1;
            }
            continue;
        }

        // Char literal — skip
        if b[i] == b'\'' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' { i += 2; continue; }
                if b[i] == b'\'' { i += 1; break; }
                i += 1;
            }
            continue;
        }

        // Ellipsis …
        if b[i..].starts_with(b"...") { out.push(Tok::Ellipsis); i += 3; continue; }

        match b[i] {
            b'*' => { out.push(Tok::Star);      i += 1; }
            b'(' => { out.push(Tok::LParen);    i += 1; }
            b')' => { out.push(Tok::RParen);    i += 1; }
            b'{' => { out.push(Tok::LBrace);    i += 1; }
            b'}' => { out.push(Tok::RBrace);    i += 1; }
            b'[' => { out.push(Tok::LBracket);  i += 1; }
            b']' => { out.push(Tok::RBracket);  i += 1; }
            b';' => { out.push(Tok::Semicolon); i += 1; }
            b',' => { out.push(Tok::Comma);     i += 1; }
            b'=' => { out.push(Tok::Equals);    i += 1; }
            // Numbers — skip (array sizes, enum values, …)
            c if c.is_ascii_digit() => {
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric()
                        || matches!(b[i], b'.' | b'_' | b'+' | b'-' | b'x' | b'X'))
                {
                    i += 1;
                }
            }
            // Identifiers
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') { i += 1; }
                out.push(Tok::Ident(src[start..i].to_string()));
            }
            // All other characters (operators, angle brackets, …) — skip
            _ => { i += 1; }
        }
    }

    out.push(Tok::Eof);
    out
}
