//! Simplified C preprocessor: collects `#define` macros and expands them
//! in a token stream (single-level, object-like macros only).
//!
//! This is intentionally minimal — we don't implement the full C preprocessor.
//! What we do:
//!  - Collect `#define NAME body` (object-like, not function-like).
//!  - Tokenize each macro body with `tokenize_raw`.
//!  - Do one pass of body-level expansion so that chains like
//!    `#define NTSYSAPI WINBASEAPI` resolve transitively.
//!  - Expand macros in the main token stream (one level, no recursion guard
//!    needed because we pre-expanded bodies and don't re-enter the table).

use std::collections::HashMap;

use super::lexer::{Tok, tokenize_raw};

/// Collect all object-like `#define` macros from the source.
/// Function-like macros (`#define FOO(x) …`) are skipped.
///
/// Returns `name → pre-expanded body tokens`.
pub fn collect_macros(src: &str) -> HashMap<String, Vec<Tok>> {
    let mut raw: HashMap<String, Vec<Tok>> = HashMap::new();

    for line in src.lines() {
        let line = match line.trim().strip_prefix("#define").map(str::trim_start) {
            Some(rest) => rest,
            None => continue,
        };

        // Extract macro name
        let name_end = line
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(line.len());
        if name_end == 0 {
            continue;
        }
        let name = &line[..name_end];
        let after = line[name_end..].trim_start();

        // Skip function-like macros: `#define FOO(x) …`
        if after.starts_with('(') {
            continue;
        }

        // Tokenize body (strip trailing comments by taking up to `//`)
        let body = match after.find("//") {
            Some(c) => after[..c].trim(),
            None => after.trim(),
        };
        if body.is_empty() {
            continue;
        }

        let body_toks: Vec<Tok> = tokenize_raw(body)
            .into_iter()
            .filter(|t| !matches!(t, Tok::Eof))
            .collect();

        if !body_toks.is_empty() {
            raw.insert(name.to_string(), body_toks);
        }
    }

    // One-pass body expansion so that chained aliases resolve:
    // e.g. `#define NTSYSAPI WINBASEAPI` → body [Ident("WINBASEAPI")]
    //       `#define WINBASEAPI __declspec(dllimport)` → body [Ident("__declspec"), …]
    // After expansion NTSYSAPI body becomes [Ident("__declspec"), …].
    let names: Vec<String> = raw.keys().cloned().collect();
    for name in &names {
        let expanded = expand_once(raw[name].clone(), &raw);
        raw.insert(name.clone(), expanded);
    }

    raw
}

/// Expand macros in `toks` using `table` (one level, not recursive).
pub fn expand_macros(toks: Vec<Tok>, table: &HashMap<String, Vec<Tok>>) -> Vec<Tok> {
    let mut out = Vec::with_capacity(toks.len());
    for tok in toks {
        match tok {
            Tok::Ident(ref name) => match table.get(name) {
                Some(expansion) => out.extend_from_slice(expansion),
                None => out.push(tok),
            },
            _ => out.push(tok),
        }
    }
    out
}

/// Single-pass expansion used internally to resolve macro bodies.
fn expand_once(toks: Vec<Tok>, table: &HashMap<String, Vec<Tok>>) -> Vec<Tok> {
    expand_macros(toks, table)
}
