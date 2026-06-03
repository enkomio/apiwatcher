//! apiwatcher — standalone Windows API call tracer
//!
//! Usage:  apiwatcher [OPTIONS] -- <target.exe> [args...]

#![allow(non_snake_case)]

mod header_parser;
mod tracer;

use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::Path;

use clap::Parser;
use regex::Regex;

use header_parser::HeaderDb;
use tracer::Debugger;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "apiwatcher", about = "Standalone Windows API call tracer")]
#[command(after_help = "\
Separate apiwatcher options from the target with --.
Example: apiwatcher -o out.csv -- notepad.exe C:\\file.txt

Exclusion format: \"dllname.FuncName\" (specific DLL) or just \"FuncName\" (any DLL).
Example: --exclude ntdll.__chkstk --exclude RtlAllocateHeap")]
struct Args {
    /// CSV output file path
    #[arg(short = 'o', long = "output", default_value = "apiwatcher.csv")]
    output: String,

    /// Log only calls whose return address is inside the main executable
    #[arg(long = "only-main")]
    only_main: bool,

    /// Restrict logging to calls targeting this DLL (e.g. kernel32 or kernel32.dll).
    /// Case-insensitive; .dll extension is optional. Combined with --only_main via AND.
    #[arg(long = "dll", value_name = "NAME")]
    dll_filter: Option<String>,

    /// Exclude functions matching a regex. Format: "dllname\\.FuncName", "FuncName", or "ntdll\\..*".
    /// Use ".*" (or the shorthand "*") to exclude everything.
    /// Can be repeated. Matched functions are never hooked.
    #[arg(long = "exclude", value_name = "PATTERN", action = clap::ArgAction::Append)]
    exclude: Vec<String>,

    /// File containing exclusion patterns, one per line (lines starting with # are comments).
    #[arg(long = "exclude-file", value_name = "FILE")]
    exclude_file: Option<String>,

    /// Directory containing .h function-definition files
    #[arg(long = "defs", default_value = "defs")]
    defs_dir: String,

    /// Target executable and its arguments (everything after --)
    #[arg(last = true, required = true)]
    target: Vec<String>,
}

// ── Exclusion helpers ─────────────────────────────────────────────────────────

/// Compile one raw exclusion line into an anchored, case-insensitive `Regex`.
///
/// Matching rules (the regex is tested against two strings in order):
///   1. `"dllbasename.funcname"` — dll name with .dll suffix stripped, lowercased
///   2. `"funcname"` alone — for patterns without a dll prefix
///
/// Special shorthand: a bare `*` is treated as `.*` (match everything).
///
/// Lines that are empty or start with `#` are silently ignored.
fn parse_exclusion_pattern(raw: &str) -> Option<Regex> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    // Bare '*' is a common glob shorthand for "exclude all".
    let pat = if s == "*" { ".*" } else { s };
    // Wrap in a non-capturing group so alternation inside the user's pattern
    // doesn't escape the anchors, then make the whole thing case-insensitive.
    match Regex::new(&format!("(?i)^(?:{pat})$")) {
        Ok(re) => Some(re),
        Err(e) => {
            eprintln!("[!] Invalid exclusion regex '{}': {}", s, e);
            None
        }
    }
}

/// Build the exclusion pattern list from CLI patterns and an optional file.
fn build_excluded(patterns: &[String], file: Option<&str>) -> Vec<Regex> {
    let mut out: Vec<Regex> = Vec::new();

    let mut add = |s: &str| {
        if let Some(re) = parse_exclusion_pattern(s) {
            out.push(re);
        }
    };

    for p in patterns {
        add(p);
    }

    if let Some(path) = file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    add(line);
                }
            }
            Err(e) => eprintln!("[!] Cannot read exclude file '{}': {}", path, e),
        }
    }

    out
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    // Build the full command-line string expected by CreateProcessW.
    let cmdline = args.target.join(" ");

    // Build the exclusion pattern list from inline patterns and optional file.
    let excluded = build_excluded(&args.exclude, args.exclude_file.as_deref());
    if !excluded.is_empty() {
        eprintln!("[*] {} exclusion pattern(s) loaded", excluded.len());
    }

    // Load function definitions from the defs/ directory.
    let mut db = HeaderDb::new();
    let defs_path = Path::new(&args.defs_dir);
    if defs_path.is_dir() {
        db.load_dir(defs_path);
        eprintln!(
            "[*] Loaded {} function definition(s) from '{}'",
            db.functions.len(),
            args.defs_dir,
        );
    } else {
        eprintln!(
            "[*] No defs directory '{}' — parameters will not be logged",
            args.defs_dir,
        );
    }

    // Open CSV output.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.output)
        .unwrap_or_else(|e| {
            eprintln!("Cannot open '{}': {}", args.output, e);
            std::process::exit(1);
        });

    let mut csv = BufWriter::new(file);

    {
        use std::io::Write;
        writeln!(
            csv,
            "timestamp,pid,tid,retaddr,caller_image,bp_addr,target_image,target_routine,params"
        )
        .unwrap();
    }

    // Launch and run the tracer.
    let (mut dbg, _pid) =
        Debugger::spawn(&cmdline, csv, args.only_main, args.dll_filter, excluded, db)
            .unwrap_or_else(|e| {
                eprintln!("Failed to launch target: {}", e);
                std::process::exit(1);
            });

    dbg.run();
}
