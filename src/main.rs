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

    /// Log only calls whose *caller* image matches this name (e.g. myapp or myapp.exe).
    /// Case-insensitive; .dll/.exe extension is optional.
    /// Combined with --only-main via AND.
    #[arg(long = "dll", value_name = "NAME")]
    dll_filter: Option<String>,

    /// Exclude functions matching a regex. Format: "dllname\\.FuncName", "FuncName", or "ntdll\\..*".
    /// Use ".*" (or the shorthand "*") to exclude everything.
    /// Can be repeated. Matched functions are never hooked.
    #[arg(long = "exclude", value_name = "PATTERN", action = clap::ArgAction::Append)]
    exclude: Vec<String>,

    /// File containing exclusion patterns, one per line (lines starting with # are comments).
    /// Defaults to "exclusions.txt" if the file exists.
    #[arg(long = "exclude-file", value_name = "FILE")]
    exclude_file: Option<String>,

    /// Always hook functions matching this regex, even if they also match an exclusion.
    /// Inclusions take priority over exclusions.
    /// Can be repeated.
    #[arg(long = "include", value_name = "PATTERN", action = clap::ArgAction::Append)]
    include: Vec<String>,

    /// File containing inclusion patterns, one per line (lines starting with # are comments).
    /// Inclusions take priority over exclusions.
    /// Defaults to "inclusions.txt" if the file exists.
    #[arg(long = "include-file", value_name = "FILE")]
    include_file: Option<String>,

    /// IAT-only mode: hook only functions imported by the main EXE via its
    /// Import Address Table, plus any function address returned at runtime by
    /// GetProcAddress.  Produces a much smaller hook set than the default
    /// full-EAT mode and is ideal for analysing what an application actually
    /// calls rather than what every loaded DLL exports.
    #[arg(long = "trace-iat")]
    trace_iat: bool,

    /// Automatically remove a function's hook after it has been intercepted
    /// this many times.  Reduces overhead for frequently-called APIs that have
    /// already been observed enough times.  Set to 0 to disable.
    #[arg(long = "max-calls", default_value = "100", value_name = "N")]
    max_calls: u32,

    /// Number of bytes to hex-dump for buffer-type parameters (LPBYTE, LPVOID, …).
    /// The dump is appended as `:{xx xx xx …}` after the pointer value.
    /// Set to 0 to disable.
    #[arg(long = "hex-bytes", default_value = "6", value_name = "N")]
    hex_bytes: usize,

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

/// Build a pattern list from CLI patterns and an optional file.
/// Used for both exclusions and inclusions.
fn build_patterns(patterns: &[String], file: Option<&str>, label: &str) -> Vec<Regex> {
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
            Err(e) => eprintln!("[!] Cannot read {} file '{}': {}", label, path, e),
        }
    }

    out
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    eprint!(r#"
  __ _ _ __ (_)__      __  __ _  _      ___  _       ___  _ __
 / _` | '_ \(_)\ \ /\ / / / _` || |_   / __|| |_    / _ \| '__|
| (_| || |_) || | \ V  V / | (_| || __|  (__| '_ \|  __/| |
 \__,_|| .__/ |_|  \_/\_/   \__,_||_|   \___|_| |_| \___|_|
        |_|                                    |_| |_|
"#);
    eprintln!(" v{}  |  Windows API call tracer\n", env!("CARGO_PKG_VERSION"));

    let args = Args::parse();

    // Build the full command-line string expected by CreateProcessW.
    let cmdline = args.target.join(" ");

    // Resolve the exclusion file: explicit --exclude-file wins; otherwise fall
    // back to "exclusions.txt" in the current directory if it exists.
    const DEFAULT_EXCLUDE_FILE: &str = "exclusions.txt";
    let exclude_file: Option<&str> = match args.exclude_file.as_deref() {
        Some(path) => Some(path),
        None if Path::new(DEFAULT_EXCLUDE_FILE).is_file() => Some(DEFAULT_EXCLUDE_FILE),
        None => None,
    };
    if let Some(f) = exclude_file {
        if args.exclude_file.is_none() {
            eprintln!("[*] Using default exclusion file '{}'", f);
        }
    }

    // Build exclusion and inclusion pattern lists.
    let excluded = build_patterns(&args.exclude, exclude_file, "exclusion");
    if !excluded.is_empty() {
        eprintln!("[*] {} exclusion pattern(s) loaded", excluded.len());
    }

    const DEFAULT_INCLUDE_FILE: &str = "inclusions.txt";
    let include_file: Option<&str> = match args.include_file.as_deref() {
        Some(path) => Some(path),
        None if Path::new(DEFAULT_INCLUDE_FILE).is_file() => Some(DEFAULT_INCLUDE_FILE),
        None => None,
    };
    if let Some(f) = include_file {
        if args.include_file.is_none() {
            eprintln!("[*] Using default inclusion file '{}'", f);
        }
    }

    let included = build_patterns(&args.include, include_file, "inclusion");
    if !included.is_empty() {
        eprintln!("[*] {} inclusion pattern(s) loaded (override exclusions)", included.len());
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
            "timestamp,pid,tid,retaddr,caller_image,bp_addr,target_image,target_routine,params,retval"
        )
        .unwrap();
    }

    // Launch and run the tracer.
    if args.trace_iat {
        eprintln!("[*] IAT-trace mode: hooking EXE imports + GetProcAddress-resolved functions");
    }

    if args.max_calls == 0 {
        eprintln!("[*] Auto-unhook disabled (--max-calls 0)");
    } else {
        eprintln!("[*] Auto-unhook after {} call(s) per function (--max-calls)", args.max_calls);
    }

    let (mut dbg, _pid) =
        Debugger::spawn(&cmdline, csv, args.only_main, args.dll_filter, excluded, included, db, args.trace_iat, args.max_calls, args.hex_bytes)
            .unwrap_or_else(|e| {
                eprintln!("Failed to launch target: {}", e);
                std::process::exit(1);
            });

    dbg.run();
}
