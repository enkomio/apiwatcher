//! apiwatcher build tasks — invoked via `cargo xtask <task>`.
//!
//! Available tasks:
//!   dist   — compile a release build and create a versioned ZIP in dist/

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

fn main() {
    let task = env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "dist" => dist(),
        _ => {
            eprintln!("Usage: cargo xtask <task>");
            eprintln!();
            eprintln!("Tasks:");
            eprintln!("  dist   build release binary and create versioned ZIP in dist/");
            exit(1);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent directory")
        .to_path_buf()
}

fn cargo() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

fn read_version(root: &Path) -> String {
    let src = fs::read_to_string(root.join("Cargo.toml"))
        .expect("cannot read Cargo.toml");
    let mut in_package = false;
    for line in src.lines() {
        let t = line.trim();
        if t == "[package]" {
            in_package = true;
        } else if t.starts_with('[') {
            in_package = false;
        } else if in_package {
            if let Some(rest) = t.strip_prefix("version") {
                if let Some(rest) = rest.trim().strip_prefix('=') {
                    return rest.trim().trim_matches('"').to_owned();
                }
            }
        }
    }
    panic!("version field not found in Cargo.toml");
}

/// Add a single file to `writer` under the given entry name.
fn zip_file(
    writer: &mut zip::ZipWriter<File>,
    src: &Path,
    entry_name: &str,
    opts: SimpleFileOptions,
) {
    writer.start_file(entry_name, opts)
        .unwrap_or_else(|e| panic!("cannot start zip entry '{}': {}", entry_name, e));
    let mut buf = Vec::new();
    File::open(src)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .unwrap_or_else(|e| panic!("cannot read {}: {}", src.display(), e));
    writer.write_all(&buf)
        .unwrap_or_else(|e| panic!("cannot write '{}' to zip: {}", entry_name, e));
}

/// Recursively add the contents of `dir` into `writer` under `zip_prefix`.
fn zip_dir(
    writer: &mut zip::ZipWriter<File>,
    dir: &Path,
    zip_prefix: &str,
    opts: SimpleFileOptions,
) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let entry_name = format!("{}{}", zip_prefix, name.to_string_lossy());

        if path.is_dir() {
            let dir_entry = format!("{}/", entry_name);
            writer.add_directory(&dir_entry, opts)
                .unwrap_or_else(|e| panic!("cannot add dir '{}' to zip: {}", dir_entry, e));
            zip_dir(writer, &path, &dir_entry, opts);
        } else {
            zip_file(writer, &path, &entry_name, opts);
        }
    }
}

// ── dist ─────────────────────────────────────────────────────────────────────

fn dist() {
    let root = root();
    let dist = root.join("dist");
    let version = read_version(&root);

    // Clean and recreate dist/
    if dist.exists() {
        fs::remove_dir_all(&dist)
            .unwrap_or_else(|e| panic!("cannot clean dist/: {}", e));
    }
    fs::create_dir_all(&dist)
        .unwrap_or_else(|e| panic!("cannot create dist/: {}", e));

    // Build
    eprintln!("[xtask] cargo build --release");
    let status = Command::new(cargo())
        .args(["build", "--release"])
        .current_dir(&root)
        .status()
        .expect("failed to spawn cargo");
    if !status.success() {
        eprintln!("[xtask] build failed");
        exit(status.code().unwrap_or(1));
    }

    // Create ZIP directly in dist/
    let zip_name = format!("apiwatcher-{}.zip", version);
    let zip_path = dist.join(&zip_name);
    let top = format!("apiwatcher-{}/", version); // top-level dir inside the archive

    let zip_file_handle = File::create(&zip_path)
        .unwrap_or_else(|e| panic!("cannot create {}: {}", zip_path.display(), e));
    let mut writer = zip::ZipWriter::new(zip_file_handle);
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated);

    writer.add_directory(&top, opts).expect("cannot add top-level dir to zip");

    // Binary
    zip_file(
        &mut writer,
        &root.join("target").join("release").join("apiwatcher.exe"),
        &format!("{}apiwatcher.exe", top),
        opts,
    );

    // defs/
    let defs = root.join("defs");
    if defs.is_dir() {
        let defs_entry = format!("{}defs/", top);
        writer.add_directory(&defs_entry, opts).expect("cannot add defs/ to zip");
        zip_dir(&mut writer, &defs, &defs_entry, opts);
    }

    // Flat files
    for name in &["exclusions.txt", "inclusions.txt", "README.md"] {
        let src = root.join(name);
        if src.is_file() {
            zip_file(&mut writer, &src, &format!("{}{}", top, name), opts);
        }
    }

    writer.finish().expect("cannot finalise zip");

    let zip_size = fs::metadata(&zip_path).map(|m| m.len()).unwrap_or(0);
    eprintln!("[xtask] dist/{} ({} KB)", zip_name, zip_size / 1024);
}
