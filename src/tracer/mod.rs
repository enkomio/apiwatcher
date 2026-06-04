//! Windows Debug-API tracer — launches and instruments a target process
//! and all child processes it spawns.

#![allow(non_snake_case)]

mod breakpoint;
mod pe;
mod process;

pub use breakpoint::{Bp, make_context};
pub use pe::get_module_size;
use pe::{get_entry_point, parse_exports, parse_imports};
pub use process::{basename, read_cstr, read_u32, read_u64, read_u8, read_wstr, write_byte};

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

use crate::header_parser::{CType, FunctionDef, HeaderDb};

// ── Module map ────────────────────────────────────────────────────────────────

pub struct ModInfo {
    pub base: usize,
    pub end: usize,
    pub name: String,
}

fn module_at(modules: &[ModInfo], addr: usize) -> Option<&ModInfo> {
    modules.iter().find(|m| addr >= m.base && addr < m.end)
}

// ── Per-process state ─────────────────────────────────────────────────────────

struct ProcState {
    /// Handle opened by the debug subsystem — valid for ReadProcessMemory /
    /// WriteProcessMemory for the lifetime of the debug session.
    handle: HANDLE,
    modules: Vec<ModInfo>,
    main_base: usize,
    main_end: usize,
    breakpoints: HashMap<usize, Bp>,
    /// False until the initial ntdll loader INT3 is consumed and breakpoints
    /// have been armed.
    initial_bp_done: bool,
}

// ── Pending return tracking ───────────────────────────────────────────────────

/// All data needed to emit a complete log line once the hooked function returns.
struct PendingReturn {
    ts_sec: u64,
    ts_usec: u32,
    tid: u32,
    caller_image: String,
    bp_addr: usize,       // address of the hooked function entry point
    target_image: String,
    target_routine: String,
    params_str: String,
    ret_size: usize,      // byte-width of the return type (0 = void)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` for handles that are safe to pass to `CloseHandle`.
/// Both `NULL` (0) and `INVALID_HANDLE_VALUE` (-1) must be rejected —
/// CloseHandle raises STATUS_INVALID_HANDLE for both.
#[inline]
fn is_valid_handle(h: HANDLE) -> bool {
    !h.is_null() && h as isize != -1
}

fn open_thread_handle(tid: u32) -> HANDLE {
    unsafe {
        OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, tid)
    }
}

/// Read one raw 64-bit parameter value.
///
/// x64 Windows calling convention at function ENTRY (RSP → return address):
///   param 0 → RCX
///   param 1 → RDX
///   param 2 → R8
///   param 3 → R9
///   param N (≥4) → [RSP + 0x28 + (N-4) × 8]
fn read_param_raw(proc: HANDLE, ctx: &CONTEXT, rsp: u64, index: usize) -> u64 {
    match index {
        0 => ctx.Rcx,
        1 => ctx.Rdx,
        2 => ctx.R8,
        3 => ctx.R9,
        n => read_u64(proc, rsp as usize + 0x28 + (n - 4) * 8).unwrap_or(0),
    }
}

/// Build the `params` CSV column for one function call.
///
/// `modules` is the list of modules loaded in the target process; it is used
/// to annotate generic void-pointer parameters (`LPVOID` / `PVOID` /
/// `LPCVOID`) with the name of the module that owns the address —
/// e.g. `lpAddress=0x00007ff812340000:[kernel32.dll]`.
pub fn format_params(
    proc: HANDLE,
    ctx: &CONTEXT,
    rsp: u64,
    def: &FunctionDef,
    typedefs: &HashMap<String, CType>,
    modules: &[ModInfo],
) -> String {
    let mut out = String::new();
    for (i, param) in def.params.iter().enumerate() {
        if !out.is_empty() {
            out.push(' ');
        }
        let raw = read_param_raw(proc, ctx, rsp, i);
        let size = param.ty.size_x64(typedefs);
        let hex = match size {
            1 => format!("{:#04x}", raw as u8),
            2 => format!("{:#06x}", raw as u16),
            4 => format!("{:#010x}", raw as u32),
            _ => format!("{:#018x}", raw),
        };
        out.push_str(&param.name);
        out.push('=');
        out.push_str(&hex);

        if raw != 0 {
            if let Some(extra) = read_str_param(proc, &param.ty, raw as usize) {
                // String pointer — append dereferenced content.
                out.push_str(&extra);
            } else if let Some(extra) = try_module_annotation(modules, &param.ty, raw as usize) {
                // Generic void pointer whose value falls inside a known module.
                out.push_str(&extra);
            }
        }
    }
    out
}

/// Maximum number of characters printed for string arguments.
const STR_MAX_CHARS: usize = 64;

/// If `ty` is a generic void-pointer alias (`LPVOID`, `PVOID`, `LPCVOID`) and
/// `addr` falls within a known module, return `":[modulename]"` to be appended
/// after the hex value.  Returns `None` for typed or opaque pointers and for
/// addresses that don't belong to any tracked module.
fn try_module_annotation(modules: &[ModInfo], ty: &CType, addr: usize) -> Option<String> {
    let name = match ty {
        CType::Named(n) => n.as_str(),
        _ => return None,
    };
    match name {
        "LPVOID" | "PVOID" | "LPCVOID" => {
            module_at(modules, addr).map(|m| format!(":[{}]", m.name))
        }
        _ => None,
    }
}

/// If `ty` is a recognised ANSI or wide string pointer type and `addr` is
/// non-null, read the string from `proc` and return it formatted as
/// `:"content"` (ANSI) or `:L"content"` (wide), ready to be appended after
/// the hex value.  Returns `None` for all other types.
///
/// Handled cases:
/// - `CType::CharPtr`  — `char*` / `const char*` parsed directly from headers
/// - `CType::WCharPtr` — `wchar_t*` / `const wchar_t*` parsed directly
/// - `CType::Named`    — Windows string-typedef aliases (`LPCSTR`, `LPWSTR`, …)
///                       that survived typedef resolution as named types
fn read_str_param(proc: HANDLE, ty: &CType, addr: usize) -> Option<String> {
    match ty {
        // ── Structural string types (emitted by the parser for raw char* / wchar_t*) ──
        CType::CharPtr => {
            let raw = read_cstr(proc, addr);
            return Some(format!(":\"{}\"", sanitize_str(&raw)));
        }
        CType::WCharPtr => {
            let raw = read_wstr(proc, addr);
            return Some(format!(":L\"{}\"", sanitize_str(&raw)));
        }
        _ => {}
    }

    // ── Named string-typedef aliases ─────────────────────────────────────────
    let name = match ty {
        CType::Named(n) => n.as_str(),
        _ => return None,
    };
    match name {
        "LPCSTR" | "LPSTR" | "PCSTR" | "PSTR" | "LPCCH" | "LPCH" => {
            let raw = read_cstr(proc, addr);
            Some(format!(":\"{}\"", sanitize_str(&raw)))
        }
        "LPCWSTR" | "LPWSTR" | "PCWSTR" | "PWSTR" | "LPCOLESTR" | "LPOLESTR" => {
            let raw = read_wstr(proc, addr);
            Some(format!(":L\"{}\"", sanitize_str(&raw)))
        }
        _ => None,
    }
}

/// Format a return value for the CSV `retval` column.
fn format_retval(rax: u64, ret_size: usize) -> String {
    match ret_size {
        0 => "void".to_owned(),
        1 => format!("{:#04x}", rax as u8),
        2 => format!("{:#06x}", rax as u16),
        4 => format!("{:#010x}", rax as u32),
        _ => format!("{:#018x}", rax),
    }
}

/// Truncate to `STR_MAX_CHARS`, replace control chars with `.`, and replace
/// characters that would break the CSV format (`"`, `,`) with safe variants.
fn sanitize_str(s: &str) -> String {
    s.chars()
        .take(STR_MAX_CHARS)
        .map(|c| match c {
            '"' => '\'',        // avoid breaking the surrounding quotes
            ',' => ';',         // avoid creating extra CSV columns
            '\n' | '\r' | '\t' => ' ',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '.',
        })
        .collect()
}

/// Read the module name from the double-pointer lpImageName field in debug
/// events.  `proc` must be the handle of the process that fired the event.
fn read_image_name(proc: HANDLE, lp_image_name: *mut std::ffi::c_void, f_unicode: u16) -> String {
    if lp_image_name.is_null() {
        return String::from("<unknown>");
    }
    let ptr_addr = lp_image_name as usize;
    let name_ptr = if f_unicode != 0 {
        read_u64(proc, ptr_addr).unwrap_or(0) as usize
    } else {
        read_u32(proc, ptr_addr).unwrap_or(0) as usize
    };
    if name_ptr == 0 {
        return String::from("<unknown>");
    }
    let full = if f_unicode != 0 {
        read_wstr(proc, name_ptr)
    } else {
        read_cstr(proc, name_ptr)
    };
    basename(&full).to_owned()
}

/// Reliably resolve the name of a module from a debug event.
///
/// Strategy (most-reliable first):
///   1. `GetFinalPathNameByHandleW(hFile)` — works for any DLL with a valid
///      file handle, including system DLLs loaded at process init.
///   2. `lpImageName` double-pointer — often NULL for early-loaded DLLs.
///   3. `"<unknown>"` — last resort.
///
/// Only the basename (e.g. `"kernel32.dll"`) is returned.
fn resolve_module_name(
    file_handle: HANDLE,
    proc_handle: HANDLE,
    lp_image_name: *mut std::ffi::c_void,
    f_unicode: u16,
) -> String {
    // ── Attempt 1: GetFinalPathNameByHandleW ──────────────────────────────────
    if is_valid_handle(file_handle) {
        let mut buf = vec![0u16; 1024];
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file_handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0, // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
            )
        };
        if n > 0 && (n as usize) < buf.len() {
            let path = String::from_utf16_lossy(&buf[..n as usize]);
            // Strip "\\?\" extended-length prefix when present.
            let path = path.strip_prefix("\\\\?\\").unwrap_or(&path);
            if !path.is_empty() {
                return basename(path).to_owned();
            }
        }
    }
    // ── Attempt 2: lpImageName double-pointer ─────────────────────────────────
    read_image_name(proc_handle, lp_image_name, f_unicode)
}

// ── DLL name filter ───────────────────────────────────────────────────────────

/// Returns `true` if `target` (the name stored in the breakpoint table, e.g.
/// `"kernel32.dll"`) matches the user-supplied `filter` (e.g. `"kernel32"` or
/// `"KERNEL32.DLL"`).  Matching is case-insensitive and tolerates the presence
/// or absence of the `.dll` extension on either side.
fn dll_name_matches(target: &str, filter: &str) -> bool {
    fn strip_ext(s: &str) -> &str {
        if s.len() >= 4 && s[s.len() - 4..].eq_ignore_ascii_case(".dll") {
            &s[..s.len() - 4]
        } else {
            s
        }
    }
    strip_ext(target).eq_ignore_ascii_case(strip_ext(filter))
}

// ── Debugger ──────────────────────────────────────────────────────────────────

pub struct Debugger {
    /// State keyed by PID.  Populated on CREATE_PROCESS_DEBUG_EVENT,
    /// removed on EXIT_PROCESS_DEBUG_EVENT.
    procs: HashMap<u32, ProcState>,
    /// tid → breakpoint address to re-arm after the next single-step exception.
    rearm: HashMap<u32, usize>,
    /// Send log lines to the background writer thread.
    /// Wrapped in `Option` so we can take it to signal shutdown.
    log_tx: Option<mpsc::Sender<String>>,
    /// Background thread that drains `log_rx` and writes to disk in batches.
    writer_thread: Option<thread::JoinHandle<()>>,
    only_main: bool,
    /// If `Some`, only log hits whose `target_image` matches this DLL name
    /// (case-insensitive, `.dll` extension optional).
    dll_filter: Option<String>,
    /// Compiled exclusion patterns.  Each `Regex` is anchored and
    /// case-insensitive; it is matched against `"dllbase.funcname"` first,
    /// then against `"funcname"` alone (for patterns with no dll prefix).
    excluded: Vec<Regex>,
    /// Inclusion patterns.  A function that matches any of these is always
    /// hooked, even if it also matches an exclusion pattern.
    /// Checked before `excluded` — inclusions win.
    included: Vec<Regex>,
    db: HeaderDb,
    /// When `true` the tracer hooks the IAT of the main EXE only (instead of
    /// every DLL's entire EAT), and additionally hooks every function address
    /// returned by `GetProcAddress` at runtime.
    trace_iat: bool,
    /// Pending GetProcAddress return hooks.
    ///
    /// Key:   `(pid, return_address_after_call_to_GetProcAddress)`
    /// Value: `(dll_name, func_name)` derived from the call arguments.
    ///
    /// When the one-shot BP at the return address fires we read RAX (the
    /// resolved function pointer) and call `set_bp` for `(dll_name, func_name)`.
    gpa_pending: HashMap<(u32, usize), (String, String)>,
    pending_returns: HashMap<(u32, usize), PendingReturn>,
}

impl Debugger {
    /// Launch `cmdline` under the debug API and return a ready `Debugger`.
    ///
    /// `DEBUG_PROCESS` without `DEBUG_ONLY_THIS_PROCESS` makes Windows forward
    /// debug events from every child process the target spawns.
    pub fn spawn(
        cmdline: &str,
        csv: BufWriter<File>,
        only_main: bool,
        dll_filter: Option<String>,
        excluded: Vec<Regex>,
        included: Vec<Regex>,
        db: HeaderDb,
        trace_iat: bool,
    ) -> Result<(Self, u32), String> {
        let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().collect();
        cmdline_w.push(0);

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DEBUG_PROCESS, // no DEBUG_ONLY_THIS_PROCESS → follow child processes
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(format!("CreateProcessW failed: {}", unsafe { GetLastError() }));
        }

        let pid = pi.dwProcessId;
        // pi.hThread is not used — close it now.
        // pi.hProcess is the SAME handle that will appear as
        // CREATE_PROCESS_DEBUG_INFO.hProcess in the first debug event; we must
        // NOT close it here or that stored handle becomes invalid.  It will be
        // closed inside EXIT_PROCESS_DEBUG_EVENT via ProcState::handle.
        unsafe { CloseHandle(pi.hThread) };

        // ── Background writer thread ──────────────────────────────────────────
        // The debug loop must return to WaitForDebugEventEx as fast as possible;
        // any disk I/O on the hot path stalls the target process.  We decouple
        // the two with an unbounded channel: the debug loop sends pre-formatted
        // log lines; the writer thread drains them in batches.
        let (tx, rx) = mpsc::channel::<String>();
        let writer_thread = thread::spawn(move || {
            use std::io::Write;
            let mut csv = csv;
            // Reuse a single String to avoid repeated allocations.
            let mut batch = String::with_capacity(256 * 1024);
            loop {
                // Block until at least one line is available (or channel closes).
                match rx.recv() {
                    Err(_) => break,   // all senders dropped → flush and exit
                    Ok(line) => {
                        batch.push_str(&line);
                        batch.push('\n');
                    }
                }
                // Drain every line that has already arrived without blocking.
                // This turns bursty events into a single large write syscall.
                while let Ok(line) = rx.try_recv() {
                    batch.push_str(&line);
                    batch.push('\n');
                }
                let _ = csv.write_all(batch.as_bytes());
                batch.clear();
            }
            // Final flush when the channel is closed.
            let _ = csv.flush();
        });

        let dbg = Debugger {
            procs: HashMap::new(),
            rearm: HashMap::new(),
            log_tx: Some(tx),
            writer_thread: Some(writer_thread),
            only_main,
            dll_filter,
            excluded,
            included,
            db,
            trace_iat,
            gpa_pending: HashMap::new(),
            pending_returns: HashMap::new(),
        };

        Ok((dbg, pid))
    }

    // ── Breakpoint management ─────────────────────────────────────────────────

    /// Return `true` if this `(dll, function)` pair should be skipped (not hooked).
    ///
    /// Priority:
    ///   1. Matches an **inclusion** pattern → always hook (return `false`)
    ///   2. Matches an **exclusion** pattern → skip (return `true`)
    ///   3. Neither                          → hook by default (return `false`)
    ///
    /// Each pattern is tested against two candidate strings:
    ///   - `"dllbase.funcname"` (dll with .dll suffix stripped, both lowercased)
    ///   - `"funcname"` alone (for bare-name patterns without a dll prefix)
    fn is_excluded(&self, dll: &str, func: &str) -> bool {
        let dl = dll.to_ascii_lowercase();
        let dl = dl.strip_suffix(".dll").unwrap_or(&dl);
        let fl = func.to_ascii_lowercase();
        let full = format!("{}.{}", dl, fl);

        let matches = |list: &[Regex]| list.iter().any(|re| re.is_match(&full) || re.is_match(&fl));

        if !self.included.is_empty() && matches(&self.included) {
            return false; // inclusion wins — always hook
        }
        !self.excluded.is_empty() && matches(&self.excluded)
    }

    fn set_bp(&mut self, pid: u32, addr: usize, target_image: String, target_routine: String) {
        // Skip excluded functions entirely — no breakpoint is placed.
        if self.is_excluded(&target_image, &target_routine) {
            return;
        }
        let proc = match self.procs.get_mut(&pid) {
            Some(p) => p,
            None => return,
        };
        if proc.breakpoints.contains_key(&addr) {
            return;
        }
        let orig = match read_u8(proc.handle, addr) {
            Some(b) => b,
            None => return,
        };
        if write_byte(proc.handle, addr, 0xCC) {
            proc.breakpoints.insert(addr, Bp { orig, target_image, target_routine, one_shot: false });
        }
    }

    /// Place a breakpoint **without** checking exclusion patterns.
    ///
    /// Used internally for:
    ///   - `GetProcAddress` itself (must always be hooked in `--trace-iat` mode
    ///     regardless of user-supplied exclusion rules)
    ///   - One-shot return-address hooks planted on `GetProcAddress` call sites
    ///
    /// Returns `true` if the breakpoint was successfully armed (or was already
    /// present), `false` if the address could not be written.
    fn set_raw_bp(
        &mut self,
        pid: u32,
        addr: usize,
        target_image: String,
        target_routine: String,
        one_shot: bool,
    ) -> bool {
        let proc = match self.procs.get_mut(&pid) {
            Some(p) => p,
            None => return false,
        };
        if proc.breakpoints.contains_key(&addr) {
            return false; // already occupied — don't clobber
        }
        let orig = match read_u8(proc.handle, addr) {
            Some(b) => b,
            None => return false,
        };
        if write_byte(proc.handle, addr, 0xCC) {
            proc.breakpoints.insert(addr, Bp { orig, target_image, target_routine, one_shot });
            true
        } else {
            false
        }
    }

    fn handle_bp_hit(&mut self, pid: u32, bp_addr: usize, thread_id: u32, thread_handle: HANDLE) {
        // Phase 1: extract everything we need from ProcState while holding a
        // short-lived immutable borrow, so later borrows of self can proceed.
        let (orig, target_image, target_routine, proc_handle, main_base, main_end) = {
            let proc = match self.procs.get(&pid) {
                Some(p) => p,
                None => return,
            };
            let bp = match proc.breakpoints.get(&bp_addr) {
                Some(b) => b,
                None => return,
            };
            (
                bp.orig,
                bp.target_image.clone(),
                bp.target_routine.clone(),
                proc.handle, // HANDLE is Copy
                proc.main_base,
                proc.main_end,
            )
        };

        // Phase 2: get thread context and rewind RIP to the INT3 location.
        let mut ctx = make_context();
        if unsafe { GetThreadContext(thread_handle, &mut ctx.0) } == 0 {
            return;
        }
        ctx.0.Rip = bp_addr as u64;
        ctx.0.EFlags |= 0x0100; // TF — single-step to re-arm (or remove) after execution

        let retaddr = read_u64(proc_handle, ctx.0.Rsp as usize).unwrap_or(0) as usize;

        // Phase 2.5: one-shot function-return hook.
        //
        // BPs with `target_routine == "<fn-return>"` are planted on the return
        // address of every intercepted call.  When one fires we:
        //   (a) hook the function address that GetProcAddress just resolved, if
        //       this was a GPA call (gpa_pending entry)
        //   (b) emit the deferred log line with the captured return value (RAX)
        if target_routine == "<fn-return>" {
            let rax = ctx.0.Rax;

            // (a) GPA interception: hook the resolved function address.
            if let Some((gpa_dll, gpa_func)) = self.gpa_pending.remove(&(pid, bp_addr)) {
                let resolved = rax as usize;
                if resolved != 0 {
                    eprintln!(
                        "[+] GetProcAddress({}.{}) → {:#x} — hooking",
                        gpa_dll, gpa_func, resolved
                    );
                    self.set_bp(pid, resolved, gpa_dll, gpa_func);
                }
            }

            // (b) Return-value logging: emit the deferred log line.
            if let Some(pr) = self.pending_returns.remove(&(pid, bp_addr)) {
                let retval = format_retval(rax, pr.ret_size);
                let line = format!(
                    "{}.{:06},{},{},{:#x},{},{:#x},{},{},{},{}",
                    pr.ts_sec, pr.ts_usec,
                    pid,
                    pr.tid,
                    bp_addr,        // = original retaddr
                    pr.caller_image,
                    pr.bp_addr,     // = original hooked-function address
                    pr.target_image,
                    pr.target_routine,
                    pr.params_str,
                    retval,
                );
                if let Some(tx) = &self.log_tx {
                    let _ = tx.send(line);
                }
            }

            write_byte(proc_handle, bp_addr, orig);
            unsafe { SetThreadContext(thread_handle, &ctx.0) };
            self.rearm.insert(thread_id, bp_addr);
            return;
        }

        // Phase 3: log (if within scope).
        let caller_ok = !self.only_main || (retaddr >= main_base && retaddr < main_end);

        // Resolve caller module name unconditionally — needed for the dll_filter
        // check below (--dll now filters on the *caller* side, not the target).
        let caller_image = self.procs
            .get(&pid)
            .and_then(|p| module_at(&p.modules, retaddr))
            .map(|m| m.name.clone())
            .unwrap_or_default();

        let dll_ok = self.dll_filter.as_deref()
            .map(|f| dll_name_matches(&caller_image, f))
            .unwrap_or(true);

        if caller_ok && dll_ok {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            let ts_sec  = ts.as_secs();
            let ts_usec = ts.subsec_micros();

            // Borrow modules for void-pointer annotation; the borrow ends as
            // soon as format_params returns (NLL), before any mutable self use.
            let modules_slice: &[ModInfo] = self.procs
                .get(&pid)
                .map(|p| p.modules.as_slice())
                .unwrap_or(&[]);

            let params_str = self
                .db
                .functions
                .get(&target_routine)
                .map(|def| {
                    format_params(proc_handle, &ctx.0, ctx.0.Rsp, def, &self.db.typedefs, modules_slice)
                })
                .unwrap_or_else(|| {
                    format!(
                        "arg0={:#018x} arg1={:#018x} arg2={:#018x} arg3={:#018x}",
                        read_param_raw(proc_handle, &ctx.0, ctx.0.Rsp, 0),
                        read_param_raw(proc_handle, &ctx.0, ctx.0.Rsp, 1),
                        read_param_raw(proc_handle, &ctx.0, ctx.0.Rsp, 2),
                        read_param_raw(proc_handle, &ctx.0, ctx.0.Rsp, 3),
                    )
                });

            let ret_size = self
                .db
                .functions
                .get(&target_routine)
                .map(|def| def.ret.size_x64(&self.db.typedefs))
                .unwrap_or(8);

            // Attempt to defer logging until the function returns so we can
            // capture RAX (the return value) and include it in the log line.
            // Falls back to immediate logging (retval=?) when:
            //   - retaddr is 0 (no valid return site)
            //   - another deferred call is already waiting at the same (pid, retaddr)
            //   - the return address is already occupied by a persistent hook
            let slot_key = (pid, retaddr);
            let already_pending = self.pending_returns.contains_key(&slot_key);
            let deferred = retaddr != 0
                && !already_pending
                && self.set_raw_bp(
                    pid, retaddr,
                    String::new(), "<fn-return>".to_owned(),
                    true, // one_shot
                );

            if deferred {
                self.pending_returns.insert(slot_key, PendingReturn {
                    ts_sec,
                    ts_usec,
                    tid: thread_id,
                    caller_image: caller_image.clone(),
                    bp_addr,
                    target_image: target_image.clone(),
                    target_routine: target_routine.clone(),
                    params_str,
                    ret_size,
                });
            } else {
                let line = format!(
                    "{}.{:06},{},{},{:#x},{},{:#x},{},{},{},?",
                    ts_sec, ts_usec,
                    pid, thread_id,
                    retaddr, caller_image,
                    bp_addr, target_image, target_routine,
                    params_str,
                );
                if let Some(tx) = &self.log_tx {
                    let _ = tx.send(line);
                }
            }
        }

        // Phase 3.5: if this call was to GetProcAddress and we are in --trace-iat
        // mode, ensure a one-shot return hook is in place so we can intercept
        // the resolved address and hook it before the caller uses it.
        // Phase 3 may have already planted a <fn-return> BP at retaddr; if so,
        // we reuse it — just record the pending GPA context.
        if self.trace_iat && target_routine == "GetProcAddress" && retaddr != 0 {
            let hmodule  = ctx.0.Rcx as usize;
            let lp_name  = ctx.0.Rdx;

            let dll_name: String = self.procs
                .get(&pid)
                .and_then(|p| module_at(&p.modules, hmodule))
                .map(|m| m.name.clone())
                .unwrap_or_default();

            let func_name: String = if lp_name >> 16 == 0 {
                format!("#{}", lp_name & 0xFFFF)
            } else {
                read_cstr(proc_handle, lp_name as usize)
            };

            // Plant a <fn-return> BP only if Phase 3 hasn't already done so.
            let bp_already = self.procs
                .get(&pid)
                .map(|p| p.breakpoints.contains_key(&retaddr))
                .unwrap_or(false);
            if !bp_already {
                self.set_raw_bp(
                    pid, retaddr,
                    String::new(), "<fn-return>".to_owned(),
                    true, // one_shot
                );
            }
            // Always record — the <fn-return> handler hooks the resolved address.
            self.gpa_pending.insert((pid, retaddr), (dll_name, func_name));
        }

        // Phase 4: restore original byte and arm single-step.
        write_byte(proc_handle, bp_addr, orig);
        unsafe { SetThreadContext(thread_handle, &ctx.0) };
        self.rearm.insert(thread_id, bp_addr);
    }

    fn handle_single_step(&mut self, pid: u32, tid: u32, thread_handle: HANDLE) {
        if let Some(addr) = self.rearm.remove(&tid) {
            // Determine whether this BP should be re-armed or permanently removed.
            let (proc_handle, one_shot) = {
                let proc = match self.procs.get(&pid) { Some(p) => p, None => return };
                let one_shot = proc.breakpoints.get(&addr)
                    .map(|bp| bp.one_shot)
                    .unwrap_or(false);
                (proc.handle, one_shot)
            };

            if one_shot {
                // Remove the one-shot BP from the table; don't write 0xCC back.
                if let Some(proc) = self.procs.get_mut(&pid) {
                    proc.breakpoints.remove(&addr);
                }
            } else {
                write_byte(proc_handle, addr, 0xCC);
            }

            let mut ctx = make_context();
            if unsafe { GetThreadContext(thread_handle, &mut ctx.0) } != 0 {
                ctx.0.EFlags &= !0x0100u32;
                unsafe { SetThreadContext(thread_handle, &ctx.0) };
            }
        }
    }

    /// Parse the Export Address Table of `module_name` (mapped at `base` in
    /// `pid`) and arm an INT3 on every named, non-forwarded export.
    fn hook_exports(&mut self, pid: u32, base: usize, module_name: &str) {
        let proc_handle = match self.procs.get(&pid) {
            Some(p) => p.handle,
            None => return,
        };
        let exports = parse_exports(proc_handle, base);
        let count = exports.len();
        for exp in exports {
            self.set_bp(pid, exp.addr, module_name.to_owned(), exp.name);
        }
        if count > 0 {
            eprintln!("[+] PID {} — {} export hook(s) from {}", pid, count, module_name);
        }
    }

    /// Place an INT3 on the PE entry point of the module at `base`.
    ///
    /// `ep_name` is what will appear in the `target_routine` CSV column:
    ///   - `"<entrypoint>"` for executables
    ///   - `"DllMain"`      for DLLs
    ///
    /// No-ops silently when the entry point RVA is zero (resource-only DLLs).
    fn hook_entry_point(&mut self, pid: u32, base: usize, module_name: &str, ep_name: &str) {
        let proc_handle = match self.procs.get(&pid) {
            Some(p) => p.handle,
            None => return,
        };
        if let Some(ep_addr) = get_entry_point(proc_handle, base) {
            self.set_bp(pid, ep_addr, module_name.to_owned(), ep_name.to_owned());
        }
    }

    // ── Module tracking ───────────────────────────────────────────────────────

    fn add_module_from_create(&mut self, pid: u32, info: &CREATE_PROCESS_DEBUG_INFO) {
        let handle = info.hProcess; // HANDLE is Copy — safe to use after insert
        let base   = info.lpBaseOfImage as usize;
        let size   = get_module_size(handle, base);
        let name   = resolve_module_name(info.hFile, handle, info.lpImageName, info.fUnicode);

        self.procs.insert(pid, ProcState {
            handle,
            modules: vec![ModInfo { base, end: base + size, name: name.clone() }],
            main_base: base,
            main_end:  base + size,
            breakpoints: HashMap::new(),
            initial_bp_done: false,
        });
        // hFile can be NULL for kernel-mapped images (e.g. ntdll) — guard before closing.
        if is_valid_handle(info.hFile) { unsafe { CloseHandle(info.hFile) }; }

        if self.trace_iat {
            // --trace-iat: hook every function the EXE imports through its IAT.
            // `handle` is Copy and still valid; `parse_imports` doesn't borrow self.
            let imports = parse_imports(handle, base);
            let count = imports.len();
            for imp in imports {
                self.set_bp(pid, imp.addr, imp.dll, imp.name);
            }
            if count > 0 {
                eprintln!("[+] PID {} — {} IAT hook(s) from {}", pid, count, name);
            }
        } else {
            // Default: hook every named export from the EXE (usually none).
            self.hook_exports(pid, base, &name);
        }

        // Always hook the EXE entry point regardless of mode.
        self.hook_entry_point(pid, base, &name, "<entrypoint>");
    }

    fn add_module_from_load(&mut self, pid: u32, info: &LOAD_DLL_DEBUG_INFO) {
        // Phase 1: read all values we need while the immutable borrow is live.
        // HANDLE is Copy so we can extract it without keeping a reference to ProcState.
        let (base, size, name, ep_addr) = {
            let proc = match self.procs.get(&pid) { Some(p) => p, None => return };
            let base = info.lpBaseOfDll as usize;
            let size = get_module_size(proc.handle, base);
            let name = resolve_module_name(info.hFile, proc.handle, info.lpImageName, info.fUnicode);
            let ep_addr = get_entry_point(proc.handle, base);
            (base, size, name, ep_addr)
        }; // immutable borrow released here

        // Phase 2: push the new module info into the module list.
        if let Some(proc) = self.procs.get_mut(&pid) {
            proc.modules.push(ModInfo { base, end: base + size, name: name.clone() });
        }

        // hFile can be NULL for in-memory or kernel-backed DLLs.
        if is_valid_handle(info.hFile) { unsafe { CloseHandle(info.hFile) }; }

        if self.trace_iat {
            // --trace-iat: don't hook EAT exports of this DLL.
            // Exception: GetProcAddress in kernel32 / kernelbase must always be
            // hooked so we can intercept dynamic resolution at runtime.
            let lc = name.to_ascii_lowercase();
            if lc == "kernel32.dll" || lc == "kernelbase.dll" {
                self.hook_gpa(pid, base, &name);
            }
        } else {
            // Default: hook all named exports.
            self.hook_exports(pid, base, &name);
        }

        // Always hook DllMain regardless of mode.
        if let Some(addr) = ep_addr {
            self.set_bp(pid, addr, name.clone(), "DllMain".to_owned());
        }
    }

    /// Scan the EAT of the DLL at `base` for `GetProcAddress` and arm an
    /// unconditional (exclusion-bypassing) INT3 on it.
    ///
    /// Called in `--trace-iat` mode when kernel32.dll or kernelbase.dll loads,
    /// so that every subsequent `GetProcAddress` call can be intercepted and
    /// the resolved address hooked before the caller uses it.
    fn hook_gpa(&mut self, pid: u32, base: usize, module_name: &str) {
        let proc_handle = match self.procs.get(&pid) { Some(p) => p.handle, None => return };
        // parse_exports doesn't borrow self, proc_handle is Copy.
        let exports = parse_exports(proc_handle, base);
        for exp in &exports {
            if exp.name == "GetProcAddress" {
                eprintln!(
                    "[+] PID {} — hooking GetProcAddress @ {:#x} ({})",
                    pid, exp.addr, module_name
                );
                // set_raw_bp bypasses is_excluded — GPA must always be hooked.
                self.set_raw_bp(
                    pid, exp.addr,
                    module_name.to_owned(), "GetProcAddress".to_owned(),
                    false, // not one-shot: stays armed for every call
                );
                break;
            }
        }
    }

    // ── Main debug event loop ─────────────────────────────────────────────────

    pub fn run(&mut self) {
        loop {
            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEventEx(&mut ev, INFINITE) } == 0 {
                break;
            }

            let pid = ev.dwProcessId;
            let tid = ev.dwThreadId;
            let mut status = DBG_CONTINUE;

            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &ev.u.CreateProcessInfo };
                    self.add_module_from_create(pid, info);
                    eprintln!("[+] Attached to PID {} — waiting for initial breakpoint…", pid);
                }

                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { &ev.u.LoadDll };
                    self.add_module_from_load(pid, info);
                }

                EXCEPTION_DEBUG_EVENT => {
                    let info = unsafe { &ev.u.Exception };
                    let rec = &info.ExceptionRecord;

                    match rec.ExceptionCode {
                        EXCEPTION_BREAKPOINT | STATUS_WX86_BREAKPOINT => {
                            let bp_addr = rec.ExceptionAddress as usize;
                            let initial_done = self.procs
                                .get(&pid)
                                .map(|p| p.initial_bp_done)
                                .unwrap_or(true);

                            if !initial_done {
                                // First breakpoint = ntdll loader's initial INT3.
                                // EAT hooks are already in place (armed during
                                // LOAD_DLL_DEBUG_EVENT before execution started).
                                if let Some(p) = self.procs.get_mut(&pid) {
                                    p.initial_bp_done = true;
                                }
                            } else {
                                let has_bp = self.procs
                                    .get(&pid)
                                    .map(|p| p.breakpoints.contains_key(&bp_addr))
                                    .unwrap_or(false);
                                if has_bp {
                                    let th = open_thread_handle(tid);
                                    if is_valid_handle(th) {
                                        self.handle_bp_hit(pid, bp_addr, tid, th);
                                        unsafe { CloseHandle(th) };
                                    }
                                } else if info.dwFirstChance != 0 {
                                    status = DBG_EXCEPTION_NOT_HANDLED;
                                }
                            }
                        }

                        EXCEPTION_SINGLE_STEP | STATUS_WX86_SINGLE_STEP => {
                            let th = open_thread_handle(tid);
                            if is_valid_handle(th) {
                                self.handle_single_step(pid, tid, th);
                                unsafe { CloseHandle(th) };
                            }
                        }

                        _ => {
                            if info.dwFirstChance != 0 {
                                status = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                    }
                }

                EXIT_PROCESS_DEBUG_EVENT => {
                    eprintln!("[+] PID {} exited.", pid);
                    if let Some(proc) = self.procs.remove(&pid) {
                        if is_valid_handle(proc.handle) {
                            unsafe { CloseHandle(proc.handle) };
                        }
                    }
                    // Always continue before deciding whether to stop.
                    unsafe { ContinueDebugEvent(pid, tid, DBG_CONTINUE) };
                    if self.procs.is_empty() {
                        // Drop the sender to close the channel; the writer
                        // thread will drain whatever is still queued, flush,
                        // and exit.  Then we join to ensure everything is on
                        // disk before returning.
                        self.log_tx = None;
                        if let Some(handle) = self.writer_thread.take() {
                            let _ = handle.join();
                        }
                        eprintln!("[+] All processes exited.");
                        break;
                    }
                    continue; // skip the ContinueDebugEvent at the bottom
                }

                _ => {}
            }

            unsafe { ContinueDebugEvent(pid, tid, status) };
        }
    }
}
