# apiwatcher

Standalone Windows API call tracer based on the Win32 Debug API.  
Spawns a target process under the debugger, hooks functions at the byte level with `INT3` breakpoints, and logs every intercepted call to a CSV file — no DLL injection, no driver required.

---

## Table of contents

1. [How it works](#1-how-it-works)
2. [Building](#2-building)
3. [Quick start](#3-quick-start)
4. [Command-line reference](#4-command-line-reference)
5. [Hooking modes](#5-hooking-modes)
6. [Output format](#6-output-format)
7. [Exclusion patterns](#7-exclusion-patterns)
8. [Inclusion patterns](#8-inclusion-patterns)
9. [Pattern syntax](#9-pattern-syntax)
10. [Function definitions (defs/)](#10-function-definitions-defs)
11. [Default filter files](#11-default-filter-files)
12. [Performance notes](#12-performance-notes)

---

## 1. How it works

apiwatcher spawns the target with `CreateProcessW(DEBUG_PROCESS)` (child processes are also debugged) and handles debug events in a tight loop:

| Event | Default (EAT) mode | `--trace-iat` mode |
|---|---|---|
| `CREATE_PROCESS_DEBUG_EVENT` | Hook every EAT export of the EXE + `<entrypoint>` | Hook every IAT import of the EXE + `<entrypoint>` |
| `LOAD_DLL_DEBUG_EVENT` | Hook every EAT export of the DLL + `DllMain` | Hook `GetProcAddress` in kernel32/kernelbase + `DllMain` |
| `EXCEPTION_BREAKPOINT` | Identify call, read context + params, restore byte, single-step to re-arm | Same |

On each breakpoint hit the tracer:
1. Rewinds `RIP` to the INT3 address and reads up to four arguments from registers / stack.
2. Enqueues a formatted log line to a background writer thread.
3. Restores the original byte, arms the hardware trace flag (TF) for single-step.
4. On the subsequent single-step exception, re-arms the INT3 (or removes it if one-shot).

A background thread drains the log queue in batches, keeping all disk I/O off the debug-event hot path.

---

## 2. Building

Requires Rust stable (2024 edition), targeting Windows x86-64.

```
cargo build --release
```

The binary is placed in `target\release\apiwatcher.exe`.

---

## 3. Quick start

```
# Trace all API calls — save to out.csv
apiwatcher -o out.csv -- notepad.exe

# Trace only calls originating from the main executable image
apiwatcher --only-main -o out.csv -- myapp.exe

# Trace only calls made by kernel32 (caller-side filter)
apiwatcher --dll kernel32 -o out.csv -- myapp.exe

# IAT mode: hook only what the EXE imports + dynamic GetProcAddress resolution
apiwatcher --trace-iat -o out.csv -- myapp.exe

# Exclude everything in ntdll except NtWriteFile
apiwatcher --exclude "ntdll\..*" --include "ntdll\.NtWriteFile" -- myapp.exe

# Use a custom exclusion file
apiwatcher --exclude-file my_filters.txt -- myapp.exe arg1 arg2
```

Always separate apiwatcher options from the target command with `--`.

---

## 4. Command-line reference

| Option | Default | Description |
|---|---|---|
| `-o`, `--output FILE` | `apiwatcher.csv` | CSV output file |
| `--only-main` | off | Log only calls whose return address is inside the main EXE image |
| `--dll NAME` | (all) | Log only calls whose **caller** image matches this name (case-insensitive, extension optional). Combined with `--only-main` via AND |
| `--trace-iat` | off | IAT mode: hook only functions imported by the EXE's IAT, plus functions resolved at runtime by `GetProcAddress` (see [§5](#5-hooking-modes)) |
| `--exclude PATTERN` | — | Exclude functions matching a regex. Repeatable |
| `--exclude-file FILE` | `exclusions.txt`* | File with exclusion patterns, one per line |
| `--include PATTERN` | — | Always hook functions matching a regex, overriding any exclusion. Repeatable |
| `--include-file FILE` | `inclusions.txt`* | File with inclusion patterns, one per line |
| `--defs DIR` | `defs` | Directory containing `.h` function-definition files for parameter decoding |

\* Loaded automatically when the file exists in the current working directory and the explicit option is not given.

---

## 5. Hooking modes

### Default mode — EAT hooking

Every named, non-forwarded export in every loaded DLL is hooked.  
This gives complete coverage but produces a large number of breakpoints (often thousands) and may slow down the target noticeably for DLL-heavy applications.

Also hooked unconditionally:
- `<entrypoint>` — the PE `AddressOfEntryPoint` of the main EXE
- `DllMain` — the PE `AddressOfEntryPoint` of every loaded DLL

### IAT mode — `--trace-iat`

A much lighter alternative focused on what the application actually calls rather than what every loaded library exports.

**At startup:** the Import Address Table of the main EXE is parsed. The loader has already filled each IAT slot with the live function address, so INT3s are planted directly on those addresses — no EAT scan needed.

**GetProcAddress interception:** when kernel32.dll or kernelbase.dll loads, an unconditional hook is placed on `GetProcAddress` (exclusion rules do not suppress it). On every call:
1. The arguments (`hModule`, `lpProcName`) are read from `RCX`/`RDX`.
2. A one-shot INT3 is planted on the call-site's return address.
3. When that return hook fires, `RAX` contains the resolved function pointer. If non-zero, a normal breakpoint is placed at that address (exclusion/inclusion rules apply).

The result is that any function the target resolves dynamically is hooked the moment it is resolved, before the first call.

**Caller-side filters (`--only-main`, `--dll`)** work identically in both modes.

---

## 6. Output format

UTF-8 CSV, one row per intercepted call:

```
timestamp,pid,tid,retaddr,caller_image,bp_addr,target_image,target_routine,params
```

| Column | Description |
|---|---|
| `timestamp` | Unix time with microsecond precision (`seconds.microseconds`) |
| `pid` | Process ID |
| `tid` | Thread ID |
| `retaddr` | Return address (hex) — the instruction the thread will resume at after the call |
| `caller_image` | Module that contains `retaddr` |
| `bp_addr` | Address of the hooked function (hex) |
| `target_image` | DLL (or EXE) that owns the function |
| `target_routine` | Function name; `DllMain` for DLL entry points, `<entrypoint>` for the EXE entry point |
| `params` | Space-separated `name=0xVALUE` pairs. String pointer types are dereferenced and shown as `:"text"` (ANSI) or `:L"text"` (wide). Falls back to `arg0…arg3` when no definition is available |

---

## 7. Exclusion patterns

Functions that match an exclusion pattern are **never hooked** — no INT3 is placed, so they carry zero runtime overhead.

```
# Exclude a specific function in ntdll
apiwatcher --exclude "ntdll\.RtlAllocateHeap" -- target.exe

# Exclude all functions whose name contains "Alloc"
apiwatcher --exclude ".*Alloc.*" -- target.exe

# Load exclusions from a file
apiwatcher --exclude-file myfilters.txt -- target.exe
```

If neither `--exclude` nor `--exclude-file` is given, `exclusions.txt` in the current directory is loaded automatically (see [§11](#11-default-filter-files)).

---

## 8. Inclusion patterns

Inclusion patterns **override exclusions**: a function that matches an inclusion is always hooked, regardless of any exclusion that also matches it.

```
# Exclude all of ntdll...
--exclude "ntdll\..*"

# ...but always trace these two:
--include "ntdll\.NtCreateFile"
--include "ntdll\.NtWriteFile"
```

Priority evaluated in `is_excluded()`:

| Matches inclusion | Matches exclusion | Result |
|---|---|---|
| yes | any | **hook** (inclusion wins) |
| no | yes | skip |
| no | no | **hook** (default) |

Inclusions can also be loaded from a file with `--include-file`. The format is identical to the exclusion file.

---

## 9. Pattern syntax

Both exclusion and inclusion patterns are **case-insensitive, anchored regular expressions**.  
Each pattern is compiled as `(?i)^(?:PATTERN)$` and tested against two strings, in order:

1. `"dllbasename.funcname"` — DLL name with `.dll` suffix stripped, both lowercased
2. `"funcname"` alone — so bare-name patterns match across any DLL

| Pattern | Matches |
|---|---|
| `ntdll\.RtlAllocateHeap` | `ntdll.RtlAllocateHeap` only |
| `ntdll\..*` | All functions exported by ntdll |
| `(kernel32\|kernelbase)\..*` | All functions from kernel32 or kernelbase |
| `.*Alloc.*` | Any function with "Alloc" anywhere in its name, from any DLL |
| `malloc` | `malloc` from any DLL |
| `.*` or `*` | **Everything** — no function is hooked |
| `DllMain` | All DLL entry points |
| `<entrypoint>` | The main executable entry point |

**File format:**
- Lines starting with `#` are comments and are ignored
- Empty lines are ignored
- A bare `*` is a shorthand for `.*` (match everything)

---

## 10. Function definitions (defs/)

apiwatcher decodes call parameters when a matching function definition is available. Definitions are plain C header files in the `defs/` directory (configurable via `--defs`).

Each file should contain standard C function prototypes. The parser handles common Win32 patterns including SAL annotations, `__declspec`, calling-convention macros (`WINAPI`, `PASCAL`, `FAR`, …), and Windows 16-bit compatibility keywords. It follows `typedef` chains to determine the size of each argument. String pointer types (`LPCSTR`, `LPCWSTR`, `PCWSTR`, …) are automatically dereferenced and their content appended after the pointer value.

**Bundled definition files:**

| File | Functions | Coverage |
|---|---|---|
| `memoryapi.h` | ~15 | `VirtualAlloc`, `VirtualFree`, `ReadProcessMemory`, `WriteProcessMemory`, … |
| `libloaderapi.h` | ~30 | `LoadLibraryW`, `GetProcAddress`, `GetModuleHandleW`, … |
| `processthreadsapi.h` | ~60 | `CreateProcessW`, `OpenProcess`, `CreateThread`, `GetThreadContext`, … |
| `synchapi.h` | ~40 | `WaitForSingleObject`, `CreateMutexW`, `CreateEventW`, … |
| `ntifs.h` | ~200 | NT native API (`NtCreateFile`, `NtReadFile`, `RtlAllocateHeap`, …) |
| `winsock.h` | ~44 | BSD socket API (`accept`, `connect`, `recv`, `send`, …) |
| `winsock2.h` | ~105 | Extended Winsock 2 (`WSAStartup`, `WSASend`, `WSAIoctl`, …) |
| `WinInet.h` | ~171 | WinINet HTTP/FTP (`InternetOpenA`, `HttpSendRequestW`, `InternetReadFile`, …) |

To add definitions for other functions, drop a `.h` file with standard C prototypes into `defs/` and restart apiwatcher.

---

## 11. Default filter files

When the explicit `--exclude-file` / `--include-file` options are not given, apiwatcher checks for the corresponding default files in the **current working directory**:

| File | Purpose |
|---|---|
| `exclusions.txt` | Functions to never hook |
| `inclusions.txt` | Functions to always hook (override exclusions) |

Both files use the regex format described in [§9](#9-pattern-syntax).

The bundled `exclusions.txt` covers categories that produce extremely high call volumes with little diagnostic value:

- Stack probes (`__chkstk`, `KiUserExceptionDispatcher`)
- Heap allocators (`RtlAllocateHeap`, `malloc`, `free`, and CRT variants)
- Synchronisation internals (critical sections, SRW locks, condition variables)
- Activation contexts (SxS loader)
- Memory and string primitives (`memcpy`, `memset`, `wcslen`, …)
- PE / loader internals (LDR functions, `RtlImageNtHeader`)
- SEH / stack unwinding
- ETW (Event Tracing for Windows)
- AppHelp / shim database
- CRT locale and atexit machinery
- COM initialisation (`CoInitialize`, `CoUninitialize`)

To temporarily disable a pattern, prefix the line with `#`.  
To exclude an entire DLL add: `mydll\..*`

---

## 12. Performance notes

- **Hook placement** happens at module-load time, not on every call. The number of exclusion/inclusion patterns affects startup speed only.
- **IAT mode** (`--trace-iat`) places far fewer breakpoints than EAT mode (tens vs. thousands) and is much less intrusive for targets with many loaded DLLs. Prefer it when you care about what the application calls rather than what libraries export.
- **Log I/O** is fully decoupled from the debug loop via an `mpsc` channel. The writer thread batches lines into a single `write_all` per burst.
- **Excluded functions** have zero overhead at runtime — the INT3 byte is never written.
- Excluding entire DLLs (e.g. `ntdll\..*`) in EAT mode significantly reduces both the hook count and startup time.
- The main source of latency in EAT mode is the cross-process memory traffic needed to read each DLL's export table and write breakpoint bytes. On a DLL-heavy process (200+ DLLs) this can take several seconds.
