//! Breakpoint state and CONTEXT helpers.

use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

/// State saved per software breakpoint (INT3).
pub struct Bp {
    /// The byte that was displaced by 0xCC.
    pub orig: u8,
    pub target_image: String,
    pub target_routine: String,
    /// When `true` the breakpoint is removed after it fires once instead of
    /// being re-armed.  Used for GetProcAddress return hooks.
    pub one_shot: bool,
}

/// Newtype wrapper that forces the 16-byte alignment required by
/// `GetThreadContext` on x64 — without it the call silently returns 0.
#[repr(C, align(16))]
pub struct AlignedCtx(pub CONTEXT);

/// Allocate a zeroed, correctly-flagged CONTEXT.
pub fn make_context() -> AlignedCtx {
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
    let mut c = AlignedCtx(unsafe { std::mem::zeroed() });
    c.0.ContextFlags = CONTEXT_FULL_AMD64;
    c
}
