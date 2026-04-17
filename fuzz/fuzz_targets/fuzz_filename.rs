#![no_main]
//! Fuzz filename sanitizer.
//!
//! Contract: for every input string, the output must not contain path
//! separators, null bytes, or the ".." sequence; and if the output is empty
//! the caller would hit the fallback (we don't test that here — we just
//! verify the pipeline cannot panic and its invariants hold).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: String| {
    let clean = ferromail::sanitize::filename::sanitize_filename(&input, 0);
    assert!(!clean.contains('/'), "separator / leaked: {clean:?}");
    assert!(!clean.contains('\\'), "separator \\ leaked: {clean:?}");
    assert!(!clean.contains('\0'), "null byte leaked: {clean:?}");
    assert!(!clean.contains(".."), ".. sequence leaked: {clean:?}");
});
