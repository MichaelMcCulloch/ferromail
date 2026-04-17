#![no_main]
//! Fuzz the MIME parser with arbitrary byte input.
//!
//! Contract: `parse_email` must not panic, must respect depth/parts/size
//! caps, and must set `mime_truncated` when it stops early.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Caps must be small enough that exhaustion paths are reachable but large
    // enough that typical inputs succeed.
    let _ = ferromail::mime_parse::parse_email(data, 10, 100, 1_000_000);
});
