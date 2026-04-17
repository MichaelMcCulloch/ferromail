#![no_main]
//! Fuzz IMAP response validators: UID parsing, date parsing, tag matching,
//! literal size gating. These are the narrow-waist functions a hostile
//! server's output runs through.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret first few bytes as different input shapes.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ferromail::imap::validate::validate_uid(s);
        let _ = ferromail::imap::validate::validate_date(s);
        let _ = ferromail::imap::validate::validate_tag(s, "A001");
    }

    // Split the input into a u64 prefix and use it as literal size.
    if data.len() >= 8 {
        let size = u64::from_le_bytes(data[..8].try_into().unwrap());
        let _ = ferromail::imap::validate::validate_literal_size(size, 26_214_400);
    }

    // Unsolicited counter must eventually refuse.
    let mut counter = ferromail::imap::validate::UnsolicitedCounter::new();
    for _ in 0..data.len().min(2000) {
        let _ = counter.increment();
    }
});
