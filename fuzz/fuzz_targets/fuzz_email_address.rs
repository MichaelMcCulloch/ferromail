#![no_main]
//! Fuzz outbound validators: email address, subject, message-id, references,
//! body normalization. Contract: no panics, and if validation returns Ok, the
//! input contains no CR/LF (for addresses / message-id / references).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: String| {
    if ferromail::sanitize::outbound::validate_email_address(&input).is_ok() {
        assert!(!input.contains('\r'));
        assert!(!input.contains('\n'));
        assert!(input.contains('@'));
    }

    if ferromail::sanitize::outbound::validate_message_id(&input).is_ok() {
        assert!(!input.contains('\r'));
        assert!(!input.contains('\n'));
        assert!(input.starts_with('<'));
        assert!(input.ends_with('>'));
    }

    if ferromail::sanitize::outbound::validate_references(&input).is_ok() {
        assert!(!input.contains('\r'));
        assert!(!input.contains('\n'));
    }

    let subj = ferromail::sanitize::outbound::sanitize_subject(&input);
    assert!(!subj.contains('\r'));
    assert!(!subj.contains('\n'));

    // Body may be rejected (oversize), but if accepted must have CRLF-only
    // line endings.
    if let Ok(body) = ferromail::sanitize::outbound::sanitize_body_outbound(&input) {
        // Every \n must be preceded by \r (no bare LF).
        for (i, byte) in body.as_bytes().iter().enumerate() {
            if *byte == b'\n' {
                assert!(i > 0 && body.as_bytes()[i - 1] == b'\r', "bare LF at {i}");
            }
        }
    }
});
