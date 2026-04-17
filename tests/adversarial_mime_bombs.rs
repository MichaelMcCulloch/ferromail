//! MIME parser DoS / resource-exhaustion adversarial tests.
//!
//! Per SPEC.md §11.4: the MIME parser must enforce:
//!   - max_message_size (default 26_214_400 bytes)
//!   - max_mime_depth (default 10 nested multiparts)
//!   - max_mime_parts (default 100)
//!
//! Attempts to exceed these limits must not panic, must not allocate
//! unbounded memory, and must set `mime_truncated = true` on the result.

use ferromail::mime_parse::parse_email;

/// An email whose raw bytes exceed max_message_size must be rejected with
/// an error, not truncated silently.
#[test]
fn oversized_message_errors() {
    let raw = vec![b'a'; 200];
    let result = parse_email(&raw, 10, 100, 100);
    assert!(result.is_err(), "oversized message was accepted");
}

/// Deeply nested multipart bodies must be truncated at max_depth.
#[test]
fn deep_nesting_truncated_not_panicked() {
    let depth = 50;
    let email = build_nested_multipart(depth);
    let result = parse_email(&email, 10, 500, 10_000_000);
    let parsed = result.expect("parser must not error on deep nesting");
    assert!(
        parsed.mime_truncated,
        "deep nesting did not set truncated flag"
    );
}

/// Thousands of parts at depth 1 must be truncated at max_parts.
#[test]
fn many_parts_truncated() {
    let email = build_flat_multipart(2000);
    let result = parse_email(&email, 10, 100, 50_000_000);
    let parsed = result.expect("parser must not error on many parts");
    assert!(
        parsed.mime_truncated,
        "expected truncated flag when part count exceeds limit"
    );
}

/// Zero-byte filename on an attachment must not cause a crash.
#[test]
fn zero_byte_filename_handled() {
    let email = b"From: a@b\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=BOUND\r\n\
        \r\n\
        --BOUND\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        body\r\n\
        --BOUND\r\n\
        Content-Type: application/octet-stream\r\n\
        Content-Disposition: attachment; filename=\"\"\r\n\
        \r\n\
        attachment data\r\n\
        --BOUND--\r\n";
    let parsed = parse_email(email, 10, 100, 1_000_000).expect("should parse");
    // Attachment should either be absent (parser treats as inline) or present
    // with a non-panicking empty filename.
    for att in &parsed.attachments {
        // If filename is Some, it must not be the empty string itself as that
        // would round-trip to nothing in the audit log.
        if let Some(ref fn_) = att.filename {
            assert!(
                !fn_.is_empty(),
                "empty filename leaked into parsed attachment"
            );
        }
    }
}

/// Right-to-left override in filename must not cause a crash; whether the
/// parser keeps or strips the control char is a sanitize-layer concern.
#[test]
fn rtl_override_filename_handled() {
    let email = b"From: a@b\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=BOUND\r\n\
        \r\n\
        --BOUND\r\n\
        Content-Type: application/octet-stream\r\n\
        Content-Disposition: attachment; filename=\"resume\xE2\x80\xAEfdp.pdf\"\r\n\
        \r\n\
        data\r\n\
        --BOUND--\r\n";
    let _ = parse_email(email, 10, 100, 1_000_000).expect("parser must not panic");
}

/// UTF-7 charset in a text/plain part must not be decoded by the MIME parser
/// itself (that's the sanitize_body layer's responsibility), but must not
/// cause a panic.
#[test]
fn utf7_charset_in_mime_part_handled() {
    let email = b"From: a@b\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: text/plain; charset=utf-7\r\n\
        \r\n\
        +ADw-script+AD4-alert(1)+ADw-/script+AD4-\r\n";
    let _ = parse_email(email, 10, 100, 1_000_000).expect("parser must not panic");
}

/// x-user-defined or entirely unknown charset must not cause a panic.
#[test]
fn unknown_charset_handled() {
    let email = b"From: a@b\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: text/plain; charset=x-user-defined\r\n\
        \r\n\
        hello world\r\n";
    let _ = parse_email(email, 10, 100, 1_000_000).expect("parser must not panic");
}

/// A completely empty body after headers must parse cleanly.
#[test]
fn empty_body_ok() {
    let email = b"From: a@b\r\nSubject: empty\r\n\r\n";
    let _ = parse_email(email, 10, 100, 1_000_000).expect("empty ok");
}

/// Malformed boundary — parser must not loop forever.
#[test]
fn malformed_boundary_terminates() {
    let email = b"From: a@b\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=BOUND\r\n\
        \r\n\
        --BOUND\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        never closed\r\n";
    let _ = parse_email(email, 10, 100, 1_000_000);
    // Just reaching this line is the contract — no infinite loop.
}

// --- helpers ---

fn build_nested_multipart(depth: usize) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"From: a@b\r\nMIME-Version: 1.0\r\n");
    msg.extend_from_slice(b"Content-Type: multipart/mixed; boundary=B0\r\n\r\n");

    fn inner(msg: &mut Vec<u8>, level: usize, max: usize) {
        let boundary = format!("B{level}");
        msg.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if level + 1 >= max {
            msg.extend_from_slice(b"Content-Type: text/plain\r\n\r\nhello\r\n");
        } else {
            let next = format!("B{}", level + 1);
            msg.extend_from_slice(
                format!("Content-Type: multipart/mixed; boundary={next}\r\n\r\n").as_bytes(),
            );
            inner(msg, level + 1, max);
        }
        msg.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    }

    inner(&mut msg, 0, depth);
    msg
}

fn build_flat_multipart(parts: usize) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"From: a@b\r\nMIME-Version: 1.0\r\n");
    msg.extend_from_slice(b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n");
    for i in 0..parts {
        msg.extend_from_slice(b"--BOUND\r\n");
        msg.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        msg.extend_from_slice(format!("part {i}\r\n").as_bytes());
    }
    msg.extend_from_slice(b"--BOUND--\r\n");
    msg
}
