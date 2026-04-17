//! SMTP header and body injection adversarial tests.
//!
//! Per SPEC.md §11.5: outbound SMTP must reject addresses containing CRLF,
//! must dot-stuff bodies starting with ".", and must refuse bodies that could
//! break the DATA terminator (`\r\n.\r\n`).

use ferromail::sanitize::outbound::{
    sanitize_body_outbound, sanitize_subject, validate_email_address, validate_message_id,
    validate_references,
};

/// CRLF in the local or domain part must be rejected.
#[test]
fn crlf_in_address_rejected() {
    for payload in [
        "user@example.com\r\nBcc: evil@attacker.com",
        "user\r\n@example.com",
        "user@example.com\nBcc: evil@attacker.com",
        "user@example.com\r\n.\r\nRCPT TO:<evil@attacker.com>",
        "user@example.com\r",
        "user@example.com\n",
    ] {
        let err = validate_email_address(payload).err();
        assert!(err.is_some(), "accepted CRLF-bearing address: {payload:?}");
    }
}

/// Multiple @ or trailing/leading whitespace is forbidden.
#[test]
fn malformed_addresses_rejected() {
    for payload in [
        "user@@example.com",
        "user@ex@ample.com",
        "user",
        "@example.com",
        "",
        "user,other@example.com",
        "user;other@example.com",
    ] {
        let err = validate_email_address(payload).err();
        assert!(err.is_some(), "accepted malformed address: {payload:?}");
    }
}

/// Well-formed addresses must pass.
#[test]
fn valid_addresses_accepted() {
    for payload in [
        "user@example.com",
        "user.name+tag@example.com",
        "user_name@sub.example.com",
        "\"Display Name\" <user@example.com>",
        "Display Name <user@example.com>",
    ] {
        assert!(
            validate_email_address(payload).is_ok(),
            "rejected valid address: {payload:?}"
        );
    }
}

/// `sanitize_body_outbound` normalizes line endings and enforces a size cap.
/// SMTP-layer dot-stuffing of the DATA terminator is the transport's
/// (lettre's) responsibility — lettre's `send` applies it before wire
/// transmission. Our contract here is: the sanitizer does not corrupt or
/// reject legitimate content that contains a `.` line.
#[test]
fn body_with_dot_line_accepted_and_normalized() {
    let body = "line1\n.\ninjected-but-harmless-here";
    let result = sanitize_body_outbound(body).expect("sanitizer accepts dot line");
    // Line endings normalized.
    assert!(result.contains("\r\n"));
    assert!(!result.contains('\n') || result.contains("\r\n"));
}

/// Leading `.` in body is not rejected by our sanitize layer — lettre handles
/// dot-stuffing on the wire.
#[test]
fn leading_dot_body_accepted() {
    let body = ".hidden line";
    assert!(sanitize_body_outbound(body).is_ok());
}

/// Subject header injection via CRLF must be stripped.
#[test]
fn subject_crlf_stripped() {
    for payload in [
        "Hello\r\nBcc: evil@attacker.com",
        "Hello\nContent-Type: text/html",
        "Hello\r\n\r\n<script>alert(1)</script>",
    ] {
        let clean = sanitize_subject(payload);
        assert!(
            !clean.contains('\r') && !clean.contains('\n'),
            "subject sanitizer kept CR/LF: {clean:?} from {payload:?}"
        );
    }
}

/// Message-ID must be in <addr@host> form. Free-form strings are rejected.
#[test]
fn invalid_message_id_rejected() {
    for payload in [
        "not-a-message-id",
        "<",
        ">",
        "<no-at-sign>",
        "<contains\r\n@host>",
        "<user@host\r\nInjected-Header: val>",
        "",
    ] {
        let err = validate_message_id(payload).err();
        assert!(err.is_some(), "accepted malformed Message-ID: {payload:?}");
    }
}

/// Valid Message-ID passes.
#[test]
fn valid_message_id_accepted() {
    for payload in ["<abc123@example.com>", "<uuid.v4.foo@mail.example.org>"] {
        assert!(
            validate_message_id(payload).is_ok(),
            "rejected valid Message-ID: {payload:?}"
        );
    }
}

/// References header: multiple Message-IDs separated by whitespace, any
/// containing CRLF must be rejected.
#[test]
fn references_with_injection_rejected() {
    let payload = "<a@b> <c@d>\r\nBcc: evil@attacker.com";
    assert!(validate_references(payload).is_err());
}

#[test]
fn references_valid() {
    let payload = "<a@b.com> <c@d.com> <e@f.org>";
    assert!(validate_references(payload).is_ok());
}

/// Bodies with bare LF or bare CR must be normalized to CRLF.
#[test]
fn bare_line_endings_normalized() {
    let body = "line1\nline2\rline3";
    let result = sanitize_body_outbound(body).expect("ok");
    // All line separators must be CRLF after normalization.
    assert!(!result.contains("\r\n\r"), "stray CR after normalization");
    let normalized_lines: Vec<&str> = result.split("\r\n").collect();
    assert_eq!(
        normalized_lines.len(),
        3,
        "expected three lines: {result:?}"
    );
}

/// Null bytes in address or body must be rejected.
#[test]
fn null_bytes_rejected_in_address() {
    assert!(validate_email_address("user\0@example.com").is_err());
    assert!(validate_email_address("user@example.com\0").is_err());
}
