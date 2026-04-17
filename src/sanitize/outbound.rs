pub fn validate_email_address(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("email address is empty".into());
    }

    if addr.contains('\r') || addr.contains('\n') {
        return Err("email address contains CR or LF".into());
    }

    for ch in addr.chars() {
        let cp = ch as u32;
        if cp <= 0x1F || cp == 0x7F {
            return Err(format!(
                "email address contains control character U+{cp:04X}"
            ));
        }
    }

    if addr.contains(',') || addr.contains(';') {
        return Err("email address contains comma or semicolon".into());
    }

    let at_count = addr.chars().filter(|&c| c == '@').count();
    if at_count == 0 {
        return Err("email address has no @".into());
    }
    if at_count > 1 {
        return Err("email address has multiple @".into());
    }

    let at_pos = addr.find('@').unwrap_or(0);
    let local = &addr[..at_pos];
    let domain = &addr[at_pos + 1..];

    if local.is_empty() {
        return Err("email address has empty local-part".into());
    }
    if domain.is_empty() {
        return Err("email address has empty domain".into());
    }

    Ok(())
}

pub fn sanitize_subject(subject: &str) -> String {
    let cleaned: String = subject
        .chars()
        .filter(|&ch| ch != '\r' && ch != '\n')
        .collect();
    truncate_chars(&cleaned, 998)
}

pub fn sanitize_body_outbound(body: &str) -> Result<String, String> {
    const MAX_BODY_BYTES: usize = 262_144; // 256 KB

    // Normalize line endings to \r\n
    let normalized = normalize_crlf(body);

    if normalized.len() > MAX_BODY_BYTES {
        return Err(format!(
            "body exceeds maximum size: {} bytes (limit: {MAX_BODY_BYTES})",
            normalized.len()
        ));
    }

    Ok(normalized)
}

pub fn validate_message_id(id: &str) -> Result<(), String> {
    if id.contains('\r') || id.contains('\n') {
        return Err("Message-ID contains CR or LF".into());
    }

    if !id.starts_with('<') || !id.ends_with('>') {
        return Err("Message-ID must be enclosed in angle brackets (<...>)".into());
    }

    let inner = &id[1..id.len() - 1];
    if inner.is_empty() {
        return Err("Message-ID inner part is empty".into());
    }
    if !inner.contains('@') {
        return Err("Message-ID must contain @ between local-part and domain".into());
    }

    Ok(())
}

pub fn validate_references(refs: &str) -> Result<(), String> {
    if refs.contains('\r') || refs.contains('\n') {
        return Err("References header contains CR or LF".into());
    }

    if refs.trim().is_empty() {
        return Err("References header is empty".into());
    }

    // References is space-separated Message-IDs
    let mut found_any = false;
    let mut remaining = refs.trim();

    while !remaining.is_empty() {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        let start = match remaining.find('<') {
            Some(pos) => pos,
            None => return Err("expected '<' in References header".into()),
        };

        let end = match remaining[start..].find('>') {
            Some(pos) => start + pos,
            None => return Err("unterminated Message-ID in References (missing '>')".into()),
        };

        let msg_id = &remaining[start..=end];
        let inner = &msg_id[1..msg_id.len() - 1];
        if !inner.contains('@') {
            return Err(format!(
                "Message-ID '{msg_id}' in References does not contain @"
            ));
        }

        found_any = true;
        remaining = &remaining[end + 1..];
    }

    if !found_any {
        return Err("no valid Message-IDs found in References".into());
    }

    Ok(())
}

fn normalize_crlf(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\r' {
            result.push_str("\r\n");
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else if ch == '\n' {
            result.push_str("\r\n");
        } else {
            result.push(ch);
        }
    }

    result
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_email() {
        assert!(validate_email_address("user@example.com").is_ok());
        assert!(validate_email_address("user+tag@example.com").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_email_address("").is_err());
    }

    #[test]
    fn rejects_no_at() {
        assert!(validate_email_address("userexample.com").is_err());
    }

    #[test]
    fn rejects_multiple_at() {
        assert!(validate_email_address("user@@example.com").is_err());
    }

    #[test]
    fn rejects_empty_local() {
        assert!(validate_email_address("@example.com").is_err());
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(validate_email_address("user@").is_err());
    }

    #[test]
    fn rejects_crlf() {
        assert!(validate_email_address("user\r\n@example.com").is_err());
    }

    #[test]
    fn rejects_control_chars() {
        assert!(validate_email_address("user\x01@example.com").is_err());
    }

    #[test]
    fn rejects_comma() {
        assert!(validate_email_address("user@example.com,other@example.com").is_err());
    }

    #[test]
    fn rejects_semicolon() {
        assert!(validate_email_address("user@example.com;other@example.com").is_err());
    }

    #[test]
    fn sanitize_subject_strips_crlf() {
        assert_eq!(
            sanitize_subject("Hello\r\nBCC: evil@attacker.com"),
            "HelloBCC: evil@attacker.com"
        );
    }

    #[test]
    fn sanitize_subject_truncates() {
        let long = "a".repeat(2000);
        assert_eq!(sanitize_subject(&long).len(), 998);
    }

    #[test]
    fn body_outbound_normalizes_line_endings() {
        let result = sanitize_body_outbound("line1\nline2\rline3\r\nline4").unwrap();
        assert_eq!(result, "line1\r\nline2\r\nline3\r\nline4");
    }

    #[test]
    fn body_outbound_rejects_oversized() {
        let big = "x".repeat(300_000);
        assert!(sanitize_body_outbound(&big).is_err());
    }

    #[test]
    fn validates_message_id() {
        assert!(validate_message_id("<abc@example.com>").is_ok());
        assert!(validate_message_id("abc@example.com").is_err());
        assert!(validate_message_id("<abc>").is_err());
    }

    #[test]
    fn validates_references() {
        assert!(validate_references("<a@b.com> <c@d.com>").is_ok());
        assert!(validate_references("").is_err());
        assert!(validate_references("not-a-msgid").is_err());
    }

    #[test]
    fn crlf_in_message_id_stripped() {
        assert!(validate_message_id("<id@example.com>\r\nBCC: evil@attacker.com").is_err());
    }
}
