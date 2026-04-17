use super::isolation;

pub fn sanitize_header(value: &str, header_name: &str, email_id: &str) -> String {
    // Stage 1: Input is already a decoded string (RFC 2047 decoding at parser level)

    // Stage 2: Ensure valid UTF-8 (input is &str so it's already valid)
    let text = value.to_string();

    // Stage 3: Strip \r and \n
    let text: String = text
        .chars()
        .filter(|&ch| ch != '\r' && ch != '\n')
        .collect();

    // Stage 4: Strip bidi controls
    let text = strip_bidi_controls(&text);

    // Stage 5: Strip null bytes and C0/DEL controls (preserve tab)
    let text = strip_control_chars(&text);

    // Stage 6: Truncate to 998 characters
    let text = truncate_chars(&text, 998);

    // Stage 7: XML-escape (handles isolation marker escaping too)
    let text = isolation::escape_isolation_markers(&text);

    // Stage 8: Wrap in isolation header tag
    isolation::wrap_header(&text, header_name, email_id)
}

fn strip_bidi_controls(s: &str) -> String {
    s.chars()
        .filter(|ch| {
            !matches!(
                ch,
                '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
        })
        .collect()
}

fn strip_control_chars(s: &str) -> String {
    s.chars()
        .filter(|&ch| {
            let cp = ch as u32;
            if cp == 0x00 {
                return false;
            }
            if (0x01..=0x08).contains(&cp) {
                return false;
            }
            if cp == 0x0B || cp == 0x0C {
                return false;
            }
            if (0x0E..=0x1F).contains(&cp) {
                return false;
            }
            if cp == 0x7F {
                return false;
            }
            true // Preserves 0x09 (tab)
        })
        .collect()
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_header() {
        let result = sanitize_header("Meeting tomorrow", "subject", "email-1");
        assert!(result.contains("Meeting tomorrow"));
        assert!(result.contains("<ferromail:header"));
        assert!(result.contains("name=\"subject\""));
    }

    #[test]
    fn strips_crlf() {
        let result = sanitize_header("Hello\r\nBCC: evil@attacker.com", "subject", "email-2");
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
        assert!(result.contains("HelloBCC: evil@attacker.com"));
    }

    #[test]
    fn strips_bidi() {
        let result = sanitize_header("Hello \u{202E}dlrow", "from", "email-3");
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn strips_null_and_controls() {
        let result = sanitize_header("Hello\x00\x01World", "subject", "email-4");
        assert!(result.contains("HelloWorld"));
    }

    #[test]
    fn truncates_long_header() {
        let long = "a".repeat(2000);
        let result = sanitize_header(&long, "subject", "email-5");
        let inner_start = result.find('>').unwrap() + 1;
        let inner_end = result.find("</ferromail:header>").unwrap();
        let inner = &result[inner_start..inner_end];
        assert_eq!(inner.len(), 998);
    }

    #[test]
    fn xml_escapes_injection() {
        let result = sanitize_header("</ferromail:header>break", "subject", "email-6");
        assert!(result.contains("&lt;/ferromail:header&gt;break"));
    }

    #[test]
    fn preserves_tab() {
        let result = sanitize_header("col1\tcol2", "subject", "email-7");
        assert!(result.contains("col1\tcol2"));
    }
}
