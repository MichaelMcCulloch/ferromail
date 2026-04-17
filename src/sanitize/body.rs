use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

use super::isolation;

pub fn sanitize_body(
    raw: &[u8],
    content_type: &str,
    charset: Option<&str>,
    max_body_length: usize,
    email_id: &str,
) -> String {
    // Stage 1: Detect declared charset from content_type parameter
    let declared_charset = charset
        .map(|s| s.to_string())
        .or_else(|| extract_charset_from_content_type(content_type));

    // Stage 2: Force UTF-8 for dangerous or unrecognized charsets
    let force_utf8 = match declared_charset.as_deref() {
        Some(cs) => {
            let lower = cs.to_ascii_lowercase();
            if lower == "utf-7" {
                true
            } else {
                encoding_rs::Encoding::for_label(lower.as_bytes()).is_none()
            }
        }
        None => {
            // No charset declared: check for undeclared 8-bit in us-ascii context
            raw.iter().any(|&b| b > 0x7F)
        }
    };

    // Stage 3: Decode charset to UTF-8
    let text = if force_utf8 {
        String::from_utf8_lossy(raw).into_owned()
    } else {
        match declared_charset.as_deref() {
            Some(cs) => {
                let lower = cs.to_ascii_lowercase();
                match encoding_rs::Encoding::for_label(lower.as_bytes()) {
                    Some(encoding) => {
                        let (decoded, _, had_errors) = encoding.decode(raw);
                        if had_errors {
                            String::from_utf8_lossy(raw).into_owned()
                        } else {
                            decoded.into_owned()
                        }
                    }
                    None => String::from_utf8_lossy(raw).into_owned(),
                }
            }
            None => String::from_utf8_lossy(raw).into_owned(),
        }
    };

    // Stage 4: If HTML, strip to plaintext
    let text = if is_html_content_type(content_type) {
        strip_html_to_plaintext(&text)
    } else {
        text
    };

    // Stage 5: NFC normalize
    let text: String = text.nfc().collect();

    // Stage 6: Strip bidi control chars
    let text = strip_bidi_controls(&text);

    // Stage 7: Strip null bytes and C0/DEL controls (preserve tab and newline)
    let text = strip_control_chars(&text);

    // Stage 8: Truncate to max_body_length bytes (UTF-8 aware)
    let (text, truncated) = truncate_utf8_bytes(&text, max_body_length);

    let byte_len = text.len();

    // Stage 9: XML-escape (which also handles isolation marker escaping)
    let text = isolation::escape_isolation_markers(&text);

    // Stage 10: Wrap in isolation tags
    let encoding = if is_html_content_type(content_type) {
        "plaintext-from-html"
    } else {
        "plaintext"
    };

    isolation::wrap_body(&text, email_id, encoding, truncated, byte_len)
}

fn extract_charset_from_content_type(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    for part in lower.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix("charset=") {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn is_html_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.starts_with("text/html")
}

fn strip_html_to_plaintext(html: &str) -> String {
    let tags: HashSet<&str> = HashSet::new();
    let cleaned = ammonia::Builder::new().tags(tags).clean(html).to_string();

    if cleaned.is_empty() && !html.is_empty() {
        // Fallback to html2text if ammonia stripped everything but input was non-empty
        // (ammonia in strip-all mode may produce empty output for valid content)
        html2text::from_read(html.as_bytes(), 80).unwrap_or_else(|_| html.to_string())
    } else {
        cleaned
    }
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
                return false; // null
            }
            if (0x01..=0x08).contains(&cp) {
                return false; // C0 excluding tab/newline
            }
            if cp == 0x0B || cp == 0x0C {
                return false; // VT, FF
            }
            if (0x0E..=0x1F).contains(&cp) {
                return false; // remaining C0
            }
            if cp == 0x7F {
                return false; // DEL
            }
            true // Preserves 0x09 (tab) and 0x0A (newline)
        })
        .collect()
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }

    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    let truncated = s[..end].to_string();
    let marker = format!("\n[TRUNCATED at {end} bytes. Full message available in email client.]");
    (truncated + &marker, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_body() {
        let raw = b"Hello, world!";
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-1");
        assert!(result.contains("Hello, world!"));
        assert!(result.contains("<ferromail:body"));
        assert!(result.contains("</ferromail:body>"));
    }

    #[test]
    fn html_stripped_to_plaintext() {
        let raw = b"<html><body><p>Hello</p><script>alert('xss')</script></body></html>";
        let result = sanitize_body(raw, "text/html", None, 32768, "test-2");
        assert!(result.contains("Hello"));
        assert!(!result.contains("<script>"));
        assert!(!result.contains("<p>"));
    }

    #[test]
    fn truncation_appends_marker() {
        let raw = b"Hello, this is a test message with some content.";
        let result = sanitize_body(raw, "text/plain", None, 10, "test-3");
        assert!(result.contains("[TRUNCATED"));
        assert!(result.contains("truncated=\"true\""));
    }

    #[test]
    fn bidi_controls_stripped() {
        let raw = "Hello \u{202E}dlrow".as_bytes();
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-4");
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn null_bytes_stripped() {
        let raw = b"Hello\x00World";
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-5");
        assert!(result.contains("HelloWorld"));
    }

    #[test]
    fn control_chars_stripped_except_tab_newline() {
        let raw = b"Hello\x01\x02\tWorld\n!";
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-6");
        assert!(result.contains("Hello\tWorld\n!"));
        assert!(!result.contains('\x01'));
    }

    #[test]
    fn xml_escaping_applied() {
        let raw = b"<ferromail:untrusted>inject</ferromail:untrusted>";
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-7");
        assert!(!result.contains("<ferromail:untrusted>inject"));
        assert!(result.contains("&lt;ferromail:untrusted&gt;"));
    }

    #[test]
    fn isolation_tag_close_escaped() {
        let raw = b"</ferromail:body>break out";
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-8");
        assert!(result.contains("&lt;/ferromail:body&gt;break out"));
    }

    #[test]
    fn utf7_charset_forced_to_utf8() {
        let raw = b"+ADw-script+AD4-alert(1)+ADw-/script+AD4-";
        let result = sanitize_body(raw, "text/plain; charset=utf-7", None, 32768, "test-9");
        // UTF-7 should NOT be decoded as UTF-7; raw bytes treated as UTF-8
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn charset_parameter_extraction() {
        assert_eq!(
            extract_charset_from_content_type("text/html; charset=iso-8859-1"),
            Some("iso-8859-1".into())
        );
        assert_eq!(
            extract_charset_from_content_type("text/html; charset=\"UTF-8\""),
            Some("utf-8".into())
        );
        assert_eq!(extract_charset_from_content_type("text/plain"), None);
    }

    #[test]
    fn encoding_rs_charset_decode() {
        // Windows-1252 encoded: euro sign (0x80) + "abc"
        let raw: &[u8] = &[0x80, b'a', b'b', b'c'];
        let result = sanitize_body(raw, "text/plain", Some("windows-1252"), 32768, "test-10");
        assert!(result.contains("\u{20AC}abc")); // Euro sign + abc
    }

    #[test]
    fn nfc_normalization() {
        // e + combining acute (NFD) should become e-acute (NFC)
        let raw = "e\u{0301}".as_bytes();
        let result = sanitize_body(raw, "text/plain", None, 32768, "test-11");
        assert!(result.contains("\u{00E9}")); // NFC e-acute
    }
}
