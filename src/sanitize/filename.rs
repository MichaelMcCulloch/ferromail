pub fn sanitize_filename(raw: &str, index: u32) -> String {
    // Stage 1-2: Input is already a Rust &str so it's valid UTF-8.
    // Stage 3: Already UTF-8.
    let mut result = String::with_capacity(raw.len());

    // Stage 4: Strip path separators
    for ch in raw.chars() {
        match ch {
            '/' | '\\' | ':' => {}
            _ => result.push(ch),
        }
    }

    // Stage 5: Strip path traversal sequences
    loop {
        let before = result.len();
        result = result.replace("..", "");
        if result.len() == before {
            break;
        }
    }

    // Stage 6: Strip null bytes
    result.retain(|ch| ch != '\0');

    // Stage 7: Strip C0 controls (except tab U+0009 and newline U+000A) and DEL
    // For filenames we strip ALL controls including tab and newline since they
    // don't belong in filenames.
    result.retain(|ch| {
        let cp = ch as u32;
        if cp == 0x7F {
            return false;
        }
        if cp <= 0x1F {
            return false;
        }
        true
    });

    // Stage 8: Strip bidi controls
    result.retain(|ch| !is_bidi_control(ch));

    // Stage 9: Truncate to 200 bytes (UTF-8 aware)
    result = truncate_utf8(&result, 200);

    // Stage 10: If empty, use fallback
    if result.is_empty() {
        return format!("attachment_{index}");
    }

    result
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_path_traversal() {
        assert_eq!(sanitize_filename("../../etc/passwd", 0), "etcpasswd");
    }

    #[test]
    fn strips_nested_traversal() {
        assert_eq!(sanitize_filename("....//....//etc/passwd", 0), "etcpasswd");
    }

    #[test]
    fn strips_windows_traversal() {
        assert_eq!(
            sanitize_filename(r"..\..\Windows\System32", 0),
            "WindowsSystem32"
        );
    }

    #[test]
    fn strips_null_bytes() {
        assert_eq!(sanitize_filename("file.pdf\x00.sh", 0), "file.pdf.sh");
    }

    #[test]
    fn truncates_long_filename() {
        let long = "a".repeat(300);
        let result = sanitize_filename(&long, 0);
        assert_eq!(result.len(), 200);
    }

    #[test]
    fn empty_after_sanitization() {
        assert_eq!(sanitize_filename("../../", 5), "attachment_5");
    }

    #[test]
    fn empty_input() {
        assert_eq!(sanitize_filename("", 0), "attachment_0");
    }

    #[test]
    fn strips_bidi_override() {
        let name = "resume\u{202E}fdp.txt".to_string();
        let result = sanitize_filename(&name, 0);
        assert!(!result.contains('\u{202E}'));
        assert_eq!(result, "resumefdp.txt");
    }

    #[test]
    fn strips_control_chars() {
        assert_eq!(sanitize_filename("file\x01\x02name.txt", 0), "filename.txt");
    }

    #[test]
    fn preserves_unicode_filenames() {
        assert_eq!(
            sanitize_filename("resume\u{0301}.pdf", 0),
            "resume\u{0301}.pdf"
        );
    }

    #[test]
    fn truncates_without_splitting_multibyte() {
        let name = "\u{1F600}".repeat(100); // Each emoji is 4 bytes, 400 total
        let result = sanitize_filename(&name, 0);
        assert!(result.len() <= 200);
        assert_eq!(result.len() % 4, 0); // No split multi-byte chars
    }
}
