//! Detection of sender-spoofing signals that the LLM should see.
//!
//! Three specific smells:
//!
//! 1. **Display-name spoofing** — `From: "CEO <ceo@company.com>" <attacker@evil.biz>`.
//!    The displayed name includes an email-looking substring that doesn't
//!    match the actual addr-spec. Classic target-of-opportunity phish.
//!
//! 2. **Homograph domains** — `pаypal.com` with Cyrillic "а", or mixed-script
//!    labels. Punycode-encode and flag if the result differs.
//!
//! 3. **Unicode lookalike at label boundary** — dots that aren't ASCII dots
//!    (U+3002 "。", etc.), invisible characters, bidi overrides.

use idna::domain_to_ascii;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpoofSignals {
    /// The display-name portion contains an `@` that doesn't belong to the
    /// actual sender address. Example trigger: `"admin@bank.com" <x@evil.biz>`.
    pub display_name_embeds_address: Option<String>,
    /// The sender domain contains mixed scripts or non-ASCII lookalikes.
    /// Value is the punycode form if different from the literal form.
    pub confusable_domain: Option<String>,
    /// The sender domain contains bidi overrides or invisible chars.
    pub invisible_chars_in_domain: bool,
    /// True if any signal fired.
    pub suspicious: bool,
}

impl SpoofSignals {
    pub fn from_sender(sender_header: &str) -> Self {
        let (display, addr) = split_display_and_addr(sender_header);
        let domain = domain_of(&addr);

        let display_name_embeds_address = display.and_then(|d| detect_embedded_addr(&d, &addr));
        let confusable_domain = domain.as_ref().and_then(|d| detect_confusable_domain(d));
        let invisible_chars_in_domain = domain
            .as_ref()
            .is_some_and(|d| contains_invisible(d));

        let suspicious = display_name_embeds_address.is_some()
            || confusable_domain.is_some()
            || invisible_chars_in_domain;

        Self {
            display_name_embeds_address,
            confusable_domain,
            invisible_chars_in_domain,
            suspicious,
        }
    }
}

fn split_display_and_addr(s: &str) -> (Option<String>, String) {
    // `"Display" <addr@dom>` or `Display Name <addr@dom>` or bare `addr@dom`.
    let s = s.trim();
    if let Some(open) = s.rfind('<')
        && let Some(close) = s[open..].find('>')
    {
        let display = s[..open].trim();
        let addr = s[open + 1..open + close].trim();
        let display = if display.is_empty() {
            None
        } else {
            Some(display.trim_matches('"').to_string())
        };
        return (display, addr.to_string());
    }
    (None, s.to_string())
}

fn domain_of(addr: &str) -> Option<String> {
    addr.rsplit_once('@').map(|(_, d)| d.to_string())
}

fn detect_embedded_addr(display: &str, actual: &str) -> Option<String> {
    // Look for any "word@word.tld" shape inside the display name.
    let mut chars = display.chars().peekable();
    let mut buf = String::new();
    while let Some(c) = chars.next() {
        if c.is_alphanumeric() || "._+-".contains(c) {
            buf.push(c);
        } else if c == '@' && !buf.is_empty() {
            // Collect the domain-looking tail.
            let mut dom = String::new();
            while let Some(&nc) = chars.peek() {
                if nc.is_alphanumeric() || nc == '.' || nc == '-' {
                    dom.push(nc);
                    chars.next();
                } else {
                    break;
                }
            }
            if dom.contains('.') {
                let candidate = format!("{buf}@{dom}");
                if !actual.eq_ignore_ascii_case(&candidate) {
                    return Some(candidate);
                }
            }
            buf.clear();
        } else {
            buf.clear();
        }
    }
    None
}

fn detect_confusable_domain(domain: &str) -> Option<String> {
    // If the domain contains any non-ASCII, compute punycode; if it changes
    // and the label would be readable, flag.
    if domain.is_ascii() {
        return None;
    }
    match domain_to_ascii(domain) {
        Ok(ascii) if ascii != domain => Some(ascii),
        Ok(_) => None,
        Err(_) => Some("<invalid IDN>".to_string()),
    }
}

fn contains_invisible(s: &str) -> bool {
    s.chars().any(|c| {
        // Bidi overrides + invisible markers.
        matches!(c,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_display_name_address_spoof() {
        let s = SpoofSignals::from_sender(r#""admin@bank.com" <evil@attacker.biz>"#);
        assert!(s.suspicious);
        assert_eq!(
            s.display_name_embeds_address.as_deref(),
            Some("admin@bank.com")
        );
    }

    #[test]
    fn accepts_matching_display_address() {
        let s = SpoofSignals::from_sender(r#""support@corp.com" <support@corp.com>"#);
        assert!(!s.suspicious);
        assert!(s.display_name_embeds_address.is_none());
    }

    #[test]
    fn bare_address_no_display() {
        let s = SpoofSignals::from_sender("user@example.com");
        assert!(!s.suspicious);
    }

    #[test]
    fn detects_cyrillic_homograph() {
        // "pаypal.com" with Cyrillic "а".
        let s = SpoofSignals::from_sender("service@p\u{0430}ypal.com");
        assert!(s.suspicious);
        assert!(s.confusable_domain.is_some());
    }

    #[test]
    fn detects_invisible_in_domain() {
        let s = SpoofSignals::from_sender("user@bank\u{200B}.com");
        assert!(s.invisible_chars_in_domain);
        assert!(s.suspicious);
    }

    #[test]
    fn pure_ascii_clean() {
        let s = SpoofSignals::from_sender("noreply@github.com");
        assert!(!s.suspicious);
    }
}
