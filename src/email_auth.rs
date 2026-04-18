//! Ingress email authentication: surfaces DKIM / SPF / DMARC / ARC trust
//! signals to the LLM so "From: ceo@company.com" isn't taken at face value.
//!
//! Two independent paths:
//!
//! 1. **Upstream** — parse `Authentication-Results` headers the receiving MX
//!    added. This is the cheap, authoritative signal: the MX did real SPF
//!    (it saw the connecting IP), real DKIM (DNS at delivery time), real
//!    DMARC alignment. If the account's provider (Gmail, Fastmail, Proton)
//!    sets these, use them.
//!
//! 2. **Local DKIM re-verification** — if [`InboundAuthConfig::verify_dkim`]
//!    is enabled, we re-run DKIM against the raw bytes as a cross-check.
//!    Catches an MX that strips or forges AR headers. Costs one DNS lookup
//!    per signature.
//!
//! Results are stuck verbatim into the `<ferromail:auth>` tag in the
//! isolation envelope so the LLM can reason about trust.

use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthResults {
    /// Summary from the receiving MX's `Authentication-Results` header,
    /// if any. A string like "dkim=pass; spf=pass; dmarc=pass (google.com)".
    pub upstream: Option<String>,
    /// Local DKIM re-verification. `Some("pass")` / `Some("fail (...)")`
    /// / `None` when disabled or no signatures present.
    pub dkim_local: Option<String>,
    /// Local ARC chain verification.
    pub arc_local: Option<String>,
    /// Any ARC authentication results forwarded through the chain (the
    /// originating MX's view as preserved by intermediate forwarders).
    pub arc_upstream: Option<String>,
    /// Heuristic: `true` if upstream says pass AND local re-verify agrees,
    /// or if upstream says pass and local is disabled.
    pub trusted: bool,
}

impl AuthResults {
    pub fn is_trusted(&self) -> bool {
        self.trusted
    }
}

#[derive(Debug, Clone)]
pub struct InboundAuthConfig {
    pub verify_dkim: bool,
    pub verify_arc: bool,
}

impl Default for InboundAuthConfig {
    fn default() -> Self {
        Self {
            verify_dkim: true,
            verify_arc: true,
        }
    }
}

static AUTHENTICATOR: OnceLock<MessageAuthenticator> = OnceLock::new();

fn authenticator() -> Option<&'static MessageAuthenticator> {
    // Cloudflare-over-TLS is the same pick as every other mail-auth user;
    // it avoids leaking every sender domain to the ISP's resolver.
    AUTHENTICATOR
        .get_or_init(|| {
            MessageAuthenticator::new_cloudflare_tls().unwrap_or_else(|_| {
                MessageAuthenticator::new_google()
                    .expect("DNS resolver available (cloudflare-tls or google)")
            })
        })
        .into()
}

/// Verify a message. `raw` is the RFC 5322 bytes as delivered.
pub async fn verify_inbound(raw: &[u8], config: &InboundAuthConfig) -> AuthResults {
    let upstream = extract_upstream_auth(raw);
    let arc_upstream = extract_upstream_arc(raw);

    let mut results = AuthResults {
        upstream: upstream.clone(),
        arc_upstream,
        ..Default::default()
    };

    let Some(authenticator) = authenticator() else {
        return results;
    };

    let Ok(parsed) = AuthenticatedMessage::parse(raw).ok_or(()) else {
        return results;
    };

    if config.verify_dkim {
        let dkim_outputs = authenticator.verify_dkim(&parsed).await;
        results.dkim_local = Some(summarize_dkim(&dkim_outputs));
    }

    if config.verify_arc {
        let arc_output = authenticator.verify_arc(&parsed).await;
        results.arc_local = Some(format_arc_result(arc_output.result()));
    }

    results.trusted = compute_trust(&upstream, &results.dkim_local);

    results
}

fn summarize_dkim(outputs: &[mail_auth::DkimOutput<'_>]) -> String {
    if outputs.is_empty() {
        return "none (no DKIM-Signature header)".into();
    }
    let mut passes = 0;
    let mut fails: Vec<String> = Vec::new();
    for out in outputs {
        match out.result() {
            DkimResult::Pass => passes += 1,
            other => fails.push(format!("{other:?}")),
        }
    }
    if fails.is_empty() {
        format!(
            "pass ({passes} signature{})",
            if passes == 1 { "" } else { "s" }
        )
    } else if passes > 0 {
        format!(
            "mixed ({passes} pass, {} fail: {})",
            fails.len(),
            fails.join(", ")
        )
    } else {
        format!("fail ({})", fails.join(", "))
    }
}

fn format_arc_result(result: &mail_auth::DkimResult) -> String {
    match result {
        DkimResult::Pass => "pass".into(),
        DkimResult::None => "none".into(),
        other => format!("{other:?}"),
    }
}

fn extract_upstream_auth(raw: &[u8]) -> Option<String> {
    // Parse RFC 5322 headers without pulling in a full parser: headers end
    // at the first blank line. Case-insensitive match on header name.
    let end_of_headers = find_header_end(raw)?;
    let header_block = &raw[..end_of_headers];
    let text = std::str::from_utf8(header_block).ok()?;

    let mut best: Option<String> = None;
    for header_line in unfold_headers(text) {
        let (name, value) = header_line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("authentication-results") {
            // Prefer the most recent one that mentions spf= and dkim=.
            let trimmed = value.trim().to_string();
            if trimmed.contains("dkim=") || trimmed.contains("spf=") {
                best = Some(trimmed);
                break;
            }
            if best.is_none() {
                best = Some(trimmed);
            }
        }
    }
    best
}

fn extract_upstream_arc(raw: &[u8]) -> Option<String> {
    let end_of_headers = find_header_end(raw)?;
    let text = std::str::from_utf8(&raw[..end_of_headers]).ok()?;
    for header_line in unfold_headers(text) {
        let (name, value) = header_line.split_once(':')?;
        if name
            .trim()
            .eq_ignore_ascii_case("arc-authentication-results")
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    for i in 0..raw.len().saturating_sub(3) {
        if &raw[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    for i in 0..raw.len().saturating_sub(1) {
        if &raw[i..i + 2] == b"\n\n" {
            return Some(i);
        }
    }
    None
}

fn unfold_headers(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let trimmed_line = line.trim_end_matches('\r');
        if trimmed_line.is_empty() {
            continue;
        }
        if (trimmed_line.starts_with(' ') || trimmed_line.starts_with('\t')) && !out.is_empty() {
            // Continuation — fold into previous.
            let last = out.last_mut().unwrap();
            last.push(' ');
            last.push_str(trimmed_line.trim());
        } else {
            out.push(trimmed_line.to_string());
        }
    }
    out
}

fn compute_trust(upstream: &Option<String>, dkim_local: &Option<String>) -> bool {
    let upstream_pass = upstream
        .as_deref()
        .map(|u| u.contains("dmarc=pass") || (u.contains("dkim=pass") && !u.contains("dkim=fail")))
        .unwrap_or(false);
    let local_ok = dkim_local
        .as_deref()
        .map(|d| d.starts_with("pass") || d.starts_with("none"))
        .unwrap_or(true);
    upstream_pass && local_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_authentication_results() {
        let raw = b"From: sender@example.com\r\n\
                    To: recipient@example.com\r\n\
                    Authentication-Results: mx.google.com; dkim=pass header.i=@example.com; \
                    spf=pass smtp.mailfrom=sender@example.com; dmarc=pass (p=NONE)\r\n\
                    Subject: Hello\r\n\
                    \r\n\
                    Body\r\n";
        let result = extract_upstream_auth(raw).expect("should extract");
        assert!(result.contains("dkim=pass"));
        assert!(result.contains("spf=pass"));
        assert!(result.contains("dmarc=pass"));
    }

    #[test]
    fn handles_folded_header() {
        let raw = b"From: sender@example.com\r\n\
                    Authentication-Results: mx.google.com;\r\n\
                    \tdkim=pass;\r\n\
                    \tspf=pass\r\n\
                    Subject: x\r\n\
                    \r\n\
                    body";
        let result = extract_upstream_auth(raw).expect("folded header");
        assert!(result.contains("dkim=pass"));
        assert!(result.contains("spf=pass"));
    }

    #[test]
    fn no_authentication_results_returns_none() {
        let raw = b"From: x@example.com\r\nSubject: y\r\n\r\nbody";
        assert!(extract_upstream_auth(raw).is_none());
    }

    #[test]
    fn trust_requires_both_signals() {
        assert!(compute_trust(
            &Some("dkim=pass; spf=pass; dmarc=pass".into()),
            &Some("pass (1 signature)".into())
        ));
        assert!(!compute_trust(
            &Some("dkim=fail".into()),
            &Some("pass (1 signature)".into())
        ));
        assert!(!compute_trust(&None, &Some("pass (1 signature)".into())));
    }
}
