//! MTA-STS (RFC 8461) policy fetching, parsing, and in-memory cache.
//!
//! ferromail is a mail user agent that submits via an MSA (e.g.
//! smtp.gmail.com), so it does *not* perform direct-to-MX delivery. MTA-STS
//! is nevertheless useful here as an auditable signal: before sending, we
//! can fetch the policy for each recipient domain and log whether the
//! outbound MSA *would* route via a policy-compliant MX. Pairs with the
//! audit subsystem for post-hoc analysis.
//!
//! The fetcher follows the RFC's HTTPS-only rule, rejects policies served
//! over HTTP, and caches by `max_age` to avoid hammering the policy server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::types::{FerromailError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub mode: Mode,
    pub mx_patterns: Vec<String>,
    pub max_age: u64,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Self> {
        let mut mode = None;
        let mut mx_patterns = Vec::new();
        let mut max_age = None;
        let mut version_seen = false;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = match line.split_once(':') {
                Some(kv) => kv,
                None => continue,
            };
            let k = k.trim();
            let v = v.trim();
            match k.to_ascii_lowercase().as_str() {
                "version" => {
                    if v != "STSv1" {
                        return Err(FerromailError::ConfigError(format!(
                            "MTA-STS: unsupported version '{v}'"
                        )));
                    }
                    version_seen = true;
                }
                "mode" => {
                    mode = Some(match v.to_ascii_lowercase().as_str() {
                        "enforce" => Mode::Enforce,
                        "testing" => Mode::Testing,
                        "none" => Mode::None,
                        other => {
                            return Err(FerromailError::ConfigError(format!(
                                "MTA-STS: unknown mode '{other}'"
                            )));
                        }
                    });
                }
                "mx" => mx_patterns.push(v.to_string()),
                "max_age" => {
                    max_age = v.parse().ok();
                }
                _ => { /* ignore unknown keys per RFC */ }
            }
        }

        if !version_seen {
            return Err(FerromailError::ConfigError(
                "MTA-STS: missing required 'version: STSv1'".into(),
            ));
        }

        Ok(Policy {
            mode: mode.ok_or_else(|| {
                FerromailError::ConfigError("MTA-STS: missing 'mode'".into())
            })?,
            mx_patterns,
            max_age: max_age.unwrap_or(86_400),
        })
    }

    /// Does the given MX hostname satisfy one of the policy's patterns?
    /// Patterns may be literal (`mx.example.com`) or single-label wildcard
    /// (`*.example.com`).
    pub fn mx_matches(&self, mx: &str) -> bool {
        let mx = mx.trim_end_matches('.').to_ascii_lowercase();
        for pattern in &self.mx_patterns {
            let pat = pattern.trim_end_matches('.').to_ascii_lowercase();
            if let Some(suffix) = pat.strip_prefix("*.") {
                // Single-label wildcard: mx = one.suffix, not any.depth.suffix.
                if let Some(rest) = mx.strip_suffix(&format!(".{suffix}"))
                    && !rest.contains('.')
                {
                    return true;
                }
            } else if pat == mx {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
struct Cached {
    policy: Policy,
    fetched_at: Instant,
}

/// Process-wide cache. Keyed on recipient domain.
static CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);

fn with_cache<R>(f: impl FnOnce(&mut HashMap<String, Cached>) -> R) -> R {
    let mut guard = CACHE.lock().expect("MTA-STS cache poisoned");
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Fetch policy from `https://mta-sts.{domain}/.well-known/mta-sts.txt`.
/// Honours a 5-second connect + read timeout and refuses redirects.
pub async fn fetch(domain: &str) -> Result<Option<Policy>> {
    if let Some(cached) = with_cache(|c| {
        c.get(domain).and_then(|entry| {
            let age = entry.fetched_at.elapsed();
            if age < Duration::from_secs(entry.policy.max_age) {
                Some(entry.policy.clone())
            } else {
                None
            }
        })
    }) {
        return Ok(Some(cached));
    }

    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| FerromailError::TlsError(format!("MTA-STS client build: {e}")))?;

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None), // Domains without MTA-STS are common.
    };

    if !resp.status().is_success() {
        return Ok(None);
    }
    // RFC 8461: policy must be served text/plain.
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.to_ascii_lowercase().starts_with("text/plain") {
        return Ok(None);
    }

    let text = resp
        .text()
        .await
        .map_err(|e| FerromailError::TlsError(format!("MTA-STS body read: {e}")))?;

    let policy = Policy::parse(&text)?;
    with_cache(|c| {
        c.insert(
            domain.to_string(),
            Cached {
                policy: policy.clone(),
                fetched_at: Instant::now(),
            },
        );
    });
    Ok(Some(policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enforce_policy() {
        let text = "version: STSv1\n\
                    mode: enforce\n\
                    mx: mail.example.com\n\
                    mx: *.mail.example.com\n\
                    max_age: 86400\n";
        let p = Policy::parse(text).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert_eq!(p.mx_patterns.len(), 2);
        assert_eq!(p.max_age, 86_400);
    }

    #[test]
    fn requires_version() {
        assert!(Policy::parse("mode: none\n").is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        let text = "version: STSv1\nmode: maybe\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let text = "version: STSv2\nmode: enforce\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn wildcard_matches_single_label() {
        let p = Policy::parse(
            "version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 1\n",
        )
        .unwrap();
        assert!(p.mx_matches("mx1.mail.example.com"));
        assert!(!p.mx_matches("a.b.mail.example.com"));
        assert!(!p.mx_matches("mail.example.com"));
    }

    #[test]
    fn literal_mx_matches_exact() {
        let p =
            Policy::parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 1\n")
                .unwrap();
        assert!(p.mx_matches("mx.example.com"));
        assert!(p.mx_matches("MX.EXAMPLE.COM"));
        assert!(!p.mx_matches("other.example.com"));
    }
}
