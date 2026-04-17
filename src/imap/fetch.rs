use chrono::{DateTime, Utc};

use crate::config::LimitsConfig;
use crate::email_auth::{self, InboundAuthConfig};
use crate::sanitize::{body::sanitize_body, header::sanitize_header, isolation, spoof::SpoofSignals};
use crate::types::{
    AttachmentInfo, EmailContent, EmailFlags, EmailMetadata, EmailMetadataPage, FlagFilter, Result,
    SortOrder,
};

use super::ImapClient;

/// Default time window applied to list_emails when no explicit date filter
/// is given. Without this, an unfiltered mailbox with hundreds of thousands
/// of messages would try to stream every UID into memory — even though
/// SEARCH results are just integers, the round-trip and sort cost are real.
/// Ninety days matches typical "recent email" agent expectations; callers
/// that need older mail pass an explicit `since`.
const DEFAULT_SEARCH_WINDOW_DAYS: i64 = 90;

#[allow(clippy::too_many_arguments)]
pub async fn list_emails(
    client: &mut ImapClient,
    _mailbox: &str,
    page: u32,
    page_size: u32,
    since: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    from: Option<&str>,
    subject: Option<&str>,
    flags: Option<&FlagFilter>,
    order: &SortOrder,
    _limits: &LimitsConfig,
) -> Result<EmailMetadataPage> {
    let page_size = page_size.clamp(1, 50);
    let page = page.max(1);

    // If the caller didn't narrow the time range at all, implicitly window
    // to the last DEFAULT_SEARCH_WINDOW_DAYS days. Passing any other filter
    // (from, subject, flags, before) leaves `since` as-is so the caller can
    // still sweep a mailbox with `since=1970-01-01T00:00:00Z` if they really
    // want the whole history.
    let effective_since = match (since, before, from, subject, flags) {
        (None, None, None, None, None) => {
            Some(Utc::now() - chrono::Duration::days(DEFAULT_SEARCH_WINDOW_DAYS))
        }
        _ => since,
    };

    let search_query = build_search_query(effective_since, before, from, subject, flags);
    let mut sorted_uids = client.uid_search(&search_query).await?;

    match order {
        SortOrder::Desc => sorted_uids.sort_unstable_by(|a, b| b.cmp(a)),
        SortOrder::Asc => sorted_uids.sort_unstable(),
    }

    let total = sorted_uids.len() as u32;
    let start = ((page - 1) * page_size) as usize;

    if start >= sorted_uids.len() {
        return Ok(EmailMetadataPage {
            emails: Vec::new(),
            page,
            page_size,
            total,
        });
    }

    let end = (start + page_size as usize).min(sorted_uids.len());
    let page_uids = &sorted_uids[start..end];

    if page_uids.is_empty() {
        return Ok(EmailMetadataPage {
            emails: Vec::new(),
            page,
            page_size,
            total,
        });
    }

    let uid_range = page_uids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let fetches = client
        .uid_fetch(&uid_range, "(UID FLAGS ENVELOPE BODYSTRUCTURE)")
        .await?;

    let mut emails = Vec::with_capacity(fetches.len());

    for fetch in &fetches {
        let uid = match fetch.uid {
            Some(uid) => uid,
            None => continue,
        };

        let mut email_flags = EmailFlags::default();
        for flag in fetch.flags() {
            match flag {
                async_imap::types::Flag::Seen => email_flags.seen = true,
                async_imap::types::Flag::Flagged => email_flags.flagged = true,
                async_imap::types::Flag::Answered => email_flags.answered = true,
                _ => {}
            }
        }

        let (subject_str, sender_str, recipients, date) = match fetch.envelope() {
            Some(env) => {
                let subj = decode_mime_header(env.subject.as_deref().unwrap_or_default());

                let from = env
                    .from
                    .as_ref()
                    .and_then(|addrs| addrs.first())
                    .map(format_imap_address)
                    .unwrap_or_default();

                let to: Vec<String> = env
                    .to
                    .as_ref()
                    .map(|addrs| addrs.iter().map(format_imap_address).collect())
                    .unwrap_or_default();

                let date_str = env
                    .date
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
                    .unwrap_or_default();
                let date = super::validate::validate_date(&date_str);

                (subj, from, to, date)
            }
            None => (
                String::new(),
                String::new(),
                Vec::new(),
                DateTime::UNIX_EPOCH,
            ),
        };

        emails.push(EmailMetadata {
            email_id: uid.to_string(),
            subject: subject_str,
            sender: sender_str,
            recipients,
            date,
            attachment_names: Vec::new(),
            flags: email_flags,
        });
    }

    Ok(EmailMetadataPage {
        emails,
        page,
        page_size,
        total,
    })
}

/// Decode an RFC 2047 "encoded-word" header value (e.g.
/// `=?utf-8?Q?=E2=99=A5?=`) into plain UTF-8. Bytes that are already
/// valid UTF-8 and contain no encoded-words pass through unchanged.
fn decode_mime_header(raw: &[u8]) -> String {
    let as_str = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return String::from_utf8_lossy(raw).into_owned(),
    };
    if !as_str.contains("=?") {
        return as_str.to_string();
    }
    rfc2047_decoder::decode(as_str.as_bytes()).unwrap_or_else(|_| as_str.to_string())
}

pub async fn get_email_content(
    client: &mut ImapClient,
    email_ids: &[String],
    _mailbox: &str,
    limits: &LimitsConfig,
) -> Result<Vec<EmailContent>> {
    let clamped_ids = if email_ids.len() > 10 {
        &email_ids[..10]
    } else {
        email_ids
    };

    if clamped_ids.is_empty() {
        return Ok(Vec::new());
    }

    let uid_range = clamped_ids.join(",");

    let fetches = client
        .uid_fetch(&uid_range, "(UID FLAGS ENVELOPE BODY[])")
        .await?;

    let mut results = Vec::with_capacity(fetches.len());

    for fetch in &fetches {
        let uid = match fetch.uid {
            Some(uid) => uid,
            None => continue,
        };

        let raw_body = match fetch.body() {
            Some(body) => body,
            None => continue,
        };

        if raw_body.len() as u64 > limits.max_message_size {
            tracing::warn!(
                uid = uid,
                size = raw_body.len(),
                "message exceeds max_message_size, skipping"
            );
            continue;
        }

        let parsed = crate::mime_parse::parse_email(
            raw_body,
            limits.max_mime_depth as usize,
            limits.max_mime_parts as usize,
            limits.max_message_size as usize,
        )?;

        let (subject_str, sender_str, recipients, date, message_id) = match fetch.envelope() {
            Some(env) => {
                let subj = decode_mime_header(env.subject.as_deref().unwrap_or_default());

                let from = env
                    .from
                    .as_ref()
                    .and_then(|addrs| addrs.first())
                    .map(format_imap_address)
                    .unwrap_or_default();

                let to: Vec<String> = env
                    .to
                    .as_ref()
                    .map(|addrs| addrs.iter().map(format_imap_address).collect())
                    .unwrap_or_default();

                let date_str = env
                    .date
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
                    .unwrap_or_default();
                let date = super::validate::validate_date(&date_str);

                let mid = env
                    .message_id
                    .as_ref()
                    .map(|m| String::from_utf8_lossy(m).into_owned())
                    .unwrap_or_default();

                (subj, from, to, date, mid)
            }
            None => (
                String::new(),
                String::new(),
                Vec::new(),
                DateTime::UNIX_EPOCH,
                String::new(),
            ),
        };

        let raw_body_text = parsed.text_body.clone().or(parsed.html_body.clone()).unwrap_or_default();
        let body_content_type = if parsed.html_body.is_some() && parsed.text_body.is_none() {
            "text/html"
        } else {
            "text/plain"
        };

        let body_truncated = truncate_body(&raw_body_text, limits.max_body_length);

        let attachment_metadata: Vec<AttachmentInfo> = parsed
            .attachments
            .iter()
            .map(|att| AttachmentInfo {
                index: att.index,
                name: att
                    .filename
                    .clone()
                    .unwrap_or_else(|| format!("attachment_{}", att.index)),
                size: att.size,
                mime_type: att.mime_type.clone(),
            })
            .collect();

        let email_id = uid.to_string();

        // Trust signals: authentication + spoof heuristics.
        let auth = email_auth::verify_inbound(raw_body, &InboundAuthConfig::default()).await;
        let spoof = SpoofSignals::from_sender(&sender_str);

        // Build the per-field XML envelope. Every string the LLM sees is
        // run through the sanitize pipeline (which handles NFC, bidi
        // strips, and `<ferromail:` escape) before wrapping.
        let sanitized_envelope = build_envelope(
            &email_id,
            &message_id,
            &subject_str,
            &sender_str,
            &recipients,
            date,
            &body_truncated,
            body_content_type,
            &attachment_metadata,
            parsed.mime_truncated,
            &auth,
            &spoof,
            limits.max_body_length,
        );

        results.push(EmailContent {
            email_id,
            message_id,
            subject: subject_str,
            sender: sender_str,
            recipients,
            date,
            body: body_truncated,
            attachment_metadata,
            mime_truncated: parsed.mime_truncated,
            sanitized_envelope,
            auth,
            spoof,
        });
    }

    Ok(results)
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    email_id: &str,
    message_id: &str,
    subject: &str,
    sender: &str,
    recipients: &[String],
    date: DateTime<Utc>,
    body_text: &str,
    body_content_type: &str,
    attachments: &[AttachmentInfo],
    mime_truncated: bool,
    auth: &crate::email_auth::AuthResults,
    spoof: &crate::sanitize::spoof::SpoofSignals,
    max_body_length: usize,
) -> String {
    let mut inner = String::new();

    // Per-field tags. The sanitize_header pipeline applies NFC/bidi/control
    // stripping + XML escape, so these are safe to concatenate.
    inner.push_str(&sanitize_header(subject, "Subject", email_id));
    inner.push_str(&sanitize_header(sender, "From", email_id));
    for to in recipients {
        inner.push_str(&sanitize_header(to, "To", email_id));
    }
    inner.push_str(&isolation::wrap_field("Date", &date.to_rfc3339()));
    if !message_id.is_empty() {
        inner.push_str(&isolation::wrap_field("Message-ID", message_id));
    }

    // Auth + spoof tags so the LLM sees trust state before it reads the body.
    inner.push_str(&isolation::wrap_auth(
        auth.upstream.as_deref(),
        auth.dkim_local.as_deref(),
        auth.arc_local.as_deref(),
        auth.trusted,
    ));
    inner.push_str(&isolation::wrap_spoof_signals(
        spoof.display_name_embeds_address.as_deref(),
        spoof.confusable_domain.as_deref(),
        spoof.invisible_chars_in_domain,
        spoof.suspicious,
    ));

    // Attachments (name is already sanitized by the downstream filename
    // pipeline when they're written; here we wrap for the envelope only).
    for att in attachments {
        inner.push_str(&isolation::wrap_attachment(
            att.index,
            &att.name,
            att.size,
            &att.mime_type,
        ));
    }
    if mime_truncated {
        inner.push_str("<ferromail:mime-truncated />");
    }

    // Body — last, since it's the largest and most dangerous field.
    inner.push_str(&sanitize_body(
        body_text.as_bytes(),
        body_content_type,
        None,
        max_body_length,
        email_id,
    ));

    isolation::wrap_untrusted(&inner, email_id)
}

fn build_search_query(
    since: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    from: Option<&str>,
    subject: Option<&str>,
    flags: Option<&FlagFilter>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(since) = since {
        parts.push(format!("SINCE {}", since.format("%d-%b-%Y")));
    }
    if let Some(before) = before {
        parts.push(format!("BEFORE {}", before.format("%d-%b-%Y")));
    }
    if let Some(from) = from {
        let sanitized = sanitize_search_param(from);
        parts.push(format!("FROM {sanitized}"));
    }
    if let Some(subject) = subject {
        let sanitized = sanitize_search_param(subject);
        parts.push(format!("SUBJECT {sanitized}"));
    }
    if let Some(flags) = flags {
        if let Some(true) = flags.seen {
            parts.push("SEEN".into());
        } else if let Some(false) = flags.seen {
            parts.push("UNSEEN".into());
        }
        if let Some(true) = flags.flagged {
            parts.push("FLAGGED".into());
        } else if let Some(false) = flags.flagged {
            parts.push("UNFLAGGED".into());
        }
        if let Some(true) = flags.answered {
            parts.push("ANSWERED".into());
        } else if let Some(false) = flags.answered {
            parts.push("UNANSWERED".into());
        }
    }

    if parts.is_empty() {
        "ALL".into()
    } else {
        parts.join(" ")
    }
}

fn sanitize_search_param(value: &str) -> String {
    let cleaned: String = value.chars().filter(|&c| c != '"').collect();
    if cleaned.contains(' ') {
        format!("\"{}\"", cleaned)
    } else {
        cleaned
    }
}

fn format_imap_address(addr: &imap_proto::types::Address) -> String {
    let mailbox = addr
        .mailbox
        .as_ref()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    let host = addr
        .host
        .as_ref()
        .map(|h| String::from_utf8_lossy(h).into_owned())
        .unwrap_or_default();

    let email = if !mailbox.is_empty() && !host.is_empty() {
        format!("{mailbox}@{host}")
    } else {
        mailbox
    };

    match &addr.name {
        Some(name) => {
            let display = decode_mime_header(name);
            if display.is_empty() {
                email
            } else {
                format!("{display} <{email}>")
            }
        }
        None => email,
    }
}

fn truncate_body(body: &str, max_length: usize) -> String {
    if body.len() <= max_length {
        return body.to_string();
    }

    let mut end = max_length;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = body[..end].to_string();
    truncated.push_str(&format!(
        "\n[TRUNCATED at {max_length} bytes. Full message available in email client.]"
    ));
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_query_all() {
        let q = build_search_query(None, None, None, None, None);
        assert_eq!(q, "ALL");
    }

    #[test]
    fn search_query_since() {
        let dt = DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let q = build_search_query(Some(dt), None, None, None, None);
        assert!(q.contains("SINCE 01-Apr-2026"));
    }

    #[test]
    fn search_query_from_with_spaces() {
        let q = build_search_query(None, None, Some("John Doe"), None, None);
        assert_eq!(q, "FROM \"John Doe\"");
    }

    #[test]
    fn search_query_subject_strips_quotes() {
        let q = build_search_query(None, None, None, Some("hello \"world\""), None);
        assert_eq!(q, "SUBJECT \"hello world\"");
    }

    #[test]
    fn search_query_flags() {
        let flags = FlagFilter {
            seen: Some(true),
            flagged: Some(false),
            answered: None,
        };
        let q = build_search_query(None, None, None, None, Some(&flags));
        assert!(q.contains("SEEN"));
        assert!(q.contains("UNFLAGGED"));
        assert!(!q.contains("ANSWERED"));
    }

    #[test]
    fn sanitize_removes_quotes() {
        assert_eq!(sanitize_search_param("hello\"world"), "helloworld");
    }

    #[test]
    fn sanitize_wraps_spaces() {
        assert_eq!(sanitize_search_param("hello world"), "\"hello world\"");
    }

    #[test]
    fn sanitize_no_spaces() {
        assert_eq!(sanitize_search_param("hello"), "hello");
    }

    #[test]
    fn truncate_short_body() {
        let body = "short text";
        assert_eq!(truncate_body(body, 100), "short text");
    }

    #[test]
    fn truncate_long_body() {
        let body = "a".repeat(100);
        let result = truncate_body(&body, 50);
        assert!(result.contains("[TRUNCATED at 50 bytes"));
        assert!(result.starts_with(&"a".repeat(50)));
    }

    #[test]
    fn truncate_respects_utf8_boundaries() {
        let body = "aaa\u{1F600}bbb"; // emoji is 4 bytes
        let result = truncate_body(body, 5);
        assert!(result.starts_with("aaa"));
        assert!(result.contains("[TRUNCATED"));
    }

    #[test]
    fn format_address_basic() {
        let addr = imap_proto::types::Address {
            name: None,
            adl: None,
            mailbox: Some(b"user"[..].into()),
            host: Some(b"example.com"[..].into()),
        };
        assert_eq!(format_imap_address(&addr), "user@example.com");
    }

    #[test]
    fn format_address_with_name() {
        let addr = imap_proto::types::Address {
            name: Some(b"Test User"[..].into()),
            adl: None,
            mailbox: Some(b"test"[..].into()),
            host: Some(b"example.com"[..].into()),
        };
        assert_eq!(format_imap_address(&addr), "Test User <test@example.com>");
    }
}
