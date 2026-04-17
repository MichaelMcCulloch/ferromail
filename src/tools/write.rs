use crate::config::AccountConfig;
use crate::imap::{self, ImapClient};
use crate::sanitize::outbound;
use crate::smtp::SmtpSender;
use crate::tls::build_tls_config;
use crate::tools::ToolContext;
use crate::types::{AuditEntry, FerromailError, Result, ToolTier};
use serde_json::{Value, json};

pub async fn send_email(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = arg_str(args, "account")?;

    let to: Vec<String> = arg_string_vec(args, "to")?;
    let cc: Vec<String> = arg_string_vec_opt(args, "cc");
    let bcc: Vec<String> = arg_string_vec_opt(args, "bcc");
    let subject = arg_str(args, "subject")?;
    let body = arg_str(args, "body")?;
    let html = args.get("html").and_then(|v| v.as_bool()).unwrap_or(false);
    let attachments: Vec<String> = arg_string_vec_opt(args, "attachments");
    let in_reply_to = args.get("in_reply_to").and_then(|v| v.as_str());
    let references = args.get("references").and_then(|v| v.as_str());
    let requested_from = args.get("from").and_then(|v| v.as_str());

    let (account, rate_limits) = {
        let config = ctx.config.read().await;
        let account = find_account(&config.accounts, account_name)?.clone();
        (account, config.rate_limits.clone())
    };

    let from_email = resolve_from_address(&account, requested_from)?;

    {
        let mut limiter = ctx.rate_limiter.lock().await;
        limiter.check(account_name, "send_email", rate_limits.send_per_hour)?;
    }

    for att in &attachments {
        ctx.sandbox.validate_outbound_path(att)?;
    }

    let body_preview: String = body.chars().take(500).collect();
    let summary = format!(
        "Send email from {} to {}\nSubject: {}\nBody preview: {}\nAttachments: {}",
        from_email,
        to.join(", "),
        subject,
        body_preview,
        if attachments.is_empty() {
            "none".into()
        } else {
            attachments.join(", ")
        }
    );

    let confirmed_by = ctx
        .gate
        .request_confirmation("send_email", &summary, ToolTier::Write)
        .await?;

    let smtp_password = ctx
        .credentials
        .retrieve(&account.name, "smtp")
        .map_err(|e| {
            FerromailError::CredentialError(format!("Failed to retrieve SMTP credentials: {e}"))
        })?;

    let sender = SmtpSender::new(
        account.smtp.clone(),
        account.email_address.clone(),
        smtp_password,
    );

    let start = std::time::Instant::now();
    let result = sender
        .send(
            &account.full_name,
            &from_email,
            &to,
            &cc,
            &bcc,
            subject,
            body,
            html,
            &attachments,
            in_reply_to,
            references,
        )
        .await?;
    let latency = start.elapsed().as_millis() as u64;

    {
        let mut audit = ctx.audit.lock().await;
        let mut entry = AuditEntry::new("mail.send", account_name);
        entry.details = json!({
            "mail.recipient_addresses": to,
            "mail.recipient_count": to.len(),
            "mail.subject": subject,
        });
        entry.confirmed_by = Some(confirmed_by.as_str().into());
        entry.latency_ms = Some(latency);
        let _ = audit.log(&entry);
        crate::metrics::global()
            .tool_calls
            .with_label_values(&["send_email", "ok"])
            .inc();
    }

    serde_json::to_value(result)
        .map_err(|e| FerromailError::InvalidArgument(format!("Serialization error: {e}")))
}

pub async fn reply_to_email(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = arg_str(args, "account")?;
    let email_id = arg_str(args, "email_id")?;
    let mailbox = args
        .get("mailbox")
        .and_then(|v| v.as_str())
        .unwrap_or("INBOX");
    let body = arg_str(args, "body")?;
    let reply_all = args
        .get("reply_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let attachments: Vec<String> = arg_string_vec_opt(args, "attachments");
    let requested_from = args.get("from").and_then(|v| v.as_str());

    let (account, timeouts, limits, rate_limits) = {
        let config = ctx.config.read().await;
        let account = find_account(&config.accounts, account_name)?.clone();
        (
            account,
            config.timeouts.clone(),
            config.limits.clone(),
            config.rate_limits.clone(),
        )
    };

    {
        let mut limiter = ctx.rate_limiter.lock().await;
        limiter.check(account_name, "send_email", rate_limits.send_per_hour)?;
    }

    let imap_password = ctx
        .credentials
        .retrieve(&account.name, "imap")
        .map_err(|e| {
            FerromailError::CredentialError(format!("Failed to retrieve IMAP credentials: {e}"))
        })?;

    let tls_config = build_tls_config(account.imap.verify_certs, &account.imap.min_tls_version)?;
    let mut imap_client = ImapClient::connect(
        &account.imap.host,
        account.imap.port,
        account.imap.tls.clone(),
        tls_config,
        &timeouts,
    )
    .await?;

    let username = account.email_address.clone();
    ctx.login_with_gate(
        &mut imap_client,
        &account.name,
        &username,
        &imap_password,
        timeouts.login,
    )
    .await?;
    imap_client.select(mailbox).await?;

    let originals =
        imap::fetch::get_email_content(&mut imap_client, &[email_id.to_string()], mailbox, &limits)
            .await?;

    let original = originals
        .into_iter()
        .next()
        .ok_or_else(|| FerromailError::ImapError(format!("Email {email_id} not found")))?;

    let in_reply_to = original.message_id.clone();
    let references = if in_reply_to.is_empty() {
        String::new()
    } else {
        in_reply_to.clone()
    };

    let mut subject = original.subject.clone();
    if !subject.starts_with("Re:") && !subject.starts_with("re:") && !subject.starts_with("RE:") {
        subject = format!("Re: {subject}");
    }

    let mut to: Vec<String> = vec![original.sender.clone()];
    if reply_all {
        to.extend(original.recipients.iter().cloned());
    }

    let mut reply_args = json!({
        "account": account_name,
        "to": to,
        "subject": subject,
        "body": body,
        "html": false,
        "attachments": attachments,
        "in_reply_to": in_reply_to,
        "references": references,
    });
    if let Some(f) = requested_from {
        reply_args["from"] = Value::String(f.to_string());
    }

    send_email(&reply_args, ctx).await
}

fn find_account<'a>(accounts: &'a [AccountConfig], name: &str) -> Result<&'a AccountConfig> {
    let account = accounts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;
    if !account.enabled {
        return Err(FerromailError::AccountDisabled(name.into()));
    }
    Ok(account)
}

/// Resolve which From: address to stamp on an outgoing message.
///
/// Precedence:
/// 1. An explicit `requested` argument, if present. Must equal
///    `account.email_address` or appear in `account.send_as`.
/// 2. `account.default_from`, if configured. Validated the same way so
///    a typo in config fails fast instead of silently falling through.
/// 3. `account.email_address` as the final fallback.
fn resolve_from_address(account: &AccountConfig, requested: Option<&str>) -> Result<String> {
    if let Some(from) = requested {
        validate_from_allowed(account, from)?;
        return Ok(from.to_string());
    }
    if !account.default_from.is_empty() {
        validate_from_allowed(account, &account.default_from)?;
        return Ok(account.default_from.clone());
    }
    Ok(account.email_address.clone())
}

fn validate_from_allowed(account: &AccountConfig, from: &str) -> Result<()> {
    outbound::validate_email_address(from).map_err(FerromailError::InvalidArgument)?;
    if from.eq_ignore_ascii_case(&account.email_address) {
        return Ok(());
    }
    if account
        .send_as
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(from))
    {
        return Ok(());
    }
    Err(FerromailError::InvalidArgument(format!(
        "From address '{from}' is not permitted for account '{}'. \
         Add it to [[account]].send_as to allow.",
        account.name
    )))
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FerromailError::InvalidArgument(format!("Missing '{key}' parameter")))
}

fn arg_string_vec(args: &Value, key: &str) -> Result<Vec<String>> {
    args.get(key)
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .ok_or_else(|| FerromailError::InvalidArgument(format!("Missing '{key}' parameter")))
}

fn arg_string_vec_opt(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ImapConfig, SmtpConfig};

    fn account(email: &str, send_as: Vec<&str>, default_from: &str) -> AccountConfig {
        AccountConfig {
            name: "test".into(),
            email_address: email.into(),
            full_name: "T".into(),
            imap: ImapConfig::default(),
            smtp: SmtpConfig::default(),
            enabled: true,
            send_as: send_as.into_iter().map(String::from).collect(),
            default_from: default_from.into(),
            auth_method: crate::oauth::AuthMethod::Password,
            oauth: None,
        }
    }

    #[test]
    fn resolve_from_falls_back_to_email_address() {
        let a = account("user@example.com", vec![], "");
        assert_eq!(
            resolve_from_address(&a, None).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn resolve_from_uses_default_when_set() {
        let a = account("user@example.com", vec!["alias@example.com"], "alias@example.com");
        assert_eq!(
            resolve_from_address(&a, None).unwrap(),
            "alias@example.com"
        );
    }

    #[test]
    fn resolve_from_rejects_default_not_in_allowlist() {
        let a = account("user@example.com", vec![], "other@example.com");
        let err = resolve_from_address(&a, None).unwrap_err();
        assert!(matches!(err, FerromailError::InvalidArgument(_)));
    }

    #[test]
    fn resolve_from_accepts_explicit_alias() {
        let a = account("user@example.com", vec!["alias@example.com"], "");
        assert_eq!(
            resolve_from_address(&a, Some("alias@example.com")).unwrap(),
            "alias@example.com"
        );
    }

    #[test]
    fn resolve_from_accepts_canonical_even_when_not_in_send_as() {
        let a = account("user@example.com", vec!["alias@example.com"], "");
        assert_eq!(
            resolve_from_address(&a, Some("user@example.com")).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn resolve_from_rejects_unlisted_alias() {
        let a = account("user@example.com", vec!["alias@example.com"], "");
        let err = resolve_from_address(&a, Some("evil@example.com")).unwrap_err();
        assert!(matches!(err, FerromailError::InvalidArgument(_)));
    }

    #[test]
    fn resolve_from_is_case_insensitive() {
        let a = account("User@Example.com", vec!["Alias@Example.com"], "");
        assert!(resolve_from_address(&a, Some("user@example.com")).is_ok());
        assert!(resolve_from_address(&a, Some("ALIAS@example.com")).is_ok());
    }

    #[test]
    fn resolve_from_rejects_malformed_address() {
        let a = account("user@example.com", vec!["not-an-email"], "");
        let err = resolve_from_address(&a, Some("not-an-email")).unwrap_err();
        assert!(matches!(err, FerromailError::InvalidArgument(_)));
    }

    #[test]
    fn explicit_arg_overrides_default_from() {
        let a = account("user@example.com", vec!["alias@example.com"], "alias@example.com");
        assert_eq!(
            resolve_from_address(&a, Some("user@example.com")).unwrap(),
            "user@example.com"
        );
    }
}
