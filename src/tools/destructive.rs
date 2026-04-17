use crate::config::AccountConfig;
use crate::imap::{self, ImapClient};
use crate::sanitize::filename::sanitize_filename;
use crate::tls::build_tls_config;
use crate::tools::ToolContext;
use crate::types::{AuditEntry, FerromailError, Result, ToolTier};
use serde_json::{Value, json};

pub async fn delete_emails(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = arg_str(args, "account")?;
    let mailbox = args
        .get("mailbox")
        .and_then(|v| v.as_str())
        .unwrap_or("INBOX");

    let email_ids: Vec<String> = args
        .get("email_ids")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .ok_or_else(|| FerromailError::InvalidArgument("Missing 'email_ids' parameter".into()))?;

    if email_ids.is_empty() || email_ids.len() > 20 {
        return Err(FerromailError::InvalidArgument(
            "email_ids must contain 1 to 20 IDs".into(),
        ));
    }

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
        limiter.check(account_name, "delete_emails", rate_limits.delete_per_hour)?;
    }

    let imap_password = ctx
        .credentials
        .retrieve(&account.name, "imap")
        .map_err(|e| {
            FerromailError::CredentialError(format!("Failed to retrieve IMAP credentials: {e}"))
        })?;

    let tls_config = build_tls_config(account.imap.verify_certs, &account.imap.min_tls_version)?;
    let mut client = ImapClient::connect(
        &account.imap.host,
        account.imap.port,
        account.imap.tls.clone(),
        tls_config,
        &timeouts,
    )
    .await?;

    let username = account.email_address.clone();
    ctx.login_with_gate(
        &mut client,
        &account.name,
        &username,
        &imap_password,
        timeouts.login,
    )
    .await?;
    client.select(mailbox).await?;

    let contents =
        imap::fetch::get_email_content(&mut client, &email_ids, mailbox, &limits).await?;

    let subjects: Vec<String> = contents.iter().map(|c| c.subject.clone()).collect();
    let summary = format!(
        "Delete {} email(s):\n{}",
        email_ids.len(),
        subjects
            .iter()
            .enumerate()
            .map(|(i, s)| format!("  {}. {}", i + 1, s))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let confirmed_by = ctx
        .gate
        .request_confirmation("delete_emails", &summary, ToolTier::Destructive)
        .await?;

    let uid_set = email_ids.join(",");
    client.store_flags(&uid_set, "+FLAGS (\\Deleted)").await?;
    client.expunge().await?;

    {
        let mut audit = ctx.audit.lock().await;
        let mut entry = AuditEntry::new("mail.delete", account_name);
        entry.details = json!({
            "mail.email_ids": email_ids,
            "mail.delete_count": email_ids.len(),
        });
        entry.confirmed_by = Some(confirmed_by.as_str().into());
        let _ = audit.log(&entry);
        crate::metrics::global()
            .tool_calls
            .with_label_values(&["delete_emails", "ok"])
            .inc();
    }

    serde_json::to_value(crate::types::DeleteResult {
        deleted_ids: email_ids,
    })
    .map_err(|e| FerromailError::InvalidArgument(format!("Serialization error: {e}")))
}

pub async fn download_attachment(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = arg_str(args, "account")?;
    let email_id = arg_str(args, "email_id")?;
    let attachment_index = args
        .get("attachment_index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            FerromailError::InvalidArgument("Missing 'attachment_index' parameter".into())
        })? as u32;
    let mailbox = args
        .get("mailbox")
        .and_then(|v| v.as_str())
        .unwrap_or("INBOX");

    let (account, timeouts, limits) = {
        let config = ctx.config.read().await;
        let account = find_account(&config.accounts, account_name)?.clone();
        (account, config.timeouts.clone(), config.limits.clone())
    };

    let imap_password = ctx
        .credentials
        .retrieve(&account.name, "imap")
        .map_err(|e| {
            FerromailError::CredentialError(format!("Failed to retrieve IMAP credentials: {e}"))
        })?;

    let tls_config = build_tls_config(account.imap.verify_certs, &account.imap.min_tls_version)?;
    let mut client = ImapClient::connect(
        &account.imap.host,
        account.imap.port,
        account.imap.tls.clone(),
        tls_config,
        &timeouts,
    )
    .await?;

    let username = account.email_address.clone();
    ctx.login_with_gate(
        &mut client,
        &account.name,
        &username,
        &imap_password,
        timeouts.login,
    )
    .await?;
    client.select(mailbox).await?;

    let raw_email = client.fetch_raw(email_id).await?;
    let parse_result = crate::mime_parse::parse_email(
        &raw_email,
        limits.max_mime_depth as usize,
        limits.max_mime_parts as usize,
        limits.max_message_size as usize,
    )?;

    let attachment = parse_result
        .attachments
        .into_iter()
        .find(|a| a.index == attachment_index)
        .ok_or_else(|| {
            FerromailError::InvalidArgument(format!(
                "Attachment index {attachment_index} not found"
            ))
        })?;

    let display_name = sanitize_filename(
        attachment.filename.as_deref().unwrap_or(""),
        attachment_index,
    );

    let dest_path = ctx.sandbox.download_path(email_id, &display_name)?;

    let summary = format!(
        "Download attachment from email {email_id}\n\
         Name: {display_name}\n\
         MIME type: {}\n\
         Size: {} bytes\n\
         Destination: {}",
        attachment.mime_type,
        attachment.size,
        dest_path.display()
    );

    let confirmed_by = ctx
        .gate
        .request_confirmation("download_attachment", &summary, ToolTier::Destructive)
        .await?;

    ctx.sandbox.write_file(&dest_path, &attachment.data).await?;

    {
        let mut audit = ctx.audit.lock().await;
        let mut entry = AuditEntry::new("mail.download", account_name);
        entry.details = json!({
            "mail.email_id": email_id,
            "mail.attachment_name": display_name,
            "mail.attachment_bytes": attachment.size,
            "file.path": dest_path.display().to_string(),
        });
        entry.confirmed_by = Some(confirmed_by.as_str().into());
        let _ = audit.log(&entry);
        crate::metrics::global()
            .tool_calls
            .with_label_values(&["download_attachment", "ok"])
            .inc();
    }

    serde_json::to_value(crate::types::AttachmentResult {
        saved_to: dest_path.display().to_string(),
        display_name,
        size: attachment.size,
        mime_type: attachment.mime_type,
    })
    .map_err(|e| FerromailError::InvalidArgument(format!("Serialization error: {e}")))
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

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FerromailError::InvalidArgument(format!("Missing '{key}' parameter")))
}
