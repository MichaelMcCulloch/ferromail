use crate::config::AccountConfig;
use crate::imap::{self, ImapClient};
use crate::tls::build_tls_config;
use crate::tools::ToolContext;
use crate::types::{FerromailError, FlagFilter, MaskedAccount, Result, SortOrder};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub async fn list_accounts(ctx: &ToolContext) -> Result<Value> {
    let config = ctx.config.read().await;
    let accounts: Vec<MaskedAccount> = config
        .accounts
        .iter()
        .map(|a| MaskedAccount {
            account_name: a.name.clone(),
            email_address: a.email_address.clone(),
            imap_host: a.imap.host.clone(),
            smtp_host: a.smtp.host.clone(),
        })
        .collect();

    serde_json::to_value(accounts)
        .map_err(|e| FerromailError::InvalidArgument(format!("Serialization error: {e}")))
}

pub async fn list_emails(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = args
        .get("account")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FerromailError::InvalidArgument("Missing 'account' parameter".into()))?;

    let mailbox = args
        .get("mailbox")
        .and_then(|v| v.as_str())
        .unwrap_or("INBOX");
    let page = args.get("page").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
    let page_size = args.get("page_size").and_then(|v| v.as_u64()).unwrap_or(20) as u32;
    let page_size = page_size.clamp(1, 50);

    let since: Option<DateTime<Utc>> = args
        .get("since")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());
    let before: Option<DateTime<Utc>> = args
        .get("before")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());
    let from = args.get("from").and_then(|v| v.as_str());
    let subject = args.get("subject").and_then(|v| v.as_str());

    let flags: Option<FlagFilter> = args
        .get("flags")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let order: SortOrder = args
        .get("order")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let (account, timeouts, limits) = {
        let config = ctx.config.read().await;
        let account = find_account(&config.accounts, account_name)?.clone();
        (account, config.timeouts.clone(), config.limits.clone())
    };

    let password = ctx
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
        &password,
        timeouts.login,
    )
    .await?;
    client.select(mailbox).await?;

    let result = imap::fetch::list_emails(
        &mut client,
        mailbox,
        page,
        page_size,
        since,
        before,
        from,
        subject,
        flags.as_ref(),
        &order,
        &limits,
    )
    .await?;

    serde_json::to_value(result)
        .map_err(|e| FerromailError::InvalidArgument(format!("Serialization error: {e}")))
}

pub async fn get_email_content(args: &Value, ctx: &ToolContext) -> Result<Value> {
    let account_name = args
        .get("account")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FerromailError::InvalidArgument("Missing 'account' parameter".into()))?;

    let mailbox = args
        .get("mailbox")
        .and_then(|v| v.as_str())
        .unwrap_or("INBOX");

    let email_ids: Vec<String> = args
        .get("email_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| FerromailError::InvalidArgument("Missing 'email_ids' parameter".into()))?;

    if email_ids.is_empty() || email_ids.len() > 10 {
        return Err(FerromailError::InvalidArgument(
            "email_ids must contain 1 to 10 IDs".into(),
        ));
    }

    let (account, timeouts, limits) = {
        let config = ctx.config.read().await;
        let account = find_account(&config.accounts, account_name)?.clone();
        (account, config.timeouts.clone(), config.limits.clone())
    };

    let password = ctx
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
        &password,
        timeouts.login,
    )
    .await?;
    client.select(mailbox).await?;

    let result = imap::fetch::get_email_content(&mut client, &email_ids, mailbox, &limits).await?;

    serde_json::to_value(result)
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
