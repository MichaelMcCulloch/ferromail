pub mod destructive;
pub mod read;
pub mod write;

use crate::types::{FerromailError, Result, ToolTier};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    pub tool: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    pub success: bool,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ToolResponse {
    pub fn ok(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(msg.into()),
        }
    }
}

pub fn tier_for_tool(name: &str) -> Result<ToolTier> {
    match name {
        "list_accounts" | "list_emails" | "get_email_content" => Ok(ToolTier::Read),
        "send_email" | "reply_to_email" => Ok(ToolTier::Write),
        "delete_emails" | "download_attachment" => Ok(ToolTier::Destructive),
        _ => Err(FerromailError::InvalidArgument(format!(
            "Unknown tool: {name}"
        ))),
    }
}

pub async fn dispatch(request: &ToolRequest, ctx: &ToolContext) -> ToolResponse {
    let result = match request.tool.as_str() {
        "list_accounts" => read::list_accounts(ctx).await,
        "list_emails" => read::list_emails(&request.arguments, ctx).await,
        "get_email_content" => read::get_email_content(&request.arguments, ctx).await,
        "send_email" => write::send_email(&request.arguments, ctx).await,
        "reply_to_email" => write::reply_to_email(&request.arguments, ctx).await,
        "delete_emails" => destructive::delete_emails(&request.arguments, ctx).await,
        "download_attachment" => destructive::download_attachment(&request.arguments, ctx).await,
        _ => Err(FerromailError::InvalidArgument(format!(
            "Unknown tool: {}",
            request.tool
        ))),
    };

    match result {
        Ok(data) => ToolResponse::ok(data),
        Err(e) => ToolResponse::err(e.to_string()),
    }
}

pub struct ToolContext {
    pub config: tokio::sync::RwLock<crate::config::Config>,
    pub gate: crate::gate::ConfirmationGate,
    pub rate_limiter: std::sync::Arc<tokio::sync::Mutex<crate::rate_limit::RateLimiter>>,
    pub audit: std::sync::Arc<tokio::sync::Mutex<crate::audit::AuditLog>>,
    pub sandbox: crate::sandbox::DownloadSandbox,
    pub credentials: crate::credential::CredentialBackend,
    pub login_gate: crate::login_gate::LoginGate,
}

impl ToolContext {
    /// Attempt to log in via the shared LoginGate. On success, reset failure
    /// count. On failure, increment; if this trips the lockout threshold,
    /// disable the account in the persisted config and return a lockout error.
    pub async fn login_with_gate(
        &self,
        client: &mut crate::imap::ImapClient,
        account_name: &str,
        username: &str,
        password: &secrecy::SecretString,
        login_timeout: u64,
    ) -> Result<()> {
        self.login_gate.check_err(account_name)?;

        match client.login(username, password, login_timeout).await {
            Ok(()) => {
                self.login_gate.record_success(account_name);
                Ok(())
            }
            Err(e) => {
                let tripped = self.login_gate.record_failure(account_name);
                if tripped {
                    // Disable the account in-memory and on disk.
                    let mut cfg = self.config.write().await;
                    if let Some(acct) = cfg.accounts.iter_mut().find(|a| a.name == account_name) {
                        acct.enabled = false;
                    }
                    // Best-effort persist. If save fails (permissions, etc.),
                    // the in-memory disable is still in effect for this process.
                    if let Err(save_err) = cfg.save() {
                        tracing::warn!(
                            account = account_name,
                            error = %save_err,
                            "account locked out but config save failed"
                        );
                    }
                    Err(FerromailError::ConfigError(format!(
                        "Account '{account_name}' DISABLED after \
                         {} consecutive LOGIN failures. Underlying error: {e}. \
                         Re-enable with `ferromail account enable {account_name}`.",
                        crate::login_gate::MAX_CONSECUTIVE_FAILURES
                    )))
                } else {
                    Err(e)
                }
            }
        }
    }
}
