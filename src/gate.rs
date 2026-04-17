use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::time::Duration;

use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::types::{FerromailError, Result, ToolTier};

pub enum ConfirmationChannel {
    Terminal {
        cooldown_seconds: u64,
    },
    /// Webhook-based confirmation. `url` receives a POST containing the
    /// operation summary; the response body is parsed as
    /// `{"approve": bool, "reason": Option<String>}`. HTTP 200 with
    /// `approve=true` is approval; anything else is denial.
    Webhook {
        url: String,
        cooldown_seconds: u64,
        timeout_seconds: u64,
    },
    /// Trust the calling MCP client (Claude Desktop, Claude Code, etc.) to
    /// surface per-tool approval in its own UI before invoking the tool.
    /// Ferromail performs no additional gating, logs the operation as
    /// `confirmed_by = "client"`, and still applies the destructive-tier
    /// cooldown as a rate-limiting backstop.
    ///
    /// Use this only when the transport is stdio under an MCP client that
    /// has its own approval UX. The trust boundary becomes the client; a
    /// client that auto-approves without user review gives the agent a
    /// free pass.
    None {
        cooldown_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmedBy {
    Terminal,
    Webhook,
    Client,
}

impl ConfirmedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmedBy::Terminal => "terminal",
            ConfirmedBy::Webhook => "webhook",
            ConfirmedBy::Client => "client",
        }
    }
}

pub struct ConfirmationGate {
    channel: ConfirmationChannel,
}

impl ConfirmationGate {
    pub fn new(channel: ConfirmationChannel) -> Self {
        Self { channel }
    }

    pub async fn request_confirmation(
        &self,
        operation: &str,
        summary: &str,
        tier: ToolTier,
    ) -> Result<ConfirmedBy> {
        match &self.channel {
            ConfirmationChannel::Terminal { cooldown_seconds } => {
                self.confirm_terminal(operation, summary, tier, *cooldown_seconds)
                    .await?;
                Ok(ConfirmedBy::Terminal)
            }
            ConfirmationChannel::Webhook {
                url,
                cooldown_seconds,
                timeout_seconds,
            } => {
                self.confirm_webhook(
                    operation,
                    summary,
                    tier,
                    url,
                    *cooldown_seconds,
                    *timeout_seconds,
                )
                .await?;
                Ok(ConfirmedBy::Webhook)
            }
            ConfirmationChannel::None { cooldown_seconds } => {
                // No ferromail-level gate. Log that we're relying on the
                // MCP client for approval, still apply the destructive-tier
                // cooldown so an auto-approving client can't burst.
                tracing::info!(
                    operation = operation,
                    tier = %tier,
                    channel = "none",
                    "confirmation delegated to MCP client"
                );
                self.apply_cooldown(tier, *cooldown_seconds).await;
                Ok(ConfirmedBy::Client)
            }
        }
    }

    async fn confirm_terminal(
        &self,
        operation: &str,
        summary: &str,
        tier: ToolTier,
        cooldown_seconds: u64,
    ) -> Result<()> {
        if !std::io::stderr().is_terminal() {
            return Err(FerromailError::CredentialError(
                "Interactive confirmation required but stderr is not a TTY".into(),
            ));
        }

        // Scope the stderr lock so it's released before the first .await.
        // ReentrantLockGuard is !Send, which would otherwise make the whole
        // future !Send and break axum handler bounds.
        {
            let mut stderr = std::io::stderr().lock();
            write!(
                stderr,
                "\n--- Confirmation Required ({tier}) ---\n\
                 Operation: {operation}\n\
                 Summary:   {summary}\n\
                 Approve? [y/N]: "
            )?;
            stderr.flush()?;
        }

        let approved = tokio::time::timeout(
            Duration::from_secs(120),
            tokio::task::spawn_blocking(|| -> Result<bool> {
                // Read from /dev/tty so we don't consume the MCP channel on stdin.
                let tty = std::fs::OpenOptions::new()
                    .read(true)
                    .open("/dev/tty")
                    .map_err(|e| {
                        FerromailError::CredentialError(format!("cannot open /dev/tty: {e}"))
                    })?;
                let mut reader = BufReader::new(tty);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line.trim().eq_ignore_ascii_case("y"))
            }),
        )
        .await
        .map_err(|_| FerromailError::OperationExpired)?
        .map_err(|e| FerromailError::Io(std::io::Error::other(e)))??;

        if !approved {
            return Err(FerromailError::OperationDenied);
        }

        self.apply_cooldown(tier, cooldown_seconds).await;
        Ok(())
    }

    async fn confirm_webhook(
        &self,
        operation: &str,
        summary: &str,
        tier: ToolTier,
        url: &str,
        cooldown_seconds: u64,
        timeout_seconds: u64,
    ) -> Result<()> {
        #[derive(Deserialize)]
        struct ApprovalResponse {
            approve: bool,
            #[allow(dead_code)]
            reason: Option<String>,
        }

        let client = HttpClient::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|e| {
                FerromailError::ConfigError(format!("failed to build webhook client: {e}"))
            })?;

        let body = json!({
            "operation": operation,
            "summary": summary,
            "tier": tier.to_string(),
        });

        let response = tokio::time::timeout(
            Duration::from_secs(timeout_seconds),
            client.post(url).json(&body).send(),
        )
        .await
        .map_err(|_| FerromailError::OperationExpired)?
        .map_err(|e| FerromailError::ConfigError(format!("webhook POST failed: {e}")))?;

        if !response.status().is_success() {
            warn!(
                status = %response.status(),
                "Webhook returned non-success status — treating as denial"
            );
            return Err(FerromailError::OperationDenied);
        }

        let body: ApprovalResponse = response
            .json()
            .await
            .map_err(|e| FerromailError::ConfigError(format!("webhook response parse: {e}")))?;

        if !body.approve {
            return Err(FerromailError::OperationDenied);
        }

        self.apply_cooldown(tier, cooldown_seconds).await;
        Ok(())
    }

    async fn apply_cooldown(&self, tier: ToolTier, cooldown_seconds: u64) {
        if tier == ToolTier::Destructive && cooldown_seconds > 0 {
            {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "Cooldown: waiting {cooldown_seconds}s before executing..."
                );
                let _ = stderr.flush();
            }
            tokio::time::sleep(Duration::from_secs(cooldown_seconds)).await;
        }
    }
}
