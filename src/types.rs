use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedAccount {
    pub account_name: String,
    pub email_address: String,
    pub imap_host: String,
    pub smtp_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    Desc,
    Asc,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlagFilter {
    pub seen: Option<bool>,
    pub flagged: Option<bool>,
    pub answered: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMetadata {
    pub email_id: String,
    pub subject: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub date: DateTime<Utc>,
    pub attachment_names: Vec<String>,
    pub flags: EmailFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailFlags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMetadataPage {
    pub emails: Vec<EmailMetadata>,
    pub page: u32,
    pub page_size: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailContent {
    pub email_id: String,
    pub message_id: String,
    pub subject: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub date: DateTime<Utc>,
    pub body: String,
    pub attachment_metadata: Vec<AttachmentInfo>,
    pub mime_truncated: bool,
    /// Full `<ferromail:untrusted>...</ferromail:untrusted>` XML envelope
    /// with every field sanitized and isolation-tag-escaped. This is what
    /// the LLM should read; the structured fields above are for filtering
    /// and UI use.
    pub sanitized_envelope: String,
    /// Authentication-Results / DKIM verification summary. `trusted` is
    /// true only if both upstream AR and local DKIM re-verify agree.
    #[serde(default)]
    pub auth: crate::email_auth::AuthResults,
    /// Sender-spoofing heuristics on the From header.
    #[serde(default)]
    pub spoof: crate::sanitize::spoof::SpoofSignals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub index: u32,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub message_id: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    pub deleted_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentResult {
    pub saved_to: String,
    pub display_name: String,
    pub size: u64,
    pub mime_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolTier {
    Read,
    Write,
    Destructive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConfirmation {
    pub id: String,
    pub operation: String,
    pub summary: String,
    pub expires_at: DateTime<Utc>,
    pub tier: ToolTier,
}

/// Audit entry formatted against OpenTelemetry semantic conventions for
/// log events. Fields are named to match the OTEL log data model so a
/// downstream collector can ingest this without transformation:
///
/// - `timestamp` = ISO-8601 UTC (OTEL `Timestamp`)
/// - `event.name`, `event.domain` (OTEL log semantic conventions)
/// - `service.name` / `service.version` (resource attributes)
/// - `user.id` (enduser.id equivalent for the account operator)
/// - `server.address`, `server.port` (when the op talks to a mail server)
/// - `mail.*` (custom domain for mail-specific fields; aligns with the
///   OTEL proposal for messaging systems)
///
/// Kept as a single struct rather than `event_attributes: Value` so the
/// audit file has a predictable shape for grep/jq.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// OTEL timestamp. Retained as `ts` for backward compat with the
    /// existing log file; the serialisation key is preserved.
    pub ts: DateTime<Utc>,

    /// OTEL `event.name` — one of the ferromail operation identifiers:
    /// `mail.send`, `mail.reply`, `mail.delete`, `mail.download`,
    /// `mail.fetch`, `auth.login`, `auth.token_refresh`,
    /// `gate.approved`, `gate.denied`, `policy.denied`.
    #[serde(rename = "event.name")]
    pub event_name: String,

    /// OTEL `event.domain` — always "mail" for ferromail events.
    #[serde(rename = "event.domain", default = "default_event_domain")]
    pub event_domain: String,

    /// Legacy `op` field, populated with the same value as `event.name`
    /// for tools that still key on it.
    pub op: String,

    /// The ferromail account name (not the email address).
    pub account: String,

    /// OTEL `user.id` — the account's email address.
    #[serde(rename = "user.id", default, skip_serializing_if = "String::is_empty")]
    pub user_id: String,

    /// OTEL `service.name` — always "ferromail".
    #[serde(rename = "service.name", default = "default_service_name")]
    pub service_name: String,

    /// OTEL `service.version` — populated from CARGO_PKG_VERSION.
    #[serde(rename = "service.version", default = "default_service_version")]
    pub service_version: String,

    /// OTEL `server.address` — mail server hostname for network ops.
    #[serde(rename = "server.address", default, skip_serializing_if = "String::is_empty")]
    pub server_address: String,

    /// OTEL `server.port`.
    #[serde(rename = "server.port", default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Operation-specific structured attributes. Keys should use OTEL
    /// dotted notation (e.g. `mail.recipient_count`,
    /// `mail.attachment_bytes`).
    #[serde(flatten)]
    pub details: serde_json::Value,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

fn default_event_domain() -> String {
    "mail".into()
}

fn default_service_name() -> String {
    "ferromail".into()
}

fn default_service_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

impl AuditEntry {
    /// Construct with the OTEL resource fields auto-populated. Callers
    /// only provide the operation-specific data.
    pub fn new(event_name: impl Into<String>, account: impl Into<String>) -> Self {
        let event_name = event_name.into();
        Self {
            ts: Utc::now(),
            op: event_name.clone(),
            event_name,
            event_domain: default_event_domain(),
            account: account.into(),
            user_id: String::new(),
            service_name: default_service_name(),
            service_version: default_service_version(),
            server_address: String::new(),
            server_port: None,
            details: serde_json::Value::Null,
            confirmed_by: None,
            denied: None,
            reason: None,
            latency_ms: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FerromailError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Account disabled: {0}")]
    AccountDisabled(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Rate limit exceeded: retry after {retry_after_seconds}s")]
    RateLimitExceeded { retry_after_seconds: u64 },

    #[error("Operation denied by user")]
    OperationDenied,

    #[error("Operation expired (confirmation timeout)")]
    OperationExpired,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("IMAP error: {0}")]
    ImapError(String),

    #[error("SMTP error: {0}")]
    SmtpError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Sandbox violation: {0}")]
    SandboxViolation(String),

    #[error("MIME parsing error: {0}")]
    MimeError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Path escape attempt: {attempted_path} does not start with {sandbox_dir}")]
    PathEscape {
        attempted_path: String,
        sandbox_dir: String,
    },

    #[error(
        "Extension '.{0}' is not in the allowed list. Configure [attachments].allowed_extensions to add it."
    )]
    DisallowedExtension(String),

    #[error("Attachment size {size} exceeds maximum {max}")]
    AttachmentTooLarge { size: u64, max: u64 },

    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("Transport error: {0}")]
    TransportError(String),
}

impl fmt::Display for ToolTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolTier::Read => write!(f, "read"),
            ToolTier::Write => write!(f, "write"),
            ToolTier::Destructive => write!(f, "destructive"),
        }
    }
}

pub type Result<T> = std::result::Result<T, FerromailError>;
