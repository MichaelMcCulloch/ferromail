// env::set_var / env::remove_var are unsafe in Edition 2024 because they are
// not thread-safe across libc boundaries. The only uses here are on the main
// thread during startup (applying and wiping FERROMAIL_* overrides) and in
// single-threaded unit tests. Keep the audit narrow by scoping the allow to
// this file rather than crate-wide.
#![allow(unsafe_code)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::types::FerromailError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum TlsMode {
    #[default]
    Required,
    StarttlsUnsafe,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub transport_type: String,
    pub host: String,
    pub port: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: "stdio".into(),
            host: "127.0.0.1".into(),
            port: 9557,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AttachmentsConfig {
    pub download_dir: String,
    pub max_file_size: u64,
    pub allowed_extensions: Vec<String>,
    pub send_allow_dirs: Vec<String>,
}

impl Default for AttachmentsConfig {
    fn default() -> Self {
        Self {
            download_dir: "~/Downloads/ferromail".into(),
            max_file_size: 52_428_800,
            allowed_extensions: vec![
                "pdf", "docx", "xlsx", "pptx", "csv", "txt", "rtf", "png", "jpg", "jpeg", "gif",
                "webp", "svg", "zip", "gz", "tar", "7z", "eml", "msg", "json", "xml", "yaml",
                "toml", "mp3", "mp4", "wav",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
            send_allow_dirs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_body_length: usize,
    pub max_emails_per_list: u32,
    pub max_email_ids_per_content: u32,
    pub max_email_ids_per_delete: u32,
    pub max_attachment_count: u32,
    pub max_mime_depth: u32,
    pub max_mime_parts: u32,
    pub max_message_size: u64,
    pub max_imap_response_size: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_length: 32_768,
            max_emails_per_list: 50,
            max_email_ids_per_content: 10,
            max_email_ids_per_delete: 20,
            max_attachment_count: 50,
            max_mime_depth: 10,
            max_mime_parts: 100,
            max_message_size: 26_214_400,
            max_imap_response_size: 104_857_600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutsConfig {
    pub connect: u64,
    pub tls_handshake: u64,
    pub login: u64,
    pub metadata_fetch: u64,
    pub body_fetch: u64,
    pub attachment_download: u64,
    pub smtp_send: u64,
    pub idle: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            connect: 15,
            tls_handshake: 15,
            login: 30,
            metadata_fetch: 30,
            body_fetch: 60,
            attachment_download: 120,
            smtp_send: 120,
            idle: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitsConfig {
    pub send_per_hour: u32,
    pub delete_per_hour: u32,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            send_per_hour: 20,
            delete_per_hour: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfirmationConfig {
    pub channel: String,
    pub webhook_url: String,
    pub timeout_seconds: u64,
    pub destructive_cooldown_seconds: u64,
}

impl Default for ConfirmationConfig {
    fn default() -> Self {
        Self {
            // "none" delegates approval to the MCP client (Claude Desktop,
            // Claude Code, etc.) which already surfaces a per-tool approval
            // UI. Users running ferromail as a standalone CLI or under an
            // MCP client without its own approval UI should switch to
            // "terminal" or "webhook" in config.toml.
            channel: "none".into(),
            webhook_url: String::new(),
            timeout_seconds: 120,
            destructive_cooldown_seconds: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub audit_file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "logfmt".into(),
            audit_file: "audit.jsonl".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialsConfig {
    pub backend: String,
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            backend: "keyring".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ImapConfig {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub verify_certs: bool,
    pub min_tls_version: String,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 993,
            tls: TlsMode::Required,
            verify_certs: true,
            min_tls_version: "1.2".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub verify_certs: bool,
    pub min_tls_version: String,
    pub save_to_sent: bool,
    pub sent_folder: String,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 465,
            tls: TlsMode::Required,
            verify_certs: true,
            min_tls_version: "1.2".into(),
            save_to_sent: true,
            sent_folder: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    pub name: String,
    pub email_address: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub imap: ImapConfig,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Additional From: addresses this account is allowed to send as
    /// (aliases, custom-domain addresses). `email_address` is always
    /// allowed implicitly. SMTP still authenticates as the canonical
    /// username — the provider is the final authority on whether the
    /// From: is accepted.
    #[serde(default)]
    pub send_as: Vec<String>,
    /// Default From: address to use when a send_email call does not
    /// specify one. If empty, falls back to `email_address`. If non-empty,
    /// must equal `email_address` or appear in `send_as`.
    #[serde(default)]
    pub default_from: String,
    /// Authentication method — password (default), XOAUTH2, or
    /// OAUTHBEARER. When non-password, the credential backend must hold a
    /// valid access token (and optionally a refresh token) under the OAuth
    /// keys.
    #[serde(default)]
    pub auth_method: crate::oauth::AuthMethod,
    /// OAuth provider configuration. Required only when `auth_method` is
    /// XOAUTH2 or OAUTHBEARER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<crate::oauth::OAuthConfig>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub transport: TransportConfig,
    pub attachments: AttachmentsConfig,
    pub limits: LimitsConfig,
    pub timeouts: TimeoutsConfig,
    pub rate_limits: RateLimitsConfig,
    pub confirmation: ConfirmationConfig,
    pub logging: LoggingConfig,
    pub credentials: CredentialsConfig,
    #[serde(rename = "account")]
    pub accounts: Vec<AccountConfig>,
}

pub struct EnvAccount {
    pub name: String,
    pub email_address: String,
    pub full_name: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_username: String,
    pub imap_password: String,
    pub imap_tls: TlsMode,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_tls: TlsMode,
}

fn take_env(key: &str) -> Option<String> {
    let val = std::env::var(key).ok()?;
    // Overwrite the value bytes in-place before removing
    if let Ok(mut raw) = std::env::var(key) {
        unsafe {
            raw.as_bytes_mut().zeroize();
        }
    }
    // SAFETY: remove_var is unsafe in edition 2024 due to thread-safety
    // concerns. We call it during single-threaded startup only, before
    // the tokio runtime is created. The security benefit (clearing
    // credentials from the process environment block) is required by spec.
    unsafe {
        std::env::remove_var(key);
    }
    Some(val)
}

fn parse_tls_mode(s: &str) -> Result<TlsMode, FerromailError> {
    match s {
        "required" => Ok(TlsMode::Required),
        "starttls-unsafe" => Ok(TlsMode::StarttlsUnsafe),
        "none" => Ok(TlsMode::None),
        other => Err(FerromailError::ConfigError(format!(
            "invalid TLS mode '{other}': expected 'required', 'starttls-unsafe', or 'none'"
        ))),
    }
}

pub fn read_env_account() -> Result<Option<EnvAccount>, FerromailError> {
    let email_address = match take_env("FERROMAIL_EMAIL_ADDRESS") {
        Some(v) => v,
        None => return Ok(None),
    };

    let name = take_env("FERROMAIL_ACCOUNT_NAME").unwrap_or_else(|| "default".into());

    let full_name = take_env("FERROMAIL_FULL_NAME").unwrap_or_else(|| {
        email_address
            .split('@')
            .next()
            .unwrap_or(&email_address)
            .to_string()
    });

    let imap_host = take_env("FERROMAIL_IMAP_HOST").ok_or_else(|| {
        FerromailError::ConfigError(
            "FERROMAIL_IMAP_HOST is required when FERROMAIL_EMAIL_ADDRESS is set".into(),
        )
    })?;

    let imap_port = take_env("FERROMAIL_IMAP_PORT")
        .map(|v| {
            v.parse::<u16>().map_err(|_| {
                FerromailError::ConfigError(format!(
                    "FERROMAIL_IMAP_PORT '{v}' is not a valid port"
                ))
            })
        })
        .transpose()?
        .unwrap_or(993);

    let imap_username =
        take_env("FERROMAIL_IMAP_USERNAME").unwrap_or_else(|| email_address.clone());

    let imap_password = take_env("FERROMAIL_IMAP_PASSWORD").ok_or_else(|| {
        FerromailError::ConfigError(
            "FERROMAIL_IMAP_PASSWORD is required when FERROMAIL_EMAIL_ADDRESS is set".into(),
        )
    })?;

    let imap_tls = take_env("FERROMAIL_IMAP_TLS")
        .map(|v| parse_tls_mode(&v))
        .transpose()?
        .unwrap_or(TlsMode::Required);

    let smtp_host = take_env("FERROMAIL_SMTP_HOST").ok_or_else(|| {
        FerromailError::ConfigError(
            "FERROMAIL_SMTP_HOST is required when FERROMAIL_EMAIL_ADDRESS is set".into(),
        )
    })?;

    let smtp_port = take_env("FERROMAIL_SMTP_PORT")
        .map(|v| {
            v.parse::<u16>().map_err(|_| {
                FerromailError::ConfigError(format!(
                    "FERROMAIL_SMTP_PORT '{v}' is not a valid port"
                ))
            })
        })
        .transpose()?
        .unwrap_or(465);

    let smtp_username =
        take_env("FERROMAIL_SMTP_USERNAME").unwrap_or_else(|| email_address.clone());

    let smtp_password = take_env("FERROMAIL_SMTP_PASSWORD").ok_or_else(|| {
        FerromailError::ConfigError(
            "FERROMAIL_SMTP_PASSWORD is required when FERROMAIL_EMAIL_ADDRESS is set".into(),
        )
    })?;

    let smtp_tls = take_env("FERROMAIL_SMTP_TLS")
        .map(|v| parse_tls_mode(&v))
        .transpose()?
        .unwrap_or(TlsMode::Required);

    Ok(Some(EnvAccount {
        name,
        email_address,
        full_name,
        imap_host,
        imap_port,
        imap_username,
        imap_password,
        imap_tls,
        smtp_host,
        smtp_port,
        smtp_username,
        smtp_password,
        smtp_tls,
    }))
}

fn check_permissions(path: &Path, expected_label: &str) -> Result<(), FerromailError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| FerromailError::ConfigError(format!("cannot stat {}: {e}", path.display())))?;

    let mode = metadata.mode();
    let world_group_bits = mode & 0o077;

    if world_group_bits != 0 {
        let fix_mode = if metadata.is_dir() { "700" } else { "600" };
        return Err(FerromailError::ConfigError(format!(
            "{expected_label} {} has mode {:04o} — group/world bits are set. \
             Run: chmod {fix_mode} {}",
            path.display(),
            mode & 0o7777,
            path.display(),
        )));
    }

    Ok(())
}

impl Config {
    pub fn config_dir() -> Result<PathBuf, FerromailError> {
        match std::env::var("FERROMAIL_CONFIG") {
            Ok(val) if !val.is_empty() => Ok(PathBuf::from(val)),
            _ => {
                let home = dirs::config_dir().ok_or_else(|| {
                    FerromailError::ConfigError(
                        "cannot determine config directory: no home directory found".into(),
                    )
                })?;
                Ok(home.join("ferromail"))
            }
        }
    }

    pub fn save(&self) -> Result<(), FerromailError> {
        let config_dir = Self::config_dir()?;
        let config_file = config_dir.join("config.toml");
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| FerromailError::ConfigError(format!("Serialization error: {e}")))?;
        std::fs::write(&config_file, toml_str)?;
        Ok(())
    }

    pub fn load() -> Result<Self, FerromailError> {
        let config_dir = Self::config_dir()?;
        let config_file = config_dir.join("config.toml");

        let config = if config_file.exists() {
            check_permissions(&config_dir, "config directory")?;
            check_permissions(&config_file, "config file")?;

            let contents = std::fs::read_to_string(&config_file).map_err(|e| {
                FerromailError::ConfigError(format!("cannot read {}: {e}", config_file.display()))
            })?;

            toml::from_str::<Config>(&contents).map_err(|e| {
                FerromailError::ConfigError(format!("cannot parse {}: {e}", config_file.display()))
            })?
        } else {
            Config::default()
        };

        Ok(config)
    }

    /// Apply any `FERROMAIL_*` environment-variable overrides to `self`.
    /// Credentials extracted from the environment are returned separately so
    /// the caller can seed them into the credential backend's ephemeral
    /// overlay (they MUST NOT be persisted). The env variables are zeroed
    /// and unset inside `read_env_account`.
    pub fn apply_env_overrides(&mut self) -> Result<Option<EnvCredentials>, FerromailError> {
        let Some(env_account) = read_env_env_account_inner()? else {
            return Ok(None);
        };

        let account = AccountConfig {
            name: env_account.name.clone(),
            email_address: env_account.email_address.clone(),
            full_name: env_account.full_name.clone(),
            imap: ImapConfig {
                host: env_account.imap_host.clone(),
                port: env_account.imap_port,
                tls: env_account.imap_tls.clone(),
                verify_certs: true,
                min_tls_version: "1.2".into(),
            },
            smtp: SmtpConfig {
                host: env_account.smtp_host.clone(),
                port: env_account.smtp_port,
                tls: env_account.smtp_tls.clone(),
                verify_certs: true,
                min_tls_version: "1.2".into(),
                save_to_sent: true,
                sent_folder: String::new(),
            },
            enabled: true,
            send_as: Vec::new(),
            default_from: String::new(),
            auth_method: crate::oauth::AuthMethod::Password,
            oauth: None,
        };

        if let Some(pos) = self.accounts.iter().position(|a| a.name == account.name) {
            self.accounts[pos] = account;
        } else {
            self.accounts.push(account);
        }

        Ok(Some(EnvCredentials {
            account_name: env_account.name,
            imap_password: env_account.imap_password,
            smtp_password: env_account.smtp_password,
        }))
    }
}

/// Credentials extracted from `FERROMAIL_*` environment variables, ready to
/// be handed to the credential backend's ephemeral overlay.
pub struct EnvCredentials {
    pub account_name: String,
    pub imap_password: String,
    pub smtp_password: String,
}

impl Drop for EnvCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.imap_password.zeroize();
        self.smtp_password.zeroize();
    }
}

fn read_env_env_account_inner() -> Result<Option<EnvAccount>, FerromailError> {
    read_env_account()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();

        assert_eq!(c.transport.transport_type, "stdio");
        assert_eq!(c.transport.host, "127.0.0.1");
        assert_eq!(c.transport.port, 9557);

        assert_eq!(c.attachments.download_dir, "~/Downloads/ferromail");
        assert_eq!(c.attachments.max_file_size, 52_428_800);
        assert!(c.attachments.allowed_extensions.contains(&"pdf".into()));
        assert!(c.attachments.allowed_extensions.contains(&"wav".into()));
        assert!(c.attachments.send_allow_dirs.is_empty());

        assert_eq!(c.limits.max_body_length, 32_768);
        assert_eq!(c.limits.max_emails_per_list, 50);
        assert_eq!(c.limits.max_email_ids_per_content, 10);
        assert_eq!(c.limits.max_email_ids_per_delete, 20);
        assert_eq!(c.limits.max_attachment_count, 50);
        assert_eq!(c.limits.max_mime_depth, 10);
        assert_eq!(c.limits.max_mime_parts, 100);
        assert_eq!(c.limits.max_message_size, 26_214_400);
        assert_eq!(c.limits.max_imap_response_size, 104_857_600);

        assert_eq!(c.timeouts.connect, 15);
        assert_eq!(c.timeouts.tls_handshake, 15);
        assert_eq!(c.timeouts.login, 30);
        assert_eq!(c.timeouts.metadata_fetch, 30);
        assert_eq!(c.timeouts.body_fetch, 60);
        assert_eq!(c.timeouts.attachment_download, 120);
        assert_eq!(c.timeouts.smtp_send, 120);
        assert_eq!(c.timeouts.idle, 300);

        assert_eq!(c.rate_limits.send_per_hour, 20);
        assert_eq!(c.rate_limits.delete_per_hour, 100);

        assert_eq!(c.confirmation.channel, "none");
        assert_eq!(c.confirmation.webhook_url, "");
        assert_eq!(c.confirmation.timeout_seconds, 120);
        assert_eq!(c.confirmation.destructive_cooldown_seconds, 3);

        assert_eq!(c.logging.level, "info");
        assert_eq!(c.logging.format, "logfmt");
        assert_eq!(c.logging.audit_file, "audit.jsonl");

        assert_eq!(c.credentials.backend, "keyring");

        assert!(c.accounts.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
[transport]
type = "sse"
host = "0.0.0.0"
port = 8080

[attachments]
download_dir = "/tmp/attachments"
max_file_size = 1000
allowed_extensions = ["pdf"]
send_allow_dirs = ["/home/user/docs"]

[limits]
max_body_length = 100
max_emails_per_list = 10
max_email_ids_per_content = 5
max_email_ids_per_delete = 5
max_attachment_count = 10
max_mime_depth = 3
max_mime_parts = 20
max_message_size = 1000
max_imap_response_size = 5000

[timeouts]
connect = 5
tls_handshake = 5
login = 10
metadata_fetch = 10
body_fetch = 20
attachment_download = 30
smtp_send = 30
idle = 60

[rate_limits]
send_per_hour = 5
delete_per_hour = 10

[confirmation]
channel = "webhook"
webhook_url = "https://example.com/hook"
timeout_seconds = 60
destructive_cooldown_seconds = 5

[logging]
level = "debug"
format = "json"
audit_file = "custom-audit.jsonl"

[credentials]
backend = "age-file"

[[account]]
name = "work"
email_address = "user@example.com"
full_name = "Test User"
enabled = true

[account.imap]
host = "imap.example.com"
port = 993
tls = "required"
verify_certs = true
min_tls_version = "1.3"

[account.smtp]
host = "smtp.example.com"
port = 465
tls = "required"
verify_certs = true
min_tls_version = "1.3"
save_to_sent = false
sent_folder = "Sent Items"

[[account]]
name = "personal"
email_address = "me@home.org"
full_name = "Me"
enabled = false

[account.imap]
host = "imap.home.org"
port = 143
tls = "starttls-unsafe"
verify_certs = false
min_tls_version = "1.2"

[account.smtp]
host = "smtp.home.org"
port = 587
tls = "starttls-unsafe"
verify_certs = false
min_tls_version = "1.2"
"#;

        let config: Config = toml::from_str(toml_str).expect("should parse");

        assert_eq!(config.transport.transport_type, "sse");
        assert_eq!(config.transport.port, 8080);
        assert_eq!(config.attachments.download_dir, "/tmp/attachments");
        assert_eq!(config.limits.max_body_length, 100);
        assert_eq!(config.timeouts.connect, 5);
        assert_eq!(config.rate_limits.send_per_hour, 5);
        assert_eq!(config.confirmation.channel, "webhook");
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.credentials.backend, "age-file");

        assert_eq!(config.accounts.len(), 2);

        let work = &config.accounts[0];
        assert_eq!(work.name, "work");
        assert_eq!(work.email_address, "user@example.com");
        assert_eq!(work.imap.host, "imap.example.com");
        assert_eq!(work.imap.tls, TlsMode::Required);
        assert_eq!(work.smtp.min_tls_version, "1.3");
        assert!(!work.smtp.save_to_sent);
        assert_eq!(work.smtp.sent_folder, "Sent Items");
        assert!(work.enabled);

        let personal = &config.accounts[1];
        assert_eq!(personal.name, "personal");
        assert_eq!(personal.imap.tls, TlsMode::StarttlsUnsafe);
        assert!(!personal.imap.verify_certs);
        assert!(!personal.enabled);
    }

    #[test]
    fn tls_mode_none_deserializes() {
        let toml_str = r#"
[[account]]
name = "local"
email_address = "dev@localhost"

[account.imap]
host = "127.0.0.1"
port = 143
tls = "none"

[account.smtp]
host = "127.0.0.1"
port = 25
tls = "none"
"#;
        let config: Config = toml::from_str(toml_str).expect("should parse");
        assert_eq!(config.accounts[0].imap.tls, TlsMode::None);
        assert_eq!(config.accounts[0].smtp.tls, TlsMode::None);
    }

    #[test]
    fn permission_check_rejects_group_readable_file() {
        let dir = TempDir::new().expect("tempdir");
        let file = dir.path().join("config.toml");
        fs::write(&file, "").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");

        let err = check_permissions(&file, "config file").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("chmod 600"),
            "error should suggest chmod 600: {msg}"
        );
    }

    #[test]
    fn permission_check_rejects_group_accessible_dir() {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");

        let err = check_permissions(dir.path(), "config directory").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("chmod 700"),
            "error should suggest chmod 700: {msg}"
        );
    }

    #[test]
    fn permission_check_accepts_correct_perms() {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");

        let file = dir.path().join("config.toml");
        fs::write(&file, "").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");

        check_permissions(dir.path(), "config directory").expect("dir ok");
        check_permissions(&file, "config file").expect("file ok");
    }

    #[test]
    fn load_returns_default_when_no_file() {
        let dir = TempDir::new().expect("tempdir");
        unsafe {
            std::env::set_var("FERROMAIL_CONFIG", dir.path().as_os_str());
        }
        let config = Config::load().expect("should load defaults");
        assert!(config.accounts.is_empty());
        assert_eq!(config.transport.transport_type, "stdio");
        unsafe {
            std::env::remove_var("FERROMAIL_CONFIG");
        }
    }

    #[test]
    fn load_rejects_bad_perms() {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod dir");

        let file = dir.path().join("config.toml");
        fs::write(&file, "[transport]\ntype = \"stdio\"\n").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod file");

        unsafe {
            std::env::set_var("FERROMAIL_CONFIG", dir.path().as_os_str());
        }
        let err = Config::load().unwrap_err();
        assert!(err.to_string().contains("chmod 600"));
        unsafe {
            std::env::remove_var("FERROMAIL_CONFIG");
        }
    }

    #[test]
    fn partial_config_fills_defaults() {
        let toml_str = r#"
[logging]
level = "trace"
"#;
        let config: Config = toml::from_str(toml_str).expect("should parse");
        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.logging.format, "logfmt");
        assert_eq!(config.transport.transport_type, "stdio");
        assert_eq!(config.limits.max_body_length, 32_768);
    }

    #[test]
    fn parse_tls_mode_valid() {
        assert_eq!(parse_tls_mode("required").unwrap(), TlsMode::Required);
        assert_eq!(
            parse_tls_mode("starttls-unsafe").unwrap(),
            TlsMode::StarttlsUnsafe
        );
        assert_eq!(parse_tls_mode("none").unwrap(), TlsMode::None);
    }

    #[test]
    fn parse_tls_mode_invalid() {
        let err = parse_tls_mode("tls").unwrap_err();
        assert!(err.to_string().contains("invalid TLS mode"));
    }

    #[test]
    fn account_enabled_defaults_true() {
        let toml_str = r#"
[[account]]
name = "test"
email_address = "t@t.com"
"#;
        let config: Config = toml::from_str(toml_str).expect("should parse");
        assert!(config.accounts[0].enabled);
    }

    #[test]
    fn read_env_account_unsets_vars() {
        unsafe {
            std::env::set_var("FERROMAIL_EMAIL_ADDRESS", "envtest@example.com");
            std::env::set_var("FERROMAIL_IMAP_HOST", "imap.example.com");
            std::env::set_var("FERROMAIL_IMAP_PASSWORD", "secret-imap");
            std::env::set_var("FERROMAIL_SMTP_HOST", "smtp.example.com");
            std::env::set_var("FERROMAIL_SMTP_PASSWORD", "secret-smtp");
        }

        let account = read_env_account()
            .expect("env parse succeeds")
            .expect("some account");

        assert_eq!(account.email_address, "envtest@example.com");
        assert_eq!(account.imap_host, "imap.example.com");
        assert_eq!(account.imap_password, "secret-imap");
        assert_eq!(account.smtp_host, "smtp.example.com");
        assert_eq!(account.smtp_password, "secret-smtp");

        // After read, env vars must be unset so subprocesses and /proc do
        // not carry credentials.
        for key in [
            "FERROMAIL_EMAIL_ADDRESS",
            "FERROMAIL_IMAP_HOST",
            "FERROMAIL_IMAP_PASSWORD",
            "FERROMAIL_SMTP_HOST",
            "FERROMAIL_SMTP_PASSWORD",
        ] {
            assert!(
                std::env::var(key).is_err(),
                "env var {key} still set after read_env_account"
            );
        }
    }

    #[test]
    fn read_env_account_returns_none_when_unset() {
        // Ensure clean state.
        unsafe {
            std::env::remove_var("FERROMAIL_EMAIL_ADDRESS");
        }
        let account = read_env_account().expect("ok");
        assert!(account.is_none());
    }
}
