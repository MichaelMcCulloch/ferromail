//! OAuth 2.0 support for XOAUTH2 / OAUTHBEARER SASL on IMAP and SMTP.
//!
//! Gmail and Microsoft 365 both require OAuth for unattended IMAP/SMTP
//! access; app passwords are being phased out. This module handles the
//! *device-code* flow (RFC 8628) — the right fit for a CLI that can't open
//! a browser but can print a URL and wait.
//!
//! Tokens live inside the same credential backend as passwords (keyring or
//! age-file), under the keys
//!   `{account}/{service}/oauth:access`
//!   `{account}/{service}/oauth:refresh`
//!   `{account}/{service}/oauth:expires`
//! where `{service}` is `imap` or `smtp`. We refresh *in place* shortly
//! before expiry so callers that ask for a password/token transparently
//! get a fresh one.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, RefreshToken, Scope,
    StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::types::{FerromailError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    #[default]
    Password,
    /// XOAUTH2 SASL mechanism (RFC 7628). Supported by Gmail, Microsoft
    /// 365, Yahoo. Our default for OAuth providers.
    Xoauth2,
    /// OAUTHBEARER SASL mechanism (RFC 7628). Newer; some servers prefer
    /// it. Semantically identical for our purposes.
    OAuthBearer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthProvider {
    #[default]
    Gmail,
    Microsoft,
    /// Anything else: the user supplies endpoint URLs and client IDs in
    /// config.
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub provider: OAuthProvider,
    pub client_id: String,
    /// Many public-client OAuth providers (Gmail desktop app, Microsoft
    /// public clients) accept an empty secret; leave blank in that case.
    #[serde(default)]
    pub client_secret: String,
    /// Overrides for Custom provider; unused for Gmail/Microsoft.
    #[serde(default)]
    pub auth_url: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub device_auth_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    pub fn endpoints(&self) -> (String, String, String, Vec<String>) {
        match self.provider {
            OAuthProvider::Gmail => (
                "https://accounts.google.com/o/oauth2/auth".into(),
                "https://oauth2.googleapis.com/token".into(),
                "https://oauth2.googleapis.com/device/code".into(),
                vec!["https://mail.google.com/".into()],
            ),
            OAuthProvider::Microsoft => (
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
                "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".into(),
                vec![
                    "https://outlook.office.com/IMAP.AccessAsUser.All".into(),
                    "https://outlook.office.com/SMTP.Send".into(),
                    "offline_access".into(),
                ],
            ),
            OAuthProvider::Custom => (
                self.auth_url.clone(),
                self.token_url.clone(),
                self.device_auth_url.clone(),
                self.scopes.clone(),
            ),
        }
    }
}

/// Access + refresh + expiry triple held for one (account, service) pair.
#[derive(Debug)]
pub struct TokenPair {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
    pub expires_at: Option<SystemTime>,
}

impl TokenPair {
    pub fn is_expired(&self, leeway: Duration) -> bool {
        match self.expires_at {
            Some(t) => SystemTime::now() + leeway >= t,
            None => false,
        }
    }
}

fn make_http_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| FerromailError::TlsError(format!("oauth http client: {e}")))
}

/// Kick off the device-code flow. Prints user-facing instructions on
/// stderr and polls until the user has finished authorising, then returns
/// the access+refresh pair.
pub async fn device_flow(cfg: &OAuthConfig) -> Result<TokenPair> {
    let (auth_s, token_s, device_s, scopes) = cfg.endpoints();
    let auth_url = AuthUrl::new(auth_s)
        .map_err(|e| FerromailError::ConfigError(format!("auth_url invalid: {e}")))?;
    let token_url = TokenUrl::new(token_s)
        .map_err(|e| FerromailError::ConfigError(format!("token_url invalid: {e}")))?;
    let device_url = DeviceAuthorizationUrl::new(device_s)
        .map_err(|e| FerromailError::ConfigError(format!("device_auth_url invalid: {e}")))?;

    let mut client = BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_device_authorization_url(device_url);
    if !cfg.client_secret.is_empty() {
        client = client.set_client_secret(ClientSecret::new(cfg.client_secret.clone()));
    }

    let http_client = make_http_client(30)?;

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scopes(scopes.into_iter().map(Scope::new))
        .request_async(&http_client)
        .await
        .map_err(|e| FerromailError::ConfigError(format!("device auth request: {e}")))?;

    eprintln!();
    eprintln!("========================================================");
    eprintln!("Open this URL in a browser:");
    eprintln!("  {}", details.verification_uri().as_str());
    eprintln!("And enter the code:");
    eprintln!("  {}", details.user_code().secret());
    eprintln!("========================================================");
    eprintln!();
    eprintln!(
        "Waiting for authorisation (up to {}s)...",
        details.expires_in().as_secs()
    );

    let token_response = client
        .exchange_device_access_token(&details)
        .request_async(&http_client, tokio::time::sleep, None)
        .await
        .map_err(|e| FerromailError::ConfigError(format!("device token exchange: {e}")))?;

    let expires_at = token_response.expires_in().map(|d| SystemTime::now() + d);

    Ok(TokenPair {
        access: SecretString::new(
            token_response
                .access_token()
                .secret()
                .clone()
                .into_boxed_str(),
        ),
        refresh: token_response
            .refresh_token()
            .map(|r| SecretString::new(r.secret().clone().into_boxed_str())),
        expires_at,
    })
}

/// Exchange a refresh token for a fresh access token.
pub async fn refresh(cfg: &OAuthConfig, refresh_token: &SecretString) -> Result<TokenPair> {
    let (auth_s, token_s, _device_s, _scopes) = cfg.endpoints();
    let auth_url = AuthUrl::new(auth_s)
        .map_err(|e| FerromailError::ConfigError(format!("auth_url invalid: {e}")))?;
    let token_url = TokenUrl::new(token_s)
        .map_err(|e| FerromailError::ConfigError(format!("token_url invalid: {e}")))?;

    let mut client = BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url);
    if !cfg.client_secret.is_empty() {
        client = client.set_client_secret(ClientSecret::new(cfg.client_secret.clone()));
    }

    let http_client = make_http_client(15)?;

    let response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.expose_secret().to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| FerromailError::ConfigError(format!("refresh token exchange: {e}")))?;

    let expires_at = response.expires_in().map(|d| SystemTime::now() + d);
    let new_refresh = response
        .refresh_token()
        .map(|r| SecretString::new(r.secret().clone().into_boxed_str()))
        .or_else(|| Some(refresh_token.clone()));

    Ok(TokenPair {
        access: SecretString::new(response.access_token().secret().clone().into_boxed_str()),
        refresh: new_refresh,
        expires_at,
    })
}

/// Build the base64-encoded XOAUTH2 SASL initial response for the given
/// user + access token. The format is defined in
/// https://developers.google.com/gmail/imap/xoauth2-protocol.
pub fn xoauth2_sasl_initial(user: &str, access_token: &SecretString) -> String {
    let raw = format!("user={user}\x01auth=Bearer {}\x01\x01", access_token.expose_secret());
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

/// OAUTHBEARER is identical modulo the literal string "Bearer" vs
/// "OAUTHBEARER" in the mechanism name. The payload is the same.
pub fn oauthbearer_sasl_initial(user: &str, access_token: &SecretString) -> String {
    xoauth2_sasl_initial(user, access_token)
}

/// Serializable form of [`TokenPair`] for persisting in the credential
/// backend as a single JSON value.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StoredTokenPair {
    pub access: String,
    pub refresh: Option<String>,
    /// Seconds since UNIX epoch.
    pub expires_unix: Option<u64>,
}

impl StoredTokenPair {
    pub fn from_pair(pair: &TokenPair) -> Self {
        Self {
            access: pair.access.expose_secret().to_string(),
            refresh: pair.refresh.as_ref().map(|r| r.expose_secret().to_string()),
            expires_unix: pair
                .expires_at
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
        }
    }

    pub fn to_pair(&self) -> TokenPair {
        TokenPair {
            access: SecretString::new(self.access.clone().into_boxed_str()),
            refresh: self
                .refresh
                .as_ref()
                .map(|r| SecretString::new(r.clone().into_boxed_str())),
            expires_at: self
                .expires_unix
                .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xoauth2_format_matches_spec() {
        let token = SecretString::new("vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==".to_string().into_boxed_str());
        let encoded = xoauth2_sasl_initial("someuser@example.com", &token);
        // Decode and verify the inner structure.
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        assert!(s.starts_with("user=someuser@example.com\x01auth=Bearer "));
        assert!(s.ends_with("\x01\x01"));
    }

    #[test]
    fn stored_roundtrip() {
        let p = TokenPair {
            access: SecretString::new("at".to_string().into_boxed_str()),
            refresh: Some(SecretString::new("rt".to_string().into_boxed_str())),
            expires_at: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        };
        let stored = StoredTokenPair::from_pair(&p);
        let p2 = stored.to_pair();
        assert_eq!(p.access.expose_secret(), p2.access.expose_secret());
        assert_eq!(
            p.refresh.as_ref().unwrap().expose_secret(),
            p2.refresh.as_ref().unwrap().expose_secret()
        );
        assert_eq!(p.expires_at, p2.expires_at);
    }

    #[test]
    fn gmail_endpoints() {
        let cfg = OAuthConfig {
            provider: OAuthProvider::Gmail,
            client_id: "x".into(),
            client_secret: "".into(),
            auth_url: "".into(),
            token_url: "".into(),
            device_auth_url: "".into(),
            scopes: vec![],
        };
        let (a, t, d, s) = cfg.endpoints();
        assert!(a.contains("accounts.google.com"));
        assert!(t.contains("oauth2.googleapis.com"));
        assert!(d.contains("device/code"));
        assert_eq!(s, vec!["https://mail.google.com/".to_string()]);
    }

    #[test]
    fn expired_detects_boundary() {
        let past = TokenPair {
            access: SecretString::new("a".to_string().into_boxed_str()),
            refresh: None,
            expires_at: Some(SystemTime::now() - Duration::from_secs(10)),
        };
        assert!(past.is_expired(Duration::from_secs(0)));

        let future = TokenPair {
            access: SecretString::new("a".to_string().into_boxed_str()),
            refresh: None,
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
        };
        assert!(!future.is_expired(Duration::from_secs(60)));
    }
}
