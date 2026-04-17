#![deny(unsafe_code)]
#![allow(dead_code)]

pub mod audit;
pub mod config;
pub mod credential;
pub mod email_auth;
pub mod gate;
pub mod imap;
pub mod login_gate;
pub mod metrics;
pub mod mime_parse;
pub mod mta_sts;
#[cfg(target_os = "linux")]
pub mod os_sandbox;
pub mod oauth;
pub mod policy;
pub mod rate_limit;
pub mod sandbox;
pub mod sanitize;
pub mod smtp;
pub mod tls;
pub mod tools;
pub mod transport;
pub mod types;

/// Test-only re-export of the HTTP serve function with an explicit
/// config_dir, so parallel integration tests don't race on the global
/// `FERROMAIL_CONFIG` env var.
pub mod transport_http_for_test {
    pub use super::transport::http::serve_with_config_dir;
}
