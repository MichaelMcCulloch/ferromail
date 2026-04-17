//! Integration test: webhook confirmation channel.
//!
//! Spins up a wiremock HTTP server that accepts POSTs from the webhook gate
//! and returns approve/deny decisions. Verifies the full request→decision
//! flow against the real `ConfirmationGate`.

use ferromail::gate::{ConfirmationChannel, ConfirmationGate, ConfirmedBy};
use ferromail::types::{FerromailError, ToolTier};
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn webhook_approval_is_accepted() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/approve"))
        .and(body_json(json!({
            "operation": "send_email",
            "summary": "test summary",
            "tier": "write",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"approve": true})))
        .mount(&server)
        .await;

    let gate = ConfirmationGate::new(ConfirmationChannel::Webhook {
        url: format!("{}/approve", server.uri()),
        cooldown_seconds: 0,
        timeout_seconds: 5,
    });

    let result = gate
        .request_confirmation("send_email", "test summary", ToolTier::Write)
        .await;

    assert!(matches!(result, Ok(ConfirmedBy::Webhook)));
}

#[tokio::test]
async fn webhook_denial_returns_operation_denied() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"approve": false})))
        .mount(&server)
        .await;

    let gate = ConfirmationGate::new(ConfirmationChannel::Webhook {
        url: format!("{}/approve", server.uri()),
        cooldown_seconds: 0,
        timeout_seconds: 5,
    });

    let result = gate
        .request_confirmation("send_email", "test summary", ToolTier::Write)
        .await;

    assert!(matches!(result, Err(FerromailError::OperationDenied)));
}

#[tokio::test]
async fn webhook_non_2xx_is_treated_as_denial() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let gate = ConfirmationGate::new(ConfirmationChannel::Webhook {
        url: format!("{}/approve", server.uri()),
        cooldown_seconds: 0,
        timeout_seconds: 5,
    });

    let result = gate
        .request_confirmation("send_email", "test summary", ToolTier::Write)
        .await;

    assert!(matches!(result, Err(FerromailError::OperationDenied)));
}

#[tokio::test]
async fn webhook_timeout_returns_expired() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(10)))
        .mount(&server)
        .await;

    let gate = ConfirmationGate::new(ConfirmationChannel::Webhook {
        url: format!("{}/approve", server.uri()),
        cooldown_seconds: 0,
        timeout_seconds: 1,
    });

    let result = gate
        .request_confirmation("send_email", "test summary", ToolTier::Write)
        .await;

    // Expect either OperationExpired (our explicit timeout) or ConfigError
    // (reqwest's internal timeout wrapping). Either is a failure mode, not
    // an approval.
    assert!(
        matches!(
            result,
            Err(FerromailError::OperationExpired) | Err(FerromailError::ConfigError(_))
        ),
        "expected timeout error, got {result:?}"
    );
}

#[tokio::test]
async fn none_channel_approves_without_prompt() {
    let gate = ConfirmationGate::new(ConfirmationChannel::None {
        cooldown_seconds: 0,
    });

    let result = gate
        .request_confirmation("send_email", "ignored", ToolTier::Write)
        .await;

    assert!(matches!(result, Ok(ConfirmedBy::Client)));
}

#[tokio::test]
async fn none_channel_still_applies_destructive_cooldown() {
    let gate = ConfirmationGate::new(ConfirmationChannel::None {
        cooldown_seconds: 2,
    });

    let start = std::time::Instant::now();
    let result = gate
        .request_confirmation("delete_emails", "ignored", ToolTier::Destructive)
        .await;
    let elapsed = start.elapsed();

    assert!(matches!(result, Ok(ConfirmedBy::Client)));
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "destructive cooldown should still apply in \"none\" mode, got {elapsed:?}"
    );
}

#[tokio::test]
async fn none_channel_skips_cooldown_for_write_tier() {
    let gate = ConfirmationGate::new(ConfirmationChannel::None {
        cooldown_seconds: 10,
    });

    let start = std::time::Instant::now();
    let result = gate
        .request_confirmation("send_email", "ignored", ToolTier::Write)
        .await;
    let elapsed = start.elapsed();

    assert!(matches!(result, Ok(ConfirmedBy::Client)));
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "write tier should not wait for the destructive cooldown"
    );
}

#[tokio::test]
async fn webhook_destructive_tier_applies_cooldown() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/approve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"approve": true})))
        .mount(&server)
        .await;

    let gate = ConfirmationGate::new(ConfirmationChannel::Webhook {
        url: format!("{}/approve", server.uri()),
        cooldown_seconds: 2,
        timeout_seconds: 5,
    });

    let start = std::time::Instant::now();
    let result = gate
        .request_confirmation("delete_emails", "deletion summary", ToolTier::Destructive)
        .await;
    let elapsed = start.elapsed();

    assert!(matches!(result, Ok(ConfirmedBy::Webhook)));
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "destructive tier should wait {cooldown}s, elapsed {elapsed:?}",
        cooldown = 2
    );
}
