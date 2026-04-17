//! Integration test: HTTP/SSE transport.
//!
//! Spins up the server on 127.0.0.1 with a random port, verifies bearer-auth
//! handling, healthz, synchronous /rpc, and MCP `initialize` + `tools/list`.

use std::sync::Arc;
use std::time::Duration;

use ferromail::audit::AuditLog;
use ferromail::config::Config;
use ferromail::credential::CredentialBackend;
use ferromail::gate::{ConfirmationChannel, ConfirmationGate};
use ferromail::login_gate::LoginGate;
use ferromail::rate_limit::RateLimiter;
use ferromail::sandbox::DownloadSandbox;
use ferromail::tools::ToolContext;
use reqwest::header::AUTHORIZATION;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex as TokioMutex, RwLock};

/// Build a ToolContext with a disabled terminal gate and a transient sandbox.
fn make_ctx(tmp: &TempDir) -> Arc<ToolContext> {
    let download_dir = tmp.path().join("downloads");
    std::fs::create_dir_all(&download_dir).unwrap();
    let sandbox = DownloadSandbox::new(
        download_dir,
        1024 * 1024,
        vec!["txt".into(), "pdf".into()],
        vec![],
    )
    .unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let audit = AuditLog::new(&audit_path).unwrap();
    let gate = ConfirmationGate::new(ConfirmationChannel::Terminal {
        cooldown_seconds: 0,
    });

    Arc::new(ToolContext {
        config: RwLock::new(Config::default()),
        gate,
        rate_limiter: Arc::new(TokioMutex::new(RateLimiter::default())),
        audit: Arc::new(TokioMutex::new(audit)),
        sandbox,
        credentials: CredentialBackend::from_config(&ferromail::config::CredentialsConfig {
            backend: "keyring".into(),
        }),
        login_gate: LoginGate::new(),
    })
}

/// Pick a free port on loopback.
async fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Spawn the HTTP server with an explicit config_dir (avoids env-var races
/// across parallel tests). Returns the bearer token that was persisted.
async fn spawn_server(tmp: &TempDir, port: u16) -> (Arc<ToolContext>, String) {
    let config_dir = tmp.path().to_path_buf();

    let ctx = make_ctx(tmp);
    let ctx_clone = ctx.clone();
    let cfg_dir_clone = config_dir.clone();
    tokio::spawn(async move {
        let _ = ferromail::transport_http_for_test::serve_with_config_dir(
            "127.0.0.1",
            port,
            ctx_clone,
            false,
            &cfg_dir_clone,
        )
        .await;
    });

    // Wait for the server to bind.
    for _ in 0..50 {
        if reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let token_path = config_dir.join("transport_token");
    let token = std::fs::read_to_string(&token_path).expect("token was written");
    (ctx, token)
}

#[tokio::test]
async fn healthz_works() {
    let tmp = TempDir::new().unwrap();
    let port = pick_port().await;
    let (_ctx, _token) = spawn_server(&tmp, port).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn rpc_requires_bearer_token() {
    let tmp = TempDir::new().unwrap();
    let port = pick_port().await;
    let (_ctx, token) = spawn_server(&tmp, port).await;

    let client = reqwest::Client::new();

    // No auth → 401.
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token → 401.
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .header(AUTHORIZATION, "Bearer not-the-token")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Correct token → 200.
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["serverInfo"]["name"], "ferromail");
}

#[tokio::test]
async fn tools_list_returns_expected_tools() {
    let tmp = TempDir::new().unwrap();
    let port = pick_port().await;
    let (_ctx, token) = spawn_server(&tmp, port).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let tools = body["result"]["tools"].as_array().expect("tools array");

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "list_accounts",
        "list_emails",
        "get_email_content",
        "send_email",
        "reply_to_email",
        "delete_emails",
        "download_attachment",
    ] {
        assert!(
            names.contains(&expected),
            "tool {expected} missing from tools/list: {names:?}"
        );
    }
}

#[tokio::test]
async fn list_accounts_returns_empty_when_no_accounts() {
    let tmp = TempDir::new().unwrap();
    let port = pick_port().await;
    let (_ctx, token) = spawn_server(&tmp, port).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_accounts",
                "arguments": {}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text.trim(), "[]");
}

#[tokio::test]
async fn bearer_token_file_is_0o600() {
    let tmp = TempDir::new().unwrap();
    let port = pick_port().await;
    let (_ctx, _token) = spawn_server(&tmp, port).await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let token_path = tmp.path().join("transport_token");
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "token file must be 0o600");
    }
}
