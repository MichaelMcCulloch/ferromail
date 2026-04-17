//! HTTP / SSE MCP transport.
//!
//! Exposes a minimal SSE-compatible surface:
//!
//!   GET  /sse            — server-sent events stream of JSON-RPC responses.
//!   POST /messages       — JSON-RPC request; response is delivered via SSE.
//!   POST /rpc            — synchronous JSON-RPC request/response (convenience
//!                          for clients that don't speak SSE).
//!
//! Every request must carry `Authorization: Bearer <token>`; the token is
//! compared in constant time. Non-loopback binds require
//! `--i-understand-network-exposure`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use futures::Stream;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::tools::{ToolContext, ToolRequest, dispatch};

/// 32-byte random bearer token, hex-encoded (64 hex chars). Zeroized on drop.
pub struct BearerToken {
    token: Vec<u8>,
    hex: String,
}

impl BearerToken {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let hex = hex_encode(&bytes);
        Self {
            token: bytes.to_vec(),
            hex,
        }
    }

    pub fn verify(&self, provided: &str) -> bool {
        let provided_bytes = provided.as_bytes();
        let expected_bytes = self.hex.as_bytes();
        if provided_bytes.len() != expected_bytes.len() {
            return false;
        }
        provided_bytes.ct_eq(expected_bytes).into()
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn write_to_file(&self, config_dir: &Path) -> crate::types::Result<()> {
        let token_path = config_dir.join("transport_token");
        std::fs::write(&token_path, &self.hex)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        for b in &mut self.token {
            *b = 0;
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone)]
struct AppState {
    token: Arc<BearerToken>,
    ctx: Arc<ToolContext>,
    /// Broadcast channel for responses produced by POST /messages to be
    /// delivered via the GET /sse stream.
    sse_tx: broadcast::Sender<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    /// JSON-RPC 2.0 notifications have no `id`.
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

pub async fn serve(
    host: &str,
    port: u16,
    ctx: Arc<ToolContext>,
    require_exposure_flag: bool,
) -> crate::types::Result<()> {
    let config_dir = crate::config::Config::config_dir().map_err(|e| {
        crate::types::FerromailError::ConfigError(format!("cannot resolve config dir: {e}"))
    })?;
    serve_with_config_dir(host, port, ctx, require_exposure_flag, &config_dir).await
}

/// Variant used by integration tests so parallel tests don't race on the
/// global `FERROMAIL_CONFIG` env var.
pub async fn serve_with_config_dir(
    host: &str,
    port: u16,
    ctx: Arc<ToolContext>,
    require_exposure_flag: bool,
    config_dir: &Path,
) -> crate::types::Result<()> {
    let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";

    if !is_loopback {
        if !require_exposure_flag {
            return Err(crate::types::FerromailError::ConfigError(format!(
                "Binding to {host} exposes ferromail to the network. \
                 Anyone with the bearer token can read and send email. \
                 Use --i-understand-network-exposure to proceed."
            )));
        }
        warn!(
            host = %host,
            "Binding to {host} exposes ferromail to the network. Anyone with the bearer token can read and send email."
        );
    }

    let token = BearerToken::generate();
    token.write_to_file(config_dir)?;

    eprintln!("Bearer token: {}", token.hex());
    info!(host = %host, port = port, "SSE/HTTP transport starting");

    let (sse_tx, _sse_rx) = broadcast::channel::<String>(64);

    let state = AppState {
        token: Arc::new(token),
        ctx,
        sse_tx,
    };

    let app = Router::new()
        .route("/sse", get(sse_handler))
        .route("/messages", post(messages_handler))
        .route("/rpc", post(rpc_handler))
        .route("/healthz", get(healthz_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let bind_addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| {
            crate::types::FerromailError::TransportError(format!("failed to bind {bind_addr}: {e}"))
        })?;

    axum::serve(listener, app).await.map_err(|e| {
        crate::types::FerromailError::TransportError(format!("HTTP server error: {e}"))
    })?;

    Ok(())
}

async fn healthz_handler() -> &'static str {
    "ok"
}

async fn metrics_handler() -> Response {
    let body = crate::metrics::global().render();
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// SSE stream: one event per JSON-RPC response emitted by `messages_handler`.
async fn sse_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !check_bearer(&state.token, &headers) {
        return unauthorized();
    }

    let rx = state.sse_tx.subscribe();
    let stream = broadcast_stream(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn broadcast_stream(
    mut rx: broadcast::Receiver<String>,
) -> impl Stream<Item = std::result::Result<Event, Infallible>> {
    async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(payload) => {
                    yield Ok(Event::default().data(payload));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Client missed n messages; emit a note so they can
                    // reconcile if needed.
                    let payload = format!("{{\"lagged\":{n}}}");
                    yield Ok(Event::default().event("lag").data(payload));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

/// Asynchronous JSON-RPC dispatch: the response is pushed to the SSE stream
/// for all connected subscribers. Returns HTTP 202 Accepted on queue.
async fn messages_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !check_bearer(&state.token, &headers) {
        return unauthorized();
    }

    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON-RPC: {e}")),
    };
    debug!(method = %req.method, "messages POST");

    let Some(resp) = handle_rpc(req, &state.ctx).await else {
        // Notification: no response per JSON-RPC 2.0.
        return StatusCode::ACCEPTED.into_response();
    };
    match serde_json::to_string(&resp) {
        Ok(payload) => {
            // Best-effort broadcast. If there are no subscribers we drop the
            // response silently — the caller should use /rpc if they need a
            // synchronous round-trip.
            let _ = state.sse_tx.send(payload);
            StatusCode::ACCEPTED.into_response()
        }
        Err(e) => internal_error(&format!("serialize response: {e}")),
    }
}

/// Synchronous JSON-RPC: request-in, response-out in a single HTTP round trip.
async fn rpc_handler(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !check_bearer(&state.token, &headers) {
        return unauthorized();
    }

    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON-RPC: {e}")),
    };
    debug!(method = %req.method, "rpc POST");

    let Some(resp) = handle_rpc(req, &state.ctx).await else {
        // Notification has no response; HTTP 204 No Content is the
        // conventional mapping.
        return StatusCode::NO_CONTENT.into_response();
    };
    let payload = match serde_json::to_vec(&resp) {
        Ok(p) => p,
        Err(e) => return internal_error(&format!("serialize response: {e}")),
    };
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        payload,
    )
        .into_response()
}

async fn handle_rpc(req: JsonRpcRequest, ctx: &Arc<ToolContext>) -> Option<JsonRpcResponse> {
    // Notifications (no id, or method prefixed `notifications/`) get no reply.
    if req.id.is_none() || req.method.starts_with("notifications/") {
        debug!(method = %req.method, "received notification (no response)");
        return None;
    }
    let id = req.id.unwrap_or(Value::Null);

    let response = match req.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "ferromail",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        },
        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "tools": super::stdio::tool_definitions_for_http()
            })),
            error: None,
        },
        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let arguments = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));

            let tool_req = ToolRequest {
                tool: tool_name,
                arguments,
            };
            let response = dispatch(&tool_req, ctx).await;

            if response.success {
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&response.data)
                                .unwrap_or_default()
                        }]
                    })),
                    error: None,
                }
            } else {
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": response.error.unwrap_or_default()
                        }],
                        "isError": true
                    })),
                    error: None,
                }
            }
        }
        other => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {other}"),
                data: None,
            }),
        },
    };
    Some(response)
}

fn check_bearer(token: &BearerToken, headers: &HeaderMap) -> bool {
    let Some(auth) = headers.get("authorization").and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Some(provided) = auth.strip_prefix("Bearer ") else {
        return false;
    };
    token.verify(provided.trim())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "").into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

fn internal_error(msg: &str) -> Response {
    warn!(error = msg, "HTTP internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}
