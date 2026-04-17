use crate::tools::{self, ToolContext, ToolRequest};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info};

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    /// JSON-RPC 2.0 notifications have no `id`. We accept both and let
    /// `handle_request` decide whether to emit a response.
    #[serde(default)]
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

pub async fn serve(ctx: std::sync::Arc<ToolContext>) -> crate::types::Result<()> {
    info!("Starting MCP stdio transport");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        debug!(request = %line, "Received JSON-RPC request");

        let response: Option<JsonRpcResponse> = match serde_json::from_str::<JsonRpcRequest>(&line)
        {
            Ok(req) => handle_request(req, &ctx).await,
            Err(e) => Some(JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: format!("Parse error: {e}"),
                    data: None,
                }),
            }),
        };

        // Per JSON-RPC 2.0: no response for notifications.
        let Some(response) = response else {
            continue;
        };

        let response_json = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!(error = %e, "Failed to serialize response");
                continue;
            }
        };

        if let Err(e) = stdout
            .write_all(format!("{response_json}\n").as_bytes())
            .await
        {
            error!(error = %e, "Failed to write response");
            break;
        }
        if let Err(e) = stdout.flush().await {
            error!(error = %e, "Failed to flush stdout");
            break;
        }
    }

    info!("stdio transport ended");
    Ok(())
}

async fn handle_request(
    req: JsonRpcRequest,
    ctx: &std::sync::Arc<ToolContext>,
) -> Option<JsonRpcResponse> {
    // Notifications (no `id`) must never get a response, per JSON-RPC 2.0.
    // MCP uses this for `notifications/initialized`, `notifications/cancelled`,
    // etc. Drop silently after any side effects.
    if req.id.is_none() || req.method.starts_with("notifications/") {
        debug!(method = %req.method, "received notification (no response)");
        return None;
    }
    let id = req.id.unwrap_or(serde_json::Value::Null);

    let response = match req.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "ferromail",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        },
        "tools/list" => {
            let tool_list = tool_definitions();
            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(serde_json::json!({ "tools": tool_list })),
                error: None,
            }
        }
        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

            let tool_req = ToolRequest {
                tool: tool_name.to_string(),
                arguments,
            };

            let response = tools::dispatch(&tool_req, ctx).await;

            if response.success {
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&response.data).unwrap_or_default()
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
        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
                data: None,
            }),
        },
    };
    Some(response)
}

pub fn tool_definitions_for_http() -> serde_json::Value {
    tool_definitions()
}

fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "list_accounts",
            "description": "List configured email accounts (masked — no passwords or sensitive details)",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "list_emails",
            "description": "List email metadata from a mailbox with filtering and pagination",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string", "description": "Account name" },
                    "mailbox": { "type": "string", "default": "INBOX" },
                    "page": { "type": "integer", "default": 1 },
                    "page_size": { "type": "integer", "default": 20, "minimum": 1, "maximum": 50 },
                    "since": { "type": "string", "description": "ISO 8601 datetime" },
                    "before": { "type": "string", "description": "ISO 8601 datetime" },
                    "from": { "type": "string" },
                    "subject": { "type": "string" },
                    "order": { "type": "string", "enum": ["Asc", "Desc"], "default": "Desc" }
                },
                "required": ["account"]
            }
        },
        {
            "name": "get_email_content",
            "description": "Get full content of emails by ID. Content is sanitized and wrapped in isolation markers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "email_ids": { "type": "array", "items": { "type": "string" }, "maxItems": 10 },
                    "mailbox": { "type": "string", "default": "INBOX" }
                },
                "required": ["account", "email_ids"]
            }
        },
        {
            "name": "send_email",
            "description": "Send an email. Requires human confirmation before sending.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "body": { "type": "string" },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "html": { "type": "boolean", "default": false },
                    "attachments": { "type": "array", "items": { "type": "string" } },
                    "in_reply_to": { "type": "string" },
                    "references": { "type": "string" },
                    "from": {
                        "type": "string",
                        "description": "Optional From: address. Must equal the account's email_address or be listed in its send_as allowlist. Defaults to the account's default_from (or email_address if unset)."
                    }
                },
                "required": ["account", "to", "subject", "body"]
            }
        },
        {
            "name": "reply_to_email",
            "description": "Reply to an existing email thread. Requires human confirmation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "email_id": { "type": "string" },
                    "mailbox": { "type": "string", "default": "INBOX" },
                    "body": { "type": "string" },
                    "reply_all": { "type": "boolean", "default": false },
                    "attachments": { "type": "array", "items": { "type": "string" } },
                    "from": {
                        "type": "string",
                        "description": "Optional From: address. Same rules as send_email."
                    }
                },
                "required": ["account", "email_id", "body"]
            }
        },
        {
            "name": "delete_emails",
            "description": "Delete emails by ID. Requires human confirmation with 3-second cooldown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "email_ids": { "type": "array", "items": { "type": "string" }, "maxItems": 20 },
                    "mailbox": { "type": "string", "default": "INBOX" }
                },
                "required": ["account", "email_ids"]
            }
        },
        {
            "name": "download_attachment",
            "description": "Download an attachment to the sandbox directory. Requires human confirmation with 3-second cooldown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "email_id": { "type": "string" },
                    "attachment_index": { "type": "integer", "minimum": 0 },
                    "mailbox": { "type": "string", "default": "INBOX" }
                },
                "required": ["account", "email_id", "attachment_index"]
            }
        }
    ])
}
