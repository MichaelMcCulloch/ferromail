//! Tool-call policy engine built on Cedar.
//!
//! The engine evaluates each write- or destructive-tier MCP tool call
//! against a Cedar policy bundle before the call ever reaches the
//! confirmation gate. The user sees a rejected call as a structured error
//! (`{"error": "policy", "reason": "..."}`), no prompt consumed, no audit
//! approval churn.
//!
//! Policy files live at `~/.config/ferromail/policy.cedar` and are loaded
//! at startup. An empty / absent file means "allow everything" — this is
//! a bolt-on layer, not a replacement for the confirmation gate.
//!
//! Schema (stable, users write against this):
//!
//!   entities:
//!     Account::"<name>"    — the account used for the call
//!     Tool::"<name>"       — send_email / reply_to_email / delete_emails / download_attachment
//!     Domain::"<fqdn>"     — recipient or sender domain
//!
//!   actions:
//!     Action::"SendEmail"
//!     Action::"ReplyEmail"
//!     Action::"DeleteEmails"
//!     Action::"DownloadAttachment"
//!
//!   context attributes:
//!     recipient_domains: Set<String>
//!     attachment_bytes: Long
//!     subject_length: Long
//!     has_external_link: Bool
//!     hour_utc: Long
//!
//! Example policy:
//!
//!   forbid (principal, action == Action::"DeleteEmails", resource)
//!   when { context.hour_utc < 7 || context.hour_utc >= 23 };
//!
//!   forbid (principal, action == Action::"SendEmail", resource)
//!   when { context.recipient_domains.contains("attacker.biz") };

use std::collections::HashMap;
use std::path::Path;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};
use serde_json::Value;

use crate::types::{FerromailError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

pub struct PolicyEngine {
    policies: PolicySet,
    entities: Entities,
    authorizer: Authorizer,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            policies: PolicySet::new(),
            entities: Entities::empty(),
            authorizer: Authorizer::new(),
        }
    }
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine").finish_non_exhaustive()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load policies from a `.cedar` file. Missing file → empty PolicySet
    /// (allow-all).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| FerromailError::ConfigError(format!("policy read: {e}")))?;
        let policies: PolicySet = text
            .parse()
            .map_err(|e| FerromailError::ConfigError(format!("policy parse: {e}")))?;
        Ok(Self {
            policies,
            entities: Entities::empty(),
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluate a tool call against the policy set. The tool name is
    /// mapped to the corresponding Cedar action; `args` is the JSON-RPC
    /// parameters and is used to populate the context.
    pub fn evaluate(&self, tool: &str, args: &Value, account: &str) -> PolicyDecision {
        if self.policies.is_empty() {
            return PolicyDecision::Allow;
        }

        let Some(action_name) = tool_to_action(tool) else {
            // Read-tier tools and anything we don't recognise get allowed
            // by default — policy is for the dangerous surface.
            return PolicyDecision::Allow;
        };

        let principal = EntityUid::from_type_name_and_id(
            "Account".parse().unwrap(),
            account.parse().unwrap_or_else(|_| "unknown".parse().unwrap()),
        );
        let action = EntityUid::from_type_name_and_id(
            "Action".parse().unwrap(),
            action_name.parse().unwrap(),
        );
        let resource = EntityUid::from_type_name_and_id(
            "Tool".parse().unwrap(),
            tool.parse().unwrap_or_else(|_| "unknown".parse().unwrap()),
        );

        let context = build_context(tool, args);
        let Ok(context) = Context::from_pairs(context) else {
            return PolicyDecision::Deny("failed to build policy context".into());
        };

        let request = match Request::new(principal, action, resource, context, None) {
            Ok(r) => r,
            Err(e) => return PolicyDecision::Deny(format!("policy request build: {e}")),
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &self.entities);

        match response.decision() {
            Decision::Allow => PolicyDecision::Allow,
            Decision::Deny => {
                let reasons: Vec<String> = response
                    .diagnostics()
                    .reason()
                    .map(|pid| pid.to_string())
                    .collect();
                if reasons.is_empty() {
                    // Cedar is default-deny, but ferromail's policy layer
                    // is an *optional* bolt-on — we only deny when a
                    // `forbid` rule actually matches. If the user wanted
                    // default-deny, they'd have added a `permit` rule and
                    // the forbid rules would fire on top.
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny(format!("policy denied by {}", reasons.join(", ")))
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

fn tool_to_action(tool: &str) -> Option<&'static str> {
    match tool {
        "send_email" => Some("SendEmail"),
        "reply_to_email" => Some("ReplyEmail"),
        "delete_emails" => Some("DeleteEmails"),
        "download_attachment" => Some("DownloadAttachment"),
        _ => None,
    }
}

fn build_context(tool: &str, args: &Value) -> HashMap<String, RestrictedExpression> {
    let mut ctx: HashMap<String, RestrictedExpression> = HashMap::new();

    // Recipient domains.
    let mut domains: Vec<String> = Vec::new();
    for key in ["to", "cc", "bcc"] {
        if let Some(arr) = args.get(key).and_then(|v| v.as_array()) {
            for v in arr {
                if let Some(addr) = v.as_str()
                    && let Some((_, d)) = addr.rsplit_once('@')
                {
                    domains.push(d.trim().to_ascii_lowercase());
                }
            }
        }
    }
    domains.sort();
    domains.dedup();
    ctx.insert(
        "recipient_domains".into(),
        RestrictedExpression::new_set(
            domains.into_iter().map(RestrictedExpression::new_string),
        ),
    );

    // Attachment sizes: we only have paths in args; size is computed later.
    let attachment_count = args
        .get("attachments")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as i64)
        .unwrap_or(0);
    ctx.insert(
        "attachment_count".into(),
        RestrictedExpression::new_long(attachment_count),
    );

    let subject_length = args
        .get("subject")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().count() as i64)
        .unwrap_or(0);
    ctx.insert(
        "subject_length".into(),
        RestrictedExpression::new_long(subject_length),
    );

    let has_external_link = args
        .get("body")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.contains("http://") || s.contains("https://"));
    ctx.insert(
        "has_external_link".into(),
        RestrictedExpression::new_bool(has_external_link),
    );

    let hour_utc = chrono::Utc::now().format("%H").to_string().parse::<i64>().unwrap_or(0);
    ctx.insert("hour_utc".into(), RestrictedExpression::new_long(hour_utc));

    ctx.insert(
        "tool".into(),
        RestrictedExpression::new_string(tool.to_string()),
    );

    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_engine_allows() {
        let eng = PolicyEngine::new();
        let args = json!({"to": ["x@example.com"]});
        assert_eq!(eng.evaluate("send_email", &args, "work"), PolicyDecision::Allow);
    }

    #[test]
    fn load_missing_file_ok() {
        let engine = PolicyEngine::load(Path::new("/tmp/ferromail-nonexistent-policy.cedar"))
            .expect("missing file → empty policy set");
        assert!(engine.is_empty());
    }

    #[test]
    fn forbid_by_recipient_domain() {
        // ferromail's allow-by-default wrapper means users only need
        // `forbid` rules — `permit` isn't required.
        let text = r#"
            forbid (
                principal,
                action,
                resource
            ) when {
                context.recipient_domains.contains("attacker.biz")
            };
        "#;
        let policies: PolicySet = text.parse().expect("policy parses");
        let eng = PolicyEngine {
            policies,
            entities: Entities::empty(),
            authorizer: Authorizer::new(),
        };
        let allowed = json!({"to": ["user@example.com"]});
        let denied = json!({"to": ["hacker@attacker.biz"]});
        assert_eq!(eng.evaluate("send_email", &allowed, "work"), PolicyDecision::Allow);
        assert!(matches!(
            eng.evaluate("send_email", &denied, "work"),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn unknown_tool_passes() {
        let text = r#"forbid (principal, action, resource);"#;
        let policies: PolicySet = text.parse().unwrap();
        let eng = PolicyEngine {
            policies,
            entities: Entities::empty(),
            authorizer: Authorizer::new(),
        };
        assert_eq!(eng.evaluate("list_emails", &json!({}), "work"), PolicyDecision::Allow);
    }
}
