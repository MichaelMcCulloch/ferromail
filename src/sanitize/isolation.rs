pub fn escape_isolation_markers(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    for ch in content.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(ch),
        }
    }
    result
}

pub fn wrap_body(
    content: &str,
    email_id: &str,
    encoding: &str,
    truncated: bool,
    length: usize,
) -> String {
    let _eid = escape_isolation_markers(email_id);
    let enc = escape_isolation_markers(encoding);
    format!(
        "<ferromail:body encoding=\"{enc}\" truncated=\"{truncated}\" length=\"{length}\">\n\
         {content}\n\
         </ferromail:body>",
        enc = enc,
        truncated = truncated,
        length = length,
        content = content,
    )
}

pub fn wrap_header(content: &str, header_name: &str, _email_id: &str) -> String {
    let name = escape_isolation_markers(header_name);
    format!(
        "<ferromail:header name=\"{name}\">{content}</ferromail:header>",
        name = name,
        content = content,
    )
}

pub fn wrap_untrusted(inner_xml: &str, email_id: &str) -> String {
    let eid = escape_isolation_markers(email_id);
    format!(
        "<ferromail:untrusted source=\"email\" email_id=\"{eid}\">\n\
         {inner_xml}\n\
         </ferromail:untrusted>",
        eid = eid,
        inner_xml = inner_xml,
    )
}

pub fn wrap_attachment(index: u32, name: &str, size: u64, mime: &str) -> String {
    let name = escape_isolation_markers(name);
    let mime = escape_isolation_markers(mime);
    format!(
        "<ferromail:attachment index=\"{index}\" name=\"{name}\" \
         size=\"{size}\" mime=\"{mime}\" />",
        index = index,
        name = name,
        size = size,
        mime = mime,
    )
}

/// Per-field wrapper for any named value (subject, from, to, date,
/// message-id, etc). The LLM can then reason about which field a claim
/// originated in, rather than seeing one undifferentiated blob.
pub fn wrap_field(name: &str, value: &str) -> String {
    let name = escape_isolation_markers(name);
    let value = escape_isolation_markers(value);
    format!(
        "<ferromail:field name=\"{name}\">{value}</ferromail:field>",
        name = name,
        value = value,
    )
}

/// Wraps upstream and local authentication-results. Values are already
/// trusted strings produced by the library (not user-controlled), but we
/// escape defensively because e.g. DKIM `d=` domain values can contain
/// arbitrary chars.
pub fn wrap_auth(
    upstream: Option<&str>,
    dkim_local: Option<&str>,
    arc_local: Option<&str>,
    trusted: bool,
) -> String {
    let mut inner = String::new();
    if let Some(u) = upstream {
        inner.push_str(&format!(
            "<ferromail:auth-upstream>{}</ferromail:auth-upstream>",
            escape_isolation_markers(u)
        ));
    }
    if let Some(d) = dkim_local {
        inner.push_str(&format!(
            "<ferromail:auth-dkim-local>{}</ferromail:auth-dkim-local>",
            escape_isolation_markers(d)
        ));
    }
    if let Some(a) = arc_local {
        inner.push_str(&format!(
            "<ferromail:auth-arc-local>{}</ferromail:auth-arc-local>",
            escape_isolation_markers(a)
        ));
    }
    format!(
        "<ferromail:auth trusted=\"{trusted}\">{inner}</ferromail:auth>",
        trusted = trusted,
        inner = inner,
    )
}

/// Wraps the spoof-signal summary. Fields that fired are surfaced; ones
/// that didn't are omitted to keep the block small.
pub fn wrap_spoof_signals(
    display_name_embeds_address: Option<&str>,
    confusable_domain: Option<&str>,
    invisible_chars_in_domain: bool,
    suspicious: bool,
) -> String {
    let mut inner = String::new();
    if let Some(d) = display_name_embeds_address {
        inner.push_str(&format!(
            "<ferromail:spoof-display-name>{}</ferromail:spoof-display-name>",
            escape_isolation_markers(d)
        ));
    }
    if let Some(c) = confusable_domain {
        inner.push_str(&format!(
            "<ferromail:spoof-confusable-domain>{}</ferromail:spoof-confusable-domain>",
            escape_isolation_markers(c)
        ));
    }
    if invisible_chars_in_domain {
        inner.push_str("<ferromail:spoof-invisible-chars-in-domain />");
    }
    format!(
        "<ferromail:spoof suspicious=\"{}\">{}</ferromail:spoof>",
        suspicious, inner
    )
}
