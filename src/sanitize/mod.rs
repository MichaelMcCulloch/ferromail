pub mod body;
pub mod filename;
pub mod header;
pub mod isolation;
pub mod outbound;
pub mod spoof;

pub fn sanitize_email_body(
    raw: &[u8],
    content_type: &str,
    charset: Option<&str>,
    max_body_length: usize,
) -> String {
    body::sanitize_body(raw, content_type, charset, max_body_length, "")
}

pub fn sanitize_header(raw: &str) -> String {
    header::sanitize_header(raw, "unknown", "")
}
