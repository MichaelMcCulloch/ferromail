use mail_parser::{MessageParser, MimeHeaders, PartType};

use crate::types::{FerromailError, Result};

#[derive(Debug, Clone)]
pub struct MimeParseResult {
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<ParsedAttachment>,
    pub mime_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedAttachment {
    pub index: u32,
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub data: Vec<u8>,
}

pub fn parse_email(
    raw: &[u8],
    max_depth: usize,
    max_parts: usize,
    max_message_size: usize,
) -> Result<MimeParseResult> {
    if raw.len() > max_message_size {
        return Err(FerromailError::MimeError(format!(
            "message size {} exceeds limit {}",
            raw.len(),
            max_message_size
        )));
    }

    let parser = MessageParser::default();
    let message = parser
        .parse(raw)
        .ok_or_else(|| FerromailError::MimeError("failed to parse email message".into()))?;

    let depths = compute_part_depths(&message);

    let mut text_body = None;
    let mut html_body = None;
    let mut attachments = Vec::new();
    let mut part_count: usize = 0;
    let mut truncated = false;

    for (idx, part) in message.parts.iter().enumerate() {
        part_count += 1;
        if part_count > max_parts {
            truncated = true;
            break;
        }

        let depth = depths.get(idx).copied().unwrap_or(0);
        if depth > max_depth {
            truncated = true;
            continue;
        }

        match &part.body {
            PartType::Text(text) => {
                if text_body.is_none() && message.text_body.contains(&idx) {
                    text_body = Some(text.to_string());
                }
            }
            PartType::Html(html) => {
                if html_body.is_none() && message.html_body.contains(&idx) {
                    html_body = Some(html.to_string());
                }
            }
            PartType::Binary(data) | PartType::InlineBinary(data) => {
                if message.attachments.contains(&idx) {
                    let filename = part.attachment_name().map(|s| s.to_string());

                    let content_type = part
                        .content_type()
                        .map(|ct| {
                            if let Some(subtype) = ct.subtype() {
                                format!("{}/{}", ct.ctype(), subtype)
                            } else {
                                ct.ctype().to_string()
                            }
                        })
                        .unwrap_or_else(|| "application/octet-stream".into());

                    attachments.push(ParsedAttachment {
                        index: attachments.len() as u32,
                        filename,
                        mime_type: content_type,
                        size: data.len() as u64,
                        data: data.to_vec(),
                    });
                }
            }
            PartType::Message(_) => {
                if message.attachments.contains(&idx) {
                    let data = raw.get(part.offset_body..part.offset_end).unwrap_or(&[]);
                    attachments.push(ParsedAttachment {
                        index: attachments.len() as u32,
                        filename: Some("message.eml".into()),
                        mime_type: "message/rfc822".into(),
                        size: data.len() as u64,
                        data: data.to_vec(),
                    });
                }
            }
            PartType::Multipart(_) => {}
        }
    }

    Ok(MimeParseResult {
        text_body,
        html_body,
        attachments,
        mime_truncated: truncated,
    })
}

fn compute_part_depths(message: &mail_parser::Message<'_>) -> Vec<usize> {
    let mut depths = vec![0usize; message.parts.len()];

    for (idx, part) in message.parts.iter().enumerate() {
        if let PartType::Multipart(children) = &part.body {
            let parent_depth = depths[idx];
            for &child_id in children {
                if child_id < depths.len() {
                    depths[child_id] = parent_depth + 1;
                }
            }
        }
    }

    depths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_text_email() -> Vec<u8> {
        b"From: sender@example.com\r\n\
          To: recipient@example.com\r\n\
          Subject: Test\r\n\
          Content-Type: text/plain; charset=utf-8\r\n\
          \r\n\
          Hello, world!"
            .to_vec()
    }

    fn multipart_email() -> Vec<u8> {
        b"From: sender@example.com\r\n\
          To: recipient@example.com\r\n\
          Subject: Test with attachment\r\n\
          MIME-Version: 1.0\r\n\
          Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n\
          \r\n\
          --boundary123\r\n\
          Content-Type: text/plain; charset=utf-8\r\n\
          \r\n\
          Body text here.\r\n\
          --boundary123\r\n\
          Content-Type: application/pdf\r\n\
          Content-Disposition: attachment; filename=\"test.pdf\"\r\n\
          Content-Transfer-Encoding: base64\r\n\
          \r\n\
          SGVsbG8gV29ybGQ=\r\n\
          --boundary123--"
            .to_vec()
    }

    fn html_email() -> Vec<u8> {
        b"From: sender@example.com\r\n\
          To: recipient@example.com\r\n\
          Subject: HTML Test\r\n\
          Content-Type: text/html; charset=utf-8\r\n\
          \r\n\
          <html><body><p>Hello!</p></body></html>"
            .to_vec()
    }

    #[test]
    fn parse_simple_text() {
        let result = parse_email(&simple_text_email(), 10, 100, 26_214_400).unwrap();
        assert!(result.text_body.is_some());
        assert!(result.text_body.unwrap().contains("Hello, world!"));
        assert!(result.html_body.is_none());
        assert!(result.attachments.is_empty());
        assert!(!result.mime_truncated);
    }

    #[test]
    fn parse_html() {
        let result = parse_email(&html_email(), 10, 100, 26_214_400).unwrap();
        assert!(result.html_body.is_some());
        assert!(result.html_body.unwrap().contains("Hello!"));
    }

    #[test]
    fn parse_multipart_with_attachment() {
        let result = parse_email(&multipart_email(), 10, 100, 26_214_400).unwrap();
        assert!(result.text_body.is_some());
        assert!(result.text_body.unwrap().contains("Body text here."));
        assert!(!result.attachments.is_empty());

        let att = &result.attachments[0];
        assert_eq!(att.index, 0);
        assert_eq!(att.filename.as_deref(), Some("test.pdf"));
        assert!(att.mime_type.contains("pdf"));
    }

    #[test]
    fn max_parts_truncates() {
        let result = parse_email(&multipart_email(), 10, 1, 26_214_400).unwrap();
        assert!(result.mime_truncated);
    }

    #[test]
    fn oversized_message_rejected() {
        let result = parse_email(&simple_text_email(), 10, 100, 10);
        assert!(result.is_err());
    }

    #[test]
    fn empty_message_fails() {
        let result = parse_email(b"", 10, 100, 26_214_400);
        assert!(result.is_err());
    }

    #[test]
    fn headers_only_message() {
        let raw = b"From: sender@example.com\r\nSubject: No body\r\n\r\n";
        let result = parse_email(raw, 10, 100, 26_214_400).unwrap();
        // mail_parser may detect an empty text body part
        if let Some(ref text) = result.text_body {
            assert!(text.trim().is_empty());
        }
        assert!(result.html_body.is_none());
        assert!(result.attachments.is_empty());
    }
}
