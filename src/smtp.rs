use crate::config::{SmtpConfig, TlsMode};
use crate::oauth::AuthMethod;
use crate::sanitize::outbound;
use crate::types::{FerromailError, Result, SendResult};
use lettre::message::{
    Attachment, Mailbox, MessageBuilder, MultiPart, SinglePart, header::ContentType,
};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use std::path::Path;
use tracing::{info, warn};

pub struct SmtpSender {
    config: SmtpConfig,
    username: String,
    /// Either a password or (when `auth_method` is XOAUTH2/OAUTHBEARER) an
    /// access token. Both are secrets of the same shape as far as the
    /// SASL mechanism is concerned.
    password: SecretString,
    auth_method: AuthMethod,
}

impl SmtpSender {
    pub fn new(config: SmtpConfig, username: String, password: SecretString) -> Self {
        Self {
            config,
            username,
            password,
            auth_method: AuthMethod::Password,
        }
    }

    pub fn with_auth_method(mut self, method: AuthMethod) -> Self {
        self.auth_method = method;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        from_name: &str,
        from_email: &str,
        to: &[String],
        cc: &[String],
        bcc: &[String],
        subject: &str,
        body: &str,
        html: bool,
        attachments: &[String],
        in_reply_to: Option<&str>,
        references: Option<&str>,
    ) -> Result<SendResult> {
        for addr in to.iter().chain(cc.iter()).chain(bcc.iter()) {
            outbound::validate_email_address(addr).map_err(FerromailError::InvalidArgument)?;
        }

        let subject = outbound::sanitize_subject(subject);
        let body_text =
            outbound::sanitize_body_outbound(body).map_err(FerromailError::InvalidArgument)?;

        if let Some(id) = in_reply_to {
            outbound::validate_message_id(id).map_err(FerromailError::InvalidArgument)?;
        }
        if let Some(refs) = references {
            outbound::validate_references(refs).map_err(FerromailError::InvalidArgument)?;
        }

        let from_mailbox: Mailbox = format!("{from_name} <{from_email}>")
            .parse()
            .map_err(|e| FerromailError::SmtpError(format!("Invalid from address: {e}")))?;

        let mut builder = MessageBuilder::new().from(from_mailbox).subject(&subject);

        for addr in to {
            let mailbox: Mailbox = addr
                .parse()
                .map_err(|e| FerromailError::SmtpError(format!("Invalid to address: {e}")))?;
            builder = builder.to(mailbox);
        }
        for addr in cc {
            let mailbox: Mailbox = addr
                .parse()
                .map_err(|e| FerromailError::SmtpError(format!("Invalid cc address: {e}")))?;
            builder = builder.cc(mailbox);
        }
        for addr in bcc {
            let mailbox: Mailbox = addr
                .parse()
                .map_err(|e| FerromailError::SmtpError(format!("Invalid bcc address: {e}")))?;
            builder = builder.bcc(mailbox);
        }

        if let Some(id) = in_reply_to {
            builder = builder.in_reply_to(id.to_string());
        }
        if let Some(refs) = references {
            builder = builder.references(refs.to_string());
        }

        let message = if attachments.is_empty() {
            let _content_type = if html {
                ContentType::TEXT_HTML
            } else {
                ContentType::TEXT_PLAIN
            };
            builder
                .body(body_text)
                .map_err(|e| FerromailError::SmtpError(format!("Failed to build message: {e}")))?
        } else {
            let text_part = if html {
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(body_text)
            } else {
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(body_text)
            };

            let mut multipart = MultiPart::mixed().singlepart(text_part);

            for path_str in attachments {
                let path = Path::new(path_str);
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("attachment")
                    .to_string();
                let file_data = tokio::fs::read(path).await.map_err(|e| {
                    FerromailError::SmtpError(format!("Failed to read attachment {path_str}: {e}"))
                })?;
                let content_type = ContentType::parse("application/octet-stream")
                    .map_err(|e| FerromailError::SmtpError(format!("Content type error: {e}")))?;
                let attachment = Attachment::new(filename).body(file_data, content_type);
                multipart = multipart.singlepart(attachment);
            }

            builder
                .multipart(multipart)
                .map_err(|e| FerromailError::SmtpError(format!("Failed to build message: {e}")))?
        };

        let message_id = message
            .headers()
            .get_raw("Message-ID")
            .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
            .unwrap_or_default();

        let transport = self.build_transport()?;

        // MTA-STS observability: fetch each recipient domain's policy,
        // non-blocking on the send itself. Logs an audit signal per
        // recipient so the user can see whether a recipient publishes
        // strict TLS expectations that their MSA needs to honour. Not an
        // enforcement gate since we submit via MSA, not direct-to-MX.
        observe_mta_sts(to, cc, bcc).await;

        transport
            .send(message)
            .await
            .map_err(|e| FerromailError::SmtpError(format!("Send failed: {e}")))?;

        info!(
            op = "send_email",
            to = ?to,
            subject = %subject,
            "Email sent successfully"
        );

        Ok(SendResult {
            message_id,
            recipients: to.to_vec(),
        })
    }

    fn build_transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let creds = Credentials::new(
            self.username.clone(),
            self.password.expose_secret().to_string(),
        );

        let builder = match self.config.tls {
            TlsMode::Required => {
                let tls_params: TlsParameters = TlsParameters::builder(self.config.host.clone())
                    .dangerous_accept_invalid_certs(!self.config.verify_certs)
                    .build()
                    .map_err(|e| FerromailError::TlsError(format!("TLS params: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                    .port(self.config.port)
                    .tls(Tls::Wrapper(tls_params))
            }
            TlsMode::StarttlsUnsafe => {
                warn!(
                    host = %self.config.host,
                    "Using STARTTLS (inherently vulnerable). Prefer tls = \"required\"."
                );
                let tls_params: TlsParameters = TlsParameters::builder(self.config.host.clone())
                    .dangerous_accept_invalid_certs(!self.config.verify_certs)
                    .build()
                    .map_err(|e| FerromailError::TlsError(format!("TLS params: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                    .port(self.config.port)
                    .tls(Tls::Required(tls_params))
            }
            TlsMode::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                    .port(self.config.port)
                    .tls(Tls::None)
            }
        };

        let mechanisms: Vec<Mechanism> = match self.auth_method {
            AuthMethod::Password => vec![Mechanism::Plain, Mechanism::Login],
            AuthMethod::Xoauth2 | AuthMethod::OAuthBearer => vec![Mechanism::Xoauth2],
        };

        Ok(builder
            .credentials(creds)
            .authentication(mechanisms)
            .build())
    }
}

async fn observe_mta_sts(to: &[String], cc: &[String], bcc: &[String]) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    for addr in to.iter().chain(cc.iter()).chain(bcc.iter()) {
        if let Some((_, domain)) = addr.rsplit_once('@') {
            let d = domain.trim().to_ascii_lowercase();
            if seen.insert(d.clone()) {
                match crate::mta_sts::fetch(&d).await {
                    Ok(Some(policy)) => {
                        tracing::info!(
                            target: "mta_sts",
                            domain = %d,
                            mode = ?policy.mode,
                            patterns = ?policy.mx_patterns,
                            "recipient publishes MTA-STS policy"
                        );
                    }
                    Ok(None) => {
                        tracing::debug!(
                            target: "mta_sts",
                            domain = %d,
                            "no MTA-STS policy published"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "mta_sts",
                            domain = %d,
                            error = %e,
                            "MTA-STS policy fetch failed"
                        );
                    }
                }
            }
        }
    }
}
