pub mod client;
pub mod fetch;
pub mod validate;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_imap::imap_proto;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config::{TimeoutsConfig, TlsMode};
use crate::tls;
use crate::types::{FerromailError, Result};

/// Cap on items returned by a single UID FETCH. Each fetch item carries
/// envelope / body / bodystructure payload, so the per-item cost is real;
/// 1000 is well above any legitimate page we'd request (page_size maxes at
/// 50) while still catching a runaway server.
const MAX_FETCH_ITEMS: usize = 1000;

/// Cap on UIDs returned by UID SEARCH. SEARCH results are just integers, so
/// a mailbox with hundreds of thousands of messages is legitimate. We keep a
/// generous ceiling as a sanity net — well past any real inbox size.
const MAX_SEARCH_UIDS: usize = 1_000_000;

type TlsImapSession = async_imap::Session<TlsStream<TcpStream>>;
type PlainImapSession = async_imap::Session<TcpStream>;
type TlsImapClient = async_imap::Client<TlsStream<TcpStream>>;
type PlainImapClient = async_imap::Client<TcpStream>;

enum InnerState {
    PreAuthTls(TlsImapClient),
    PreAuthPlain(PlainImapClient),
    AuthTls(TlsImapSession),
    AuthPlain(PlainImapSession),
    Consumed,
}

#[allow(clippy::large_enum_variant)]
pub enum ImapSession {
    Tls(TlsImapSession),
    Plain(PlainImapSession),
}

impl fmt::Debug for ImapSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImapSession::Tls(_) => write!(f, "ImapSession::Tls(...)"),
            ImapSession::Plain(_) => write!(f, "ImapSession::Plain(...)"),
        }
    }
}

pub struct ImapClient {
    state: InnerState,
    consecutive_login_failures: u32,
    host: String,
    timeouts: TimeoutsConfig,
}

impl ImapClient {
    pub async fn connect(
        host: &str,
        port: u16,
        tls_mode: TlsMode,
        tls_config: Arc<ClientConfig>,
        timeouts: &TimeoutsConfig,
    ) -> Result<Self> {
        let connect_timeout = Duration::from_secs(timeouts.connect);
        let tls_timeout = Duration::from_secs(timeouts.tls_handshake);

        let timeouts_owned = timeouts.clone();
        match tls_mode {
            TlsMode::Required => {
                Self::connect_implicit_tls(
                    host,
                    port,
                    tls_config,
                    connect_timeout,
                    tls_timeout,
                    timeouts_owned,
                )
                .await
            }
            TlsMode::None => {
                Self::connect_plaintext(host, port, connect_timeout, timeouts_owned).await
            }
            TlsMode::StarttlsUnsafe => {
                Self::connect_starttls(
                    host,
                    port,
                    tls_config,
                    connect_timeout,
                    tls_timeout,
                    timeouts_owned,
                )
                .await
            }
        }
    }

    async fn connect_implicit_tls(
        host: &str,
        port: u16,
        tls_config: Arc<ClientConfig>,
        connect_timeout: Duration,
        tls_timeout: Duration,
        timeouts: TimeoutsConfig,
    ) -> Result<Self> {
        let tcp = timeout(connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| FerromailError::ImapError("TCP connect timed out".into()))?
            .map_err(|e| FerromailError::ImapError(format!("TCP connect failed: {e}")))?;

        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| FerromailError::TlsError(format!("invalid server name: {e}")))?;

        let connector = TlsConnector::from(tls_config);
        let tls_stream = timeout(tls_timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| FerromailError::TlsError("TLS handshake timed out".into()))?
            .map_err(|e| FerromailError::TlsError(format!("TLS handshake failed: {e}")))?;

        let mut client = async_imap::Client::new(tls_stream);

        let greeting = client
            .read_response()
            .await
            .ok_or_else(|| FerromailError::ImapError("no greeting from server".into()))?
            .map_err(|e| FerromailError::ImapError(format!("failed to read greeting: {e}")))?;

        verify_greeting_parsed(greeting.parsed(), host, true)?;

        Ok(Self {
            state: InnerState::PreAuthTls(client),
            consecutive_login_failures: 0,
            host: host.to_string(),
            timeouts,
        })
    }

    async fn connect_plaintext(
        host: &str,
        port: u16,
        connect_timeout: Duration,
        timeouts: TimeoutsConfig,
    ) -> Result<Self> {
        let ip = tls::check_loopback(host).await?;

        let tcp = timeout(connect_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| FerromailError::ImapError("TCP connect timed out".into()))?
            .map_err(|e| FerromailError::ImapError(format!("TCP connect failed: {e}")))?;

        let mut client = async_imap::Client::new(tcp);

        let greeting = client
            .read_response()
            .await
            .ok_or_else(|| FerromailError::ImapError("no greeting from server".into()))?
            .map_err(|e| FerromailError::ImapError(format!("failed to read greeting: {e}")))?;

        verify_greeting_parsed(greeting.parsed(), host, false)?;

        Ok(Self {
            state: InnerState::PreAuthPlain(client),
            consecutive_login_failures: 0,
            host: host.to_string(),
            timeouts,
        })
    }

    async fn connect_starttls(
        host: &str,
        port: u16,
        tls_config: Arc<ClientConfig>,
        connect_timeout: Duration,
        tls_timeout: Duration,
        timeouts: TimeoutsConfig,
    ) -> Result<Self> {
        let tcp = timeout(connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| FerromailError::ImapError("TCP connect timed out".into()))?
            .map_err(|e| FerromailError::ImapError(format!("TCP connect failed: {e}")))?;

        let mut client = async_imap::Client::new(tcp);

        let greeting = client
            .read_response()
            .await
            .ok_or_else(|| FerromailError::ImapError("no greeting from server".into()))?
            .map_err(|e| FerromailError::ImapError(format!("failed to read greeting: {e}")))?;

        verify_greeting_parsed(greeting.parsed(), host, false)?;

        client
            .run_command_and_check_ok("STARTTLS", None)
            .await
            .map_err(|e| {
                tracing::warn!(
                    host = host,
                    "STARTTLS rejected by server — possible stripping attack or misconfigured server"
                );
                FerromailError::TlsError(format!("STARTTLS command failed: {e}"))
            })?;

        let tcp_stream = client.into_inner();

        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| FerromailError::TlsError(format!("invalid server name: {e}")))?;

        let connector = TlsConnector::from(tls_config);
        let tls_stream = timeout(tls_timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| FerromailError::TlsError("TLS handshake timed out".into()))?
            .map_err(|e| FerromailError::TlsError(format!("TLS handshake failed: {e}")))?;

        // Discard pre-TLS state, start fresh protocol session
        let mut tls_client = async_imap::Client::new(tls_stream);

        // Re-request CAPABILITY after STARTTLS per spec section 11.3.3
        tls_client
            .run_command_and_check_ok("CAPABILITY", None)
            .await
            .map_err(|e| {
                FerromailError::ImapError(format!("post-STARTTLS CAPABILITY failed: {e}"))
            })?;

        Ok(Self {
            state: InnerState::PreAuthTls(tls_client),
            consecutive_login_failures: 0,
            host: host.to_string(),
            timeouts,
        })
    }

    pub async fn login(
        &mut self,
        username: &str,
        password: &SecretString,
        timeout_secs: u64,
    ) -> Result<()> {
        let login_timeout = Duration::from_secs(timeout_secs);

        let old_state = std::mem::replace(&mut self.state, InnerState::Consumed);

        match old_state {
            InnerState::PreAuthTls(client) => {
                let session = timeout(
                    login_timeout,
                    client.login(username, password.expose_secret()),
                )
                .await
                .map_err(|_| {
                    self.consecutive_login_failures += 1;
                    FerromailError::ImapError("LOGIN timed out".into())
                })?
                .map_err(|(e, client)| {
                    self.consecutive_login_failures += 1;
                    self.state = InnerState::PreAuthTls(client);
                    FerromailError::ImapError(format!("LOGIN failed: {e}"))
                })?;

                self.consecutive_login_failures = 0;
                self.state = InnerState::AuthTls(session);
                Ok(())
            }
            InnerState::PreAuthPlain(client) => {
                self.state = InnerState::PreAuthPlain(client);
                Err(FerromailError::ImapError(
                    "authentication is disabled for tls=none connections".into(),
                ))
            }
            auth @ (InnerState::AuthTls(_) | InnerState::AuthPlain(_)) => {
                self.state = auth;
                Err(FerromailError::ImapError("already authenticated".into()))
            }
            InnerState::Consumed => Err(FerromailError::ImapError(
                "connection has been consumed".into(),
            )),
        }
    }

    pub async fn select(&mut self, mailbox: &str) -> Result<()> {
        let op_timeout = Duration::from_secs(self.timeouts.metadata_fetch);
        match &mut self.state {
            InnerState::AuthTls(session) => {
                timeout(op_timeout, session.select(mailbox))
                    .await
                    .map_err(|_| FerromailError::ImapError("SELECT timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("SELECT failed: {e}")))?;
            }
            InnerState::AuthPlain(session) => {
                timeout(op_timeout, session.select(mailbox))
                    .await
                    .map_err(|_| FerromailError::ImapError("SELECT timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("SELECT failed: {e}")))?;
            }
            _ => {
                return Err(FerromailError::ImapError(
                    "not authenticated — cannot SELECT".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn uid_search(&mut self, query: &str) -> Result<Vec<u32>> {
        let op_timeout = Duration::from_secs(self.timeouts.metadata_fetch);
        let result = match &mut self.state {
            InnerState::AuthTls(s) => timeout(op_timeout, s.uid_search(query))
                .await
                .map_err(|_| FerromailError::ImapError("UID SEARCH timed out".into()))?
                .map_err(|e| FerromailError::ImapError(format!("UID SEARCH failed: {e}")))?,
            InnerState::AuthPlain(s) => timeout(op_timeout, s.uid_search(query))
                .await
                .map_err(|_| FerromailError::ImapError("UID SEARCH timed out".into()))?
                .map_err(|e| FerromailError::ImapError(format!("UID SEARCH failed: {e}")))?,
            _ => return Err(FerromailError::ImapError("not authenticated".into())),
        };

        let uids: Vec<u32> = result.into_iter().collect();
        if uids.len() > MAX_SEARCH_UIDS {
            return Err(FerromailError::ProtocolViolation(format!(
                "UID SEARCH returned {} items (limit {MAX_SEARCH_UIDS}) — possible server abuse",
                uids.len()
            )));
        }
        Ok(uids)
    }

    /// UID FETCH with a per-item stream cap. `items` selects the FETCH
    /// macro (e.g. "(UID FLAGS ENVELOPE BODYSTRUCTURE)" or
    /// "(UID FLAGS ENVELOPE BODY[])"). The body_fetch timeout is used when
    /// `items` contains BODY[, otherwise metadata_fetch.
    pub async fn uid_fetch(
        &mut self,
        uid_range: &str,
        items: &str,
    ) -> Result<Vec<async_imap::types::Fetch>> {
        let op_timeout = Duration::from_secs(if items.contains("BODY[") {
            self.timeouts.body_fetch
        } else {
            self.timeouts.metadata_fetch
        });

        async fn collect_capped<S>(mut stream: S) -> Result<Vec<async_imap::types::Fetch>>
        where
            S: futures::Stream<
                    Item = std::result::Result<async_imap::types::Fetch, async_imap::error::Error>,
                > + Unpin,
        {
            use futures::StreamExt;
            let mut out = Vec::new();
            while let Some(item) = stream.next().await {
                let fetch = item.map_err(|e| {
                    FerromailError::ImapError(format!("failed to read fetch result: {e}"))
                })?;
                out.push(fetch);
                if out.len() > MAX_FETCH_ITEMS {
                    return Err(FerromailError::ProtocolViolation(format!(
                        "UID FETCH stream exceeded {MAX_FETCH_ITEMS} items — possible server abuse"
                    )));
                }
            }
            Ok(out)
        }

        match &mut self.state {
            InnerState::AuthTls(s) => {
                let stream = timeout(op_timeout, s.uid_fetch(uid_range, items))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID FETCH timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("UID FETCH failed: {e}")))?;
                timeout(op_timeout, collect_capped(stream))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID FETCH stream timed out".into()))?
            }
            InnerState::AuthPlain(s) => {
                let stream = timeout(op_timeout, s.uid_fetch(uid_range, items))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID FETCH timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("UID FETCH failed: {e}")))?;
                timeout(op_timeout, collect_capped(stream))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID FETCH stream timed out".into()))?
            }
            _ => Err(FerromailError::ImapError("not authenticated".into())),
        }
    }

    pub async fn store_flags(&mut self, uid_set: &str, flags: &str) -> Result<()> {
        use futures::TryStreamExt;
        let op_timeout = Duration::from_secs(self.timeouts.metadata_fetch);
        match &mut self.state {
            InnerState::AuthTls(s) => {
                let stream = timeout(op_timeout, s.uid_store(uid_set, flags))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID STORE timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("UID STORE failed: {e}")))?;
                let _: Vec<_> = timeout(op_timeout, stream.try_collect())
                    .await
                    .map_err(|_| FerromailError::ImapError("UID STORE collect timed out".into()))?
                    .map_err(|e| {
                        FerromailError::ImapError(format!("UID STORE collect failed: {e}"))
                    })?;
                Ok(())
            }
            InnerState::AuthPlain(s) => {
                let stream = timeout(op_timeout, s.uid_store(uid_set, flags))
                    .await
                    .map_err(|_| FerromailError::ImapError("UID STORE timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("UID STORE failed: {e}")))?;
                let _: Vec<_> = timeout(op_timeout, stream.try_collect())
                    .await
                    .map_err(|_| FerromailError::ImapError("UID STORE collect timed out".into()))?
                    .map_err(|e| {
                        FerromailError::ImapError(format!("UID STORE collect failed: {e}"))
                    })?;
                Ok(())
            }
            _ => Err(FerromailError::ImapError("not authenticated".into())),
        }
    }

    pub async fn expunge(&mut self) -> Result<()> {
        use futures::TryStreamExt;
        let op_timeout = Duration::from_secs(self.timeouts.metadata_fetch);
        match &mut self.state {
            InnerState::AuthTls(s) => {
                let stream = timeout(op_timeout, s.expunge())
                    .await
                    .map_err(|_| FerromailError::ImapError("EXPUNGE timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("EXPUNGE failed: {e}")))?;
                let _: Vec<_> = timeout(op_timeout, stream.try_collect())
                    .await
                    .map_err(|_| FerromailError::ImapError("EXPUNGE collect timed out".into()))?
                    .map_err(|e| {
                        FerromailError::ImapError(format!("EXPUNGE collect failed: {e}"))
                    })?;
                Ok(())
            }
            InnerState::AuthPlain(s) => {
                let stream = timeout(op_timeout, s.expunge())
                    .await
                    .map_err(|_| FerromailError::ImapError("EXPUNGE timed out".into()))?
                    .map_err(|e| FerromailError::ImapError(format!("EXPUNGE failed: {e}")))?;
                let _: Vec<_> = timeout(op_timeout, stream.try_collect())
                    .await
                    .map_err(|_| FerromailError::ImapError("EXPUNGE collect timed out".into()))?
                    .map_err(|e| {
                        FerromailError::ImapError(format!("EXPUNGE collect failed: {e}"))
                    })?;
                Ok(())
            }
            _ => Err(FerromailError::ImapError("not authenticated".into())),
        }
    }

    pub async fn fetch_raw(&mut self, uid: &str) -> Result<Vec<u8>> {
        // fetch_raw is only called for attachment download; it uses body_fetch
        // timeout via uid_fetch's BODY[ detection.
        let fetches = self.uid_fetch(uid, "BODY[]").await?;
        let fetch = fetches
            .into_iter()
            .next()
            .ok_or_else(|| FerromailError::ImapError(format!("no data returned for UID {uid}")))?;
        fetch
            .body()
            .map(|b| b.to_vec())
            .ok_or_else(|| FerromailError::ImapError(format!("no body returned for UID {uid}")))
    }

    pub fn consecutive_login_failures(&self) -> u32 {
        self.consecutive_login_failures
    }
}

pub async fn connect_and_login(
    host: &str,
    port: u16,
    tls_mode: &TlsMode,
    tls_config: Arc<ClientConfig>,
    timeouts: &TimeoutsConfig,
    username: &str,
    password: &SecretString,
) -> Result<ImapClient> {
    let mut client =
        ImapClient::connect(host, port, tls_mode.clone(), tls_config, timeouts).await?;
    client.login(username, password, timeouts.login).await?;
    Ok(client)
}

fn verify_greeting_parsed(
    response: &imap_proto::Response<'_>,
    host: &str,
    is_encrypted: bool,
) -> Result<()> {
    let greeting_debug = format!("{response:?}");
    check_response_for_referral(&greeting_debug);

    match response {
        imap_proto::Response::Data {
            status: imap_proto::Status::Ok,
            ..
        } => Ok(()),
        imap_proto::Response::Data {
            status: imap_proto::Status::PreAuth,
            ..
        } => {
            if is_encrypted {
                tracing::info!(
                    host = host,
                    "Received PREAUTH on implicit TLS connection — unusual but not dangerous"
                );
                Ok(())
            } else {
                tracing::warn!(
                    host = host,
                    "Received PREAUTH on unencrypted connection — possible attack to prevent TLS"
                );
                Err(FerromailError::ProtocolViolation(
                    "PREAUTH received on unencrypted connection".into(),
                ))
            }
        }
        imap_proto::Response::Data {
            status: imap_proto::Status::Bye,
            information,
            ..
        } => {
            let info = information.as_deref().unwrap_or("no reason given");
            Err(FerromailError::ImapError(format!(
                "server sent BYE during greeting: {info}"
            )))
        }
        _ => Err(FerromailError::ProtocolViolation(
            "Post-TLS protocol mismatch — possible Opossum desynchronization".into(),
        )),
    }
}

pub fn check_response_for_referral(response_text: &str) {
    if let Some(pos) = response_text.find("[REFERRAL") {
        let referral_end = response_text[pos..]
            .find(']')
            .map(|end| &response_text[pos..pos + end + 1])
            .unwrap_or("[REFERRAL ...]");
        tracing::warn!(
            referral = referral_end,
            "Server sent IMAP referral — ignored. ferromail never follows referrals."
        );
    }
}
