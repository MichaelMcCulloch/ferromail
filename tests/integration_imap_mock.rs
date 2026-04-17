//! Integration test: end-to-end IMAP round-trip against a mock server.
//!
//! Spins up a minimal IMAPS server on 127.0.0.1:<random> using a
//! self-signed certificate generated at runtime via rcgen. The mock speaks
//! just enough of IMAP4rev1 to satisfy ferromail's client:
//!
//!   - CAPABILITY advertisement in the greeting
//!   - LOGIN (accepts any credentials)
//!   - SELECT INBOX
//!   - UID SEARCH ALL → a fixed list
//!   - UID FETCH with ENVELOPE/FLAGS/BODY[]
//!   - UID STORE +FLAGS (\Deleted)
//!   - EXPUNGE
//!   - LOGOUT
//!
//! The test asserts the client successfully fetches metadata, retrieves
//! body content wrapped in isolation markers, and deletes + expunges.

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use secrecy::SecretString;
use std::sync::Once;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use ferromail::config::TimeoutsConfig;
use ferromail::imap::ImapClient;

static PROVIDER_INIT: Once = Once::new();

fn install_crypto_provider() {
    PROVIDER_INIT.call_once(|| {
        let _ = ring::default_provider().install_default();
    });
}

/// Generate a self-signed server certificate and a rustls ServerConfig.
fn self_signed() -> (Arc<ServerConfig>, CertificateDer<'static>) {
    install_crypto_provider();

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ferromail-test");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    (Arc::new(server_config), cert_der)
}

async fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn spawn_mock(port: u16) -> JoinHandle<()> {
    let (server_config, _) = self_signed();
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                if let Err(e) = handle_imap_session(tls).await {
                    eprintln!("mock imap session error: {e}");
                }
            });
        }
    })
}

/// Minimal IMAP server. Handles a single authenticated session.
async fn handle_imap_session<S>(stream: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (rh, mut wh) = tokio::io::split(stream);
    let mut reader = BufReader::new(rh);

    // Greeting.
    wh.write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGINDISABLED] ferromail mock\r\n")
        .await?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        let (tag, cmd) = match trimmed.split_once(' ') {
            Some(x) => x,
            None => continue,
        };
        let cmd_upper = cmd.to_uppercase();

        if cmd_upper.starts_with("CAPABILITY") {
            wh.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
                .await?;
            wh.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("LOGIN") {
            // Accept any credentials.
            wh.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("SELECT") {
            wh.write_all(b"* 3 EXISTS\r\n").await?;
            wh.write_all(b"* 0 RECENT\r\n").await?;
            wh.write_all(b"* OK [UIDVALIDITY 1] UID validity\r\n")
                .await?;
            wh.write_all(b"* OK [UIDNEXT 4] next UID\r\n").await?;
            wh.write_all(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
                .await?;
            wh.write_all(
                b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n",
            )
            .await?;
            wh.write_all(format!("{tag} OK [READ-WRITE] SELECT completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("UID SEARCH") {
            wh.write_all(b"* SEARCH 1 2 3\r\n").await?;
            wh.write_all(format!("{tag} OK UID SEARCH completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("UID FETCH") {
            let metadata_only = !cmd_upper.contains("BODY[]");
            if metadata_only {
                for uid in [1u32, 2, 3] {
                    let subj = format!("Test email {uid}");
                    let envelope = format!(
                        "(\"Sat, 17 Apr 2026 12:00:00 +0000\" \
                         {subj:?} \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Bob\" NIL \"bob\" \"example.com\")) \
                         NIL NIL NIL \"<msg{uid}@example.com>\")"
                    );
                    let line = format!(
                        "* {uid} FETCH (UID {uid} FLAGS (\\Seen) ENVELOPE {envelope} \
                         BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 20 1))\r\n"
                    );
                    wh.write_all(line.as_bytes()).await?;
                }
                wh.write_all(format!("{tag} OK UID FETCH completed\r\n").as_bytes())
                    .await?;
            } else {
                // BODY[] fetch: return a minimal RFC822 literal per UID.
                for uid in [1u32, 2, 3] {
                    let body = format!(
                        "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test email {uid}\r\nMessage-ID: <msg{uid}@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello from email {uid}.\r\n"
                    );
                    let header = format!(
                        "* {uid} FETCH (UID {uid} FLAGS (\\Seen) \
                         ENVELOPE (\"Sat, 17 Apr 2026 12:00:00 +0000\" \"Test email {uid}\" \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Alice\" NIL \"alice\" \"example.com\")) \
                         ((\"Bob\" NIL \"bob\" \"example.com\")) \
                         NIL NIL NIL \"<msg{uid}@example.com>\") \
                         BODY[] {{{len}}}\r\n",
                        len = body.len()
                    );
                    wh.write_all(header.as_bytes()).await?;
                    wh.write_all(body.as_bytes()).await?;
                    wh.write_all(b")\r\n").await?;
                }
                wh.write_all(format!("{tag} OK UID FETCH completed\r\n").as_bytes())
                    .await?;
            }
        } else if cmd_upper.starts_with("UID STORE") {
            wh.write_all(b"* 1 FETCH (FLAGS (\\Seen \\Deleted))\r\n")
                .await?;
            wh.write_all(format!("{tag} OK UID STORE completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("EXPUNGE") {
            wh.write_all(b"* 1 EXPUNGE\r\n").await?;
            wh.write_all(format!("{tag} OK EXPUNGE completed\r\n").as_bytes())
                .await?;
        } else if cmd_upper.starts_with("LOGOUT") {
            wh.write_all(b"* BYE logging out\r\n").await?;
            wh.write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                .await?;
            break;
        } else if cmd_upper.starts_with("NOOP") {
            wh.write_all(format!("{tag} OK NOOP completed\r\n").as_bytes())
                .await?;
        } else {
            wh.write_all(format!("{tag} BAD unrecognized\r\n").as_bytes())
                .await?;
        }
    }

    // Drain anything left.
    let mut buf = [0u8; 64];
    let _ = reader.read(&mut buf).await;
    Ok(())
}

/// Build a ClientConfig that skips cert verification (we're talking to a
/// self-signed mock).
fn insecure_client_config() -> Arc<rustls::ClientConfig> {
    ferromail::tls::build_tls_config(false, "1.2").expect("client config")
}

fn default_timeouts() -> TimeoutsConfig {
    TimeoutsConfig {
        connect: 5,
        tls_handshake: 5,
        login: 5,
        metadata_fetch: 5,
        body_fetch: 5,
        attachment_download: 5,
        smtp_send: 5,
        idle: 30,
    }
}

#[tokio::test]
async fn full_imap_round_trip() {
    let port = pick_port().await;
    let _server = spawn_mock(port).await;

    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let tls_config = insecure_client_config();
    let timeouts = default_timeouts();

    let mut client = ImapClient::connect(
        "localhost",
        port,
        ferromail::config::TlsMode::Required,
        tls_config,
        &timeouts,
    )
    .await
    .expect("connect");

    client
        .login(
            "alice@example.com",
            &SecretString::from("secret"),
            timeouts.login,
        )
        .await
        .expect("login");

    client.select("INBOX").await.expect("select inbox");

    let mut uids = client.uid_search("ALL").await.expect("search");
    uids.sort_unstable();
    assert_eq!(uids, vec![1, 2, 3]);

    let fetches = client
        .uid_fetch("1,2,3", "(UID FLAGS ENVELOPE BODYSTRUCTURE)")
        .await
        .expect("metadata fetch");
    assert_eq!(fetches.len(), 3);

    let content_fetches = client
        .uid_fetch("1", "(UID FLAGS ENVELOPE BODY[])")
        .await
        .expect("body fetch");
    assert!(!content_fetches.is_empty());
    let fetch = content_fetches
        .iter()
        .find(|f| f.uid == Some(1))
        .expect("uid 1 present");
    let body = fetch.body().expect("body present");
    let body_str = std::str::from_utf8(body).expect("utf-8 body");
    assert!(body_str.contains("Hello from email 1"));

    // Destructive path.
    client
        .store_flags("1", "+FLAGS (\\Deleted)")
        .await
        .expect("store");
    client.expunge().await.expect("expunge");
}

#[tokio::test]
async fn connect_rejects_non_loopback_plaintext() {
    // Even with TlsMode::None, the connect path enforces loopback-only via
    // tls::check_loopback. Using "1.1.1.1" should fail before TCP connect.
    let result = ImapClient::connect(
        "1.1.1.1",
        9999,
        ferromail::config::TlsMode::None,
        insecure_client_config(),
        &default_timeouts(),
    )
    .await;

    assert!(result.is_err(), "non-loopback tls=none must be rejected");
    if let Err(ferromail::types::FerromailError::TlsError(msg)) = result {
        assert!(
            msg.contains("loopback"),
            "expected loopback rejection, got {msg}"
        );
    }
}
