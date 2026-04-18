#![deny(unsafe_code)]
#![allow(dead_code)]

mod account;

use clap::{Parser, Subcommand};
use ferromail::audit;
use ferromail::config::Config;
use ferromail::credential::CredentialBackend;
use ferromail::gate::{ConfirmationChannel, ConfirmationGate};
use ferromail::rate_limit;
use ferromail::sandbox;
use ferromail::tools;
use ferromail::transport;
use ferromail::types;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ferromail", version, about = "Hardened IMAP/SMTP MCP server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive first-time setup
    Init,

    /// Manage email accounts
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },

    /// Start the MCP server
    Serve {
        /// Transport type
        #[arg(long, default_value = "stdio")]
        transport: String,

        /// Bind host (SSE/HTTP only)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Bind port (SSE/HTTP only)
        #[arg(long, default_value = "9557")]
        port: u16,

        /// Acknowledge network exposure risk
        #[arg(long)]
        i_understand_network_exposure: bool,
    },

    /// Print version
    Version,

    /// Check file permission security
    CheckPermissions,
}

#[derive(Subcommand)]
enum AccountAction {
    /// Add a new email account
    Add { name: String },
    /// Remove an email account
    Rm { name: String },
    /// Edit an email account
    Edit { name: String },
    /// List configured accounts
    List,
    /// Test account connectivity
    Test { name: String },
    /// Enable a disabled account
    Enable { name: String },
    /// Disable an account
    Disable { name: String },
}

/// Narrowly-scoped `unsafe` for the process-startup hardening calls. Each
/// line here is a one-shot libc call with no aliasing or memory concerns; the
/// allow is on this helper only so the rest of the binary stays `deny`.
#[allow(unsafe_code)]
fn apply_process_hardening() {
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no preconditions; return value is
    // advisory. Called once on the main thread before any secrets exist.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    #[cfg(unix)]
    // SAFETY: setrlimit(RLIMIT_CORE, ..) takes a pointer to a fully-initialized
    // rlimit we own on the stack; kernel copies it.
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
    }
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
}

fn main() {
    apply_process_hardening();

    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!("ferromail {}", env!("CARGO_PKG_VERSION"));
        }

        Commands::Init => {
            if let Err(e) = run_init() {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }

        Commands::CheckPermissions => match Config::load() {
            Ok(_) => eprintln!("All permission checks passed."),
            Err(e) => {
                eprintln!("Permission check failed: {e}");
                std::process::exit(1);
            }
        },

        Commands::Account { action } => {
            let mut config = match Config::load() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading config: {e}");
                    std::process::exit(1);
                }
            };

            let creds = CredentialBackend::from_config(&config.credentials);

            let rt = build_runtime();
            let result = rt.block_on(async {
                match action {
                    AccountAction::Add { name } => account::add(&name, &mut config, &creds),
                    AccountAction::Rm { name } => account::remove(&name, &mut config, &creds),
                    AccountAction::Edit { name } => account::edit(&name, &mut config, &creds),
                    AccountAction::List => {
                        account::list(&config);
                        Ok(())
                    }
                    AccountAction::Test { name } => account::test(&name, &config, &creds).await,
                    AccountAction::Enable { name } => account::enable(&name, &mut config),
                    AccountAction::Disable { name } => account::disable(&name, &mut config),
                }
            });

            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }

        Commands::Serve {
            transport: transport_type,
            host,
            port,
            i_understand_network_exposure,
        } => {
            let config = match Config::load() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading config: {e}");
                    std::process::exit(1);
                }
            };

            setup_tracing(&config.logging.level, &config.logging.format);

            let config_dir = Config::config_dir().unwrap_or_else(|e| {
                eprintln!("Error finding config dir: {e}");
                std::process::exit(1);
            });
            let download_dir = shellexpand(&config.attachments.download_dir);
            let send_allow_dirs: Vec<std::path::PathBuf> = config
                .attachments
                .send_allow_dirs
                .iter()
                .map(|d| shellexpand(d))
                .collect();

            // Apply OS sandbox before tokio starts so its worker threads,
            // spawned via clone(), inherit both the Landlock domain and the
            // seccomp filter.
            #[cfg(target_os = "linux")]
            {
                let sbx = ferromail::os_sandbox::SandboxConfig {
                    config_dir: config_dir.clone(),
                    download_dir: download_dir.clone(),
                    send_allow_dirs: send_allow_dirs.clone(),
                };
                if let Err(e) = ferromail::os_sandbox::apply(&sbx) {
                    eprintln!("OS sandbox init failed: {e}");
                    std::process::exit(1);
                }
            }

            let rt = build_runtime();
            rt.block_on(serve_main(
                config,
                config_dir,
                download_dir,
                send_allow_dirs,
                transport_type,
                host,
                port,
                i_understand_network_exposure,
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_main(
    mut config: Config,
    config_dir: std::path::PathBuf,
    download_dir: std::path::PathBuf,
    send_allow_dirs: Vec<std::path::PathBuf>,
    transport_type: String,
    host: String,
    port: u16,
    i_understand_network_exposure: bool,
) {
    let creds = CredentialBackend::from_config(&config.credentials);

    // Apply FERROMAIL_* env-var overrides: zero and unset the env
    // vars, seed the credential overlay with the extracted passwords.
    match config.apply_env_overrides() {
        Ok(Some(env_creds)) => {
            use secrecy::SecretString;
            creds.set_ephemeral(
                &env_creds.account_name,
                "imap",
                SecretString::from(env_creds.imap_password.clone()),
            );
            creds.set_ephemeral(
                &env_creds.account_name,
                "smtp",
                SecretString::from(env_creds.smtp_password.clone()),
            );
            drop(env_creds);
            tracing::info!("env-var account override applied");
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error applying env overrides: {e}");
            std::process::exit(1);
        }
    }

    let gate = build_gate(&config.confirmation).unwrap_or_else(|e| {
        eprintln!("Error building confirmation gate: {e}");
        std::process::exit(1);
    });

    let audit_path = config_dir.join(&config.logging.audit_file);
    let audit_log = match audit::AuditLog::new(&audit_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error opening audit log: {e}");
            std::process::exit(1);
        }
    };

    let sandbox = match sandbox::DownloadSandbox::new(
        download_dir,
        config.attachments.max_file_size,
        config.attachments.allowed_extensions.clone(),
        send_allow_dirs,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error initializing download sandbox: {e}");
            std::process::exit(1);
        }
    };

    let ctx = Arc::new(tools::ToolContext {
        config: tokio::sync::RwLock::new(config),
        gate,
        rate_limiter: Arc::new(Mutex::new(rate_limit::RateLimiter::default())),
        audit: Arc::new(Mutex::new(audit_log)),
        sandbox,
        credentials: creds,
        login_gate: ferromail::login_gate::LoginGate::new(),
    });

    let result = match transport_type.as_str() {
        "stdio" => transport::stdio::serve(ctx).await,
        "sse" | "streamable-http" => {
            transport::http::serve(&host, port, ctx, i_understand_network_exposure).await
        }
        _ => {
            eprintln!("Unknown transport: {transport_type}. Use stdio, sse, or streamable-http.");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

fn run_init() -> types::Result<()> {
    let config_dir = Config::config_dir()?;
    std::fs::create_dir_all(&config_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let config_path = config_dir.join("config.toml");
    if config_path.exists() {
        eprintln!("Config already exists at {}", config_path.display());
        return Ok(());
    }

    let default_config = Config::default();
    let toml_str = toml::to_string_pretty(&default_config)
        .map_err(|e| types::FerromailError::ConfigError(format!("Serialization error: {e}")))?;
    std::fs::write(&config_path, toml_str)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("Created config at {}", config_path.display());
    eprintln!("Next: run `ferromail account add <name>` to add an email account.");
    Ok(())
}

fn setup_tracing(level: &str, format: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
    }
}

fn shellexpand(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    std::path::PathBuf::from(path)
}

fn build_gate(conf: &ferromail::config::ConfirmationConfig) -> types::Result<ConfirmationGate> {
    match conf.channel.as_str() {
        "terminal" => Ok(ConfirmationGate::new(ConfirmationChannel::Terminal {
            cooldown_seconds: conf.destructive_cooldown_seconds,
        })),
        "webhook" => {
            if conf.webhook_url.is_empty() {
                return Err(types::FerromailError::ConfigError(
                    "[confirmation].channel = \"webhook\" requires webhook_url to be set".into(),
                ));
            }
            if !conf.webhook_url.starts_with("https://")
                && !conf.webhook_url.starts_with("http://localhost")
            {
                return Err(types::FerromailError::ConfigError(format!(
                    "webhook_url must be https:// or http://localhost (got {})",
                    conf.webhook_url
                )));
            }
            Ok(ConfirmationGate::new(ConfirmationChannel::Webhook {
                url: conf.webhook_url.clone(),
                cooldown_seconds: conf.destructive_cooldown_seconds,
                timeout_seconds: conf.timeout_seconds,
            }))
        }
        "none" | "client" => {
            tracing::warn!(
                "confirmation channel = \"none\": ferromail will NOT prompt before \
                 write/destructive operations. The MCP client is the trust boundary. \
                 Only use this under clients (Claude Desktop, Claude Code) that surface \
                 per-tool approval in their own UI."
            );
            Ok(ConfirmationGate::new(ConfirmationChannel::None {
                cooldown_seconds: conf.destructive_cooldown_seconds,
            }))
        }
        other => Err(types::FerromailError::ConfigError(format!(
            "Unknown confirmation channel '{other}': expected 'terminal', 'webhook', or 'none'"
        ))),
    }
}
