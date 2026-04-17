use ferromail::config::{AccountConfig, Config, ImapConfig, SmtpConfig, TlsMode};
use ferromail::credential::CredentialBackend;
use ferromail::tls::build_tls_config;
use ferromail::types::{FerromailError, Result};
use secrecy::SecretString;
use std::io::{self, Write};
use tracing::info;

fn prompt(msg: &str) -> Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    let input = prompt(&format!("{msg} [{default}]: "))?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

fn prompt_password(msg: &str) -> Result<SecretString> {
    let pass = rpassword::prompt_password(msg)
        .map_err(|e| FerromailError::ConfigError(format!("Password input error: {e}")))?;
    Ok(SecretString::from(pass))
}

fn prompt_tls_mode(protocol: &str) -> Result<TlsMode> {
    let input = prompt_default(
        &format!("{protocol} TLS mode (required/starttls-unsafe/none)"),
        "required",
    )?;
    match input.as_str() {
        "required" => Ok(TlsMode::Required),
        "starttls-unsafe" => Ok(TlsMode::StarttlsUnsafe),
        "none" => Ok(TlsMode::None),
        _ => Err(FerromailError::ConfigError(format!(
            "Invalid TLS mode: {input}"
        ))),
    }
}

pub fn add(name: &str, config: &mut Config, creds: &CredentialBackend) -> Result<()> {
    if config.accounts.iter().any(|a| a.name == name) {
        return Err(FerromailError::ConfigError(format!(
            "Account '{name}' already exists"
        )));
    }

    eprintln!("Adding email account: {name}");

    let email = prompt("Email address: ")?;
    let full_name = prompt_default("Full name", email.split('@').next().unwrap_or(&email))?;

    eprintln!("\n--- IMAP Settings ---");
    let imap_host = prompt("IMAP host: ")?;
    let imap_port: u16 = prompt_default("IMAP port", "993")?
        .parse()
        .map_err(|_| FerromailError::ConfigError("Invalid port number".into()))?;
    let imap_tls = prompt_tls_mode("IMAP")?;
    let imap_password = prompt_password("IMAP password: ")?;

    eprintln!("\n--- SMTP Settings ---");
    let smtp_host = prompt("SMTP host: ")?;
    let smtp_port: u16 = prompt_default("SMTP port", "465")?
        .parse()
        .map_err(|_| FerromailError::ConfigError("Invalid port number".into()))?;
    let smtp_tls = prompt_tls_mode("SMTP")?;
    let smtp_password = prompt_password("SMTP password: ")?;

    creds.store(name, "imap", &imap_password)?;
    creds.store(name, "smtp", &smtp_password)?;

    let account = AccountConfig {
        name: name.to_string(),
        email_address: email,
        full_name,
        imap: ImapConfig {
            host: imap_host,
            port: imap_port,
            tls: imap_tls,
            verify_certs: true,
            min_tls_version: "1.2".into(),
        },
        smtp: SmtpConfig {
            host: smtp_host,
            port: smtp_port,
            tls: smtp_tls,
            verify_certs: true,
            min_tls_version: "1.2".into(),
            save_to_sent: true,
            sent_folder: String::new(),
        },
        enabled: true,
        send_as: Vec::new(),
        default_from: String::new(),
        auth_method: ferromail::oauth::AuthMethod::Password,
        oauth: None,
    };

    config.accounts.push(account);
    config.save()?;

    info!(account = name, "Account added successfully");
    eprintln!("Account '{name}' added. Run `ferromail account test {name}` to verify.");
    Ok(())
}

pub fn remove(name: &str, config: &mut Config, creds: &CredentialBackend) -> Result<()> {
    let idx = config
        .accounts
        .iter()
        .position(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;

    let confirm = prompt(&format!(
        "Remove account '{name}'? This cannot be undone. [y/N]: "
    ))?;
    if confirm.to_lowercase() != "y" {
        eprintln!("Cancelled.");
        return Ok(());
    }

    let _ = creds.delete(name, "imap");
    let _ = creds.delete(name, "smtp");
    config.accounts.remove(idx);
    config.save()?;

    info!(account = name, "Account removed");
    eprintln!("Account '{name}' removed.");
    Ok(())
}

pub fn list(config: &Config) {
    if config.accounts.is_empty() {
        eprintln!("No accounts configured. Run `ferromail account add <name>` to add one.");
        return;
    }

    for account in &config.accounts {
        let status = if account.enabled {
            "enabled"
        } else {
            "DISABLED"
        };
        eprintln!(
            "  {name}  {email}  IMAP: {imap}  SMTP: {smtp}  [{status}]",
            name = account.name,
            email = account.email_address,
            imap = account.imap.host,
            smtp = account.smtp.host,
        );
    }
}

pub async fn test(name: &str, config: &Config, creds: &CredentialBackend) -> Result<()> {
    let account = config
        .accounts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;

    eprintln!("Testing account '{name}'...");

    // Test IMAP
    eprint!("  IMAP ({})... ", account.imap.host);
    io::stderr().flush()?;

    let imap_password = creds.retrieve(name, "imap")?;
    let tls_config = build_tls_config(account.imap.verify_certs, &account.imap.min_tls_version)?;

    match ferromail::imap::client::ImapClient::connect(
        &account.imap.host,
        account.imap.port,
        account.imap.tls.clone(),
        tls_config,
        &config.timeouts,
    )
    .await
    {
        Ok(mut client) => {
            match client
                .login(
                    &account.email_address,
                    &imap_password,
                    config.timeouts.login,
                )
                .await
            {
                Ok(()) => match client.select("INBOX").await {
                    Ok(()) => eprintln!("OK (connected, logged in, INBOX selected)"),
                    Err(e) => eprintln!("WARN (logged in but SELECT INBOX failed: {e})"),
                },
                Err(e) => eprintln!("FAIL (connected but login failed: {e})"),
            }
        }
        Err(e) => eprintln!("FAIL (connection failed: {e})"),
    }

    // Test SMTP
    eprint!("  SMTP ({})... ", account.smtp.host);
    io::stderr().flush()?;

    let _smtp_password = creds.retrieve(name, "smtp")?;
    eprintln!("OK (credentials retrieved; full send test requires a recipient)");

    Ok(())
}

pub fn enable(name: &str, config: &mut Config) -> Result<()> {
    let account = config
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;

    account.enabled = true;
    config.save()?;
    eprintln!("Account '{name}' enabled.");
    Ok(())
}

pub fn disable(name: &str, config: &mut Config) -> Result<()> {
    let account = config
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;

    account.enabled = false;
    config.save()?;
    eprintln!("Account '{name}' disabled.");
    Ok(())
}

pub fn edit(name: &str, config: &mut Config, creds: &CredentialBackend) -> Result<()> {
    let idx = config
        .accounts
        .iter()
        .position(|a| a.name == name)
        .ok_or_else(|| FerromailError::AccountNotFound(name.into()))?;

    let current = config.accounts[idx].clone();
    eprintln!(
        "Editing account '{name}'. Press Enter to keep the current value shown in [brackets]."
    );

    let email = prompt_default("Email address", &current.email_address)?;
    let full_name = prompt_default("Full name", &current.full_name)?;

    eprintln!("\n--- IMAP Settings ---");
    let imap_host = prompt_default("IMAP host", &current.imap.host)?;
    let imap_port: u16 = prompt_default("IMAP port", &current.imap.port.to_string())?
        .parse()
        .map_err(|_| FerromailError::ConfigError("Invalid port number".into()))?;
    let imap_tls = prompt_tls_mode_default("IMAP", &current.imap.tls)?;
    let imap_verify = prompt_bool("IMAP verify certificates", current.imap.verify_certs)?;
    let imap_min_tls = prompt_default("IMAP min TLS version", &current.imap.min_tls_version)?;
    let change_imap_password = prompt_bool("Update IMAP password?", false)?;
    if change_imap_password {
        let pass = prompt_password("New IMAP password: ")?;
        creds.store(name, "imap", &pass)?;
    }

    eprintln!("\n--- SMTP Settings ---");
    let smtp_host = prompt_default("SMTP host", &current.smtp.host)?;
    let smtp_port: u16 = prompt_default("SMTP port", &current.smtp.port.to_string())?
        .parse()
        .map_err(|_| FerromailError::ConfigError("Invalid port number".into()))?;
    let smtp_tls = prompt_tls_mode_default("SMTP", &current.smtp.tls)?;
    let smtp_verify = prompt_bool("SMTP verify certificates", current.smtp.verify_certs)?;
    let smtp_min_tls = prompt_default("SMTP min TLS version", &current.smtp.min_tls_version)?;
    let save_to_sent = prompt_bool("Save sent mail to Sent folder?", current.smtp.save_to_sent)?;
    let sent_folder = prompt_default("Sent folder (blank = auto)", &current.smtp.sent_folder)?;
    let change_smtp_password = prompt_bool("Update SMTP password?", false)?;
    if change_smtp_password {
        let pass = prompt_password("New SMTP password: ")?;
        creds.store(name, "smtp", &pass)?;
    }

    let updated = AccountConfig {
        name: current.name.clone(),
        email_address: email,
        full_name,
        imap: ImapConfig {
            host: imap_host,
            port: imap_port,
            tls: imap_tls,
            verify_certs: imap_verify,
            min_tls_version: imap_min_tls,
        },
        smtp: SmtpConfig {
            host: smtp_host,
            port: smtp_port,
            tls: smtp_tls,
            verify_certs: smtp_verify,
            min_tls_version: smtp_min_tls,
            save_to_sent,
            sent_folder,
        },
        enabled: current.enabled,
        send_as: current.send_as.clone(),
        default_from: current.default_from.clone(),
        auth_method: current.auth_method.clone(),
        oauth: current.oauth.clone(),
    };

    config.accounts[idx] = updated;
    config.save()?;
    info!(account = name, "Account edited successfully");
    eprintln!("Account '{name}' updated.");
    Ok(())
}

fn prompt_bool(msg: &str, default: bool) -> Result<bool> {
    let default_str = if default { "y" } else { "n" };
    let input = prompt(&format!("{msg} [{default_str}]: "))?;
    if input.is_empty() {
        return Ok(default);
    }
    Ok(matches!(
        input.to_ascii_lowercase().as_str(),
        "y" | "yes" | "true" | "1"
    ))
}

fn prompt_tls_mode_default(protocol: &str, default: &TlsMode) -> Result<TlsMode> {
    let default_str = match default {
        TlsMode::Required => "required",
        TlsMode::StarttlsUnsafe => "starttls-unsafe",
        TlsMode::None => "none",
    };
    let input = prompt_default(
        &format!("{protocol} TLS mode (required/starttls-unsafe/none)"),
        default_str,
    )?;
    match input.as_str() {
        "required" => Ok(TlsMode::Required),
        "starttls-unsafe" => Ok(TlsMode::StarttlsUnsafe),
        "none" => Ok(TlsMode::None),
        _ => Err(FerromailError::ConfigError(format!(
            "Invalid TLS mode: {input}"
        ))),
    }
}
