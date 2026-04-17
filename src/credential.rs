use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::types::{FerromailError, Result};

pub trait CredentialStore {
    fn store(&self, account: &str, protocol: &str, password: &SecretString) -> Result<()>;
    fn retrieve(&self, account: &str, protocol: &str) -> Result<SecretString>;
    fn delete(&self, account: &str, protocol: &str) -> Result<()>;
}

pub struct KeyringBackend;

impl KeyringBackend {
    fn entry(account: &str, protocol: &str) -> Result<keyring::Entry> {
        let service = format!("ferromail/{account}/{protocol}_password");
        keyring::Entry::new(&service, account)
            .map_err(|e| FerromailError::CredentialError(e.to_string()))
    }
}

impl CredentialStore for KeyringBackend {
    fn store(&self, account: &str, protocol: &str, password: &SecretString) -> Result<()> {
        let entry = Self::entry(account, protocol)?;
        entry
            .set_password(password.expose_secret())
            .map_err(|e| FerromailError::CredentialError(e.to_string()))
    }

    fn retrieve(&self, account: &str, protocol: &str) -> Result<SecretString> {
        let entry = Self::entry(account, protocol)?;
        let password = entry
            .get_password()
            .map_err(|e| FerromailError::CredentialError(e.to_string()))?;
        Ok(SecretString::from(password))
    }

    fn delete(&self, account: &str, protocol: &str) -> Result<()> {
        let entry = Self::entry(account, protocol)?;
        entry
            .delete_credential()
            .map_err(|e| FerromailError::CredentialError(e.to_string()))
    }
}

#[derive(Serialize, Deserialize, Default)]
struct AgeVault {
    accounts: HashMap<String, HashMap<String, String>>,
}

pub struct AgeFileBackend {
    path: PathBuf,
}

impl AgeFileBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_vault(&self, passphrase: &SecretString) -> Result<AgeVault> {
        if !self.path.exists() {
            return Ok(AgeVault::default());
        }

        let ciphertext = fs::read(&self.path)?;
        if ciphertext.is_empty() {
            return Ok(AgeVault::default());
        }

        let identity = age::scrypt::Identity::new(passphrase.clone());
        let mut plaintext = age::decrypt(&identity, &ciphertext)
            .map_err(|e| FerromailError::CredentialError(format!("age decrypt: {e}")))?;

        let vault: AgeVault = serde_json::from_slice(&plaintext)
            .map_err(|e| FerromailError::CredentialError(format!("vault parse: {e}")))?;

        plaintext.zeroize();
        Ok(vault)
    }

    fn write_vault(&self, vault: &AgeVault, passphrase: &SecretString) -> Result<()> {
        let mut json = serde_json::to_vec(vault)
            .map_err(|e| FerromailError::CredentialError(format!("vault serialize: {e}")))?;

        let recipient = age::scrypt::Recipient::new(passphrase.clone());
        let ciphertext = age::encrypt(&recipient, &json)
            .map_err(|e| FerromailError::CredentialError(format!("age encrypt: {e}")))?;

        json.zeroize();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, &ciphertext)?;
        Ok(())
    }

    fn prompt_passphrase() -> Result<SecretString> {
        let pass = rpassword::prompt_password("Age vault passphrase: ")
            .map_err(|e| FerromailError::CredentialError(format!("passphrase prompt: {e}")))?;
        Ok(SecretString::from(pass))
    }
}

impl CredentialStore for AgeFileBackend {
    fn store(&self, account: &str, protocol: &str, password: &SecretString) -> Result<()> {
        let passphrase = Self::prompt_passphrase()?;
        let mut vault = self.read_vault(&passphrase)?;

        let key = format!("{protocol}_password");
        vault
            .accounts
            .entry(account.to_owned())
            .or_default()
            .insert(key, password.expose_secret().to_owned());

        self.write_vault(&vault, &passphrase)?;
        Ok(())
    }

    fn retrieve(&self, account: &str, protocol: &str) -> Result<SecretString> {
        let passphrase = Self::prompt_passphrase()?;
        let vault = self.read_vault(&passphrase)?;

        let key = format!("{protocol}_password");
        let value = vault
            .accounts
            .get(account)
            .and_then(|m| m.get(&key))
            .ok_or_else(|| {
                FerromailError::CredentialError(format!(
                    "no {protocol} credential for account '{account}'"
                ))
            })?;

        Ok(SecretString::from(value.clone()))
    }

    fn delete(&self, account: &str, protocol: &str) -> Result<()> {
        let passphrase = Self::prompt_passphrase()?;
        let mut vault = self.read_vault(&passphrase)?;

        let key = format!("{protocol}_password");
        if let Some(acct) = vault.accounts.get_mut(account) {
            acct.remove(&key);
            if acct.is_empty() {
                vault.accounts.remove(account);
            }
        }

        self.write_vault(&vault, &passphrase)?;
        Ok(())
    }
}

enum Inner {
    Keyring(KeyringBackend),
    AgeFile(AgeFileBackend),
}

/// Credential backend with an optional in-memory ephemeral overlay.
///
/// The overlay takes precedence over the persistent backend during
/// `retrieve`, so credentials sourced from `FERROMAIL_*` env vars at
/// startup never touch the keyring or the encrypted file. The overlay
/// lives only for the process lifetime; `SecretString` zeroizes on drop.
pub struct CredentialBackend {
    inner: Inner,
    ephemeral: Mutex<HashMap<(String, String), SecretString>>,
}

impl CredentialBackend {
    pub fn from_config(config: &crate::config::CredentialsConfig) -> Self {
        let inner = match config.backend.as_str() {
            "age-file" => {
                let config_dir =
                    crate::config::Config::config_dir().unwrap_or_else(|_| PathBuf::from("."));
                Inner::AgeFile(AgeFileBackend::new(config_dir.join("credentials.age")))
            }
            _ => Inner::Keyring(KeyringBackend),
        };
        Self {
            inner,
            ephemeral: Mutex::new(HashMap::new()),
        }
    }

    /// Seed the in-memory overlay. Used for env-var bootstrap so that
    /// `FERROMAIL_*_PASSWORD` never reaches the persistent store.
    pub fn set_ephemeral(&self, account: &str, protocol: &str, password: SecretString) {
        let mut map = self.ephemeral.lock().expect("ephemeral map mutex poisoned");
        map.insert((account.to_string(), protocol.to_string()), password);
    }

    pub fn store(&self, account: &str, protocol: &str, password: &SecretString) -> Result<()> {
        match &self.inner {
            Inner::Keyring(b) => b.store(account, protocol, password),
            Inner::AgeFile(b) => b.store(account, protocol, password),
        }
    }

    pub fn retrieve(&self, account: &str, protocol: &str) -> Result<SecretString> {
        {
            let map = self.ephemeral.lock().expect("ephemeral map mutex poisoned");
            if let Some(secret) = map.get(&(account.to_string(), protocol.to_string())) {
                return Ok(secret.clone());
            }
        }
        match &self.inner {
            Inner::Keyring(b) => b.retrieve(account, protocol),
            Inner::AgeFile(b) => b.retrieve(account, protocol),
        }
    }

    pub fn delete(&self, account: &str, protocol: &str) -> Result<()> {
        {
            let mut map = self.ephemeral.lock().expect("ephemeral map mutex poisoned");
            map.remove(&(account.to_string(), protocol.to_string()));
        }
        match &self.inner {
            Inner::Keyring(b) => b.delete(account, protocol),
            Inner::AgeFile(b) => b.delete(account, protocol),
        }
    }
}
