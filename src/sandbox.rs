use crate::types::{FerromailError, Result};
use std::path::{Path, PathBuf};
use tracing::error;

pub struct DownloadSandbox {
    download_dir: PathBuf,
    max_file_size: u64,
    allowed_extensions: Vec<String>,
    send_allow_dirs: Vec<PathBuf>,
}

impl DownloadSandbox {
    pub fn new(
        download_dir: PathBuf,
        max_file_size: u64,
        allowed_extensions: Vec<String>,
        send_allow_dirs: Vec<PathBuf>,
    ) -> Result<Self> {
        std::fs::create_dir_all(&download_dir)?;
        Ok(Self {
            download_dir,
            max_file_size,
            allowed_extensions,
            send_allow_dirs,
        })
    }

    pub fn download_path(&self, email_id: &str, sanitized_name: &str) -> Result<PathBuf> {
        let extension = Path::new(sanitized_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
            .to_lowercase();

        if !self.allowed_extensions.iter().any(|e| e == &extension) {
            return Err(FerromailError::DisallowedExtension(extension));
        }

        let target_filename = format!("{email_id}_{sanitized_name}");
        let full_path = self.download_dir.join(&target_filename);

        self.assert_within_sandbox(&full_path)?;

        let full_path = self.resolve_unique(full_path, &extension)?;

        Ok(full_path)
    }

    pub async fn write_file(&self, path: &Path, data: &[u8]) -> Result<()> {
        let size = data.len() as u64;
        if size > self.max_file_size {
            return Err(FerromailError::AttachmentTooLarge {
                size,
                max: self.max_file_size,
            });
        }

        self.assert_within_sandbox(path)?;

        tokio::fs::write(path, data).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    pub fn validate_outbound_path(&self, path_str: &str) -> Result<PathBuf> {
        let path = Path::new(path_str);

        let canonical = std::fs::canonicalize(path).map_err(|e| {
            FerromailError::SandboxViolation(format!("Cannot resolve path {path_str}: {e}"))
        })?;

        let canonical_download = std::fs::canonicalize(&self.download_dir).ok();

        let in_download = canonical_download
            .as_ref()
            .is_some_and(|d| canonical.starts_with(d));

        let in_allowed = self.send_allow_dirs.iter().any(|dir| {
            std::fs::canonicalize(dir)
                .ok()
                .is_some_and(|d| canonical.starts_with(&d))
        });

        if !in_download && !in_allowed {
            return Err(FerromailError::SandboxViolation(format!(
                "Path {} is not within any allowed directory",
                canonical.display()
            )));
        }

        if !canonical.is_file() {
            return Err(FerromailError::SandboxViolation(format!(
                "Path {} is not a regular file",
                canonical.display()
            )));
        }

        let metadata = std::fs::metadata(&canonical)?;
        if metadata.len() > self.max_file_size {
            return Err(FerromailError::AttachmentTooLarge {
                size: metadata.len(),
                max: self.max_file_size,
            });
        }

        Ok(canonical)
    }

    fn assert_within_sandbox(&self, path: &Path) -> Result<()> {
        let canonical_dir = std::fs::canonicalize(&self.download_dir).map_err(|e| {
            FerromailError::SandboxViolation(format!("Cannot canonicalize download dir: {e}"))
        })?;

        // For new files, canonicalize the parent directory
        let canonical_path = if path.exists() {
            std::fs::canonicalize(path)?
        } else {
            let parent = path
                .parent()
                .ok_or_else(|| FerromailError::SandboxViolation("No parent directory".into()))?;
            let canonical_parent = std::fs::canonicalize(parent)?;
            canonical_parent.join(
                path.file_name()
                    .ok_or_else(|| FerromailError::SandboxViolation("No filename".into()))?,
            )
        };

        if !canonical_path.starts_with(&canonical_dir) {
            error!(
                attempted_path = %canonical_path.display(),
                download_dir = %canonical_dir.display(),
                "Path escape attempt"
            );
            return Err(FerromailError::PathEscape {
                attempted_path: canonical_path.display().to_string(),
                sandbox_dir: canonical_dir.display().to_string(),
            });
        }

        Ok(())
    }

    fn resolve_unique(&self, base_path: PathBuf, extension: &str) -> Result<PathBuf> {
        if !base_path.exists() {
            return Ok(base_path);
        }

        let stem = base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file");

        let parent = base_path
            .parent()
            .ok_or_else(|| FerromailError::SandboxViolation("No parent directory".into()))?;

        for i in 1..=1000 {
            let candidate = parent.join(format!("{stem}_{i}.{extension}"));
            if !candidate.exists() {
                self.assert_within_sandbox(&candidate)?;
                return Ok(candidate);
            }
        }

        Err(FerromailError::SandboxViolation(
            "Could not find unique filename after 1000 attempts".into(),
        ))
    }
}
