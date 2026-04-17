use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::types::{AuditEntry, FerromailError, Result};

pub struct AuditLog {
    file: File,
}

impl AuditLog {
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    pub fn log(&mut self, entry: &AuditEntry) -> Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|e| {
            FerromailError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        Ok(())
    }
}
