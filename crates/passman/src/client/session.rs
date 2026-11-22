use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::client::error::{ClientError, ClientResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub server_url: String,
    /// Normalized email (trim + lowercase).
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in_secs: u64,
    pub refresh_expires_in_secs: u64,
    pub kdf_salt: String,
}

impl Session {
    pub fn load(path: &Path) -> ClientResult<Option<Self>> {
        let Some(raw) = crate::client::storage::read_to_string(path)? else {
            return Ok(None);
        };
        let session = serde_json::from_str(&raw)
            .map_err(|e| ClientError::Config(format!("invalid session file: {e}")))?;
        Ok(Some(session))
    }

    pub fn save(&self, path: &Path) -> ClientResult<()> {
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| ClientError::Serde(format!("failed to serialize session: {e}")))?;
        crate::client::storage::write_atomic(path, raw.as_bytes(), 0o600)
    }

    pub fn clear(path: &Path) -> ClientResult<()> {
        if path.exists() {
            std::fs::remove_file(path).map_err(|source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Ok(())
    }
}
