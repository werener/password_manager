use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server_url: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> ClientResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&raw).map_err(|e| ClientError::Config(format!("invalid config: {e}")))
    }

    pub fn save(&self, path: &Path) -> ClientResult<()> {
        let raw = toml::to_string_pretty(self)
            .map_err(|e| ClientError::Serde(format!("failed to serialize config: {e}")))?;
        crate::storage::write_atomic(path, raw.as_bytes(), 0o600)
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
    pub config: PathBuf,
    pub session: PathBuf,
}

impl Paths {
    pub fn discover() -> ClientResult<Self> {
        let base = directories::BaseDirs::new()
            .ok_or_else(|| ClientError::Config("could not determine home directory".into()))?;
        let dir = base.config_dir().join("passman");
        Ok(Self {
            config: dir.join("config.toml"),
            session: dir.join("session.json"),
            dir,
        })
    }
}
