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
        toml::from_str(&raw).map_err(|_| ClientError::Config("corrupted config file".to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupted_config_returns_friendly_error() {
        let dir = std::env::temp_dir().join(format!("passman-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "server_url = [broken").unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("corrupted config file"));
        assert!(!err.to_lowercase().contains("toml"));
    }
}
