use std::env;
use std::net::SocketAddr;

/// Runtime configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub redis_url: String,
}

/// Errors returned when loading [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    Missing(&'static str),

    #[error("invalid environment variable {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

impl Config {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr_raw = require_env("BIND_ADDR")?;
        let bind_addr = bind_addr_raw.parse().map_err(|e| ConfigError::Invalid {
            name: "BIND_ADDR",
            message: format!("{e}"),
        })?;

        Ok(Self {
            bind_addr,
            database_url: require_env("DATABASE_URL")?,
            redis_url: require_env("REDIS_URL")?,
        })
    }
}

fn require_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing(name))
}
