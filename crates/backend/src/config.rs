use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::ConfigError;

/// Runtime configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub backend_url: SocketAddr,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub login_rate_limit_max: u32,
    pub login_rate_limit_window: Duration,
}

impl Config {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let backend_url_raw = require_env("BACKEND_URL")?;
        let backend_url = backend_url_raw.parse().map_err(|e| ConfigError::Invalid {
            name: "BACKEND_URL",
            message: format!("{e}"),
        })?;

        Ok(Self {
            backend_url,
            database_url: require_env("DATABASE_URL")?,
            redis_url: require_env("REDIS_URL")?,
            jwt_secret: require_env("JWT_SECRET")?,
            access_token_ttl: parse_duration_secs("ACCESS_TOKEN_TTL_SECONDS")?,
            refresh_token_ttl: parse_duration_secs("REFRESH_TOKEN_TTL_SECONDS")?,
            login_rate_limit_max: parse_u32("LOGIN_RATE_LIMIT_MAX")?,
            login_rate_limit_window: parse_duration_secs("LOGIN_RATE_LIMIT_WINDOW_SECONDS")?,
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

fn parse_u32(name: &'static str) -> Result<u32, ConfigError> {
    let raw = require_env(name)?;
    raw.parse().map_err(|e| ConfigError::Invalid {
        name,
        message: format!("{e}"),
    })
}

fn parse_duration_secs(name: &'static str) -> Result<Duration, ConfigError> {
    let secs = parse_u32(name)?;
    if secs == 0 {
        return Err(ConfigError::Invalid {
            name,
            message: "must be greater than zero".to_string(),
        });
    }
    Ok(Duration::from_secs(u64::from(secs)))
}
