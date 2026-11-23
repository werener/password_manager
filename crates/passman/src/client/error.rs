use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("config error: {0}")]
    Config(String),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("{0}")]
    Network(String),

    #[error("{message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    NotFound(String),
}

impl ClientError {
    pub fn network(err: &reqwest::Error) -> Self {
        let msg = if err.is_builder() {
            "invalid server URL; check `passman server <url>`".to_string()
        } else if err.is_timeout() {
            "request timed out; check server availability and try again".to_string()
        } else if err.is_connect() {
            "could not connect to server; check server URL and that the server is running"
                .to_string()
        } else if err.is_request() {
            "failed to send request; check network connection".to_string()
        } else if err.is_decode() {
            "received invalid response from server".to_string()
        } else {
            format!("network request failed: {err}")
        };
        Self::Network(msg)
    }
}

pub type ClientResult<T> = Result<T, ClientError>;
