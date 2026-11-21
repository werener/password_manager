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

    #[error("network error: {0}")]
    Network(String),

    #[error("api error ({status}, {code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type ClientResult<T> = Result<T, ClientError>;
