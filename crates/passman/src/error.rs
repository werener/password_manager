#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Crypto(#[from] password_manager_crypto::CryptoError),

    #[error("{0}")]
    Message(String),

    #[error(transparent)]
    Client(#[from] password_manager_client::error::ClientError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CliResult<T> = Result<T, CliError>;
