#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    InvalidData(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal crypto error")]
    Internal,
}
