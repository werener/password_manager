use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::CryptoError;

pub fn encode_hs256<T: Serialize>(secret: &str, claims: &T) -> Result<String, CryptoError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| CryptoError::Internal)
}

pub fn decode_hs256<T: DeserializeOwned>(secret: &str, token: &str) -> Result<T, CryptoError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|_| CryptoError::Unauthorized)
}
