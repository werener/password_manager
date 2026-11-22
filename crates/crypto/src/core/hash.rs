use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::CryptoError;

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn argon2_hash(secret: &[u8]) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret, &salt)
        .map(|h| h.to_string())
        .map_err(|_| CryptoError::Internal)
}

pub fn argon2_verify(secret: &[u8], hash: &str) -> Result<bool, CryptoError> {
    let parsed =
        PasswordHash::new(hash).map_err(|_| CryptoError::InvalidData("invalid hash".into()))?;
    Ok(Argon2::default().verify_password(secret, &parsed).is_ok())
}
