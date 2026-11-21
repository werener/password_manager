use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub token_type: String,
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn validate_email(email: &str) -> AppResult<()> {
    let ok = email.contains('@')
        && !email.starts_with('@')
        && !email.ends_with('@')
        && email.len() <= 320;
    if !ok {
        return Err(AppError::BadRequest("invalid email".to_string()));
    }
    Ok(())
}

pub fn decode_base64(field: &'static str, value: &str) -> AppResult<Vec<u8>> {
    BASE64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{field} must be valid base64")))
}

pub fn encode_base64(value: &[u8]) -> String {
    BASE64.encode(value)
}

pub fn hash_auth_verifier(auth_verifier: &[u8]) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(auth_verifier, &salt)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to hash auth verifier");
            AppError::Internal
        })?
        .to_string();
    Ok(hash)
}

pub fn verify_auth_verifier(auth_verifier: &[u8], password_hash: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| {
        tracing::error!(error = %e, "invalid stored password hash");
        AppError::Internal
    })?;
    Ok(Argon2::default()
        .verify_password(auth_verifier, &parsed)
        .is_ok())
}

pub fn create_access_token(
    secret: &str,
    user_id: Uuid,
    session_id: Uuid,
    ttl: std::time::Duration,
) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + ChronoDuration::from_std(ttl).map_err(|_| AppError::Internal)?;
    let claims = AccessClaims {
        sub: user_id,
        sid: session_id,
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
        token_type: "access".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to encode access token");
        AppError::Internal
    })
}

pub fn decode_access_token(secret: &str, token: &str) -> AppResult<AccessClaims> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized)?;
    if data.claims.token_type != "access" {
        return Err(AppError::Unauthorized);
    }
    Ok(data.claims)
}

pub fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_base64(&bytes)
}

pub fn hash_refresh_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}
