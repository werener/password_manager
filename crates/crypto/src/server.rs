use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::{base64, hash, jwt, rand},
    error::CryptoError,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub token_type: String,
}

pub fn create_access_token(
    secret: &str,
    user_id: Uuid,
    session_id: Uuid,
    ttl_seconds: u64,
) -> Result<String, CryptoError> {
    let now = Utc::now();
    let exp = now + ChronoDuration::seconds(ttl_seconds as i64);
    let claims = AccessClaims {
        sub: user_id,
        sid: session_id,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        token_type: "access".to_string(),
    };
    jwt::encode_hs256(secret, &claims)
}

pub fn decode_access_token(secret: &str, token: &str) -> Result<AccessClaims, CryptoError> {
    let claims: AccessClaims = jwt::decode_hs256(secret, token)?;
    if claims.token_type != "access" {
        return Err(CryptoError::Unauthorized);
    }
    Ok(claims)
}

pub fn generate_refresh_token() -> String {
    base64::encode(&rand::bytes::<32>())
}

pub fn deterministic_fake_kdf_salt(secret: &str, email_normalized: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(secret.len() + 9 + email_normalized.len());
    data.extend_from_slice(secret.as_bytes());
    data.extend_from_slice(b":prelogin:");
    data.extend_from_slice(email_normalized.as_bytes());
    hash::sha256(&data)[..16].to_vec()
}

pub fn hash_email_for_rate_limit(email_normalized: &str) -> String {
    hash::sha256(email_normalized.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
