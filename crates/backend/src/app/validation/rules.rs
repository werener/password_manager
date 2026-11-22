use password_manager_crypto::core;

use crate::error::{AppError, AppResult};

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

pub fn decode_base64_field(field: &'static str, value: &str) -> AppResult<Vec<u8>> {
    core::base64::decode(value)
        .map_err(|_| AppError::BadRequest(format!("{field} must be valid base64")))
}

pub fn validate_text(field: &'static str, value: &str, min: usize, max: usize) -> AppResult<()> {
    if value.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "{field} contains invalid control characters"
        )));
    }
    let len = value.trim().chars().count();
    if len < min || len > max {
        return Err(AppError::BadRequest(format!(
            "{field} length must be between {min} and {max} characters"
        )));
    }
    Ok(())
}

pub fn validate_opt_text(field: &'static str, value: &Option<String>, max: usize) -> AppResult<()> {
    if let Some(v) = value {
        validate_text(field, v, 0, max)?;
    }
    Ok(())
}

pub fn validate_len(field: &'static str, bytes: &[u8], min: usize, max: usize) -> AppResult<()> {
    if bytes.len() < min || bytes.len() > max {
        return Err(AppError::BadRequest(format!(
            "{field} length must be between {min} and {max} bytes"
        )));
    }
    Ok(())
}

pub fn validate_idempotency_key(key: &str) -> AppResult<()> {
    let len = key.chars().count();
    if !(1..=128).contains(&len) {
        return Err(AppError::BadRequest(
            "Idempotency-Key length must be between 1 and 128 characters".to_string(),
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(AppError::BadRequest(
            "Idempotency-Key contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_credential_metadata(
    name: &str,
    username: &Option<String>,
    url: &Option<String>,
    notes: &Option<String>,
) -> AppResult<()> {
    validate_text("name", name, 1, 200)?;
    validate_opt_text("username", username, 200)?;
    validate_opt_text("url", url, 2048)?;
    validate_opt_text("notes", notes, 512)?;
    Ok(())
}

pub fn validate_secret(ciphertext: &[u8], nonce: &[u8]) -> AppResult<()> {
    validate_len("password_ciphertext", ciphertext, 1, 8192)?;
    validate_len("password_nonce", nonce, 24, 24)?;
    Ok(())
}
