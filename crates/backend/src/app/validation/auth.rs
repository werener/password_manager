use password_manager_dto::auth::{
    LoginRequest, LogoutRequest, PreloginRequest, RefreshRequest, RegisterRequest,
};

use password_manager_crypto::core;

use crate::error::AppError;

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn validate_email(email: &str) -> Result<(), AppError> {
    let ok = email.contains('@')
        && !email.starts_with('@')
        && !email.ends_with('@')
        && email.len() <= 320;
    if !ok {
        return Err(AppError::BadRequest("invalid email".to_string()));
    }
    Ok(())
}

use super::rules::validate_len;

pub struct RegisterInput {
    pub email: String,
    pub email_normalized: String,
    pub verifier_bytes: Vec<u8>,
    pub kdf_salt: Vec<u8>,
}

impl TryFrom<RegisterRequest> for RegisterInput {
    type Error = AppError;

    fn try_from(payload: RegisterRequest) -> Result<Self, Self::Error> {
        let email = payload.email.trim().to_string();
        let email_normalized = normalize_email(&email);
        validate_email(&email_normalized)?;

        let verifier_bytes = core::base64::decode(&payload.auth_verifier)
            .map_err(|_| AppError::BadRequest("auth_verifier must be valid base64".to_string()))?;
        let kdf_salt = core::base64::decode(&payload.kdf_salt)
            .map_err(|_| AppError::BadRequest("kdf_salt must be valid base64".to_string()))?;
        validate_len("auth_verifier", &verifier_bytes, 32, 32)?;
        validate_len("kdf_salt", &kdf_salt, 32, 32)?;

        Ok(Self {
            email,
            email_normalized,
            verifier_bytes,
            kdf_salt,
        })
    }
}

pub struct PreloginInput {
    pub email_normalized: String,
}

impl TryFrom<PreloginRequest> for PreloginInput {
    type Error = AppError;

    fn try_from(payload: PreloginRequest) -> Result<Self, Self::Error> {
        let email_normalized = normalize_email(&payload.email);
        validate_email(&email_normalized)?;
        Ok(Self { email_normalized })
    }
}

pub struct LoginInput {
    pub email_normalized: String,
    pub verifier_bytes: Vec<u8>,
}

impl TryFrom<LoginRequest> for LoginInput {
    type Error = AppError;

    fn try_from(payload: LoginRequest) -> Result<Self, Self::Error> {
        let email_normalized = normalize_email(&payload.email);
        validate_email(&email_normalized)?;
        if payload.auth_verifier.trim().is_empty() {
            return Err(AppError::BadRequest(
                "auth_verifier is required".to_string(),
            ));
        }
        let verifier_bytes = core::base64::decode(&payload.auth_verifier)
            .map_err(|_| AppError::BadRequest("auth_verifier must be valid base64".to_string()))?;
        validate_len("auth_verifier", &verifier_bytes, 32, 32)?;
        Ok(Self {
            email_normalized,
            verifier_bytes,
        })
    }
}

pub struct RefreshInput {
    pub refresh_token: String,
}

impl TryFrom<RefreshRequest> for RefreshInput {
    type Error = AppError;

    fn try_from(payload: RefreshRequest) -> Result<Self, Self::Error> {
        let refresh_token = payload.refresh_token.trim().to_string();
        if refresh_token.is_empty() {
            return Err(AppError::BadRequest(
                "refresh_token is required".to_string(),
            ));
        }
        Ok(Self { refresh_token })
    }
}

pub struct LogoutInput {
    pub refresh_token: String,
}

impl TryFrom<LogoutRequest> for LogoutInput {
    type Error = AppError;

    fn try_from(payload: LogoutRequest) -> Result<Self, Self::Error> {
        let refresh_token = payload.refresh_token.trim().to_string();
        if refresh_token.is_empty() {
            return Err(AppError::BadRequest(
                "refresh_token is required".to_string(),
            ));
        }
        Ok(Self { refresh_token })
    }
}
