use crate::{
    app::dto::auth::{
        LoginRequest, LogoutRequest, PreloginRequest, RefreshRequest, RegisterRequest,
    },
    crypto::{decode_base64, normalize_email, validate_email},
    error::AppError,
};

use super::validate_len;

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

        let verifier_bytes = decode_base64("auth_verifier", &payload.auth_verifier)?;
        let kdf_salt = decode_base64("kdf_salt", &payload.kdf_salt)?;
        validate_len("auth_verifier", &verifier_bytes, 1, 256)?;
        validate_len("kdf_salt", &kdf_salt, 16, 64)?;

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
        let verifier_bytes = decode_base64("auth_verifier", &payload.auth_verifier)?;
        validate_len("auth_verifier", &verifier_bytes, 1, 256)?;
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
