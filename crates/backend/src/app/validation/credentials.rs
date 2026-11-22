use password_manager_dto::credentials::{CreateCredentialRequest, UpdateCredentialRequest};

use crate::{
    app::extractors::IdempotencyKey,
    crypto::decode_base64,
    error::{AppError, AppResult},
};

use super::rules::{
    validate_credential_metadata, validate_opt_text, validate_secret, validate_text,
};

pub struct CreateCredentialInput {
    pub idempotency_key: String,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password_ciphertext: Vec<u8>,
    pub password_nonce: Vec<u8>,
}

impl CreateCredentialInput {
    pub fn try_new(
        idempotency_key: IdempotencyKey,
        payload: CreateCredentialRequest,
    ) -> AppResult<Self> {
        validate_credential_metadata(
            &payload.name,
            &payload.username,
            &payload.url,
            &payload.notes,
        )?;
        let password_ciphertext =
            decode_base64("password_ciphertext", &payload.password_ciphertext)?;
        let password_nonce = decode_base64("password_nonce", &payload.password_nonce)?;
        validate_secret(&password_ciphertext, &password_nonce)?;

        Ok(Self {
            idempotency_key: idempotency_key.0,
            name: payload.name.trim().to_string(),
            username: payload.username.map(|v| v.trim().to_string()),
            url: payload.url,
            notes: payload.notes,
            password_ciphertext,
            password_nonce,
        })
    }
}

pub struct SecretBytes {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct UpdateCredentialInput {
    pub name: Option<String>,
    pub username: Option<Option<String>>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub secret: Option<SecretBytes>,
}

impl TryFrom<UpdateCredentialRequest> for UpdateCredentialInput {
    type Error = AppError;

    fn try_from(payload: UpdateCredentialRequest) -> Result<Self, Self::Error> {
        if let Some(name) = &payload.name {
            let Some(name) = name else {
                return Err(AppError::BadRequest("name cannot be null".to_string()));
            };
            validate_text("name", name, 1, 200)?;
        }
        if let Some(username) = &payload.username {
            validate_opt_text("username", username, 200)?;
        }
        if let Some(url) = &payload.url {
            validate_opt_text("url", url, 2048)?;
        }
        if let Some(notes) = &payload.notes {
            validate_opt_text("notes", notes, 512)?;
        }
        let secret = match (
            payload.password_ciphertext.as_ref(),
            payload.password_nonce.as_ref(),
        ) {
            (Some(Some(ct)), Some(Some(nonce))) => {
                let ciphertext = decode_base64("password_ciphertext", ct)?;
                let nonce_bytes = decode_base64("password_nonce", nonce)?;
                validate_secret(&ciphertext, &nonce_bytes)?;
                Some(SecretBytes {
                    ciphertext,
                    nonce: nonce_bytes,
                })
            }
            (None, None) => None,
            (Some(None), _) | (_, Some(None)) => {
                return Err(AppError::BadRequest(
                    "password_ciphertext and password_nonce cannot be null".to_string(),
                ));
            }
            _ => {
                return Err(AppError::BadRequest(
                    "password_ciphertext and password_nonce must be provided together".to_string(),
                ));
            }
        };

        Ok(Self {
            name: payload.name.and_then(|v| v).map(|v| v.trim().to_string()),
            username: payload.username.map(|v| v.map(|s| s.trim().to_string())),
            url: payload.url,
            notes: payload.notes,
            secret,
        })
    }
}
