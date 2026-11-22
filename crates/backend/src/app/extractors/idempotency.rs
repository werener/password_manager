use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{HeaderName, request::Parts},
};

use crate::{app::AppState, app::validation::rules::validate_idempotency_key, error::AppError};

static IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Required `Idempotency-Key` header.
#[derive(Debug, Clone)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let key = raw.trim();
        if key.is_empty() {
            return Err(AppError::BadRequest(
                "Idempotency-Key header is required".to_string(),
            ));
        }
        validate_idempotency_key(key)?;
        Ok(Self(key.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[async_trait]
impl FromRequestParts<AppState> for IdempotencyKey {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(&IDEMPOTENCY_KEY)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::BadRequest("Idempotency-Key header is required".to_string())
            })?;
        Self::parse(raw)
    }
}
