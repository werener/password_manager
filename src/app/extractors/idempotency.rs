use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{HeaderName, request::Parts},
};

use crate::{app::state::AppState, error::AppError};

static IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Required `Idempotency-Key` header.
#[derive(Debug, Clone)]
pub struct IdempotencyKey(pub String);

#[async_trait]
impl FromRequestParts<AppState> for IdempotencyKey {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get(&IDEMPOTENCY_KEY)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("Idempotency-Key header is required".to_string())
            })?;
        Ok(Self(key.to_string()))
    }
}
