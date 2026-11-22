use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};

use password_manager_crypto::server;

use crate::{app::state::AppState, error::AppError};

/// Authenticated user extracted from a Bearer access token.
#[derive(Debug, Clone, Copy)]
pub struct AuthUser(pub uuid::Uuid);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let token = auth.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
        let claims = server::decode_access_token(&state.config.jwt_secret, token)
            .map_err(|_| AppError::Unauthorized)?;
        Ok(Self(claims.sub))
    }
}
