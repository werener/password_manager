use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// Client-derived authentication verifier; raw master password is never sent.
    pub auth_verifier: String,
    pub kdf_salt: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    /// Client-derived authentication verifier; raw master password is never sent.
    pub auth_verifier: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthTokensResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub access_expires_in_secs: u64,
    pub refresh_expires_in_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
}

async fn register(
    State(_state): State<AppState>,
    Json(_payload): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    Err(AppError::NotImplemented("POST /auth/register"))
}

async fn login(
    State(_state): State<AppState>,
    Json(_payload): Json<LoginRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    Err(AppError::NotImplemented("POST /auth/login"))
}

async fn refresh(
    State(_state): State<AppState>,
    Json(_payload): Json<RefreshRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    Err(AppError::NotImplemented("POST /auth/refresh"))
}

async fn logout(
    State(_state): State<AppState>,
    Json(_payload): Json<LogoutRequest>,
) -> AppResult<StatusCode> {
    Err(AppError::NotImplemented("POST /auth/logout"))
}
