use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_credentials).post(create_credential))
        .route(
            "/:id",
            get(get_credential)
                .put(update_credential)
                .delete(delete_credential),
        )
}

#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Client-side encrypted secret (opaque to server in zero-knowledge mode).
    pub password_ciphertext: String,
    /// Nonce used by client-side encryption.
    pub password_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Client-side encrypted secret (opaque to server in zero-knowledge mode).
    pub password_ciphertext: Option<String>,
    /// Nonce used by client-side encryption.
    pub password_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password_ciphertext: String,
    pub password_nonce: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialMetadataResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

async fn create_credential(
    State(_state): State<AppState>,
    Json(_payload): Json<CreateCredentialRequest>,
) -> AppResult<(StatusCode, Json<CredentialResponse>)> {
    Err(AppError::NotImplemented("POST /credentials"))
}

async fn list_credentials(
    State(_state): State<AppState>,
) -> AppResult<Json<Vec<CredentialMetadataResponse>>> {
    Err(AppError::NotImplemented("GET /credentials"))
}

async fn get_credential(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> AppResult<Json<CredentialResponse>> {
    Err(AppError::NotImplemented("GET /credentials/:id"))
}

async fn update_credential(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_payload): Json<UpdateCredentialRequest>,
) -> AppResult<Json<CredentialResponse>> {
    Err(AppError::NotImplemented("PUT /credentials/:id"))
}

async fn delete_credential(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    Err(AppError::NotImplemented("DELETE /credentials/:id"))
}
