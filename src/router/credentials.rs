use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto::{decode_access_token, decode_base64, encode_base64},
    error::{AppError, AppResult},
    models::credential,
    state::AppState,
};

use super::validation::{
    double_option, validate_credential_metadata, validate_idempotency_key, validate_opt_text,
    validate_secret, validate_text,
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
    #[serde(default, deserialize_with = "double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub url: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub notes: Option<Option<String>>,
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
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateCredentialRequest>,
) -> AppResult<(StatusCode, Json<CredentialResponse>)> {
    let user_id = authenticate(&state, &headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;

    validate_credential_metadata(
        &payload.name,
        &payload.username,
        &payload.url,
        &payload.notes,
    )?;
    validate_idempotency_key(&idempotency_key)?;
    let ciphertext = decode_base64("password_ciphertext", &payload.password_ciphertext)?;
    let nonce = decode_base64("password_nonce", &payload.password_nonce)?;
    validate_secret(&ciphertext, &nonce)?;

    let now = Utc::now().fixed_offset();
    let id = Uuid::new_v4();
    let model = credential::ActiveModel {
        id: Set(id),
        user_id: Set(user_id),
        idempotency_key: Set(Some(idempotency_key.clone())),
        name: Set(payload.name.trim().to_string()),
        username: Set(payload.username.map(|v| v.trim().to_string())),
        url: Set(payload.url),
        notes: Set(payload.notes),
        password_ciphertext: Set(ciphertext),
        password_nonce: Set(nonce),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match model.insert(&state.db).await {
        Ok(saved) => Ok((StatusCode::CREATED, Json(to_response(saved)))),
        Err(e) => {
            if is_unique_violation(&e) {
                return Err(AppError::Conflict(
                    "duplicate idempotency key for this user".to_string(),
                ));
            }
            Err(AppError::Database(e))
        }
    }
}

async fn list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<CredentialMetadataResponse>>> {
    let user_id = authenticate(&state, &headers)?;
    let rows = credential::Entity::find()
        .filter(credential::Column::UserId.eq(user_id))
        .order_by_desc(credential::Column::CreatedAt)
        .all(&state.db)
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| CredentialMetadataResponse {
                id: r.id,
                name: r.name,
                username: r.username,
                url: r.url,
                notes: r.notes,
            })
            .collect(),
    ))
}

async fn get_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<CredentialResponse>> {
    let user_id = authenticate(&state, &headers)?;
    let row = find_owned(&state, user_id, id).await?;
    Ok(Json(to_response(row)))
}

async fn update_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCredentialRequest>,
) -> AppResult<Json<CredentialResponse>> {
    let user_id = authenticate(&state, &headers)?;
    let row = find_owned(&state, user_id, id).await?;

    let mut active: credential::ActiveModel = row.into();
    if let Some(name) = payload.name {
        validate_text("name", &name, 1, 200)?;
        active.name = Set(name.trim().to_string());
    }
    if let Some(username) = payload.username {
        validate_opt_text("username", &username, 200)?;
        active.username = Set(username.map(|v| v.trim().to_string()));
    }
    if let Some(url) = payload.url {
        validate_opt_text("url", &url, 2048)?;
        active.url = Set(url);
    }
    if let Some(notes) = payload.notes {
        validate_opt_text("notes", &notes, 512)?;
        active.notes = Set(notes);
    }
    match (payload.password_ciphertext, payload.password_nonce) {
        (Some(ct), Some(nonce)) => {
            let ct = decode_base64("password_ciphertext", &ct)?;
            let nonce = decode_base64("password_nonce", &nonce)?;
            validate_secret(&ct, &nonce)?;
            active.password_ciphertext = Set(ct);
            active.password_nonce = Set(nonce);
        }
        (None, None) => {}
        _ => {
            return Err(AppError::BadRequest(
                "password_ciphertext and password_nonce must be provided together".to_string(),
            ));
        }
    }
    active.updated_at = Set(Utc::now().fixed_offset());

    let saved = active.update(&state.db).await?;
    Ok(Json(to_response(saved)))
}

async fn delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = authenticate(&state, &headers)?;
    let row = find_owned(&state, user_id, id).await?;
    credential::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> AppResult<Uuid> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = auth.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
    let claims = decode_access_token(&state.config.jwt_secret, token)?;
    Ok(claims.sub)
}

fn required_idempotency_key(headers: &HeaderMap) -> AppResult<String> {
    let key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::BadRequest("Idempotency-Key header is required".to_string()))?;
    Ok(key.to_string())
}

async fn find_owned(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<credential::Model> {
    credential::Entity::find_by_id(id)
        .filter(credential::Column::UserId.eq(user_id))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)
}

fn to_response(row: credential::Model) -> CredentialResponse {
    CredentialResponse {
        id: row.id,
        name: row.name,
        username: row.username,
        url: row.url,
        notes: row.notes,
        password_ciphertext: encode_base64(&row.password_ciphertext),
        password_nonce: encode_base64(&row.password_nonce),
    }
}

fn is_unique_violation(err: &sea_orm::DbErr) -> bool {
    matches!(
        err.sql_err(),
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
    )
}
