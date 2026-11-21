use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get as route_get,
};
use chrono::Utc;
use sea_orm::Set;
use uuid::Uuid;

use crate::{
    app::{
        dto::credentials::{
            CreateCredentialRequest, CredentialMetadataResponse, CredentialResponse,
            UpdateCredentialRequest,
        },
        extractors::{AuthUser, IdempotencyKey},
        state::AppState,
        validation::credentials::{CreateCredentialInput, UpdateCredentialInput},
    },
    crypto::encode_base64,
    db::{models::credential, queries::credentials},
    error::{AppError, AppResult},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", route_get(list).post(create))
        .route("/:id", route_get(get).put(update).delete(delete))
}

async fn create(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    idempotency_key: IdempotencyKey,
    Json(payload): Json<CreateCredentialRequest>,
) -> AppResult<(StatusCode, Json<CredentialResponse>)> {
    let input = CreateCredentialInput::try_new(idempotency_key, payload)?;

    let now = Utc::now().fixed_offset();
    let id = Uuid::new_v4();
    match credentials::create(
        &state.db,
        credentials::NewCredential {
            id,
            user_id,
            idempotency_key: input.idempotency_key,
            name: input.name,
            username: input.username,
            url: input.url,
            notes: input.notes,
            password_ciphertext: input.password_ciphertext,
            password_nonce: input.password_nonce,
            now,
        },
    )
    .await
    {
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

async fn list(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> AppResult<Json<Vec<CredentialMetadataResponse>>> {
    let rows = credentials::list_by_user(&state.db, user_id).await?;

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

async fn get(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<CredentialResponse>> {
    let row = find_owned(&state, user_id, id).await?;
    Ok(Json(to_response(row)))
}

async fn update(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCredentialRequest>,
) -> AppResult<Json<CredentialResponse>> {
    let input = UpdateCredentialInput::try_from(payload)?;
    let row = find_owned(&state, user_id, id).await?;

    let mut active: credential::ActiveModel = row.into();
    if let Some(name) = input.name {
        active.name = Set(name);
    }
    if let Some(username) = input.username {
        active.username = Set(username);
    }
    if let Some(url) = input.url {
        active.url = Set(url);
    }
    if let Some(notes) = input.notes {
        active.notes = Set(notes);
    }
    if let Some(secret) = input.secret {
        active.password_ciphertext = Set(secret.ciphertext);
        active.password_nonce = Set(secret.nonce);
    }
    active.updated_at = Set(Utc::now().fixed_offset());

    let saved = credentials::update(&state.db, active).await?;
    Ok(Json(to_response(saved)))
}

async fn delete(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let row = find_owned(&state, user_id, id).await?;
    credentials::delete_by_id(&state.db, row.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn find_owned(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<credential::Model> {
    credentials::find_owned(&state.db, user_id, id)
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
