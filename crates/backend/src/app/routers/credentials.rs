use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get as route_get,
};
use chrono::Utc;
use sea_orm::Set;
use uuid::Uuid;

use password_manager_crypto::core;
use password_manager_dto::credentials::{
    CreateCredentialRequest, CredentialMetadataResponse, CredentialResponse,
    UpdateCredentialRequest,
};

use crate::{
    app::{
        extractors::{AuthUser, IdempotencyKey},
        state::AppState,
        validation::credentials::{CreateCredentialInput, UpdateCredentialInput},
    },
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
            if credentials::is_unique_violation(&e) {
                let msg = e.to_string();
                if msg.contains("uq_credentials_user_id_name") {
                    return Err(AppError::Conflict(
                        "credential title already exists".to_string(),
                    ));
                }
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
    Path(id): Path<String>,
) -> AppResult<Json<CredentialResponse>> {
    let row = credentials::find_owned_by_id_or_name(&state.db, user_id, &id).await?;
    Ok(Json(to_response(row)))
}

async fn update(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<UpdateCredentialRequest>,
) -> AppResult<Json<CredentialResponse>> {
    let input = UpdateCredentialInput::try_from(payload)?;
    let row = credentials::find_owned_by_id_or_name(&state.db, user_id, &id).await?;

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

    let saved = match credentials::update(&state.db, active).await {
        Ok(saved) => saved,
        Err(AppError::Database(e)) => {
            if credentials::is_unique_violation(&e) {
                let msg = e.to_string();
                if msg.contains("uq_credentials_user_id_name") {
                    return Err(AppError::Conflict(
                        "credential title already exists".to_string(),
                    ));
                }
            }
            return Err(AppError::Database(e));
        }
        Err(e) => return Err(e),
    };
    Ok(Json(to_response(saved)))
}

async fn delete(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let row = credentials::find_owned_by_id_or_name(&state.db, user_id, &id).await?;
    credentials::delete_by_id(&state.db, row.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn to_response(row: credential::Model) -> CredentialResponse {
    CredentialResponse {
        id: row.id,
        name: row.name,
        username: row.username,
        url: row.url,
        notes: row.notes,
        password_ciphertext: core::base64::encode(&row.password_ciphertext),
        password_nonce: core::base64::encode(&row.password_nonce),
    }
}
