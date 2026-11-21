use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration as ChronoDuration, Utc};
use redis::AsyncCommands;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    crypto::{
        create_access_token, decode_base64, encode_base64, generate_refresh_token,
        hash_auth_verifier, hash_refresh_token, normalize_email, validate_email,
        verify_auth_verifier,
    },
    error::{AppError, AppResult},
    models::{refresh_token, user},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/prelogin", post(prelogin))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// Client-derived authentication verifier; raw master password is never sent.
    pub auth_verifier: String,
    /// Base64-encoded KDF salt used by client to derive keys.
    pub kdf_salt: String,
}

#[derive(Debug, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
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
    /// Base64-encoded KDF salt for client-side key derivation.
    pub kdf_salt: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub kdf_salt: String,
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    let email_normalized = normalize_email(&payload.email);
    validate_email(&email_normalized)?;

    if payload.auth_verifier.trim().is_empty() {
        return Err(AppError::BadRequest(
            "auth_verifier is required".to_string(),
        ));
    }
    let kdf_salt = decode_base64("kdf_salt", &payload.kdf_salt)?;
    if kdf_salt.is_empty() {
        return Err(AppError::BadRequest("kdf_salt is required".to_string()));
    }

    let existing = user::Entity::find()
        .filter(user::Column::EmailNormalized.eq(&email_normalized))
        .one(&state.db)
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict("email already registered".to_string()));
    }

    let verifier_bytes = decode_base64("auth_verifier", &payload.auth_verifier)?;
    let password_hash = hash_auth_verifier(&verifier_bytes)?;
    let now = Utc::now().fixed_offset();
    let id = Uuid::new_v4();

    let model = user::ActiveModel {
        id: Set(id),
        email: Set(payload.email.trim().to_string()),
        email_normalized: Set(email_normalized),
        password_hash: Set(password_hash),
        kdf_salt: Set(kdf_salt),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(&state.db).await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id: id,
            email: payload.email.trim().to_string(),
        }),
    ))
}

async fn prelogin(
    State(state): State<AppState>,
    Json(payload): Json<PreloginRequest>,
) -> AppResult<Json<PreloginResponse>> {
    let email_normalized = normalize_email(&payload.email);
    validate_email(&email_normalized)?;

    let user = user::Entity::find()
        .filter(user::Column::EmailNormalized.eq(&email_normalized))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(PreloginResponse {
        kdf_salt: encode_base64(&user.kdf_salt),
    }))
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    let email_normalized = normalize_email(&payload.email);
    validate_email(&email_normalized)?;
    if payload.auth_verifier.trim().is_empty() {
        return Err(AppError::BadRequest(
            "auth_verifier is required".to_string(),
        ));
    }

    enforce_login_rate_limit(&state, addr.ip().to_string().as_str(), &email_normalized).await?;

    let user = user::Entity::find()
        .filter(user::Column::EmailNormalized.eq(&email_normalized))
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let verifier_bytes = decode_base64("auth_verifier", &payload.auth_verifier)?;
    let ok = verify_auth_verifier(&verifier_bytes, &user.password_hash)?;
    if !ok {
        return Err(AppError::Unauthorized);
    }

    issue_tokens(&state, user.id, &user.kdf_salt).await
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    if payload.refresh_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "refresh_token is required".to_string(),
        ));
    }

    let token_hash = hash_refresh_token(&payload.refresh_token);
    let now = Utc::now().fixed_offset();

    let found = refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash.clone()))
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if found.expires_at <= now {
        let _ = refresh_token::Entity::delete_by_id(found.id)
            .exec(&state.db)
            .await;
        return Err(AppError::Unauthorized);
    }

    let user = user::Entity::find_by_id(found.user_id)
        .one(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let new_refresh_token = generate_refresh_token();
    let new_hash = hash_refresh_token(&new_refresh_token);
    let new_id = Uuid::new_v4();
    let expires_at = (Utc::now()
        + ChronoDuration::from_std(state.config.refresh_token_ttl)
            .map_err(|_| AppError::Internal)?)
    .fixed_offset();

    let txn = state.db.begin().await?;
    refresh_token::Entity::delete_by_id(found.id)
        .exec(&txn)
        .await?;
    refresh_token::ActiveModel {
        id: Set(new_id),
        user_id: Set(found.user_id),
        session_id: Set(found.session_id),
        token_hash: Set(new_hash),
        expires_at: Set(expires_at),
        created_at: Set(Utc::now().fixed_offset()),
    }
    .insert(&txn)
    .await?;
    txn.commit().await?;

    let access_token = create_access_token(
        &state.config.jwt_secret,
        found.user_id,
        found.session_id,
        state.config.access_token_ttl,
    )?;

    Ok(Json(AuthTokensResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer",
        access_expires_in_secs: state.config.access_token_ttl.as_secs(),
        refresh_expires_in_secs: state.config.refresh_token_ttl.as_secs(),
        kdf_salt: encode_base64(&user.kdf_salt),
    }))
}

async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> AppResult<StatusCode> {
    if payload.refresh_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "refresh_token is required".to_string(),
        ));
    }
    let token_hash = hash_refresh_token(&payload.refresh_token);
    refresh_token::Entity::delete_many()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .exec(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    kdf_salt: &[u8],
) -> AppResult<Json<AuthTokensResponse>> {
    let session_id = Uuid::new_v4();
    let refresh_token = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&refresh_token);
    let expires_at = (Utc::now()
        + ChronoDuration::from_std(state.config.refresh_token_ttl)
            .map_err(|_| AppError::Internal)?)
    .fixed_offset();

    refresh_token::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        session_id: Set(session_id),
        token_hash: Set(refresh_hash),
        expires_at: Set(expires_at),
        created_at: Set(Utc::now().fixed_offset()),
    }
    .insert(&state.db)
    .await?;

    let access_token = create_access_token(
        &state.config.jwt_secret,
        user_id,
        session_id,
        state.config.access_token_ttl,
    )?;

    Ok(Json(AuthTokensResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        access_expires_in_secs: state.config.access_token_ttl.as_secs(),
        refresh_expires_in_secs: state.config.refresh_token_ttl.as_secs(),
        kdf_salt: BASE64.encode(kdf_salt),
    }))
}

async fn enforce_login_rate_limit(
    state: &AppState,
    ip: &str,
    email_normalized: &str,
) -> AppResult<()> {
    let email_hash = Sha256::digest(email_normalized.as_bytes());
    let key = format!("rl:login:{}:{:x}", ip, email_hash);
    let mut conn = state.redis.clone();
    let count: i64 = conn.incr(&key, 1).await?;
    if count == 1 {
        let _: () = conn
            .expire(&key, state.config.login_rate_limit_window.as_secs() as i64)
            .await?;
    }
    if count as u32 > state.config.login_rate_limit_max {
        return Err(AppError::TooManyRequests);
    }
    Ok(())
}
