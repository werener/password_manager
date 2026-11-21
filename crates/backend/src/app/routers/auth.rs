use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
};
use chrono::{Duration as ChronoDuration, Utc};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    app::{
        dto::auth::{
            AuthTokensResponse, LoginRequest, LogoutRequest, PreloginRequest, PreloginResponse,
            RefreshRequest, RegisterRequest, RegisterResponse,
        },
        state::AppState,
        validation::auth::{LoginInput, LogoutInput, PreloginInput, RefreshInput, RegisterInput},
    },
    crypto::{
        create_access_token, encode_base64, generate_refresh_token, hash_auth_verifier,
        hash_refresh_token, verify_auth_verifier,
    },
    db::queries::{refresh_tokens, users},
    error::{AppError, AppResult},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/prelogin", post(prelogin))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    let input = RegisterInput::try_from(payload)?;

    if users::find_by_email_normalized(&state.db, &input.email_normalized)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("email already registered".to_string()));
    }

    let password_hash = hash_auth_verifier(&input.verifier_bytes)?;
    let now = Utc::now().fixed_offset();
    let id = Uuid::new_v4();

    users::create(
        &state.db,
        users::NewUser {
            id,
            email: input.email.clone(),
            email_normalized: input.email_normalized,
            password_hash,
            kdf_salt: input.kdf_salt,
            now,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id: id,
            email: input.email,
        }),
    ))
}

async fn prelogin(
    State(state): State<AppState>,
    Json(payload): Json<PreloginRequest>,
) -> AppResult<Json<PreloginResponse>> {
    let input = PreloginInput::try_from(payload)?;

    let user = users::find_by_email_normalized(&state.db, &input.email_normalized).await?;

    let kdf_salt = match user {
        Some(u) => u.kdf_salt,
        None => fake_kdf_salt(&state.config.jwt_secret, &input.email_normalized),
    };

    Ok(Json(PreloginResponse {
        kdf_salt: encode_base64(&kdf_salt),
    }))
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    let input = LoginInput::try_from(payload)?;

    enforce_login_rate_limit(
        &state,
        addr.ip().to_string().as_str(),
        &input.email_normalized,
    )
    .await?;

    let user = users::find_by_email_normalized(&state.db, &input.email_normalized)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let ok = verify_auth_verifier(&input.verifier_bytes, &user.password_hash)?;
    if !ok {
        return Err(AppError::Unauthorized);
    }

    issue_tokens(&state, user.id, &user.kdf_salt).await
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<Json<AuthTokensResponse>> {
    let input = RefreshInput::try_from(payload)?;

    let token_hash = hash_refresh_token(&input.refresh_token);
    let now = Utc::now().fixed_offset();

    let found = refresh_tokens::find_by_hash(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if found.expires_at <= now {
        let _ = refresh_tokens::delete_by_id(&state.db, found.id).await;
        return Err(AppError::Unauthorized);
    }

    let user = users::find_by_id(&state.db, found.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let new_refresh_token = generate_refresh_token();
    let new_hash = hash_refresh_token(&new_refresh_token);
    let new_id = Uuid::new_v4();
    let expires_at = (Utc::now()
        + ChronoDuration::from_std(state.config.refresh_token_ttl)
            .map_err(|_| AppError::Internal)?)
    .fixed_offset();

    refresh_tokens::rotate(
        &state.db,
        found.id,
        refresh_tokens::NewRefreshToken {
            id: new_id,
            user_id: found.user_id,
            session_id: found.session_id,
            token_hash: new_hash,
            expires_at,
            created_at: Utc::now().fixed_offset(),
        },
    )
    .await?;

    let access_token = create_access_token(
        &state.config.jwt_secret,
        found.user_id,
        found.session_id,
        state.config.access_token_ttl,
    )?;

    Ok(Json(AuthTokensResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        access_expires_in_secs: state.config.access_token_ttl.as_secs(),
        refresh_expires_in_secs: state.config.refresh_token_ttl.as_secs(),
        kdf_salt: encode_base64(&user.kdf_salt),
    }))
}

async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> AppResult<StatusCode> {
    let input = LogoutInput::try_from(payload)?;
    let token_hash = hash_refresh_token(&input.refresh_token);
    refresh_tokens::delete_by_hash(&state.db, &token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn fake_kdf_salt(secret: &str, email_normalized: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":prelogin:");
    hasher.update(email_normalized.as_bytes());
    hasher.finalize()[..16].to_vec()
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

    refresh_tokens::create(
        &state.db,
        refresh_tokens::NewRefreshToken {
            id: Uuid::new_v4(),
            user_id,
            session_id,
            token_hash: refresh_hash,
            expires_at,
            created_at: Utc::now().fixed_offset(),
        },
    )
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
        token_type: "Bearer".to_string(),
        access_expires_in_secs: state.config.access_token_ttl.as_secs(),
        refresh_expires_in_secs: state.config.refresh_token_ttl.as_secs(),
        kdf_salt: encode_base64(kdf_salt),
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
