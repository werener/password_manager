pub mod auth;
pub mod credentials;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;

use crate::app::state::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    db: &'static str,
    redis: &'static str,
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let db_ok = state.db.ping().await.is_ok();

    let mut redis_conn = state.redis.clone();
    let redis_ok: bool = redis::cmd("PING")
        .query_async::<String>(&mut redis_conn)
        .await
        .is_ok();

    let all_ok = db_ok && redis_ok;
    (
        if all_ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(HealthResponse {
            status: if all_ok { "ok" } else { "degraded" },
            db: if db_ok { "up" } else { "down" },
            redis: if redis_ok { "up" } else { "down" },
        }),
    )
}

/// Builds the application router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/auth", auth::router())
        .nest("/credentials", credentials::router())
        .with_state(state)
}
