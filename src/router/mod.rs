pub mod auth;
pub mod credentials;
mod validation;

use axum::{Router, routing::get};

use crate::state::AppState;

async fn health() -> &'static str {
    "ok"
}

/// Builds the application router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/auth", auth::router())
        .nest("/credentials", credentials::router())
        .with_state(state)
}
