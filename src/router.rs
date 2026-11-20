use axum::{Router, routing::get};

use crate::state::AppState;

async fn health() -> &'static str {
    "ok"
}

/// Build the application's HTTP router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(state)
}
