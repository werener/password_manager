pub mod auth;
pub mod credentials;

use axum::{Json, Router, extract::State, http::StatusCode, middleware, routing::get};
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
    let api = Router::new()
        .nest("/auth", auth::router())
        .nest("/credentials", credentials::router())
        .layer(middleware::from_fn(sanitize_framework_errors));
    Router::new()
        .route("/health", get(health))
        .merge(api)
        .with_state(state)
}

use axum::{body::Body, http::Response, middleware::Next};

async fn sanitize_framework_errors(req: axum::http::Request<Body>, next: Next) -> Response<Body> {
    let resp = next.run(req).await;
    let status = resp.status();
    if status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST {
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024)
            .await
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        let looks_internal = text.contains("Failed to deserialize")
            || text.contains("missing field")
            || text.contains("UUID parsing failed")
            || text.contains("Invalid URL");
        if looks_internal {
            let body =
                serde_json::json!({"code":"bad_request","message":"invalid request"}).to_string();
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
        }
        return Response::from_parts(parts, Body::from(bytes));
    }
    resp
}
