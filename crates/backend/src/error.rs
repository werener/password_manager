use crate::app::dto::ApiErrorBody;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Application error type mapped to HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("internal error")]
    Internal,
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error(transparent)]
    Redis(#[from] redis::RedisError),
}

/// Result alias using [`AppError`].
pub type AppResult<T> = Result<T, AppError>;

/// Errors returned when loading [`crate::config::Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    Missing(&'static str),

    #[error("invalid environment variable {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, log_internal) = match &self {
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, "bad_request", msg.clone(), false)
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Unauthorized".to_string(),
                false,
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Forbidden".to_string(),
                false,
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "Not found".to_string(),
                false,
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone(), false),
            AppError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "Too many requests".to_string(),
                false,
            ),
            AppError::NotImplemented(feature) => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                format!("{feature} is not implemented yet"),
                false,
            ),
            AppError::Internal | AppError::Database(_) | AppError::Redis(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error".to_string(),
                true,
            ),
        };

        if log_internal {
            tracing::error!(error = ?self, "request failed");
        }

        let body = ApiErrorBody {
            code: code.to_string(),
            message,
            details: None,
        };

        (status, Json(body)).into_response()
    }
}
