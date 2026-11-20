use sea_orm::DatabaseConnection;

use crate::config::Config;

/// Shared application state passed to HTTP handlers via axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Config,
}
