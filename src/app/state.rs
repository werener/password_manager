use sea_orm::DatabaseConnection;

use crate::config::Config;

/// Shared application state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: redis::aio::ConnectionManager,
    pub config: Config,
}
