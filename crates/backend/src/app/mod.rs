pub mod dto;
pub mod extractors;
pub mod routers;
pub mod state;
pub mod validation;

use std::time::Duration;

use migration::{Migrator, MigratorTrait};
use redis::aio::ConnectionManager;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use crate::{config::Config, error::AppError};

pub use state::AppState;

/// Connects to Postgres using application config.
pub async fn connect_db(config: &Config) -> Result<DatabaseConnection, AppError> {
    let mut opt = ConnectOptions::new(config.database_url.clone());
    opt.max_connections(10)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(5))
        .acquire_timeout(Duration::from_secs(5))
        .sqlx_logging(true);
    Ok(Database::connect(opt).await?)
}

/// Connects to Redis using application config.
pub async fn connect_redis(config: &Config) -> Result<ConnectionManager, AppError> {
    let client = redis::Client::open(config.redis_url.as_str())?;
    Ok(ConnectionManager::new(client).await?)
}

/// Builds shared application state and applies pending migrations.
pub async fn build_state(config: Config) -> Result<AppState, AppError> {
    let db = connect_db(&config).await?;
    Migrator::up(&db, None).await?;
    let redis = connect_redis(&config).await?;
    Ok(AppState {
        db,
        redis,
        config,
        fail_access_mint: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

/// Builds the Axum router for the given application state.
pub fn build_router(state: AppState) -> axum::Router {
    routers::build_router(state)
}
