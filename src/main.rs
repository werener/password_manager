use std::time::Duration;

use migration::{Migrator, MigratorTrait};
use password_manager::config::Config;
use sea_orm::{ConnectOptions, Database};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,password_manager=debug,sea_orm_migration=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    tracing::info!(bind_addr = %config.bind_addr, "configuration loaded");

    let mut opt = ConnectOptions::new(config.database_url.clone());
    opt.max_connections(10)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(5))
        .acquire_timeout(Duration::from_secs(5))
        .sqlx_logging(true);

    let db = Database::connect(opt).await?;
    tracing::info!("database connection established");

    Migrator::up(&db, None).await?;
    tracing::info!("database migrations applied");

    tracing::info!("storage/runtime foundation is ready; waiting for shutdown signal (Ctrl+C)");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    db.close().await?;
    tracing::info!("database connection closed");

    Ok(())
}
