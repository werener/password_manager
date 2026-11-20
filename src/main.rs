use std::time::Duration;

use migration::{Migrator, MigratorTrait};
use password_manager::{config::Config, router::build_router, state::AppState};
use redis::aio::ConnectionManager;
use sea_orm::{ConnectOptions, Database};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,password_manager=debug,sea_orm_migration=info,tower_http=debug".into()
            }),
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

    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis = ConnectionManager::new(redis_client).await?;
    tracing::info!("redis connection established");

    let bind_addr = config.bind_addr;
    let state = AppState {
        db: db.clone(),
        redis,
        config,
    };
    let app = build_router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown signal received, closing database connection");
    db.close().await?;
    tracing::info!("server shut down gracefully");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
