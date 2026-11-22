use sea_orm_migration::prelude::*;

#[tokio::main]
async fn main() {
    cli::run_cli(password_manager_backend::migration::Migrator).await;
}
