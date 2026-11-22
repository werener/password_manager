pub use sea_orm_migration::prelude::*;

mod m20261121_000001_init;
mod m20261123_000001_unique_credential_name;

/// Database migrator.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20261121_000001_init::Migration),
            Box::new(m20261123_000001_unique_credential_name::Migration),
        ]
    }
}
