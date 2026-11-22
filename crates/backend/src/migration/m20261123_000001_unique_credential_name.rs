use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("uq_credentials_user_id_name")
                    .table(Credentials::Table)
                    .col(Credentials::UserId)
                    .col(Credentials::Name)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("uq_credentials_user_id_name")
                    .table(Credentials::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Credentials {
    Table,
    UserId,
    Name,
}
