use chrono::{DateTime, FixedOffset};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    QueryFilter, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::{db::models::refresh_token, error::AppResult};

pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<FixedOffset>,
    pub created_at: DateTime<FixedOffset>,
}

pub async fn insert(
    db: &DatabaseConnection,
    input: NewRefreshToken,
) -> AppResult<refresh_token::Model> {
    let model = refresh_token::ActiveModel {
        id: Set(input.id),
        user_id: Set(input.user_id),
        session_id: Set(input.session_id),
        token_hash: Set(input.token_hash),
        expires_at: Set(input.expires_at),
        created_at: Set(input.created_at),
    };
    Ok(model.insert(db).await?)
}

pub async fn find_by_hash(
    db: &DatabaseConnection,
    token_hash: &[u8],
) -> AppResult<Option<refresh_token::Model>> {
    Ok(refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash.to_vec()))
        .one(db)
        .await?)
}

pub async fn delete_by_id(db: &DatabaseConnection, id: Uuid) -> AppResult<()> {
    refresh_token::Entity::delete_by_id(id).exec(db).await?;
    Ok(())
}

pub async fn delete_by_hash(db: &DatabaseConnection, token_hash: &[u8]) -> AppResult<()> {
    refresh_token::Entity::delete_many()
        .filter(refresh_token::Column::TokenHash.eq(token_hash.to_vec()))
        .exec(db)
        .await?;
    Ok(())
}

/// Rotates a refresh token in a transaction: delete old, insert new.
pub async fn rotate(
    db: &DatabaseConnection,
    old_id: Uuid,
    new_token: NewRefreshToken,
) -> AppResult<refresh_token::Model> {
    let txn: DatabaseTransaction = db.begin().await?;
    refresh_token::Entity::delete_by_id(old_id)
        .exec(&txn)
        .await?;
    let model = refresh_token::ActiveModel {
        id: Set(new_token.id),
        user_id: Set(new_token.user_id),
        session_id: Set(new_token.session_id),
        token_hash: Set(new_token.token_hash),
        expires_at: Set(new_token.expires_at),
        created_at: Set(new_token.created_at),
    };
    let inserted = model.insert(&txn).await?;
    txn.commit().await?;
    Ok(inserted)
}
