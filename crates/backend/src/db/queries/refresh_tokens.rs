use chrono::{DateTime, FixedOffset, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
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

pub async fn create(
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

pub async fn peek_active_by_hash(
    db: &DatabaseConnection,
    token_hash: &[u8],
) -> AppResult<Option<refresh_token::Model>> {
    let now = Utc::now().fixed_offset();
    Ok(refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash.to_vec()))
        .filter(refresh_token::Column::ExpiresAt.gt(now))
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

pub struct RefreshRotation {
    pub old: refresh_token::Model,
}

pub struct RotatedRefreshInput {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<FixedOffset>,
    pub created_at: DateTime<FixedOffset>,
}

/// Atomically rotate a refresh token: lock active row, delete old, insert new.
/// Returns `Ok(None)` if token is missing, expired, or already consumed.
pub async fn rotate_by_hash(
    db: &DatabaseConnection,
    token_hash: &[u8],
    new_token: RotatedRefreshInput,
) -> AppResult<Option<RefreshRotation>> {
    let txn = db.begin().await?;
    let now = Utc::now().fixed_offset();

    let found = refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash.to_vec()))
        .lock_exclusive()
        .one(&txn)
        .await?;

    let Some(found) = found else {
        txn.rollback().await?;
        return Ok(None);
    };

    if found.expires_at <= now {
        refresh_token::Entity::delete_by_id(found.id)
            .exec(&txn)
            .await?;
        txn.commit().await?;
        return Ok(None);
    }

    let deleted = refresh_token::Entity::delete_many()
        .filter(refresh_token::Column::Id.eq(found.id))
        .filter(refresh_token::Column::TokenHash.eq(token_hash.to_vec()))
        .exec(&txn)
        .await?;
    if deleted.rows_affected != 1 {
        txn.rollback().await?;
        return Ok(None);
    }

    let model = refresh_token::ActiveModel {
        id: Set(new_token.id),
        user_id: Set(found.user_id),
        session_id: Set(found.session_id),
        token_hash: Set(new_token.token_hash),
        expires_at: Set(new_token.expires_at),
        created_at: Set(new_token.created_at),
    };
    model.insert(&txn).await?;
    txn.commit().await?;
    Ok(Some(RefreshRotation { old: found }))
}
