use chrono::{DateTime, FixedOffset};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryOrder,
    Set,
};
use uuid::Uuid;

use crate::{db::models::credential, error::AppResult};

pub struct NewCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub idempotency_key: String,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password_ciphertext: Vec<u8>,
    pub password_nonce: Vec<u8>,
    pub now: DateTime<FixedOffset>,
}

pub async fn create(
    db: &DatabaseConnection,
    input: NewCredential,
) -> Result<credential::Model, DbErr> {
    let model = credential::ActiveModel {
        id: Set(input.id),
        user_id: Set(input.user_id),
        idempotency_key: Set(Some(input.idempotency_key)),
        name: Set(input.name),
        username: Set(input.username),
        url: Set(input.url),
        notes: Set(input.notes),
        password_ciphertext: Set(input.password_ciphertext),
        password_nonce: Set(input.password_nonce),
        created_at: Set(input.now),
        updated_at: Set(input.now),
    };
    model.insert(db).await
}

pub async fn list_by_user(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> AppResult<Vec<credential::Model>> {
    Ok(credential::Entity::find()
        .filter(credential::Column::UserId.eq(user_id))
        .order_by_desc(credential::Column::CreatedAt)
        .all(db)
        .await?)
}

pub async fn find_owned(
    db: &DatabaseConnection,
    user_id: Uuid,
    id: Uuid,
) -> AppResult<Option<credential::Model>> {
    Ok(credential::Entity::find_by_id(id)
        .filter(credential::Column::UserId.eq(user_id))
        .one(db)
        .await?)
}

pub async fn find_owned_by_name(
    db: &DatabaseConnection,
    user_id: Uuid,
    name: &str,
) -> AppResult<Option<credential::Model>> {
    Ok(credential::Entity::find()
        .filter(credential::Column::UserId.eq(user_id))
        .filter(credential::Column::Name.eq(name))
        .one(db)
        .await?)
}

pub async fn update(
    db: &DatabaseConnection,
    active: credential::ActiveModel,
) -> AppResult<credential::Model> {
    Ok(active.update(db).await?)
}

pub async fn delete_by_id(db: &DatabaseConnection, id: Uuid) -> AppResult<()> {
    credential::Entity::delete_by_id(id).exec(db).await?;
    Ok(())
}
