use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::{db::models::user, error::AppResult};

pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub password_hash: String,
    pub kdf_salt: Vec<u8>,
    pub now: chrono::DateTime<chrono::FixedOffset>,
}

pub async fn find_by_email_normalized(
    db: &DatabaseConnection,
    email_normalized: &str,
) -> AppResult<Option<user::Model>> {
    Ok(user::Entity::find()
        .filter(user::Column::EmailNormalized.eq(email_normalized))
        .one(db)
        .await?)
}

pub async fn find_by_id(db: &DatabaseConnection, id: Uuid) -> AppResult<Option<user::Model>> {
    Ok(user::Entity::find_by_id(id).one(db).await?)
}

pub async fn create(db: &DatabaseConnection, input: NewUser) -> AppResult<user::Model> {
    let model = user::ActiveModel {
        id: Set(input.id),
        email: Set(input.email),
        email_normalized: Set(input.email_normalized),
        password_hash: Set(input.password_hash),
        kdf_salt: Set(input.kdf_salt),
        created_at: Set(input.now),
        updated_at: Set(input.now),
    };
    Ok(model.insert(db).await?)
}
