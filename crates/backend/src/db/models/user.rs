use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// User account.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub email: String,
    /// Normalized email.
    #[sea_orm(unique)]
    pub email_normalized: String,
    /// Password hash for authentication.
    pub password_hash: String,
    /// Salt for vault key derivation.
    #[sea_orm(column_type = "VarBinary(StringLen::None)")]
    pub kdf_salt: Vec<u8>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::refresh_token::Entity")]
    RefreshTokens,
    #[sea_orm(has_many = "super::credential::Entity")]
    Credentials,
}

impl Related<super::refresh_token::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RefreshTokens.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credentials.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
