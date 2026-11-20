//! SeaORM entities.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub mod user {
    use super::*;

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
}

pub mod refresh_token {
    use super::*;

    /// Refresh token record.
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
    #[sea_orm(table_name = "refresh_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub session_id: Uuid,
        /// Hash of the refresh token.
        #[sea_orm(unique, column_type = "VarBinary(StringLen::None)")]
        pub token_hash: Vec<u8>,
        pub expires_at: DateTimeWithTimeZone,
        pub created_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_update = "NoAction",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod credential {
    use super::*;

    /// Encrypted credential entry.
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
    #[sea_orm(table_name = "credentials")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub idempotency_key: Option<String>,
        pub name: String,
        pub username: Option<String>,
        pub url: Option<String>,
        pub notes: Option<String>,
        #[sea_orm(column_type = "VarBinary(StringLen::None)")]
        pub password_ciphertext: Vec<u8>,
        #[sea_orm(column_type = "VarBinary(StringLen::None)")]
        pub password_nonce: Vec<u8>,
        pub created_at: DateTimeWithTimeZone,
        pub updated_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_update = "NoAction",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}
