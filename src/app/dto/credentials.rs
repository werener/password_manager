use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::validation::double_option;

#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Client-side encrypted secret (opaque to server in zero-knowledge mode).
    pub password_ciphertext: String,
    /// Nonce used by client-side encryption.
    pub password_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub url: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub notes: Option<Option<String>>,
    /// Client-side encrypted secret (opaque to server in zero-knowledge mode).
    pub password_ciphertext: Option<String>,
    /// Nonce used by client-side encryption.
    pub password_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password_ciphertext: String,
    pub password_nonce: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialMetadataResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}
