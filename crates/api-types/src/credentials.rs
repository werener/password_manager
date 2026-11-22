use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::serde::double_option;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCredentialRequest {
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub username: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub url: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub notes: Option<Option<String>>,
    /// Client-side encrypted secret (opaque to server in zero-knowledge mode).
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_ciphertext: Option<Option<String>>,
    /// Nonce used by client-side encryption.
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_nonce: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password_ciphertext: String,
    pub password_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadataResponse {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn update_request_omits_unchanged_fields() {
        let req = UpdateCredentialRequest {
            name: None,
            username: None,  // keep
            url: Some(None), // clear
            notes: Some(Some("n".into())),
            password_ciphertext: None,
            password_nonce: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v, json!({"url": null, "notes": "n"}));
    }

    #[test]
    fn update_request_double_option_deserializes() {
        let v = json!({"username": null, "notes": "hello"});
        let req: UpdateCredentialRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.username, Some(None));
        assert_eq!(req.notes, Some(Some("hello".into())));
        assert_eq!(req.url, None);
    }
}
