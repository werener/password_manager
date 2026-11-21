use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};

pub const KDF_SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
const AUTH_INFO: &[u8] = b"passman.v1.auth-verifier";
const VAULT_INFO: &[u8] = b"passman.v1.vault-key";

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn generate_kdf_salt() -> [u8; KDF_SALT_LEN] {
    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn derive_master_key(password: &str, salt: &[u8]) -> ClientResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| ClientError::Crypto(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| ClientError::Crypto(format!("argon2 derive failed: {e}")))?;
    Ok(out)
}

fn hkdf_expand(master_key: &[u8; KEY_LEN], info: &[u8]) -> ClientResult<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|_| ClientError::Crypto("hkdf expand failed".into()))?;
    Ok(out)
}

pub fn derive_auth_verifier(master_key: &[u8; KEY_LEN]) -> ClientResult<[u8; KEY_LEN]> {
    hkdf_expand(master_key, AUTH_INFO)
}

pub fn derive_vault_key(master_key: &[u8; KEY_LEN]) -> ClientResult<Zeroizing<[u8; KEY_LEN]>> {
    let key = hkdf_expand(master_key, VAULT_INFO)?;
    Ok(Zeroizing::new(key))
}

pub fn encode_b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

pub fn decode_b64(field: &str, value: &str) -> ClientResult<Vec<u8>> {
    BASE64
        .decode(value)
        .map_err(|_| ClientError::Crypto(format!("{field} must be valid base64")))
}

pub fn encrypt_secret(
    vault_key: &[u8; KEY_LEN],
    email_normalized: &str,
    password: &str,
) -> ClientResult<(String, String)> {
    let payload = serde_json::json!({ "v": 1, "password": password });
    let plaintext = serde_json::to_vec(&payload)
        .map_err(|e| ClientError::Crypto(format!("failed to encode secret payload: {e}")))?;
    let nonce = generate_nonce();
    let cipher = XChaCha20Poly1305::new(vault_key.into());
    let aad = format!("passman.v1.credential-secret:{email_normalized}");
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| ClientError::Crypto("encryption failed".into()))?;
    Ok((encode_b64(&ciphertext), encode_b64(&nonce)))
}

pub fn decrypt_secret(
    vault_key: &[u8; KEY_LEN],
    email_normalized: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> ClientResult<String> {
    let ciphertext = decode_b64("password_ciphertext", ciphertext_b64)?;
    let nonce = decode_b64("password_nonce", nonce_b64)?;
    if nonce.len() != NONCE_LEN {
        return Err(ClientError::Crypto(
            "password_nonce must be 24 bytes".into(),
        ));
    }
    let cipher = XChaCha20Poly1305::new(vault_key.into());
    let aad = format!("passman.v1.credential-secret:{email_normalized}");
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| {
            ClientError::Crypto("vault decryption failed / wrong key or corrupted data".into())
        })?;

    let value: serde_json::Value = serde_json::from_slice(&plaintext).map_err(|_| {
        ClientError::Crypto("vault decryption failed / wrong key or corrupted data".into())
    })?;
    let v = value.get("v").and_then(|v| v.as_i64());
    let password = value.get("password").and_then(|v| v.as_str());
    match (v, password) {
        (Some(1), Some(p)) => Ok(p.to_string()),
        _ => Err(ClientError::Crypto(
            "vault decryption failed / wrong key or corrupted data".into(),
        )),
    }
}
