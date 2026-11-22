use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    core::{aead, base64, kdf, rand},
    error::CryptoError,
};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

const KDF_PARAMS: kdf::Argon2idParams = kdf::Argon2idParams {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 1,
    output_len: KEY_LEN,
};
const AUTH_INFO: &[u8] = b"passman.v1.auth-verifier";
const VAULT_INFO: &[u8] = b"passman.v1.vault-key";

#[derive(Serialize, Deserialize)]
struct SecretPayload<'a> {
    v: u8,
    password: &'a str,
}

pub fn derive_master_key(
    password: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    kdf::argon2id_derive::<KEY_LEN>(password.as_bytes(), salt, KDF_PARAMS)
}

pub fn derive_auth_verifier(master_key: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    kdf::hkdf_sha256::<KEY_LEN>(master_key, AUTH_INFO)
}

pub fn derive_vault_key(
    master_key: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    Ok(Zeroizing::new(kdf::hkdf_sha256::<KEY_LEN>(
        master_key, VAULT_INFO,
    )?))
}

pub fn encrypt_secret(
    vault_key: &[u8; KEY_LEN],
    email_normalized: &str,
    password: &str,
) -> Result<(String, String), CryptoError> {
    let payload = SecretPayload { v: 1, password };
    let plaintext = serde_json::to_vec(&payload).map_err(|_| CryptoError::Internal)?;
    let nonce: [u8; NONCE_LEN] = rand::bytes();
    let aad = format!("passman.v1.credential-secret:{email_normalized}");
    let ciphertext =
        aead::xchacha20poly1305_encrypt(vault_key, &nonce, &plaintext, aad.as_bytes())?;
    Ok((base64::encode(&ciphertext), base64::encode(&nonce)))
}

pub fn decrypt_secret(
    vault_key: &[u8; KEY_LEN],
    email_normalized: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> Result<String, CryptoError> {
    let ciphertext = base64::decode(ciphertext_b64)?;
    let nonce = base64::decode(nonce_b64)?;
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidData("password_nonce must be 24 bytes".into()))?;
    let aad = format!("passman.v1.credential-secret:{email_normalized}");
    let plaintext =
        aead::xchacha20poly1305_decrypt(vault_key, &nonce, &ciphertext, aad.as_bytes())?;
    #[derive(Deserialize)]
    struct Out {
        v: i64,
        password: String,
    }
    let out: Out = serde_json::from_slice(&plaintext).map_err(|_| CryptoError::Unauthorized)?;
    if out.v != 1 {
        return Err(CryptoError::Unauthorized);
    }
    Ok(out.password)
}
