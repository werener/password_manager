use password_manager_crypto::{CryptoError, client, core, server};
use uuid::Uuid;

#[test]
fn base64_roundtrip_and_invalid() {
    let bytes = b"hello-world";
    let enc = core::base64::encode(bytes);
    assert_eq!(core::base64::decode(&enc).unwrap(), bytes);
    let err = core::base64::decode("not-base64!!").unwrap_err();
    assert!(matches!(err, CryptoError::InvalidData(_)));
}

#[test]
fn sha256_is_deterministic() {
    let a = core::hash::sha256(b"abc");
    let b = core::hash::sha256(b"abc");
    let c = core::hash::sha256(b"abd");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn argon2_password_hash_roundtrip() {
    let secret = b"client-derived-verifier";
    let hash = core::hash::argon2_hash(secret).expect("hash");
    assert!(core::hash::argon2_verify(secret, &hash).expect("verify"));
    assert!(!core::hash::argon2_verify(b"wrong", &hash).expect("verify wrong"));
    let err = core::hash::argon2_verify(secret, "not-a-hash").unwrap_err();
    assert!(matches!(err, CryptoError::InvalidData(_)));
}

#[test]
fn access_token_roundtrip_and_wrong_secret() {
    let secret = "test-secret";
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let token = server::create_access_token(secret, user_id, session_id, 60).expect("token");
    let claims = server::decode_access_token(secret, &token).expect("claims");
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.sid, session_id);
    assert_eq!(claims.token_type, "access");
    let err = server::decode_access_token("wrong-secret", &token).unwrap_err();
    assert!(matches!(err, CryptoError::Unauthorized));
}

#[test]
fn refresh_token_generation_and_hashing() {
    let t1 = server::generate_refresh_token();
    let t2 = server::generate_refresh_token();
    assert_ne!(t1, t2);
    assert_eq!(
        core::hash::sha256(t1.as_bytes()),
        core::hash::sha256(t1.as_bytes())
    );
    assert_ne!(
        core::hash::sha256(t1.as_bytes()),
        core::hash::sha256(t2.as_bytes())
    );
}

#[test]
fn deterministic_fake_kdf_salt_is_stable() {
    let a = server::deterministic_fake_kdf_salt("secret", "user@example.com");
    let b = server::deterministic_fake_kdf_salt("secret", "user@example.com");
    let c = server::deterministic_fake_kdf_salt("secret", "other@example.com");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 16);
}

#[test]
fn rate_limit_email_hash_is_stable_hex() {
    let a = server::hash_email_for_rate_limit("user@example.com");
    let b = server::hash_email_for_rate_limit("user@example.com");
    let c = server::hash_email_for_rate_limit("other@example.com");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn client_secret_roundtrip() {
    let salt: [u8; 32] = core::rand::bytes();
    let master = client::derive_master_key("pw", &salt).unwrap();
    let auth = client::derive_auth_verifier(&master).unwrap();
    let vault = client::derive_vault_key(&master).unwrap();
    assert_ne!(auth, *vault);

    let (ct, nonce) = client::encrypt_secret(&vault, "user@example.com", "secret").unwrap();
    let plain = client::decrypt_secret(&vault, "user@example.com", &ct, &nonce).unwrap();
    assert_eq!(plain, "secret");

    let err = client::decrypt_secret(&vault, "other@example.com", &ct, &nonce).unwrap_err();
    assert!(matches!(err, CryptoError::Unauthorized));
}
