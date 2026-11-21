use password_manager_backend::crypto::{
    create_access_token, decode_access_token, decode_base64, encode_base64, generate_refresh_token,
    hash_auth_verifier, hash_refresh_token, normalize_email, validate_email, verify_auth_verifier,
};
use uuid::Uuid;

#[test]
fn email_normalization_and_validation() {
    assert_eq!(normalize_email("  User@Example.COM "), "user@example.com");
    assert!(validate_email("user@example.com").is_ok());
    assert!(validate_email("invalid").is_err());
}

#[test]
fn base64_roundtrip_and_invalid_input() {
    let bytes = b"hello";
    let enc = encode_base64(bytes);
    assert_eq!(decode_base64("field", &enc).unwrap(), bytes);
    assert!(decode_base64("field", "not-base64!!").is_err());
}

#[test]
fn auth_verifier_hash_and_verify() {
    let verifier = b"client-derived-verifier";
    let hash = hash_auth_verifier(verifier).expect("hash");
    assert!(verify_auth_verifier(verifier, &hash).expect("verify"));
    assert!(!verify_auth_verifier(b"wrong", &hash).expect("verify wrong"));
}

#[test]
fn access_token_roundtrip() {
    let secret = "test-secret";
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let token = create_access_token(
        secret,
        user_id,
        session_id,
        std::time::Duration::from_secs(60),
    )
    .expect("token");
    let claims = decode_access_token(secret, &token).expect("claims");
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.sid, session_id);
    assert_eq!(claims.token_type, "access");
    assert!(decode_access_token("wrong-secret", &token).is_err());
}

#[test]
fn refresh_token_generation_and_hashing() {
    let t1 = generate_refresh_token();
    let t2 = generate_refresh_token();
    assert_ne!(t1, t2);
    assert_eq!(hash_refresh_token(&t1), hash_refresh_token(&t1));
    assert_ne!(hash_refresh_token(&t1), hash_refresh_token(&t2));
}
