use crate::client::{api::ApiClient, config, session::Session};
use password_manager_crypto::{client as crypto, core};
use password_manager_dto::auth::AuthTokensResponse;

use crate::cli::{
    error::{CliError, CliResult},
    prompt,
};

pub(super) fn get_server(cfg: &config::Config) -> CliResult<String> {
    cfg.server_url
        .clone()
        .ok_or_else(|| CliError::Message("server URL not set; run `passman server <url>`".into()))
}

pub(super) fn resolve_email(email: Option<String>) -> CliResult<String> {
    let email = prompt::resolve_line(email, "Email: ")?.to_lowercase();
    if email.is_empty() {
        return Err(CliError::Message("email cannot be empty".into()));
    }
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(CliError::Message("invalid email".into()));
    }
    Ok(email)
}

pub(super) fn resolve_master_for_register() -> CliResult<String> {
    prompt::prompt_password_confirm()
}

pub(super) fn load_session(paths: &config::Paths) -> CliResult<Session> {
    Session::load(&paths.session)?
        .ok_or_else(|| CliError::Message("not logged in; run `passman login`".into()))
}

pub(super) fn apply_refresh_response(
    sess: &mut Session,
    resp: AuthTokensResponse,
    session_path: &std::path::Path,
) -> CliResult<()> {
    if resp.kdf_salt != sess.kdf_salt {
        return Err(CliError::Message(
            "refresh protocol error: kdf_salt mismatch; run `passman login`".into(),
        ));
    }
    sess.access_token = resp.access_token;
    sess.refresh_token = resp.refresh_token;
    sess.access_expires_in_secs = resp.access_expires_in_secs;
    sess.refresh_expires_in_secs = resp.refresh_expires_in_secs;
    sess.save(session_path)?;
    Ok(())
}

async fn refresh_session_locked(
    api: &ApiClient,
    paths: &config::Paths,
    sess: &mut Session,
) -> CliResult<bool> {
    let _lock = crate::client::storage::lock_exclusive(&paths.session)?;
    let latest = load_session(paths)?;
    if latest.access_token != sess.access_token || latest.refresh_token != sess.refresh_token {
        *sess = latest;
        return Ok(true);
    }
    let resp = api
        .refresh(&password_manager_dto::auth::RefreshRequest {
            refresh_token: sess.refresh_token.clone(),
        })
        .await
        .map_err(map_refresh_error)?;
    apply_refresh_response(sess, resp, &paths.session)?;
    Ok(false)
}

fn map_refresh_error(err: crate::client::error::ClientError) -> CliError {
    match err {
        crate::client::error::ClientError::Unauthorized(_) => {
            CliError::Message("session expired; run `passman login`".into())
        }
        other => CliError::Client(other),
    }
}

pub(super) async fn with_auth_retry<T, F, Fut>(
    api: &ApiClient,
    paths: &config::Paths,
    sess: &mut Session,
    mut f: F,
) -> CliResult<T>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, crate::client::error::ClientError>>,
{
    match f(sess.access_token.clone()).await {
        Ok(v) => Ok(v),
        Err(crate::client::error::ClientError::Unauthorized(_)) => {
            let reloaded = refresh_session_locked(api, paths, sess).await?;
            if reloaded {
                return match f(sess.access_token.clone()).await {
                    Ok(v) => Ok(v),
                    Err(crate::client::error::ClientError::Unauthorized(_)) => {
                        refresh_session_locked(api, paths, sess).await?;
                        f(sess.access_token.clone()).await.map_err(|e| match e {
                            crate::client::error::ClientError::Unauthorized(_) => {
                                CliError::Message("session expired; run `passman login`".into())
                            }
                            other => CliError::Client(other),
                        })
                    }
                    Err(e) => Err(CliError::Client(e)),
                };
            }
            f(sess.access_token.clone()).await.map_err(|e| match e {
                crate::client::error::ClientError::Unauthorized(_) => {
                    CliError::Message("session expired; run `passman login`".into())
                }
                other => CliError::Client(other),
            })
        }
        Err(e) => Err(CliError::Client(e)),
    }
}

const VAULT_CHECK_PLAINTEXT: &str = "passman-vault-check-v1";

pub(super) fn create_vault_check(vault_key: &[u8; 32], email: &str) -> CliResult<(String, String)> {
    crypto::encrypt_secret(vault_key, email, VAULT_CHECK_PLAINTEXT)
        .map_err(|_| CliError::Message("failed to create vault check".into()))
}

fn verify_vault_check(sess: &Session, vault_key: &[u8; 32]) -> CliResult<()> {
    let (Some(ciphertext), Some(nonce)) = (&sess.vault_check_ciphertext, &sess.vault_check_nonce)
    else {
        return Err(CliError::Message(
            "session missing vault check; run `passman login`".into(),
        ));
    };
    crypto::decrypt_secret(vault_key, &sess.email, ciphertext, nonce)
        .map_err(|_| CliError::Message("invalid master password".into()))?;
    Ok(())
}

pub(super) async fn derive_and_verify_vault_key(
    api: &ApiClient,
    paths: &config::Paths,
    sess: &mut Session,
    password: &str,
) -> CliResult<zeroize::Zeroizing<[u8; 32]>> {
    let salt = core::base64::decode(&sess.kdf_salt)
        .map_err(|_| CliError::Message("kdf_salt must be valid base64".to_string()))?;
    let master = crypto::derive_master_key(password, &salt)?;
    let vault = crypto::derive_vault_key(&master)?;

    if sess.vault_check_ciphertext.is_some() && sess.vault_check_nonce.is_some() {
        verify_vault_check(sess, &vault)?;
        return Ok(vault);
    }

    // Backward-compatible upgrade for sessions created before vault check existed.
    let verifier = crypto::derive_auth_verifier(&master)?;
    let resp = api
        .login(&password_manager_dto::auth::LoginRequest {
            email: sess.email.clone(),
            auth_verifier: core::base64::encode(&verifier),
        })
        .await
        .map_err(|e| match e {
            crate::client::error::ClientError::Unauthorized(_) => {
                CliError::Message("invalid master password".into())
            }
            other => CliError::Client(other),
        })?;
    if resp.kdf_salt != sess.kdf_salt {
        return Err(CliError::Message(
            "login protocol error: kdf_salt mismatch; run `passman login`".into(),
        ));
    }

    let (vault_check_ciphertext, vault_check_nonce) = create_vault_check(&vault, &sess.email)?;
    sess.access_token = resp.access_token;
    sess.refresh_token = resp.refresh_token;
    sess.access_expires_in_secs = resp.access_expires_in_secs;
    sess.refresh_expires_in_secs = resp.refresh_expires_in_secs;
    sess.kdf_salt = resp.kdf_salt;
    sess.vault_check_ciphertext = Some(vault_check_ciphertext);
    sess.vault_check_nonce = Some(vault_check_nonce);
    sess.save(&paths.session)?;
    Ok(vault)
}

pub(super) fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn resolve_optional_field(
    value: Option<String>,
    label: &str,
) -> CliResult<Option<String>> {
    match value {
        Some(v) => Ok(empty_to_none(v)),
        None => Ok(empty_to_none(prompt::prompt_line(label)?)),
    }
}

pub(super) fn edited_optional(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn sanitize_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub(super) fn prompt_prefilled(label: &str, current: &str) -> Result<String, CliError> {
    prompt::prompt_line_prefilled(label, current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use password_manager_dto::auth::AuthTokensResponse;
    use std::fs;
    use uuid::Uuid;

    fn temp_session_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("passman-test-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("session.json")
    }

    fn session() -> Session {
        Session {
            server_url: "http://localhost:3000".into(),
            email: "user@example.com".into(),
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            access_expires_in_secs: 900,
            refresh_expires_in_secs: 604800,
            kdf_salt: "salt-a".into(),
            vault_check_ciphertext: None,
            vault_check_nonce: None,
        }
    }

    fn refresh_resp(kdf_salt: &str) -> AuthTokensResponse {
        AuthTokensResponse {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            token_type: "Bearer".into(),
            access_expires_in_secs: 100,
            refresh_expires_in_secs: 200,
            kdf_salt: kdf_salt.into(),
        }
    }

    #[test]
    fn refresh_session_rejects_kdf_salt_mismatch() {
        let path = temp_session_path("kdf-mismatch");
        let mut sess = session();
        sess.save(&path).unwrap();
        let before = fs::read_to_string(&path).unwrap();

        let err = apply_refresh_response(&mut sess, refresh_resp("salt-b"), &path).unwrap_err();
        assert!(format!("{err}").contains("kdf_salt mismatch"), "{err}");
        assert_eq!(sess.access_token, "old-access");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn refresh_session_updates_tokens_when_kdf_salt_matches() {
        let path = temp_session_path("kdf-ok");
        let mut sess = session();
        sess.save(&path).unwrap();

        apply_refresh_response(&mut sess, refresh_resp("salt-a"), &path).unwrap();
        assert_eq!(sess.access_token, "new-access");
        assert_eq!(sess.refresh_token, "new-refresh");
        assert_eq!(sess.kdf_salt, "salt-a");
        let loaded = Session::load(&path).unwrap().unwrap();
        assert_eq!(loaded.access_token, "new-access");
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_terminal;

    #[test]
    fn sanitize_terminal_escapes_control_chars() {
        let s = "a\x1b[31mRED\x1b[0m\0\n";
        let out = sanitize_terminal(s);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\0'));
        assert!(out.contains("\\u{1b}"));
        assert!(out.contains("\\0"));
        assert!(out.contains("\\n"));
    }
}
