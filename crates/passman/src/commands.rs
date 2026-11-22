use password_manager_api_types::{
    auth::{LoginRequest, LogoutRequest, PreloginRequest, RegisterRequest},
    credentials::{CreateCredentialRequest, UpdateCredentialRequest},
};
use password_manager_client::{api::ApiClient, config, crypto, session::Session};
use uuid::Uuid;

use crate::{
    error::{CliError, CliResult},
    prompt,
};

fn get_server(cfg: &config::Config) -> CliResult<String> {
    cfg.server_url
        .clone()
        .ok_or_else(|| CliError::Message("server URL not set; run `passman server <url>`".into()))
}

fn resolve_email(email: Option<String>) -> CliResult<String> {
    let raw = prompt::resolve_line(email, "Email: ")?;
    let email = crypto::normalize_email(&raw);
    if email.is_empty() {
        return Err(CliError::Message("email cannot be empty".into()));
    }
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(CliError::Message("invalid email".into()));
    }
    Ok(email)
}

fn resolve_master_for_register() -> CliResult<String> {
    prompt::prompt_password_confirm()
}

fn load_session(paths: &config::Paths) -> CliResult<Session> {
    Session::load(&paths.session)?
        .ok_or_else(|| CliError::Message("not logged in; run `passman login`".into()))
}

fn apply_refresh_response(
    sess: &mut Session,
    resp: password_manager_api_types::auth::AuthTokensResponse,
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
    let _lock = password_manager_client::storage::lock_exclusive(&paths.session)?;
    let latest = load_session(paths)?;
    if latest.access_token != sess.access_token || latest.refresh_token != sess.refresh_token {
        *sess = latest;
        return Ok(true);
    }
    let resp = api
        .refresh(&password_manager_api_types::auth::RefreshRequest {
            refresh_token: sess.refresh_token.clone(),
        })
        .await
        .map_err(map_refresh_error)?;
    apply_refresh_response(sess, resp, &paths.session)?;
    Ok(false)
}

fn map_refresh_error(err: password_manager_client::error::ClientError) -> CliError {
    match err {
        password_manager_client::error::ClientError::Unauthorized(_) => {
            CliError::Message("session expired; run `passman login`".into())
        }
        other => CliError::Client(other),
    }
}

async fn with_auth_retry<T, F, Fut>(
    api: &ApiClient,
    paths: &config::Paths,
    sess: &mut Session,
    mut f: F,
) -> CliResult<T>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, password_manager_client::error::ClientError>>,
{
    match f(sess.access_token.clone()).await {
        Ok(v) => Ok(v),
        Err(password_manager_client::error::ClientError::Unauthorized(_)) => {
            let reloaded = refresh_session_locked(api, paths, sess).await?;
            if reloaded {
                return match f(sess.access_token.clone()).await {
                    Ok(v) => Ok(v),
                    Err(password_manager_client::error::ClientError::Unauthorized(_)) => {
                        refresh_session_locked(api, paths, sess).await?;
                        f(sess.access_token.clone()).await.map_err(|e| match e {
                            password_manager_client::error::ClientError::Unauthorized(_) => {
                                CliError::Message("session expired; run `passman login`".into())
                            }
                            other => CliError::Client(other),
                        })
                    }
                    Err(e) => Err(CliError::Client(e)),
                };
            }
            f(sess.access_token.clone()).await.map_err(|e| match e {
                password_manager_client::error::ClientError::Unauthorized(_) => {
                    CliError::Message("session expired; run `passman login`".into())
                }
                other => CliError::Client(other),
            })
        }
        Err(e) => Err(CliError::Client(e)),
    }
}

pub async fn register(
    paths: &config::Paths,
    email: Option<String>,
) -> CliResult<()> {
    let cfg = config::Config::load(&paths.config)?;
    let server = get_server(&cfg)?;
    let email = resolve_email(email)?;
    let password = resolve_master_for_register()?;

    let salt = crypto::generate_kdf_salt();
    let master = crypto::derive_master_key(&password, &salt)?;
    let verifier = crypto::derive_auth_verifier(&master)?;

    let api = ApiClient::new(server)?;
    api.register(&RegisterRequest {
        email: email.clone(),
        auth_verifier: crypto::encode_b64(&verifier),
        kdf_salt: crypto::encode_b64(&salt),
    })
    .await?;

    println!("registered {email}");
    Ok(())
}

pub async fn login(paths: &config::Paths, email: Option<String>) -> CliResult<()> {
    let cfg = config::Config::load(&paths.config)?;
    let server = get_server(&cfg)?;
    let email = resolve_email(email)?;
    let password = prompt::prompt_password("Master password: ")?;

    let api = ApiClient::new(server.clone())?;
    let pre = api
        .prelogin(&PreloginRequest {
            email: email.clone(),
        })
        .await?;
    let salt = crypto::decode_b64("kdf_salt", &pre.kdf_salt)?;
    let master = crypto::derive_master_key(&password, &salt)?;
    let verifier = crypto::derive_auth_verifier(&master)?;

    let resp = api
        .login(&LoginRequest {
            email: email.clone(),
            auth_verifier: crypto::encode_b64(&verifier),
        })
        .await?;

    if resp.kdf_salt != pre.kdf_salt {
        return Err(CliError::Message(
            "login protocol error: kdf_salt mismatch".into(),
        ));
    }

    let sess = Session {
        server_url: server,
        email,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        access_expires_in_secs: resp.access_expires_in_secs,
        refresh_expires_in_secs: resp.refresh_expires_in_secs,
        kdf_salt: resp.kdf_salt,
    };
    sess.save(&paths.session)?;
    println!("logged in as {}", sess.email);
    Ok(())
}

pub async fn logout(paths: &config::Paths) -> CliResult<()> {
    let cfg = config::Config::load(&paths.config)?;
    let Some(sess) = Session::load(&paths.session)? else {
        println!("no active session");
        return Ok(());
    };
    if let Some(server) = cfg.server_url.clone().or(Some(sess.server_url.clone())) {
        if let Ok(api) = ApiClient::new(server) {
            let _ = api
                .logout(&LogoutRequest {
                    refresh_token: sess.refresh_token.clone(),
                })
                .await;
        }
    }
    Session::clear(&paths.session)?;
    println!("logged out");
    Ok(())
}

fn derive_vault_key_for_session(
    sess: &Session,
    password: &str,
) -> CliResult<zeroize::Zeroizing<[u8; 32]>> {
    let salt = crypto::decode_b64("kdf_salt", &sess.kdf_salt)?;
    let master = crypto::derive_master_key(password, &salt)?;
    let vault = crypto::derive_vault_key(&master)?;
    Ok(vault)
}

pub async fn add(
    paths: &config::Paths,
    name: Option<String>,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    secret: Option<String>,
) -> CliResult<()> {
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let password = prompt::prompt_password("Master password: ")?;
    let vault = derive_vault_key_for_session(&sess, &password)?;

    let name = prompt::resolve_line(name, "Name: ")?;
    if name.trim().is_empty() {
        return Err(CliError::Message("name cannot be empty".into()));
    }
    let username = resolve_optional_field(username, "Username (optional): ")?;
    let url = resolve_optional_field(url, "URL (optional): ")?;
    let notes = resolve_optional_field(notes, "Notes (optional): ")?;
    let secret = prompt::resolve_password(secret, "Credential secret: ")?;

    let (ciphertext, nonce) = crypto::encrypt_secret(&vault, &sess.email, &secret)?;
    let req = CreateCredentialRequest {
        name: name.trim().to_string(),
        username,
        url,
        notes,
        password_ciphertext: ciphertext,
        password_nonce: nonce,
    };
    let idempotency_key = Uuid::new_v4().to_string();
    let resp = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let req = req.clone();
        let idempotency_key = idempotency_key.clone();
        async move { api.create_credential(&token, &idempotency_key, &req).await }
    })
    .await?;

    println!("created credential {}", resp.id);
    Ok(())
}

pub async fn list(paths: &config::Paths) -> CliResult<()> {
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let rows = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        async move { api.list_credentials(&token).await }
    })
    .await?;

    if rows.is_empty() {
        println!("no credentials");
        return Ok(());
    }
    for r in rows {
        println!(
            "{}\t{}\t{}\t{}",
            r.id,
            r.name,
            r.username.as_deref().unwrap_or("-"),
            r.url.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

pub async fn get(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id_raw = prompt::resolve_line(id, "Credential id: ")?;
    let id = Uuid::parse_str(id_raw.trim()).map_err(|_| CliError::InvalidId(id_raw))?;
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let password = prompt::prompt_password("Master password: ")?;
    let vault = derive_vault_key_for_session(&sess, &password)?;

    let row = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        async move { api.get_credential(&token, id).await }
    })
    .await?;

    let secret = crypto::decrypt_secret(
        &vault,
        &sess.email,
        &row.password_ciphertext,
        &row.password_nonce,
    )?;
    println!("id: {}", row.id);
    println!("name: {}", row.name);
    println!("username: {}", row.username.as_deref().unwrap_or(""));
    println!("url: {}", row.url.as_deref().unwrap_or(""));
    println!("notes: {}", row.notes.as_deref().unwrap_or(""));
    println!("secret: {secret}");
    Ok(())
}

pub async fn edit(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id_raw = prompt::resolve_line(id, "Credential id: ")?;
    let id = Uuid::parse_str(id_raw.trim()).map_err(|_| CliError::InvalidId(id_raw))?;
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let password = prompt::prompt_password("Master password: ")?;
    let vault = derive_vault_key_for_session(&sess, &password)?;

    let row = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        async move { api.get_credential(&token, id).await }
    })
    .await?;

    println!("Leave blank to keep current value. For username/url/notes, enter '-' to clear.");
    let name = prompt::prompt_line(&format!("Name [{}]: ", row.name))?;
    let username = prompt::prompt_line(&format!(
        "Username [{}]: ",
        row.username.as_deref().unwrap_or("")
    ))?;
    let url = prompt::prompt_line(&format!("URL [{}]: ", row.url.as_deref().unwrap_or("")))?;
    let notes = prompt::prompt_line(&format!("Notes [{}]: ", row.notes.as_deref().unwrap_or("")))?;
    let secret = prompt::prompt_password("New secret (blank to keep): ")?;

    let mut req = UpdateCredentialRequest {
        name: if name.trim().is_empty() {
            None
        } else {
            Some(name.trim().to_string())
        },
        username: prompt_optional_update(username),
        url: prompt_optional_update(url),
        notes: prompt_optional_update(notes),
        password_ciphertext: None,
        password_nonce: None,
    };

    if !secret.is_empty() {
        let (ciphertext, nonce) = crypto::encrypt_secret(&vault, &sess.email, &secret)?;
        req.password_ciphertext = Some(ciphertext);
        req.password_nonce = Some(nonce);
    }

    let updated = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let req = req.clone();
        async move { api.update_credential(&token, id, &req).await }
    })
    .await?;

    println!("updated credential {}", updated.id);
    Ok(())
}

pub async fn delete(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id_raw = prompt::resolve_line(id, "Credential id: ")?;
    let id = Uuid::parse_str(id_raw.trim()).map_err(|_| CliError::InvalidId(id_raw))?;
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;

    let confirm = prompt::prompt_line(&format!("Delete credential {id}? [y/N]: "))?;
    if !matches!(confirm.to_lowercase().as_str(), "y" | "yes") {
        println!("cancelled");
        return Ok(());
    }

    with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        async move { api.delete_credential(&token, id).await }
    })
    .await?;

    println!("deleted {id}");
    Ok(())
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_optional_field(value: Option<String>, label: &str) -> CliResult<Option<String>> {
    match value {
        Some(v) => Ok(empty_to_none(v)),
        None => Ok(empty_to_none(prompt::prompt_line(label)?)),
    }
}

fn prompt_optional_update(value: String) -> Option<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed == "-" {
        Some(None)
    } else {
        Some(Some(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use password_manager_api_types::auth::AuthTokensResponse;
    use std::fs;

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

pub fn server(paths: &config::Paths, url: Option<String>) -> CliResult<String> {
    let url = prompt::resolve_line(url, "Server URL: ")?;
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err(CliError::Message("server URL cannot be empty".into()));
    }
    let mut cfg = config::Config::load(&paths.config)?;
    let changed = cfg.server_url.as_deref() != Some(url.as_str());
    cfg.server_url = Some(url.clone());
    cfg.save(&paths.config)?;

    if changed {
        if let Some(mut sess) = Session::load(&paths.session)? {
            sess.server_url = url.clone();
            sess.save(&paths.session)?;
        }
    }
    Ok(url)
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use std::fs;

    fn test_paths(name: &str) -> config::Paths {
        let dir = std::env::temp_dir().join(format!("passman-server-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        config::Paths {
            dir: dir.clone(),
            config: dir.join("config.toml"),
            session: dir.join("session.json"),
        }
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
        }
    }

    #[test]
    fn server_updates_active_session_url() {
        let paths = test_paths("updates-session");
        let mut cfg = config::Config::default();
        cfg.server_url = Some("http://old".into());
        cfg.save(&paths.config).unwrap();
        let mut sess = session();
        sess.server_url = "http://old".into();
        sess.save(&paths.session).unwrap();

        let url = server(&paths, Some("http://new".into())).unwrap();
        assert_eq!(url, "http://new");
        let sess = Session::load(&paths.session).unwrap().unwrap();
        assert_eq!(sess.server_url, "http://new");
    }
}
