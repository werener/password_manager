use crate::client::{api::ApiClient, config, session::Session};
use password_manager_crypto::{client as crypto, core};
use password_manager_dto::{
    auth::{LoginRequest, LogoutRequest, PreloginRequest, RegisterRequest},
    credentials::{CreateCredentialRequest, UpdateCredentialRequest},
};
use uuid::Uuid;

use crate::cli::{
    error::{CliError, CliResult},
    prompt,
    utils::{
        derive_vault_key_for_session, get_server, load_session, prompt_line_with_current,
        prompt_optional_update, resolve_email, resolve_master_for_register, resolve_optional_field,
        sanitize_terminal, with_auth_retry,
    },
};

pub async fn register(paths: &config::Paths, email: Option<String>) -> CliResult<()> {
    let cfg = config::Config::load(&paths.config)?;
    let server = get_server(&cfg)?;
    let email = resolve_email(email)?;
    let password = resolve_master_for_register()?;

    let salt: [u8; 32] = core::rand::bytes();
    let master = crypto::derive_master_key(&password, &salt)?;
    let verifier = crypto::derive_auth_verifier(&master)?;

    let api = ApiClient::new(server)?;
    api.register(&RegisterRequest {
        email: email.clone(),
        auth_verifier: core::base64::encode(&verifier),
        kdf_salt: core::base64::encode(&salt),
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
    let salt = core::base64::decode(&pre.kdf_salt)
        .map_err(|_| CliError::Message("kdf_salt must be valid base64".to_string()))?;
    let master = crypto::derive_master_key(&password, &salt)?;
    let verifier = crypto::derive_auth_verifier(&master)?;

    let resp = api
        .login(&LoginRequest {
            email: email.clone(),
            auth_verifier: core::base64::encode(&verifier),
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

    let username = resolve_optional_field(username, "Username: ")?;
    let secret = prompt::resolve_password(secret, "Credential (password): ")?;
    let name = prompt::resolve_line(name, "Title: ")?;
    if name.trim().is_empty() {
        return Err(CliError::Message("title cannot be empty".into()));
    }
    let url = resolve_optional_field(url, "URL: ")?;
    let notes = resolve_optional_field(notes, "Notes: ")?;

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

pub async fn list(paths: &config::Paths, show_ids: bool) -> CliResult<()> {
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
    let mut table: Vec<Vec<String>> = Vec::new();
    if show_ids {
        table.push(vec![
            "ID".into(),
            "Title".into(),
            "Username".into(),
            "URL".into(),
            "Notes".into(),
        ]);
    } else {
        table.push(vec![
            "Title".into(),
            "Username".into(),
            "URL".into(),
            "Notes".into(),
        ]);
    }
    for r in &rows {
        let row = if show_ids {
            vec![
                r.id.to_string(),
                sanitize_terminal(&r.name),
                sanitize_terminal(r.username.as_deref().unwrap_or("-")),
                sanitize_terminal(r.url.as_deref().unwrap_or("-")),
                sanitize_terminal(r.notes.as_deref().unwrap_or("-")),
            ]
        } else {
            vec![
                sanitize_terminal(&r.name),
                sanitize_terminal(r.username.as_deref().unwrap_or("-")),
                sanitize_terminal(r.url.as_deref().unwrap_or("-")),
                sanitize_terminal(r.notes.as_deref().unwrap_or("-")),
            ]
        };
        table.push(row);
    }
    let cols = table[0].len();
    let mut widths = vec![0usize; cols];
    for row in &table {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    for row in &table {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            if i + 1 < cols {
                let pad = widths[i].saturating_sub(cell.chars().count());
                for _ in 0..pad {
                    line.push(' ');
                }
            }
        }
        println!("{line}");
    }
    Ok(())
}

pub async fn get(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id = prompt::resolve_line(id, "Credential title/id: ")?;
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err(CliError::Message(
            "credential title/id cannot be empty".into(),
        ));
    }
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let password = prompt::prompt_password("Master password: ")?;
    let vault = derive_vault_key_for_session(&sess, &password)?;

    let row = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let id = id.clone();
        async move { api.get_credential(&token, &id).await }
    })
    .await?;

    let secret = crypto::decrypt_secret(
        &vault,
        &sess.email,
        &row.password_ciphertext,
        &row.password_nonce,
    )?;
    println!("ID: {}", row.id);
    println!(
        "Username: {}",
        sanitize_terminal(row.username.as_deref().unwrap_or(""))
    );
    println!("Credential: {}", sanitize_terminal(&secret));
    println!("Title: {}", sanitize_terminal(&row.name));
    println!(
        "URL: {}",
        sanitize_terminal(row.url.as_deref().unwrap_or(""))
    );
    println!(
        "Notes: {}",
        sanitize_terminal(row.notes.as_deref().unwrap_or(""))
    );
    Ok(())
}

pub async fn edit(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id = prompt::resolve_line(id, "Credential title/id: ")?;
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err(CliError::Message(
            "credential title/id cannot be empty".into(),
        ));
    }
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;
    let password = prompt::prompt_password("Master password: ")?;
    let vault = derive_vault_key_for_session(&sess, &password)?;

    let row = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let id = id.clone();
        async move { api.get_credential(&token, &id).await }
    })
    .await?;

    println!("Leave blank to keep current value. For username/url/notes, enter '-' to clear.");
    let name_input = prompt_line_with_current("Name", &row.name)?;
    let username_input =
        prompt_line_with_current("Username", row.username.as_deref().unwrap_or(""))?;
    let url_input = prompt_line_with_current("URL", row.url.as_deref().unwrap_or(""))?;
    let notes_input = prompt_line_with_current("Notes", row.notes.as_deref().unwrap_or(""))?;
    let secret = prompt::prompt_password("New secret (blank to keep): ")?;

    let mut req = UpdateCredentialRequest {
        name: if name_input.trim().is_empty() {
            None
        } else {
            Some(Some(name_input.trim().to_string()))
        },
        username: prompt_optional_update(username_input),
        url: prompt_optional_update(url_input),
        notes: prompt_optional_update(notes_input),
        password_ciphertext: None,
        password_nonce: None,
    };

    if !secret.is_empty() {
        let (ciphertext, nonce) = crypto::encrypt_secret(&vault, &sess.email, &secret)?;
        req.password_ciphertext = Some(Some(ciphertext));
        req.password_nonce = Some(Some(nonce));
    }

    let target_id = row.id.to_string();
    let updated = with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let req = req.clone();
        let target_id = target_id.clone();
        async move { api.update_credential(&token, &target_id, &req).await }
    })
    .await?;

    println!("updated credential {}", updated.id);
    Ok(())
}

pub async fn delete(paths: &config::Paths, id: Option<String>) -> CliResult<()> {
    let id = prompt::resolve_line(id, "Credential title/id: ")?;
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err(CliError::Message(
            "credential title/id cannot be empty".into(),
        ));
    }
    let mut sess = load_session(paths)?;
    let api = ApiClient::new(sess.server_url.clone())?;

    let confirm = prompt::prompt_line(&format!("Delete credential {id}? [Y/n]: "))?;
    if matches!(confirm.to_lowercase().as_str(), "n" | "no") {
        println!("cancelled");
        return Ok(());
    }

    let id_owned = id.clone();
    with_auth_retry(&api, paths, &mut sess, |token| {
        let api = api.clone();
        let id_owned = id_owned.clone();
        async move { api.delete_credential(&token, &id_owned).await }
    })
    .await?;

    println!("deleted {id}");
    Ok(())
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
