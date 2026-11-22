use std::net::SocketAddr;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use migration::{Migrator, MigratorTrait};
use password_manager_backend::{app, config::Config};
use redis::aio::ConnectionManager;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use serde_json::{Value, json};
use tower::{Service, ServiceExt, util::BoxCloneService};
use uuid::Uuid;

fn test_config() -> Config {
    let path = if std::path::Path::new(".env.test").exists() {
        ".env.test"
    } else {
        ".env.example"
    };
    dotenvy::from_filename(path).ok();
    Config::from_env().expect("load test config")
}

async fn setup() -> (
    BoxCloneService<Request<Body>, axum::response::Response, std::convert::Infallible>,
    DatabaseConnection,
    ConnectionManager,
    app::AppState,
) {
    let config = test_config();
    let mut opt = ConnectOptions::new(config.database_url.clone());
    opt.max_connections(5).min_connections(1);
    let db = Database::connect(opt).await.expect("db connect");
    Migrator::up(&db, None).await.expect("migrate");

    let redis_client = redis::Client::open(config.redis_url.clone()).expect("redis client");
    let redis = ConnectionManager::new(redis_client)
        .await
        .expect("redis connect");
    let state = app::AppState {
        db: db.clone(),
        redis: redis.clone(),
        config,
    };
    let router = app::build_router(state.clone());
    let svc = router.into_service().boxed_clone();
    (svc, db, redis, state)
}

async fn request(
    app: &mut BoxCloneService<Request<Body>, axum::response::Response, std::convert::Infallible>,
    req: Request<Body>,
) -> (StatusCode, Value) {
    let resp = app.ready().await.unwrap().call(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body)}))
    };
    (status, json)
}

fn json_req_at(method: Method, uri: &str, body: Value, ip: [u8; 4], port: u16) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((ip, port))))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn json_req(method: Method, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn auth_json_req(method: Method, uri: &str, token: &str, body: Value) -> Request<Body> {
    let mut req = json_req(method, uri, body);
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    req
}

fn auth_req(method: Method, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))))
        .body(Body::empty())
        .unwrap()
}

fn b64(bytes: &[u8]) -> String {
    password_manager_crypto::core::base64::encode(bytes)
}

#[tokio::test]
async fn auth_flow_and_credentials_flow() {
    let (mut app, db, mut redis_conn, _state) = setup().await;
    let email = format!("test+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[1u8; 32]);
    let kdf_salt = b64(&[1u8; 32]);

    // register
    let (status, body) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email":email,"auth_verifier":verifier,"kdf_salt":kdf_salt}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body["user_id"].is_string());

    // prelogin
    let (status, body) = request(
        &mut app,
        json_req(Method::POST, "/auth/prelogin", json!({"email":email})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kdf_salt"], kdf_salt);

    // prelogin unknown email - no enumeration
    let (status, body) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/prelogin",
            json!({"email":"unknown@example.com"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["kdf_salt"].is_string());

    // login wrong verifier
    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":b64(&[8u8;32])}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // login ok
    let (status, login) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":verifier}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let access = login["access_token"].as_str().unwrap();
    let refresh = login["refresh_token"].as_str().unwrap().to_string();

    // create credential
    let create_body = json!({"name":"n","username":"u","url":"https://x","notes":"note","password_ciphertext":b64(b"ct"),"password_nonce":b64(&[7u8;24])});
    let mut create_req = auth_json_req(Method::POST, "/credentials", access, create_body.clone());
    create_req
        .headers_mut()
        .insert("Idempotency-Key", "idem-1".parse().unwrap());
    let (status, created) = request(&mut app, create_req).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_string();

    // duplicate idempotency
    let mut dup_req = auth_json_req(Method::POST, "/credentials", access, create_body.clone());
    dup_req
        .headers_mut()
        .insert("Idempotency-Key", "idem-1".parse().unwrap());
    let (status, _) = request(&mut app, dup_req).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // missing idempotency
    let (status, _) = request(
        &mut app,
        auth_json_req(Method::POST, "/credentials", access, create_body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // list/get
    let (status, list) = request(&mut app, auth_req(Method::GET, "/credentials", access)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (status, got) = request(
        &mut app,
        auth_req(Method::GET, &format!("/credentials/{id}"), access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["password_ciphertext"], b64(b"ct"));

    // update clear notes
    let (status, upd) = request(
        &mut app,
        auth_json_req(
            Method::PUT,
            &format!("/credentials/{id}"),
            access,
            json!({"notes":null}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{upd}");
    assert!(upd["notes"].is_null());

    // refresh rotation
    let (status, refreshed) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token":refresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let refresh2 = refreshed["refresh_token"].as_str().unwrap().to_string();
    // old refresh should fail
    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token":login["refresh_token"]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // logout
    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/logout",
            json!({"refresh_token":refresh2}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // cleanup
    sqlx_cleanup(&db, &email).await;
    redis_cleanup_login(&mut redis_conn, &email).await;
}

#[tokio::test]
async fn login_rate_limit_and_auth_errors() {
    let (mut app, db, mut redis_conn, _state) = setup().await;
    let email = format!("rl+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[5u8; 32]);
    let kdf_salt = b64(&[2u8; 32]);

    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email":email,"auth_verifier":verifier,"kdf_salt":kdf_salt}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    for _ in 0..5 {
        let (status, _) = request(
            &mut app,
            json_req_at(
                Method::POST,
                "/auth/login",
                json!({"email":email,"auth_verifier":verifier}),
                [127, 0, 0, 9],
                41000,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = request(
        &mut app,
        json_req_at(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":verifier}),
            [127, 0, 0, 9],
            41000,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token":"bad"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = request(
        &mut app,
        json_req(Method::POST, "/auth/logout", json!({"refresh_token":"  "})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    sqlx_cleanup(&db, &email).await;
    redis_cleanup_login(&mut redis_conn, &email).await;
}

#[tokio::test]
async fn credentials_security_and_validation() {
    let (mut app, db, mut redis_conn, _state) = setup().await;
    let email_a = format!("a+{}@example.com", Uuid::new_v4());
    let email_b = format!("b+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[9u8; 32]);
    let salt = b64(&[3u8; 32]);
    for email in [&email_a, &email_b] {
        let (status, _) = request(
            &mut app,
            json_req(
                Method::POST,
                "/auth/register",
                json!({"email":email,"auth_verifier":verifier,"kdf_salt":salt}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, login_a) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email_a,"auth_verifier":verifier}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token_a = login_a["access_token"].as_str().unwrap();
    let (status, login_b) = request(
        &mut app,
        json_req_at(
            Method::POST,
            "/auth/login",
            json!({"email":email_b,"auth_verifier":verifier}),
            [127, 0, 0, 8],
            42000,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token_b = login_b["access_token"].as_str().unwrap();

    let create = json!({"name":"n","username":"u","url":"https://x","notes":"n","password_ciphertext":b64(b"ct"),"password_nonce":b64(&[7u8;24])});
    let mut req = auth_json_req(Method::POST, "/credentials", token_a, create.clone());
    req.headers_mut()
        .insert("Idempotency-Key", "k1".parse().unwrap());
    let (status, created) = request(&mut app, req).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap();

    // owner-scope
    let (status, _) = request(
        &mut app,
        auth_req(Method::GET, &format!("/credentials/{id}"), token_b),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &mut app,
        auth_req(Method::DELETE, &format!("/credentials/{id}"), token_b),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // validation
    let mut bad = auth_json_req(Method::POST, "/credentials", token_a, create.clone());
    bad.headers_mut()
        .insert("Idempotency-Key", "bad key!".parse().unwrap());
    let (status, _) = request(&mut app, bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut bad2 = auth_json_req(
        Method::POST,
        "/credentials",
        token_a,
        json!({"name":"n","username":"u","url":"https://x","notes":"n","password_ciphertext":"not-base64!!","password_nonce":b64(&[7u8;24])}),
    );
    bad2.headers_mut()
        .insert("Idempotency-Key", "k2".parse().unwrap());
    let (status, _) = request(&mut app, bad2).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // unauthorized
    let (status, _) = request(&mut app, auth_req(Method::GET, "/credentials", "bad-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // delete
    let (status, _) = request(
        &mut app,
        auth_req(Method::DELETE, &format!("/credentials/{id}"), token_a),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = request(
        &mut app,
        auth_req(Method::GET, &format!("/credentials/{id}"), token_a),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    sqlx_cleanup(&db, &email_a).await;
    sqlx_cleanup(&db, &email_b).await;
    redis_cleanup_login(&mut redis_conn, &email_a).await;
    redis_cleanup_login(&mut redis_conn, &email_b).await;
}

async fn sqlx_cleanup(db: &DatabaseConnection, email: &str) {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    if let Ok(Some(u)) = password_manager_backend::db::models::user::Entity::find()
        .filter(password_manager_backend::db::models::user::Column::Email.eq(email))
        .one(db)
        .await
    {
        let _ = password_manager_backend::db::models::user::Entity::delete_by_id(u.id)
            .exec(db)
            .await;
    }
}

async fn redis_cleanup_login(redis: &mut ConnectionManager, email: &str) {
    let normalized = email.trim().to_lowercase();
    let hash = password_manager_crypto::server::hash_email_for_rate_limit(&normalized);
    let key = format!("rl:login:127.0.0.1:{}", hash);
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query_async(redis)
        .await
        .unwrap_or(());
    let key9 = format!("rl:login:127.0.0.9:{}", hash);
    let _: () = redis::cmd("DEL")
        .arg(&key9)
        .query_async(redis)
        .await
        .unwrap_or(());
    let key8 = format!("rl:login:127.0.0.8:{}", hash);
    let _: () = redis::cmd("DEL")
        .arg(&key8)
        .query_async(redis)
        .await
        .unwrap_or(());
}

#[tokio::test]
async fn refresh_concurrent_same_token_only_one_succeeds() {
    let (mut app, db, mut redis_conn, _state) = setup().await;
    let email = format!("race+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[6u8; 32]);
    let kdf_salt = b64(&[7u8; 32]);

    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email":email,"auth_verifier":verifier,"kdf_salt":kdf_salt}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":verifier}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let refresh = login["refresh_token"].as_str().unwrap().to_string();

    let mut app1 = app.clone();
    let mut app2 = app.clone();
    let r1 = refresh.clone();
    let r2 = refresh.clone();
    let (a, b) = tokio::join!(
        request(
            &mut app1,
            json_req(Method::POST, "/auth/refresh", json!({"refresh_token": r1})),
        ),
        request(
            &mut app2,
            json_req(Method::POST, "/auth/refresh", json!({"refresh_token": r2})),
        ),
    );

    let statuses = [a.0, b.0];
    let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let unauthorized_count = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!(
        ok_count, 1,
        "exactly one refresh should succeed: {statuses:?} {a:?} {b:?}"
    );
    assert_eq!(
        unauthorized_count, 1,
        "other concurrent refresh should be unauthorized: {statuses:?} {a:?} {b:?}"
    );

    // Old token must be rejected
    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token": refresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Winning token should work
    let winning_refresh = if a.0 == StatusCode::OK {
        a.1["refresh_token"].as_str().unwrap().to_string()
    } else {
        b.1["refresh_token"].as_str().unwrap().to_string()
    };
    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token": winning_refresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    sqlx_cleanup(&db, &email).await;
    redis_cleanup_login(&mut redis_conn, &email).await;
}

#[tokio::test]
async fn login_does_not_persist_refresh_token_when_access_mint_fails() {
    let (mut app, db, mut redis_conn, state) = setup().await;
    let email = format!("mintfail+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48,
    ]);
    let kdf_salt = b64(&[8u8; 32]);

    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email":email,"auth_verifier":verifier,"kdf_salt":kdf_salt}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let user = password_manager_backend::db::models::user::Entity::find()
        .filter(password_manager_backend::db::models::user::Column::Email.eq(email.clone()))
        .one(&db)
        .await
        .unwrap()
        .expect("user exists");

    let fail_app = app::build_router(state.clone()).layer(axum::Extension(
        password_manager_backend::app::routers::auth::AccessTokenMinterExt(std::sync::Arc::new(
            |_, _, _, _| Err(password_manager_backend::error::AppError::Internal),
        )),
    ));
    let mut fail_app = fail_app.into_service().boxed_clone();
    let (status, body) = request(
        &mut fail_app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":verifier}),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let count = password_manager_backend::db::models::refresh_token::Entity::find()
        .filter(password_manager_backend::db::models::refresh_token::Column::UserId.eq(user.id))
        .all(&db)
        .await
        .unwrap()
        .len();
    assert_eq!(
        count, 0,
        "no refresh token should be persisted on mint failure"
    );

    sqlx_cleanup(&db, &email).await;
    redis_cleanup_login(&mut redis_conn, &email).await;
}

#[tokio::test]
async fn refresh_does_not_rotate_when_access_mint_fails() {
    let (mut app, db, mut redis_conn, state) = setup().await;
    let email = format!("refresh-mint-fail+{}@example.com", Uuid::new_v4());
    let verifier = b64(&[
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
        44, 45, 46, 47, 48, 49, 50, 51, 52,
    ]);
    let kdf_salt = b64(&[9u8; 32]);

    let (status, _) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email":email,"auth_verifier":verifier,"kdf_salt":kdf_salt}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email":email,"auth_verifier":verifier}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let refresh = login["refresh_token"].as_str().unwrap().to_string();

    let fail_app = app::build_router(state.clone()).layer(axum::Extension(
        password_manager_backend::app::routers::auth::AccessTokenMinterExt(std::sync::Arc::new(
            |_, _, _, _| Err(password_manager_backend::error::AppError::Internal),
        )),
    ));
    let mut fail_app = fail_app.into_service().boxed_clone();
    let (status, body) = request(
        &mut fail_app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token": refresh}),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    // Old refresh token must still be valid because mint failed before commit.
    let (status, refreshed) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/refresh",
            json!({"refresh_token": refresh}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "old token should remain valid after mint failure: {refreshed}"
    );

    sqlx_cleanup(&db, &email).await;
    redis_cleanup_login(&mut redis_conn, &email).await;
}

#[tokio::test]
async fn credential_text_fields_reject_nul_control_chars() {
    let (mut app, db, redis, _state) = setup().await;
    let email = format!("nul-{}@example.com", Uuid::new_v4());
    let (status, reg) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email": email, "auth_verifier": b64(&[7u8;32]), "kdf_salt": b64(&[8u8;32])}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let (status, login) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email": email, "auth_verifier": b64(&[7u8;32])}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let token = login["access_token"].as_str().unwrap();

    let fields = ["name", "username", "url", "notes"];
    for field in fields {
        let mut body = json!({
            "name": "ok",
            "username": null,
            "url": null,
            "notes": null,
            "password_ciphertext": b64(b"ct"),
            "password_nonce": b64(&[1u8;24]),
        });
        body[field] = json!("a\u{0000}b");
        let mut req = auth_json_req(Method::POST, "/credentials", token, body);
        req.headers_mut()
            .insert("Idempotency-Key", format!("nul-{field}").parse().unwrap());
        let (status, resp) = request(&mut app, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {resp}");
        assert_eq!(resp["code"], "bad_request", "{field}: {resp}");
    }

    let _ = (db, redis);
}

#[tokio::test]
async fn framework_rejections_are_mapped_to_app_errors() {
    let (mut app, _db, _redis, _state) = setup().await;
    let (status, body) = request(
        &mut app,
        json_req(Method::POST, "/auth/register", json!({"email":"a@b.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "bad_request");
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(!msg.contains("Failed to deserialize"), "{msg}");
    assert!(!msg.contains("missing field"), "{msg}");

    // need token for credential path? invalid uuid path can be tested without auth? route is protected; bad auth may happen first. Use a bogus token to pass auth? easier: register/login to get token.
    let email = format!("rej-{}@example.com", Uuid::new_v4());
    let _ = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/register",
            json!({"email": email, "auth_verifier": b64(&[1u8;32]), "kdf_salt": b64(&[2u8;32])}),
        ),
    )
    .await;
    let (_, login) = request(
        &mut app,
        json_req(
            Method::POST,
            "/auth/login",
            json!({"email": email, "auth_verifier": b64(&[1u8;32])}),
        ),
    )
    .await;
    let token = login["access_token"].as_str().unwrap();
    let (status, body) = request(
        &mut app,
        auth_req(Method::GET, "/credentials/not-a-uuid", token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");
}
