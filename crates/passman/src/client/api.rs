use password_manager_dto::{
    auth::{
        AuthTokensResponse, LoginRequest, LogoutRequest, PreloginRequest, PreloginResponse,
        RefreshRequest, RegisterRequest, RegisterResponse,
    },
    credentials::{
        CreateCredentialRequest, CredentialMetadataResponse, CredentialResponse,
        UpdateCredentialRequest,
    },
    error::ApiErrorBody,
};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::error::{ClientError, ClientResult};

#[derive(Debug, Clone)]
pub struct ApiClient {
    base_url: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> ClientResult<Self> {
        let base_url = base_url.into().trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(ClientError::Config("server_url is not set".into()));
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(Self { base_url, http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        access_token: Option<&str>,
        idempotency_key: Option<&str>,
        body: Option<impl Serialize>,
    ) -> ClientResult<T> {
        let mut req = self.http.request(method, self.url(path));
        if let Some(token) = access_token {
            req = req.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            req = req.header("Idempotency-Key", key);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        self.parse_response(resp).await
    }

    async fn send_empty(
        &self,
        method: Method,
        path: &str,
        access_token: Option<&str>,
        body: Option<impl Serialize>,
    ) -> ClientResult<()> {
        let mut req = self.http.request(method, self.url(path));
        if let Some(token) = access_token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(self.parse_error(status, resp).await)
    }

    async fn parse_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> ClientResult<T> {
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| ClientError::Network(format!("invalid response json: {e}")))
        } else {
            Err(self.parse_error(status, resp).await)
        }
    }

    async fn parse_error(&self, status: StatusCode, resp: reqwest::Response) -> ClientError {
        let bytes = resp.bytes().await.unwrap_or_default();
        if let Ok(body) = serde_json::from_slice::<ApiErrorBody>(&bytes) {
            if status == StatusCode::UNAUTHORIZED {
                return ClientError::Unauthorized(body.message);
            }
            if status == StatusCode::NOT_FOUND {
                return ClientError::NotFound(body.message);
            }
            return ClientError::Api {
                status: status.as_u16(),
                code: body.code,
                message: body.message,
            };
        }
        ClientError::Api {
            status: status.as_u16(),
            code: "unknown".to_string(),
            message: String::from_utf8_lossy(&bytes).to_string(),
        }
    }

    pub async fn register(&self, req: &RegisterRequest) -> ClientResult<RegisterResponse> {
        self.send_json(Method::POST, "/auth/register", None, None, Some(req))
            .await
    }

    pub async fn prelogin(&self, req: &PreloginRequest) -> ClientResult<PreloginResponse> {
        self.send_json(Method::POST, "/auth/prelogin", None, None, Some(req))
            .await
    }

    pub async fn login(&self, req: &LoginRequest) -> ClientResult<AuthTokensResponse> {
        self.send_json(Method::POST, "/auth/login", None, None, Some(req))
            .await
    }

    pub async fn refresh(&self, req: &RefreshRequest) -> ClientResult<AuthTokensResponse> {
        self.send_json(Method::POST, "/auth/refresh", None, None, Some(req))
            .await
    }

    pub async fn logout(&self, req: &LogoutRequest) -> ClientResult<()> {
        self.send_empty(Method::POST, "/auth/logout", None, Some(req))
            .await
    }

    pub async fn create_credential(
        &self,
        access_token: &str,
        idempotency_key: &str,
        req: &CreateCredentialRequest,
    ) -> ClientResult<CredentialResponse> {
        self.send_json(
            Method::POST,
            "/credentials",
            Some(access_token),
            Some(idempotency_key),
            Some(req),
        )
        .await
    }

    pub async fn list_credentials(
        &self,
        access_token: &str,
    ) -> ClientResult<Vec<CredentialMetadataResponse>> {
        self.send_json(
            Method::GET,
            "/credentials",
            Some(access_token),
            None,
            None::<()>,
        )
        .await
    }

    pub async fn get_credential(
        &self,
        access_token: &str,
        id: &str,
    ) -> ClientResult<CredentialResponse> {
        self.send_json(
            Method::GET,
            &format!("/credentials/{id}"),
            Some(access_token),
            None,
            None::<()>,
        )
        .await
    }

    pub async fn update_credential(
        &self,
        access_token: &str,
        id: &str,
        req: &UpdateCredentialRequest,
    ) -> ClientResult<CredentialResponse> {
        self.send_json(
            Method::PUT,
            &format!("/credentials/{id}"),
            Some(access_token),
            None,
            Some(req),
        )
        .await
    }

    pub async fn delete_credential(&self, access_token: &str, id: &str) -> ClientResult<()> {
        self.send_empty(
            Method::DELETE,
            &format!("/credentials/{id}"),
            Some(access_token),
            None::<()>,
        )
        .await
    }
}
