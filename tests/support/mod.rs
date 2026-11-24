//! A stub OpenBao server that records every request, shared by the test binaries.
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::LOCATION},
    response::{IntoResponse, Response},
};
use figment_openbao::{Auth, Domain, Manifest, OpenBao};
use serde_json::{Value, json};
use url::Url;

pub const PREFIX: &str = "dev/billing-test";
pub const DATABASE_URL: &str = "postgresql://billing:do-not-log-password@db/billing";
pub const UNKNOWN_KEY: &str = "pasted-credential-as-key";

pub const MANIFEST: Manifest = Manifest::new(&[
    Domain::new("database", &["database_url"]),
    Domain::new("app", &["listen", "ca_pem", "webhook"]),
]);

/// Requests seen by the stub: `METHOD /path`, `X-Vault-Token`, and the JSON body.
/// A request that names a namespace is recorded, and answered, as
/// `METHOD /path @namespace`.
pub type Seen = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

#[derive(Clone)]
struct Stub {
    responses: Arc<HashMap<String, (u16, Value)>>,
    delays: Arc<HashMap<String, Duration>>,
    seen: Seen,
}

async fn respond(
    State(stub): State<Stub>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut request = format!("{method} {}", uri.path());
    if let Some(namespace) = headers
        .get("X-Vault-Namespace")
        .and_then(|value| value.to_str().ok())
    {
        request = format!("{request} @{namespace}");
    }
    let token = headers
        .get("X-Vault-Token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    stub.seen
        .lock()
        .unwrap()
        .push((request.clone(), token, body));
    if let Some(delay) = stub.delays.get(&request) {
        tokio::time::sleep(*delay).await;
    }
    let (status, response) = stub
        .responses
        .get(&request)
        .cloned()
        .unwrap_or((404, json!({ "errors": [] })));
    let status = StatusCode::from_u16(status).unwrap();
    // A redirect entry names its target in a `location` field.
    match response.get("location").and_then(Value::as_str) {
        Some(location) if status.is_redirection() => {
            (status, [(LOCATION, location.to_owned())]).into_response()
        }
        _ => (status, Json(response)).into_response(),
    }
}

pub async fn serve(responses: Vec<(String, (u16, Value))>) -> (Url, Seen) {
    serve_slowly(responses, Vec::new()).await
}

pub async fn serve_slowly(
    responses: Vec<(String, (u16, Value))>,
    delays: Vec<(String, Duration)>,
) -> (Url, Seen) {
    let seen = Seen::default();
    let stub = Stub {
        responses: Arc::new(responses.into_iter().collect()),
        delays: Arc::new(delays.into_iter().collect()),
        seen: seen.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let app = Router::new().fallback(respond).with_state(stub);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, seen)
}

pub fn read(domain: &str) -> String {
    format!("GET /v1/secret/data/{PREFIX}/{domain}")
}

/// A KV v2 read response, as OpenBao returns it.
#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites pass freshly built literals"
)]
pub fn secret(fields: Value) -> (u16, Value) {
    (
        200,
        json!({
            "request_id": "request",
            "lease_id": "",
            "lease_duration": 0,
            "renewable": false,
            "data": {
                "data": fields,
                "metadata": {
                    "created_time": "2026-11-16T00:00:00Z",
                    "custom_metadata": null,
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 3,
                },
            },
            "wrap_info": null,
            "warnings": null,
            "auth": null,
        }),
    )
}

/// A Kubernetes login response, as OpenBao returns it.
pub fn login(accessor: &str) -> (u16, Value) {
    (
        200,
        json!({
            "request_id": "request",
            "lease_id": "",
            "lease_duration": 0,
            "renewable": false,
            "data": null,
            "wrap_info": null,
            "warnings": ["login warning do-not-log"],
            "auth": {
                "client_token": "login-token",
                "accessor": accessor,
                "policies": ["billing-test"],
                "token_policies": ["billing-test"],
                "metadata": null,
                "lease_duration": 60,
                "renewable": false,
                "entity_id": "entity",
                "token_type": "service",
                "orphan": true,
            },
        }),
    )
}

pub fn database() -> (String, (u16, Value)) {
    (
        read("database"),
        secret(json!({ "database_url": DATABASE_URL })),
    )
}

pub fn with_token(address: Url) -> OpenBao {
    OpenBao::new(address, PREFIX, Auth::Token("inline-token".into()))
}

pub fn with_kubernetes(address: Url, mount: &str, jwt: &tempfile::NamedTempFile) -> OpenBao {
    OpenBao::new(
        address,
        PREFIX,
        Auth::Kubernetes {
            mount: mount.into(),
            role: "billing-test".into(),
            jwt_path: jwt.path().into(),
        },
    )
}

pub fn service_account_token(content: &str) -> tempfile::NamedTempFile {
    let jwt = tempfile::NamedTempFile::new().unwrap();
    fs::write(jwt.path(), content).unwrap();
    jwt
}
