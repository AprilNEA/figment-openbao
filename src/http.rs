//! The three OpenBao HTTP calls this crate makes: Kubernetes login, a KV v2
//! read, and revoking the caller's own token. All three name the namespace
//! when one is set.
//!
//! Nothing here logs, and no error keeps the server's response text.

use std::{fs, path::Path};

use reqwest::{
    Method, Response,
    header::{CONTENT_TYPE, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use url::Url;

use crate::error::{Error, Failure};

const TOKEN_HEADER: &str = "X-Vault-Token";
const NAMESPACE_HEADER: &str = "X-Vault-Namespace";
const USER_AGENT: &str = concat!("figment-openbao/", env!("CARGO_PKG_VERSION"));

pub(crate) struct Client {
    http: reqwest::Client,
    base: Url,
    namespace: Option<HeaderValue>,
    token: Option<HeaderValue>,
}

/// The token issued by a login.
pub(crate) struct Login {
    pub(crate) token: String,
    /// Batch tokens have no accessor and cannot be revoked.
    pub(crate) revocable: bool,
}

/// The fields and version of one KV v2 secret.
pub(crate) struct Secret {
    pub(crate) fields: Map<String, Value>,
    pub(crate) version: u64,
}

impl Client {
    pub(crate) fn new(address: &Url, ca_file: Option<&Path>) -> Result<Self, Error> {
        // A redirect would carry the token header to whatever address the
        // response names, so redirects are reported as failures instead.
        let mut builder = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(USER_AGENT);
        if let Some(path) = ca_file {
            let pem = fs::read(path).map_err(|_| Error::CaFile)?;
            let certificates =
                reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| Error::CaFile)?;
            // The rustls backend returns an empty list for a file without
            // certificates, which would surface later as an opaque TLS failure.
            if certificates.is_empty() {
                return Err(Error::CaFile);
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let mut base = address.clone();
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self {
            http: builder.build().map_err(|_| Error::Client)?,
            base,
            namespace: None,
            token: None,
        })
    }

    /// Send every later request to `namespace` instead of the root namespace.
    pub(crate) fn set_namespace(&mut self, namespace: &str) -> Result<(), Failure> {
        self.namespace = Some(HeaderValue::from_str(namespace).map_err(|_| Failure::CLIENT)?);
        Ok(())
    }

    /// Send `token` with every later request.
    pub(crate) fn set_token(&mut self, token: &str) -> Result<(), Failure> {
        let mut value = HeaderValue::from_str(token).map_err(|_| Failure::CLIENT)?;
        value.set_sensitive(true);
        self.token = Some(value);
        Ok(())
    }

    pub(crate) async fn kubernetes_login(
        &self,
        mount: &str,
        role: &str,
        jwt: &str,
    ) -> Result<Login, Failure> {
        let body = json!({ "role": role, "jwt": jwt }).to_string();
        let response = self
            .send(Method::POST, &["v1/auth", mount, "login"], Some(body))
            .await?;
        let login: LoginResponse = decode(response).await?;
        let auth = login
            .auth
            .filter(|auth| !auth.client_token.is_empty())
            .ok_or(Failure::INVALID)?;
        Ok(Login {
            revocable: !auth.accessor.is_empty(),
            token: auth.client_token,
        })
    }

    /// Read the latest version of the secret at `<mount>/<path>`.
    pub(crate) async fn read_secret(&self, mount: &str, path: &str) -> Result<Secret, Failure> {
        let response = self
            .send(Method::GET, &["v1", mount, "data", path], None)
            .await?;
        let read: ReadResponse = decode(response).await?;
        let data = read.data.ok_or(Failure::INVALID)?;
        match data.data {
            Value::Object(fields) => Ok(Secret {
                fields,
                version: data.metadata.version,
            }),
            // OpenBao answers a deleted version with 404; this covers a
            // successful response that still carries no data.
            Value::Null => Err(Failure::DELETED),
            _ => Err(Failure::INVALID),
        }
    }

    pub(crate) async fn revoke_self(&self) -> Result<(), Failure> {
        self.send(Method::POST, &["v1/auth/token/revoke-self"], None)
            .await
            .map(drop)
    }

    async fn send(
        &self,
        method: Method,
        path: &[&str],
        body: Option<String>,
    ) -> Result<Response, Failure> {
        let mut request = self.http.request(method, self.url(path)?);
        if let Some(namespace) = &self.namespace {
            request = request.header(NAMESPACE_HEADER, namespace);
        }
        if let Some(token) = &self.token {
            request = request.header(TOKEN_HEADER, token);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        // The transport error can quote the URL; keep only the category.
        let response = request.send().await.map_err(|_| Failure::TRANSPORT)?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Failure::from_status(response.status().as_u16()))
        }
    }

    /// Append `path` to the address, percent-encoding each segment. Mounts and
    /// prefixes come from configuration and may hold characters such as `?`
    /// that would otherwise change the meaning of the URL.
    fn url(&self, path: &[&str]) -> Result<Url, Failure> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| Failure::CLIENT)?
            .pop_if_empty()
            .extend(
                path.iter()
                    .flat_map(|part| part.split('/'))
                    .filter(|segment| !segment.is_empty()),
            );
        Ok(url)
    }
}

/// Parse a response body. The parse error can quote the body, so it is dropped.
async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, Failure> {
    let body = response.bytes().await.map_err(|_| Failure::TRANSPORT)?;
    serde_json::from_slice(&body).map_err(|_| Failure::INVALID)
}

// These types hold tokens and configuration values, so they have no `Debug`.

#[derive(Deserialize)]
struct LoginResponse {
    auth: Option<LoginAuth>,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: String,
    #[serde(default)]
    accessor: String,
}

#[derive(Deserialize)]
struct ReadResponse {
    data: Option<ReadData>,
}

#[derive(Deserialize)]
struct ReadData {
    data: Value,
    metadata: ReadMetadata,
}

#[derive(Deserialize)]
struct ReadMetadata {
    version: u64,
}
