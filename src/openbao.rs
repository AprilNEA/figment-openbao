//! Connection settings and the startup load.

use std::{
    env,
    ffi::OsString,
    fmt, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures_util::future::join_all;
use serde_json::{Map, Value};
use tokio::time::timeout;
use url::Url;

use crate::{
    error::{DomainError, Error, Failure, Problem},
    http::{Client, Secret},
    manifest::{Domain, Manifest},
    snapshot::{DomainReport, Report, Snapshot},
};

/// Default bound on authentication plus every domain read.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Revoking the login token gets this long after the load, even if the load timed out.
const REVOKE_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_KV_MOUNT: &str = "secret";
const DEFAULT_K8S_MOUNT: &str = "kubernetes";
const DEFAULT_K8S_TOKEN_PATH: &str = "/var/run/secrets/openbao/token";

/// How the process authenticates to OpenBao.
#[derive(Clone)]
#[non_exhaustive]
pub enum Auth {
    /// Use this token as is. The caller owns it; it is never revoked.
    Token(String),
    /// Log in with a Kubernetes `ServiceAccount` token, then revoke the login
    /// token once the document is read.
    Kubernetes {
        /// Mount of the Kubernetes auth method.
        mount: String,
        /// OpenBao role bound to the `ServiceAccount`.
        role: String,
        /// File holding the projected `ServiceAccount` token. It is read on
        /// every load because the kubelet rotates it.
        jwt_path: PathBuf,
    },
}

impl Auth {
    /// Kubernetes login for `role` with the default mount (`kubernetes`) and
    /// token file (`/var/run/secrets/openbao/token`).
    #[must_use]
    pub fn kubernetes(role: impl Into<String>) -> Self {
        Self::Kubernetes {
            mount: DEFAULT_K8S_MOUNT.into(),
            role: role.into(),
            jwt_path: DEFAULT_K8S_TOKEN_PATH.into(),
        }
    }

    const fn method(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::Kubernetes { .. } => "kubernetes",
        }
    }
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("Token(<redacted>)"),
            Self::Kubernetes {
                mount,
                role,
                jwt_path,
            } => f
                .debug_struct("Kubernetes")
                .field("mount", mount)
                .field("role", role)
                .field("jwt_path", jwt_path)
                .finish(),
        }
    }
}

/// Where a configuration document lives in OpenBao and how to reach it.
///
/// ```no_run
/// # async fn load() -> Result<(), figment_openbao::Error> {
/// use figment_openbao::{Auth, Domain, Manifest, OpenBao};
///
/// const MANIFEST: Manifest = Manifest::new(&[Domain::new("database", &["database_url"])]);
///
/// let address = "https://openbao.example.com:8200".parse().expect("a valid URL");
/// let snapshot = OpenBao::new(address, "prod/billing", Auth::kubernetes("billing"))
///     .ca_file("/etc/openbao/ca.crt")
///     .load(&MANIFEST)
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct OpenBao {
    address: Url,
    ca_file: Option<PathBuf>,
    namespace: Option<String>,
    mount: String,
    prefix: String,
    auth: Auth,
    timeout: Duration,
}

impl fmt::Debug for OpenBao {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The origin leaves out any userinfo embedded in the address.
        f.debug_struct("OpenBao")
            .field("origin", &self.address.origin().ascii_serialization())
            .field("ca_file", &self.ca_file)
            .field("namespace", &self.namespace)
            .field("mount", &self.mount)
            .field("prefix", &self.prefix)
            .field("auth", &self.auth)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OpenBao {
    /// Read secrets under `prefix` of the `secret` KV v2 mount at `address`.
    ///
    /// Each domain is read from `<mount>/<prefix>/<domain>`. An empty prefix
    /// reads `<mount>/<domain>`.
    #[must_use]
    pub fn new(address: Url, prefix: impl Into<String>, auth: Auth) -> Self {
        Self {
            address,
            ca_file: None,
            namespace: None,
            mount: DEFAULT_KV_MOUNT.into(),
            prefix: prefix.into().trim_matches('/').to_owned(),
            auth,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Read from this namespace instead of the root namespace.
    ///
    /// Every request then carries the `X-Vault-Namespace` header, including
    /// the Kubernetes login and the revocation, so the auth mount, the role,
    /// and the secrets must exist in that namespace. The path may be nested,
    /// such as `team/billing`. Surrounding whitespace and slashes are ignored,
    /// and an empty path selects the root namespace.
    ///
    /// A path with an empty, `.`, or `..` segment, or with a character other
    /// than visible ASCII, is rejected by [`load`](Self::load) before any
    /// request.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace_path(&namespace.into());
        self
    }

    /// Use another KV v2 mount instead of `secret`.
    #[must_use]
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        mount.into().trim_matches('/').clone_into(&mut self.mount);
        self
    }

    /// Trust the PEM certificates in this file in addition to the system roots.
    #[must_use]
    pub fn ca_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_file = Some(path.into());
        self
    }

    /// Bound authentication plus every domain read. Defaults to [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Read the connection from `BAO_*` environment variables.
    ///
    /// `Ok(None)` means `BAO_ADDR` is unset or blank: OpenBao is not configured
    /// for this process, and the caller decides whether that is acceptable.
    ///
    /// | Variable | Meaning |
    /// | --- | --- |
    /// | `BAO_ADDR` | Server address, `http` or `https`. |
    /// | `BAO_CACERT` | PEM file with additional trusted certificates. |
    /// | `BAO_NAMESPACE` | Namespace to read from. Unset means the root namespace. |
    /// | `BAO_KV_MOUNT` | KV v2 mount. Defaults to `secret`. |
    /// | `BAO_KV_PATH` | Prefix of this service's secrets. Required. |
    /// | `BAO_AUTH_METHOD` | `token` (default) or `kubernetes`. |
    /// | `BAO_TOKEN`, `BAO_TOKEN_PATH` | Token, or a file holding it. Without either, `$HOME/.vault-token` is read. |
    /// | `BAO_K8S_ROLE` | Role for Kubernetes login. Required for that method. |
    /// | `BAO_K8S_MOUNT` | Kubernetes auth mount. Defaults to `kubernetes`. |
    /// | `BAO_K8S_TOKEN_PATH` | `ServiceAccount` token file. Defaults to `/var/run/secrets/openbao/token`. |
    ///
    /// Values are trimmed, and blank values count as unset.
    ///
    /// # Errors
    /// Reject variables that are not Unicode, an address that is not an HTTP
    /// URL, a namespace that cannot be sent, a missing prefix or role, an
    /// unknown method, and a missing token.
    pub fn from_env() -> Result<Option<Self>, Error> {
        Self::from_lookup(env::var_os)
    }

    /// [`from_env`](Self::from_env) with the variables supplied by `lookup`.
    ///
    /// # Errors
    /// See [`from_env`](Self::from_env).
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Option<OsString>,
    ) -> Result<Option<Self>, Error> {
        let var = |name: &'static str| -> Result<Option<String>, Error> {
            let Some(value) = lookup(name) else {
                return Ok(None);
            };
            let value = value.into_string().map_err(|_| Error::NotUnicode(name))?;
            let value = value.trim();
            Ok((!value.is_empty()).then(|| value.to_owned()))
        };
        let Some(address) = var("BAO_ADDR")? else {
            return Ok(None);
        };
        let address = Url::parse(&address)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .ok_or(Error::Invalid("BAO_ADDR"))?;
        let namespace = var("BAO_NAMESPACE")?.and_then(|value| namespace_path(&value));
        if namespace
            .as_deref()
            .is_some_and(|path| !is_namespace_path(path))
        {
            return Err(Error::Invalid("BAO_NAMESPACE"));
        }
        let mount = path_var(var("BAO_KV_MOUNT")?).unwrap_or_else(|| DEFAULT_KV_MOUNT.into());
        let prefix = path_var(var("BAO_KV_PATH")?).ok_or(Error::Missing("BAO_KV_PATH"))?;
        let auth = match var("BAO_AUTH_METHOD")?.as_deref() {
            None | Some("token") => Auth::Token(token(
                var("BAO_TOKEN")?,
                var("BAO_TOKEN_PATH")?,
                var("HOME")?,
            )?),
            Some("kubernetes") => Auth::Kubernetes {
                mount: path_var(var("BAO_K8S_MOUNT")?).unwrap_or_else(|| DEFAULT_K8S_MOUNT.into()),
                role: var("BAO_K8S_ROLE")?.ok_or(Error::Missing("BAO_K8S_ROLE"))?,
                jwt_path: var("BAO_K8S_TOKEN_PATH")?
                    .unwrap_or_else(|| DEFAULT_K8S_TOKEN_PATH.into())
                    .into(),
            },
            Some(_) => return Err(Error::Invalid("BAO_AUTH_METHOD")),
        };
        Ok(Some(Self {
            address,
            ca_file: var("BAO_CACERT")?.map(PathBuf::from),
            namespace,
            mount,
            prefix,
            auth,
            timeout: DEFAULT_TIMEOUT,
        }))
    }

    /// `<mount>/<prefix>`, as it appears in errors, logs, and the [`Report`].
    /// A namespace comes first: `<namespace>/<mount>/<prefix>`.
    #[must_use]
    pub fn location(&self) -> String {
        let path = if self.prefix.is_empty() {
            self.mount.clone()
        } else {
            format!("{}/{}", self.mount, self.prefix)
        };
        match &self.namespace {
            Some(namespace) => format!("{namespace}/{path}"),
            None => path,
        }
    }

    /// Authenticate, read every domain of `manifest`, and merge them into one
    /// document, or fail as a whole.
    ///
    /// Every domain must exist and hold at least one key it owns. Keys are
    /// matched to the manifest ASCII case-insensitively and stored under the
    /// manifest's spelling. A key owned by another domain, or set twice in
    /// different case, rejects the load. Keys outside the manifest are dropped
    /// and only counted, because their names are not trusted.
    ///
    /// A Kubernetes login token is revoked after the reads; a failed
    /// revocation is logged and does not fail the load, since the token still
    /// expires with its TTL.
    ///
    /// This must run inside a Tokio runtime with the time driver enabled.
    ///
    /// # Errors
    /// Reject a malformed manifest, an unusable CA file or `ServiceAccount`
    /// token, a namespace that cannot be sent, a rejected login, a load slower
    /// than the timeout, and any unusable domain. Errors carry no
    /// configuration value, token, or server message.
    pub async fn load(&self, manifest: &Manifest) -> Result<Snapshot, Error> {
        manifest.validate()?;
        let started = Instant::now();
        let mut client = self.client()?;
        let mut revoke = false;
        let reads = timeout(self.timeout, async {
            if let Auth::Kubernetes {
                mount,
                role,
                jwt_path,
            } = &self.auth
            {
                let jwt = read_token(jwt_path).ok_or(Error::ServiceAccountToken)?;
                let login = client
                    .kubernetes_login(mount, role, &jwt)
                    .await
                    .map_err(Error::Login)?;
                client.set_token(&login.token).map_err(Error::Login)?;
                revoke = login.revocable;
            }
            let reads = manifest
                .domains()
                .iter()
                .map(|domain| self.read_domain(&client, domain));
            Ok::<_, Error>(join_all(reads).await)
        })
        .await;
        if revoke
            && !matches!(
                timeout(REVOKE_TIMEOUT, client.revoke_self()).await,
                Ok(Ok(()))
            )
        {
            tracing::warn!(location = %self.location(), "OpenBao login token revocation failed");
        }
        let reads = reads.map_err(|_| Error::Timeout(self.timeout))??;

        let location = self.location();
        let document = merge(manifest, reads).map_err(|errors| Error::Domains {
            location: location.clone(),
            errors,
        })?;
        for domain in &document.domains {
            if domain.unexpected > 0 {
                tracing::warn!(
                    path = %format_args!("{location}/{}", domain.name),
                    unexpected = domain.unexpected,
                    "OpenBao config keys not in manifest were ignored",
                );
            }
        }
        let absent = manifest
            .keys()
            .filter(|key| !document.fields.contains_key(*key))
            .collect();
        let report = Report {
            location,
            domains: document.domains,
            absent,
        };
        tracing::info!(
            location = %report.location,
            auth_method = self.auth.method(),
            domains = report.domains.len(),
            keys = report.keys(),
            absent = ?report.absent,
            unexpected = report.unexpected(),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "OpenBao config loaded",
        );
        Ok(Snapshot::new(document.fields, report))
    }

    fn client(&self) -> Result<Client, Error> {
        let mut client = Client::new(&self.address, self.ca_file.as_deref())?;
        if let Some(namespace) = &self.namespace {
            if !is_namespace_path(namespace) {
                return Err(Error::InvalidNamespace);
            }
            client
                .set_namespace(namespace)
                .map_err(|_| Error::InvalidNamespace)?;
        }
        if let Auth::Token(token) = &self.auth {
            client.set_token(token).map_err(|_| Error::InvalidToken)?;
        }
        Ok(client)
    }

    async fn read_domain(&self, client: &Client, domain: &Domain) -> DomainRead {
        let path = if self.prefix.is_empty() {
            domain.name().to_owned()
        } else {
            format!("{}/{}", self.prefix, domain.name())
        };
        let secret = client.read_secret(&self.mount, &path).await;
        if let Ok(secret) = &secret {
            tracing::info!(
                path = %format_args!("{}/{}", self.location(), domain.name()),
                version = secret.version,
                keys = secret.fields.len(),
                "OpenBao config domain loaded",
            );
        }
        (*domain, secret)
    }
}

fn path_var(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

/// A namespace path without surrounding whitespace and slashes. `None` is the
/// root namespace.
fn namespace_path(value: &str) -> Option<String> {
    let path = value.trim_matches(|c: char| c == '/' || c.is_whitespace());
    (!path.is_empty()).then(|| path.to_owned())
}

/// Whether OpenBao can name `path` and an HTTP header can carry it.
fn is_namespace_path(path: &str) -> bool {
    path.split('/').all(|segment| {
        !matches!(segment, "" | "." | "..") && segment.chars().all(|c| c.is_ascii_graphic())
    })
}

/// `BAO_TOKEN`, then `BAO_TOKEN_PATH`, then `$HOME/.vault-token`.
fn token(
    inline: Option<String>,
    path: Option<String>,
    home: Option<String>,
) -> Result<String, Error> {
    if let Some(token) = inline {
        return Ok(token);
    }
    if let Some(path) = path {
        return read_token(Path::new(&path)).ok_or(Error::Token("BAO_TOKEN_PATH"));
    }
    home.and_then(|home| read_token(&Path::new(&home).join(".vault-token")))
        .ok_or(Error::Token("BAO_TOKEN"))
}

fn read_token(path: &Path) -> Option<String> {
    let token = fs::read_to_string(path).ok()?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

type DomainRead = (Domain, Result<Secret, Failure>);

struct Document {
    fields: Map<String, Value>,
    domains: Vec<DomainReport>,
}

fn merge(manifest: &Manifest, reads: Vec<DomainRead>) -> Result<Document, Vec<DomainError>> {
    let mut fields = Map::new();
    let mut domains = Vec::with_capacity(reads.len());
    let mut errors = Vec::new();
    for (domain, read) in reads {
        let name = domain.name();
        let mut problem = |problem| {
            errors.push(DomainError {
                domain: name,
                problem,
            });
        };
        let secret = match read {
            Ok(secret) => secret,
            Err(failure) => {
                problem(Problem::Read(failure));
                continue;
            }
        };
        let mut owned = 0_usize;
        let mut unexpected = 0_usize;
        for (key, value) in secret.fields {
            match manifest.owner(&key) {
                None => unexpected += 1,
                Some((key, domain)) if domain != name => problem(Problem::Misplaced(key)),
                Some((key, _)) => {
                    owned += 1;
                    if fields.insert(key.to_owned(), value).is_some() {
                        problem(Problem::Duplicate(key));
                    }
                }
            }
        }
        if owned == 0 {
            problem(Problem::Empty);
        }
        domains.push(DomainReport {
            name,
            version: secret.version,
            keys: owned,
            unexpected,
        });
    }
    if errors.is_empty() {
        Ok(Document { fields, domains })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests;
