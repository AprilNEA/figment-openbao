//! Errors that never carry configuration values, tokens, or remote response text.

use std::{fmt, time::Duration};

use crate::manifest::ManifestError;

/// A failed load. No variant holds a configuration value, a token, or text
/// returned by the server; names come from the manifest or from fixed lists.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An environment variable is not valid Unicode.
    #[error("{0} is not valid Unicode")]
    NotUnicode(&'static str),
    /// A required environment variable is unset or blank.
    #[error("{0} must be set when BAO_ADDR is set")]
    Missing(&'static str),
    /// An environment variable has an unsupported value.
    #[error("{0} is invalid")]
    Invalid(&'static str),
    /// No usable token was found through the named environment variable.
    #[error("OpenBao token from {0} is missing or empty")]
    Token(&'static str),
    /// The Kubernetes `ServiceAccount` token file is unreadable or empty.
    #[error("Kubernetes ServiceAccount token file is missing or empty")]
    ServiceAccountToken,
    /// The CA certificate file is unreadable or holds no PEM certificate.
    #[error("OpenBao CA certificate file could not be loaded")]
    CaFile,
    /// The token cannot be sent as an HTTP header value.
    #[error("OpenBao token is not a valid HTTP header value")]
    InvalidToken,
    /// The namespace has an empty, `.`, or `..` segment, or a character that
    /// is not visible ASCII.
    #[error("OpenBao namespace is invalid")]
    InvalidNamespace,
    /// The HTTP client could not be built.
    #[error("OpenBao client could not be initialized")]
    Client,
    /// Kubernetes login was rejected or failed.
    #[error("OpenBao Kubernetes login failed: {0}")]
    Login(Failure),
    /// Authentication and the domain reads exceeded the configured bound.
    #[error("OpenBao load exceeded {0:?}")]
    Timeout(Duration),
    /// The manifest itself is malformed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// At least one domain was unusable. No partial document is returned.
    #[error("OpenBao config at {location} is unusable: {}", join(.errors))]
    Domains {
        /// `<mount>/<prefix>` taken from the connection settings, after the
        /// namespace when one is set.
        location: String,
        /// Every unusable domain.
        errors: Vec<DomainError>,
    },
}

fn join(errors: &[DomainError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// One unusable domain. Key names here are manifest keys, never remote ones.
#[derive(Debug, thiserror::Error)]
#[error("{domain}: {problem}")]
#[non_exhaustive]
pub struct DomainError {
    /// Manifest domain name.
    pub domain: &'static str,
    /// What made the domain unusable.
    pub problem: Problem,
}

/// Why a domain could not contribute to the document.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// The secret could not be read.
    #[error("{0}")]
    Read(Failure),
    /// The secret holds a key that another domain owns.
    #[error("key {0} belongs to another domain")]
    Misplaced(&'static str),
    /// The secret sets one key twice, in different letter case.
    #[error("key {0} is set more than once")]
    Duplicate(&'static str),
    /// The secret holds none of the keys its domain owns.
    #[error("contains none of its keys")]
    Empty,
}

/// Why a request to OpenBao failed, without the server's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// HTTP 404: the path does not exist or its latest version is deleted.
    NotFound,
    /// HTTP 403: the token may not read the path.
    PermissionDenied,
    /// Any other status that is not a success, including redirects.
    Rejected,
    /// A successful response whose latest version carries no data.
    Deleted,
    /// A response that is not the expected JSON shape.
    InvalidResponse,
    /// The request did not complete.
    Transport,
    /// The request could not be built.
    Client,
}

impl Reason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not found",
            Self::PermissionDenied => "permission denied",
            Self::Rejected => "server rejected the request",
            Self::Deleted => "latest version is deleted",
            Self::InvalidResponse => "invalid response",
            Self::Transport => "transport failure",
            Self::Client => "client failure",
        }
    }
}

/// A redacted request failure: a fixed category and the HTTP status, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    reason: Reason,
    status: Option<u16>,
}

impl Failure {
    pub(crate) const CLIENT: Self = Self::new(Reason::Client, None);
    pub(crate) const DELETED: Self = Self::new(Reason::Deleted, None);
    pub(crate) const INVALID: Self = Self::new(Reason::InvalidResponse, None);
    pub(crate) const TRANSPORT: Self = Self::new(Reason::Transport, None);

    const fn new(reason: Reason, status: Option<u16>) -> Self {
        Self { reason, status }
    }

    pub(crate) fn from_status(status: u16) -> Self {
        let reason = match status {
            403 => Reason::PermissionDenied,
            404 => Reason::NotFound,
            _ => Reason::Rejected,
        };
        Self::new(reason, Some(status))
    }

    /// The failure category.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// The HTTP status returned by OpenBao, if a response arrived.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(f, "{} (HTTP {status})", self.reason.as_str()),
            None => f.write_str(self.reason.as_str()),
        }
    }
}
