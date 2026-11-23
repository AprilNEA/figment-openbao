//! A [Figment] provider that loads startup configuration from
//! [OpenBao](https://openbao.org) KV v2 secrets.
//!
//! One configuration document is split across a few secrets, called domains.
//! Each domain owns some top-level keys of the document, so a database
//! credential and a mail credential can be granted, reviewed, and rotated
//! separately. A [`Manifest`] declares the split in code. [`OpenBao::load`]
//! authenticates, reads every domain, and returns a [`Snapshot`] that Figment
//! merges like any other provider.
//!
//! ```no_run
//! use figment::{Figment, providers::Serialized};
//! use figment_openbao::{Domain, Manifest, OpenBao};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize)]
//! struct Settings {
//!     database_url: String,
//!     listen: String,
//!     mail: Option<Mail>,
//! }
//!
//! #[derive(Deserialize)]
//! struct Mail {
//!     api_key: String,
//! }
//!
//! /// Command-line and environment overrides, parsed elsewhere.
//! #[derive(Serialize)]
//! struct Overrides {
//!     #[serde(skip_serializing_if = "Option::is_none")]
//!     listen: Option<String>,
//! }
//!
//! const MANIFEST: Manifest = Manifest::new(&[
//!     Domain::new("database", &["database_url"]),
//!     Domain::new("app", &["listen", "mail"]),
//! ]);
//!
//! # async fn load(overrides: Overrides) -> Result<Settings, Box<dyn std::error::Error>> {
//! let mut figment = Figment::new();
//! if let Some(openbao) = OpenBao::from_env()? {
//!     figment = figment.merge(openbao.load(&MANIFEST).await?);
//! }
//! let settings: Settings = figment.merge(Serialized::defaults(overrides)).extract()?;
//! # Ok(settings) }
//! ```
//!
//! # Load semantics
//!
//! - The document is read once. A snapshot never contacts OpenBao again;
//!   restart the process to pick up changed secrets.
//! - Every domain must exist and hold at least one key it owns. Any failure
//!   rejects the whole load; there is no partial document and no fallback.
//! - A key stored in the wrong domain, or set twice in different letter case,
//!   rejects the load. Keys outside the manifest are dropped and counted.
//! - Redirects are not followed, so the token is never sent to an address
//!   other than the configured one.
//! - Errors, logs, and `Debug` output never contain configuration values,
//!   tokens, or server messages. See [`Report`] for what is recorded instead.
//!
//! # Logging
//!
//! The crate emits `tracing` events under its own target: one `INFO` per
//! domain, one `INFO` summary, and a `WARN` for dropped keys or a failed token
//! revocation. Install a subscriber before loading, or log the [`Report`]
//! afterwards.
//!
//! # Limits
//!
//! OpenBao itself rounds integers beyond 2^53 in KV v2 data (observed on
//! 2.7.2). Store larger identifiers as strings.
//!
//! [Figment]: figment::Figment

#[cfg(not(any(feature = "rustls", feature = "native-tls")))]
compile_error!("figment-openbao needs a TLS backend: enable the `rustls` or `native-tls` feature");

mod error;
mod http;
mod manifest;
mod openbao;
mod snapshot;

pub use error::{DomainError, Error, Failure, Problem, Reason};
pub use manifest::{Domain, Manifest, ManifestError};
pub use openbao::{Auth, DEFAULT_TIMEOUT, OpenBao};
pub use snapshot::{DomainReport, Report, Snapshot};

/// Compile the README's examples as doctests so they cannot drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
