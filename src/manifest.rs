//! Which secrets hold a configuration document, and which top-level keys each one owns.

use std::collections::BTreeSet;

use serde::de::{self, DeserializeOwned, Deserializer, Visitor};

/// One KV v2 secret and the top-level configuration keys it owns.
///
/// The secret lives at `<mount>/<prefix>/<name>`. Its fields are top-level keys
/// of the configuration document; each value keeps its shape (object, array,
/// or scalar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    name: &'static str,
    keys: &'static [&'static str],
}

impl Domain {
    /// Declare a secret and the top-level keys stored in it.
    #[must_use]
    pub const fn new(name: &'static str, keys: &'static [&'static str]) -> Self {
        Self { name, keys }
    }

    /// Secret path below the connection prefix.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Top-level configuration keys stored in this secret.
    #[must_use]
    pub const fn keys(&self) -> &'static [&'static str] {
        self.keys
    }
}

/// The layout of one configuration document across KV v2 secrets.
///
/// A manifest is a compile-time constant, so every name that can appear in an
/// error or a log line comes from code and never from the server.
///
/// ```
/// use figment_openbao::{Domain, Manifest};
///
/// const MANIFEST: Manifest = Manifest::new(&[
///     Domain::new("database", &["database_url"]),
///     Domain::new("app", &["listen", "mail"]),
/// ])
/// .max_keys_per_domain(10);
/// # MANIFEST.validate().unwrap();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Manifest {
    domains: &'static [Domain],
    max_keys: Option<usize>,
}

impl Manifest {
    /// Declare the domains of one configuration document.
    #[must_use]
    pub const fn new(domains: &'static [Domain]) -> Self {
        Self {
            domains,
            max_keys: None,
        }
    }

    /// Reject domains that own more than `max` keys, so one secret stays small
    /// enough to review and rotate on its own. There is no limit by default.
    #[must_use]
    pub const fn max_keys_per_domain(self, max: usize) -> Self {
        Self {
            domains: self.domains,
            max_keys: Some(max),
        }
    }

    /// The declared domains, in declaration order.
    #[must_use]
    pub const fn domains(&self) -> &'static [Domain] {
        self.domains
    }

    /// Verify the manifest's own structure.
    ///
    /// [`OpenBao::load`](crate::OpenBao::load) calls this before any request.
    ///
    /// # Errors
    /// Reject an empty manifest, invalid or repeated domain names, domains with
    /// no keys or more keys than the limit, blank or padded keys, and keys owned
    /// twice (ASCII case-insensitively).
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.domains.is_empty() {
            return Err(ManifestError::NoDomains);
        }
        let mut names = BTreeSet::new();
        let mut owned = BTreeSet::new();
        for domain in self.domains {
            if !valid_name(domain.name) {
                return Err(ManifestError::InvalidName(domain.name));
            }
            if !names.insert(domain.name) {
                return Err(ManifestError::DuplicateDomain(domain.name));
            }
            if domain.keys.is_empty() {
                return Err(ManifestError::NoKeys(domain.name));
            }
            if let Some(max) = self.max_keys.filter(|max| domain.keys.len() > *max) {
                return Err(ManifestError::TooManyKeys {
                    domain: domain.name,
                    max,
                });
            }
            for &key in domain.keys {
                if key.is_empty() || key.trim() != key {
                    return Err(ManifestError::InvalidKey(domain.name));
                }
                if !owned.insert(key.to_ascii_lowercase()) {
                    return Err(ManifestError::DuplicateKey(key));
                }
            }
        }
        Ok(())
    }

    /// Verify the structure, and that the domains own every top-level field of
    /// `T` exactly once.
    ///
    /// Run this in a unit test for each configuration type: a field added
    /// without a domain then fails in CI instead of at startup.
    ///
    /// # Errors
    /// Reject everything [`validate`](Self::validate) rejects, targets that are
    /// not plain structs, keys that are not fields of `T`, and fields that no
    /// domain owns.
    pub fn check<T: DeserializeOwned>(&self) -> Result<(), ManifestError> {
        self.validate()?;
        let fields = struct_fields::<T>().ok_or(ManifestError::NotAStruct)?;
        if let Some(key) = self.keys().find(|key| !fields.contains(key)) {
            return Err(ManifestError::UnknownKey(key));
        }
        let owned: BTreeSet<String> = self.keys().map(str::to_ascii_lowercase).collect();
        match fields
            .iter()
            .find(|field| !owned.contains(&field.to_ascii_lowercase()))
        {
            Some(field) => Err(ManifestError::Unowned(field)),
            None => Ok(()),
        }
    }

    /// Every owned key, in declaration order.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &'static str> {
        self.domains
            .iter()
            .flat_map(|domain| domain.keys.iter().copied())
    }

    /// The manifest spelling and owning domain of a key read from a secret.
    pub(crate) fn owner(&self, key: &str) -> Option<(&'static str, &'static str)> {
        self.domains.iter().find_map(|domain| {
            domain
                .keys
                .iter()
                .find(|owned| owned.eq_ignore_ascii_case(key))
                .map(|&owned| (owned, domain.name))
        })
    }
}

/// A manifest that is malformed or does not describe its configuration type.
/// Every name comes from code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The manifest declares no domains.
    #[error("OpenBao manifest declares no domains")]
    NoDomains,
    /// A domain name is not a `/`-separated path of ASCII letters, digits, `-`, and `_`.
    #[error("OpenBao domain {0:?} must be a path of ASCII letters, digits, '-' and '_'")]
    InvalidName(&'static str),
    /// A domain is declared twice.
    #[error("OpenBao domain {0} is declared twice")]
    DuplicateDomain(&'static str),
    /// A domain owns no keys.
    #[error("OpenBao domain {0} owns no keys")]
    NoKeys(&'static str),
    /// A domain owns more keys than the manifest allows.
    #[error("OpenBao domain {domain} owns more than {max} keys")]
    TooManyKeys {
        /// The oversized domain.
        domain: &'static str,
        /// The limit set with [`Manifest::max_keys_per_domain`].
        max: usize,
    },
    /// A domain lists a key that is empty or has surrounding whitespace.
    #[error("OpenBao domain {0} lists an empty or padded key")]
    InvalidKey(&'static str),
    /// A key is owned twice, by one domain or by two.
    #[error("OpenBao manifest key {0} is owned more than once")]
    DuplicateKey(&'static str),
    /// The configuration type is not a plain struct with named fields.
    #[error("OpenBao manifest target must be a struct without flattened fields")]
    NotAStruct,
    /// A domain owns a key that is not a field of the configuration type.
    #[error("OpenBao manifest key {0} is not a configuration field")]
    UnknownKey(&'static str),
    /// A field of the configuration type is owned by no domain.
    #[error("configuration field {0} has no OpenBao domain")]
    Unowned(&'static str),
}

/// Names become URL path segments, so only an unambiguous character set is allowed.
fn valid_name(name: &str) -> bool {
    name.split('/').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

/// Serde passes a struct's field names to `deserialize_struct`; capture them
/// without deserializing any data.
fn struct_fields<T: DeserializeOwned>() -> Option<&'static [&'static str]> {
    let mut fields = None;
    let _probe_always_fails = T::deserialize(FieldProbe(&mut fields));
    fields
}

struct FieldProbe<'a>(&'a mut Option<&'static [&'static str]>);

impl<'de> Deserializer<'de> for FieldProbe<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("not a struct"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = Some(fields);
        Err(de::Error::custom("fields captured"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[allow(dead_code, reason = "only field names are inspected")]
    struct Settings {
        database_url: String,
        listen: Option<String>,
        #[serde(rename = "api_key")]
        key: Option<String>,
    }

    #[derive(Deserialize)]
    #[allow(dead_code, reason = "only field names are inspected")]
    struct Flattened {
        database_url: String,
        #[serde(flatten)]
        rest: BTreeMap<String, String>,
    }

    const DATABASE: Domain = Domain::new("database", &["database_url"]);

    /// A slice of `Domain::new` calls is only `'static` inside a constant, which
    /// is how manifests are declared. Tests that vary the manifest leak it.
    fn manifest(domains: Vec<Domain>) -> Manifest {
        Manifest::new(Box::leak(domains.into_boxed_slice()))
    }

    fn check(domains: Vec<Domain>) -> Result<(), ManifestError> {
        manifest(domains).check::<Settings>()
    }

    #[test]
    fn manifest_owns_every_serde_field_exactly_once() {
        check(vec![DATABASE, Domain::new("app-2", &["listen", "api_key"])]).unwrap();

        assert_eq!(
            check(vec![DATABASE, Domain::new("app", &["listen"])]),
            Err(ManifestError::Unowned("api_key"))
        );
        // The Rust field name is not the configuration key once it is renamed.
        assert_eq!(
            check(vec![DATABASE, Domain::new("app", &["listen", "key"])]),
            Err(ManifestError::UnknownKey("key"))
        );
        assert_eq!(
            check(vec![
                DATABASE,
                Domain::new("app", &["listen", "api_key"]),
                Domain::new("extra", &["LISTEN"]),
            ]),
            Err(ManifestError::DuplicateKey("LISTEN"))
        );
    }

    #[test]
    fn structure_is_rejected_before_any_request() {
        assert_eq!(Manifest::new(&[]).validate(), Err(ManifestError::NoDomains));
        assert_eq!(
            manifest(vec![DATABASE, DATABASE]).validate(),
            Err(ManifestError::DuplicateDomain("database"))
        );
        assert_eq!(
            manifest(vec![DATABASE, Domain::new("app", &[])]).validate(),
            Err(ManifestError::NoKeys("app"))
        );
        for key in ["", " listen", "listen\n"] {
            let keys: &'static [&'static str] = Box::leak(Box::new([key]));
            assert_eq!(
                manifest(vec![Domain::new("app", keys)]).validate(),
                Err(ManifestError::InvalidKey("app")),
                "{key:?}"
            );
        }
    }

    #[test]
    fn key_limit_applies_only_when_set() {
        let wide = manifest(vec![Domain::new("app", &["a", "b", "c"])]);
        wide.validate().unwrap();
        wide.max_keys_per_domain(3).validate().unwrap();
        assert_eq!(
            wide.max_keys_per_domain(2).validate(),
            Err(ManifestError::TooManyKeys {
                domain: "app",
                max: 2
            })
        );
    }

    #[test]
    fn domain_names_are_safe_path_segments() {
        for name in ["app", "app-2", "App_x", "worker/temporal"] {
            manifest(vec![Domain::new(name, &["database_url"])])
                .validate()
                .unwrap();
        }
        for name in [
            "", "/app", "app/", "a//b", "app x", "app.x", "..", "app?x", "app%2f", "é",
        ] {
            assert_eq!(
                manifest(vec![Domain::new(name, &["database_url"])]).validate(),
                Err(ManifestError::InvalidName(name)),
                "{name:?}"
            );
        }
    }

    #[test]
    fn manifest_target_must_be_a_plain_struct() {
        let manifest = manifest(vec![DATABASE]);
        assert_eq!(
            manifest.check::<BTreeMap<String, String>>(),
            Err(ManifestError::NotAStruct)
        );
        assert_eq!(
            manifest.check::<Flattened>(),
            Err(ManifestError::NotAStruct)
        );
    }

    #[test]
    fn owner_matches_keys_case_insensitively() {
        let manifest = manifest(vec![DATABASE, Domain::new("app", &["listen"])]);
        assert_eq!(manifest.owner("LISTEN"), Some(("listen", "app")));
        assert_eq!(
            manifest.owner("database_url"),
            Some(("database_url", "database"))
        );
        assert_eq!(manifest.owner("unknown"), None);
    }
}
