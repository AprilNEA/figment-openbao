//! The loaded document as a Figment provider, and a value-free report about the load.

use std::fmt;

use figment::{
    Metadata, Profile, Provider, Source,
    value::{Dict, Empty, Map, Num, Tag, Value},
};
use serde_json::Value as Json;

/// One configuration document read from OpenBao, held in memory.
///
/// A snapshot is a [`Provider`]: merge it into a [`Figment`](figment::Figment)
/// below command-line and environment overrides. It never contacts OpenBao
/// again; restart the process to pick up changed secrets.
///
/// `Debug` prints the [`Report`] and no values.
pub struct Snapshot {
    values: Dict,
    report: Report,
}

impl Snapshot {
    pub(crate) fn new(fields: serde_json::Map<String, Json>, report: Report) -> Self {
        Self {
            values: fields
                .into_iter()
                .map(|(key, value)| (key, convert(value)))
                .collect(),
            report,
        }
    }

    /// What was loaded, without any values.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

impl Provider for Snapshot {
    fn metadata(&self) -> Metadata {
        Metadata::named("OpenBao").source(Source::Custom(self.report.location.clone()))
    }

    fn data(&self) -> Result<Map<Profile, Dict>, figment::Error> {
        Ok(Profile::Default.collect(self.values.clone()))
    }
}

/// What one load read, by name and count only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// `<mount>/<prefix>` the document was read from, after the namespace
    /// when one is set.
    pub location: String,
    /// Every domain, in manifest order.
    pub domains: Vec<DomainReport>,
    /// Manifest keys that no secret set. A misspelled key in a secret shows up
    /// here, and as an unexpected key in its domain.
    pub absent: Vec<&'static str>,
}

impl Report {
    /// Number of top-level keys in the document.
    #[must_use]
    pub fn keys(&self) -> usize {
        self.domains.iter().map(|domain| domain.keys).sum()
    }

    /// Number of keys outside the manifest that were dropped, across all domains.
    #[must_use]
    pub fn unexpected(&self) -> usize {
        self.domains.iter().map(|domain| domain.unexpected).sum()
    }
}

/// What one domain contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DomainReport {
    /// Manifest domain name.
    pub name: &'static str,
    /// KV v2 version of the secret that was read.
    pub version: u64,
    /// Number of keys this domain owns that the secret set.
    pub keys: usize,
    /// Number of keys outside the manifest that were dropped.
    pub unexpected: usize,
}

/// Build Figment values directly, so numbers keep their type whatever
/// `serde_json` features the dependency graph enables.
fn convert(value: Json) -> Value {
    match value {
        Json::Null => Value::Empty(Tag::Default, Empty::None),
        Json::Bool(value) => Value::Bool(Tag::Default, value),
        Json::Number(value) => number(&value),
        Json::String(value) => Value::String(Tag::Default, value),
        Json::Array(items) => Value::Array(Tag::Default, items.into_iter().map(convert).collect()),
        Json::Object(fields) => Value::Dict(
            Tag::Default,
            fields
                .into_iter()
                .map(|(key, value)| (key, convert(value)))
                .collect(),
        ),
    }
}

fn number(value: &serde_json::Number) -> Value {
    let number = if let Some(value) = value.as_u64() {
        Num::U64(value)
    } else if let Some(value) = value.as_i64() {
        Num::I64(value)
    } else if let Some(value) = value.as_f64() {
        Num::F64(value)
    } else {
        return Value::String(Tag::Default, value.to_string());
    };
    Value::Num(Tag::Default, number)
}

#[cfg(test)]
mod tests {
    use figment::Figment;
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        big: u64,
        negative: i32,
        ratio: f64,
        whole_as_float: f64,
        flag: bool,
        text: String,
        missing: Option<String>,
        disabled: Option<Nested>,
        nested: Nested,
        list: Vec<Nested>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Nested {
        name: String,
        retries: u8,
    }

    fn snapshot(fields: Json) -> Snapshot {
        let Json::Object(fields) = fields else {
            panic!("fields must be an object");
        };
        Snapshot::new(
            fields,
            Report {
                location: "secret/test".into(),
                domains: Vec::new(),
                absent: Vec::new(),
            },
        )
    }

    #[test]
    fn json_values_keep_their_shape_and_integer_precision() {
        let snapshot = snapshot(json!({
            "big": u64::MAX,
            "negative": -7,
            "ratio": 0.25,
            "whole_as_float": 3,
            "flag": true,
            "text": "line one\n\t\"quoted\" é",
            "disabled": null,
            "nested": { "name": "primary", "retries": 3 },
            "list": [{ "name": "a", "retries": 0 }, { "name": "b", "retries": 255 }],
        }));
        let settings: Settings = Figment::from(&snapshot).extract().unwrap();
        assert_eq!(
            settings,
            Settings {
                big: u64::MAX,
                negative: -7,
                ratio: 0.25,
                whole_as_float: 3.0,
                flag: true,
                text: "line one\n\t\"quoted\" é".into(),
                missing: None,
                disabled: None,
                nested: Nested {
                    name: "primary".into(),
                    retries: 3
                },
                list: vec![
                    Nested {
                        name: "a".into(),
                        retries: 0
                    },
                    Nested {
                        name: "b".into(),
                        retries: 255
                    },
                ],
            }
        );
    }

    #[test]
    fn debug_output_and_figment_errors_name_the_source_without_values() {
        let snapshot = snapshot(json!({ "big": "do-not-log" }));
        assert!(!format!("{snapshot:?}").contains("do-not-log"));

        let metadata = snapshot.metadata();
        assert_eq!(metadata.name, "OpenBao");
        assert_eq!(
            metadata.source.map(|source| source.to_string()).as_deref(),
            Some("secret/test")
        );
    }
}
