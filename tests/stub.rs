//! Loads against a stub server that records every request, covering the
//! behavior that cannot be exercised without controlling the responses:
//! Kubernetes login and revocation, failure categories, timeouts, and redaction.

mod support;

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use figment::{Figment, providers::Serialized};
use figment_openbao::{Auth, Error, Manifest, OpenBao, Problem, Reason, Snapshot};
use serde::Deserialize;
use serde_json::{Value, json};
use support::{
    DATABASE_URL, MANIFEST, PREFIX, UNKNOWN_KEY, database, login, read, secret, serve,
    serve_slowly, service_account_token, with_kubernetes, with_token,
};
use url::Url;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Settings {
    database_url: String,
    listen: Option<String>,
    ca_pem: Option<String>,
    webhook: Option<Hook>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Hook {
    url: String,
    retries: u8,
}

fn extract(snapshot: &Snapshot) -> Settings {
    Figment::from(snapshot).extract().unwrap()
}

fn assert_redacted(error: &Error) {
    let output = format!("{error:?}: {error}");
    for secret in [
        DATABASE_URL,
        "do-not-log",
        UNKNOWN_KEY,
        "inline-token",
        "login-token",
        "service-jwt",
    ] {
        assert!(!output.contains(secret), "{output}");
    }
}

#[tokio::test]
async fn token_auth_merges_owned_domains_into_one_document() {
    let ca_pem = "-----BEGIN CERTIFICATE-----\n\tMII \"quoted\" é\n-----END CERTIFICATE-----\n";
    let (address, seen) = serve(vec![
        (
            read("database"),
            secret(json!({ "database_url": DATABASE_URL, UNKNOWN_KEY: "ignored" })),
        ),
        (
            read("app"),
            secret(json!({
                "LISTEN": "0.0.0.0:8081",
                "ca_pem": ca_pem,
                "webhook": { "url": "https://events.example.test", "retries": 3 },
            })),
        ),
    ])
    .await;

    let snapshot = with_token(address).load(&MANIFEST).await.unwrap();

    // `deny_unknown_fields` proves the key outside the manifest was dropped, and
    // `LISTEN` arrives under the manifest's spelling.
    assert_eq!(
        extract(&snapshot),
        Settings {
            database_url: DATABASE_URL.into(),
            listen: Some("0.0.0.0:8081".into()),
            ca_pem: Some(ca_pem.into()),
            webhook: Some(Hook {
                url: "https://events.example.test".into(),
                retries: 3,
            }),
        }
    );
    let report = snapshot.report();
    assert_eq!(report.location, format!("secret/{PREFIX}"));
    assert_eq!((report.keys(), report.unexpected()), (4, 1));
    assert!(report.absent.is_empty());
    let summary: Vec<_> = report
        .domains
        .iter()
        .map(|domain| (domain.name, domain.version, domain.keys, domain.unexpected))
        .collect();
    assert_eq!(summary, [("database", 3, 1, 1), ("app", 3, 3, 0)]);
    assert!(!format!("{snapshot:?}").contains("do-not-log"));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for (request, token, _) in seen.iter() {
        assert!(request.starts_with("GET /v1/secret/data/"), "{request}");
        assert_eq!(token.as_deref(), Some("inline-token"));
    }
}

#[tokio::test]
async fn overrides_merged_after_the_snapshot_win() {
    let (address, _) = serve(vec![
        database(),
        (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
    ])
    .await;
    let snapshot = with_token(address).load(&MANIFEST).await.unwrap();

    let settings: Settings = Figment::from(snapshot)
        .merge(Serialized::default("listen", "127.0.0.1:9000"))
        .extract()
        .unwrap();
    assert_eq!(settings.listen.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(settings.database_url, DATABASE_URL);
}

#[tokio::test]
async fn mount_and_empty_prefix_select_the_secret_path() {
    let (address, seen) = serve(vec![
        (
            "GET /v1/kv/data/database".into(),
            secret(json!({ "database_url": DATABASE_URL })),
        ),
        (
            "GET /v1/kv/data/app".into(),
            secret(json!({ "listen": "0.0.0.0:8081" })),
        ),
    ])
    .await;
    let openbao = OpenBao::new(address, "", Auth::Token("inline-token".into())).mount("kv");

    let snapshot = openbao.load(&MANIFEST).await.unwrap();
    assert_eq!(snapshot.report().location, "kv");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn the_address_path_is_kept_and_segments_are_percent_encoded() {
    let (address, seen) = serve(vec![
        (
            "GET /openbao/v1/kv%20v2/data/team%20a/billing%3Fdebug/database".into(),
            secret(json!({ "database_url": DATABASE_URL })),
        ),
        (
            "GET /openbao/v1/kv%20v2/data/team%20a/billing%3Fdebug/app".into(),
            secret(json!({ "listen": "0.0.0.0:8081" })),
        ),
    ])
    .await;
    // A mount or prefix holding `?` must stay part of the path.
    let openbao = OpenBao::new(
        address.join("openbao/").unwrap(),
        "team a/billing?debug",
        Auth::Token("inline-token".into()),
    )
    .mount("kv v2");

    let result = openbao.load(&MANIFEST).await;
    assert!(result.is_ok(), "{result:?}\n{:?}", seen.lock().unwrap());
}

#[tokio::test]
async fn redirects_are_not_followed_so_the_token_stays_with_the_configured_address() {
    let (target, target_seen) = serve(vec![
        database(),
        (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
    ])
    .await;
    let location = target
        .join(&format!("v1/secret/data/{PREFIX}/app"))
        .unwrap();
    let (address, _) = serve(vec![
        database(),
        (read("app"), (307, json!({ "location": location.as_str() }))),
    ])
    .await;

    let error = with_token(address).load(&MANIFEST).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "OpenBao config at secret/{PREFIX} is unusable: \
             app: server rejected the request (HTTP 307)"
        )
    );
    assert!(target_seen.lock().unwrap().is_empty(), "{target_seen:?}");
}

#[tokio::test]
async fn kubernetes_auth_logs_in_reads_with_the_login_token_and_revokes_it() {
    let jwt = service_account_token("service-jwt\n");
    let (address, seen) = serve(vec![
        (
            "POST /v1/auth/cluster-a/login".into(),
            login("login-accessor"),
        ),
        ("POST /v1/auth/token/revoke-self".into(), (204, Value::Null)),
        database(),
        (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
    ])
    .await;

    let snapshot = with_kubernetes(address, "cluster-a", &jwt)
        .load(&MANIFEST)
        .await
        .unwrap();
    assert_eq!(extract(&snapshot).listen.as_deref(), Some("0.0.0.0:8081"));

    let seen = seen.lock().unwrap();
    let (request, token, body) = &seen[0];
    assert_eq!(request, "POST /v1/auth/cluster-a/login");
    assert_eq!(token, &None);
    assert_eq!(
        body,
        &json!({ "role": "billing-test", "jwt": "service-jwt" })
    );
    for (_, token, _) in &seen[1..] {
        assert_eq!(token.as_deref(), Some("login-token"));
    }
    assert_eq!(seen.len(), 4);
    assert_eq!(seen.last().unwrap().0, "POST /v1/auth/token/revoke-self");
}

#[tokio::test]
async fn batch_login_tokens_are_not_revoked() {
    let jwt = service_account_token("service-jwt");
    let (address, seen) = serve(vec![
        ("POST /v1/auth/kubernetes/login".into(), login("")),
        database(),
        (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
    ])
    .await;

    with_kubernetes(address, "kubernetes", &jwt)
        .load(&MANIFEST)
        .await
        .unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        seen.iter()
            .all(|(request, _, _)| !request.contains("revoke")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn any_unusable_domain_rejects_the_whole_document() {
    let deleted = json!({
        "data": {
            "data": null,
            "metadata": {
                "created_time": "2026-11-16T00:00:00Z",
                "custom_metadata": null,
                "deletion_time": "2026-11-16T01:00:00Z",
                "destroyed": false,
                "version": 4,
            },
        },
    });
    let cases: Vec<((u16, Value), &str)> = vec![
        ((404, json!({ "errors": [] })), "app: not found (HTTP 404)"),
        ((404, deleted), "app: not found (HTTP 404)"),
        (secret(Value::Null), "app: latest version is deleted"),
        (secret(json!(["listen"])), "app: invalid response"),
        (
            (403, json!({ "errors": ["permission denied: do-not-log"] })),
            "app: permission denied (HTTP 403)",
        ),
        (
            (500, json!({ "errors": ["do-not-log"] })),
            "app: server rejected the request (HTTP 500)",
        ),
        (
            secret(json!({ UNKNOWN_KEY: "do-not-log" })),
            "app: contains none of its keys",
        ),
        (secret(json!({})), "app: contains none of its keys"),
        (
            secret(json!({ "listen": "0.0.0.0:1", "database_url": DATABASE_URL })),
            "app: key database_url belongs to another domain",
        ),
        (
            secret(json!({ "listen": "0.0.0.0:1", "LISTEN": "0.0.0.0:2" })),
            "app: key listen is set more than once",
        ),
    ];
    for (app, expected) in cases {
        let (address, _) = serve(vec![database(), (read("app"), app)]).await;
        let error = with_token(address).load(&MANIFEST).await.unwrap_err();
        assert!(matches!(error, Error::Domains { .. }), "{error:?}");
        assert_eq!(
            error.to_string(),
            format!("OpenBao config at secret/{PREFIX} is unusable: {expected}")
        );
        assert_redacted(&error);
    }

    let (address, _) = serve(Vec::new()).await;
    let error = with_token(address).load(&MANIFEST).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "OpenBao config at secret/{PREFIX} is unusable: \
             database: not found (HTTP 404); app: not found (HTTP 404)"
        )
    );
    let Error::Domains { errors, .. } = error else {
        panic!("expected a domain error");
    };
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[1].domain, "app");
    assert!(matches!(
        errors[1].problem,
        Problem::Read(failure)
            if failure.reason() == Reason::NotFound && failure.status() == Some(404)
    ));
}

#[tokio::test]
async fn an_unreachable_server_is_a_transport_failure() {
    // Bind and drop a listener so the port is very likely closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    drop(listener);

    let error = with_token(address).load(&MANIFEST).await.unwrap_err();
    let Error::Domains { errors, .. } = &error else {
        panic!("expected a domain error: {error:?}");
    };
    assert!(errors.iter().all(|error| matches!(
        error.problem,
        Problem::Read(failure)
            if failure.reason() == Reason::Transport && failure.status().is_none()
    )));
    assert_redacted(&error);
}

#[tokio::test]
async fn rejected_kubernetes_login_reads_nothing() {
    let jwt = service_account_token("service-jwt");
    let (address, seen) = serve(vec![(
        "POST /v1/auth/kubernetes/login".into(),
        (403, json!({ "errors": ["service-jwt rejected"] })),
    )])
    .await;

    let error = with_kubernetes(address.clone(), "kubernetes", &jwt)
        .load(&MANIFEST)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "OpenBao Kubernetes login failed: permission denied (HTTP 403)"
    );
    assert_redacted(&error);
    assert_eq!(seen.lock().unwrap().len(), 1);

    let missing = OpenBao::new(
        address.clone(),
        PREFIX,
        Auth::Kubernetes {
            mount: "kubernetes".into(),
            role: "billing-test".into(),
            jwt_path: "/nonexistent/openbao/token".into(),
        },
    );
    assert!(matches!(
        missing.load(&MANIFEST).await,
        Err(Error::ServiceAccountToken)
    ));
    let blank = service_account_token(" \n");
    assert!(matches!(
        with_kubernetes(address, "kubernetes", &blank)
            .load(&MANIFEST)
            .await,
        Err(Error::ServiceAccountToken)
    ));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_login_response_without_a_token_is_invalid() {
    let jwt = service_account_token("service-jwt");
    let mut empty_token = login("accessor").1;
    empty_token["auth"]["client_token"] = json!("");
    for response in [
        json!({ "auth": null }),
        json!({ "data": {} }),
        empty_token,
        json!("do-not-log"),
    ] {
        let (address, seen) = serve(vec![
            ("POST /v1/auth/kubernetes/login".into(), (200, response)),
            database(),
        ])
        .await;
        let error = with_kubernetes(address, "kubernetes", &jwt)
            .load(&MANIFEST)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OpenBao Kubernetes login failed: invalid response"
        );
        assert_redacted(&error);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_malformed_manifest_or_ca_file_fails_before_any_request() {
    const EMPTY: Manifest = Manifest::new(&[]);
    let (address, seen) = serve(vec![database()]).await;

    assert!(matches!(
        with_token(address.clone()).load(&EMPTY).await,
        Err(Error::Manifest(_))
    ));
    let not_a_certificate = service_account_token("not a certificate");
    for path in [
        not_a_certificate.path().to_owned(),
        "/nonexistent/ca.crt".into(),
    ] {
        let result = with_token(address.clone())
            .ca_file(path)
            .load(&MANIFEST)
            .await;
        assert!(matches!(result, Err(Error::CaFile)), "{result:?}");
    }
    let unsendable = OpenBao::new(address, PREFIX, Auth::Token("inline\ntoken".into()));
    assert!(matches!(
        unsendable.load(&MANIFEST).await,
        Err(Error::InvalidToken)
    ));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_slow_server_is_reported_as_a_timeout() {
    let limit = Duration::from_millis(200);
    let (address, _) = serve_slowly(
        vec![
            database(),
            (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
        ],
        vec![(read("app"), Duration::from_secs(30))],
    )
    .await;

    let started = Instant::now();
    let error = with_token(address)
        .timeout(limit)
        .load(&MANIFEST)
        .await
        .unwrap_err();

    // The bound covers the load as a whole, so a hanging read is a timeout and
    // not a transport failure of one domain.
    assert!(
        matches!(error, Error::Timeout(bound) if bound == limit),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "OpenBao load exceeded 200ms");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn the_login_token_is_revoked_after_a_timeout() {
    let jwt = service_account_token("service-jwt");
    let (address, seen) = serve_slowly(
        vec![
            ("POST /v1/auth/kubernetes/login".into(), login("accessor")),
            ("POST /v1/auth/token/revoke-self".into(), (204, Value::Null)),
            database(),
            (read("app"), secret(json!({ "listen": "0.0.0.0:8081" }))),
        ],
        vec![(read("app"), Duration::from_secs(30))],
    )
    .await;

    let error = with_kubernetes(address, "kubernetes", &jwt)
        .timeout(Duration::from_millis(200))
        .load(&MANIFEST)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Timeout(_)), "{error:?}");
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().any(|(request, token, _)| {
            request == "POST /v1/auth/token/revoke-self" && token.as_deref() == Some("login-token")
        }),
        "{seen:?}"
    );
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `call` with every event at every level captured as plain text.
async fn logged<F: Future>(call: F) -> (F::Output, String) {
    let logs = LogCapture::default();
    let writer = logs.clone();
    // Callsite interest is cached process-wide; a second live dispatcher keeps
    // concurrent tests from caching this crate's callsites as disabled.
    let _concurrent_tests = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    ));
    let output = call.await;
    drop(guard);
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    (output, logs)
}

#[tokio::test]
async fn logs_at_every_level_omit_remote_messages_tokens_and_values() {
    let jwt = service_account_token("service-jwt");
    let mut database = secret(json!({ "database_url": DATABASE_URL, UNKNOWN_KEY: "x" }));
    database.1["warnings"] = json!(["read warning do-not-log"]);
    let (address, _) = serve(vec![
        ("POST /v1/auth/kubernetes/login".into(), login("accessor")),
        (
            "POST /v1/auth/token/revoke-self".into(),
            (500, json!({ "errors": ["revoke do-not-log"] })),
        ),
        (read("database"), database),
        (
            read("app"),
            (403, json!({ "errors": ["permission denied: do-not-log"] })),
        ),
    ])
    .await;
    let openbao = with_kubernetes(address, "kubernetes", &jwt);

    let (result, output) = logged(openbao.load(&MANIFEST)).await;
    let error = result.unwrap_err();

    assert_eq!(
        error.to_string(),
        format!("OpenBao config at secret/{PREFIX} is unusable: app: permission denied (HTTP 403)")
    );
    assert!(output.contains("OpenBao config domain loaded"), "{output}");
    assert!(
        output.contains("OpenBao login token revocation failed"),
        "{output}"
    );
    for secret in [
        DATABASE_URL,
        "do-not-log",
        UNKNOWN_KEY,
        "login-token",
        "service-jwt",
        "inline-token",
    ] {
        assert!(!output.contains(secret), "{secret} leaked:\n{output}");
    }
}

#[tokio::test]
async fn summary_lists_absent_keys_and_counts_unknown_keys_per_domain() {
    // A misspelled `ca_pem` is an unknown key in `app` and leaves `ca_pem` absent.
    let (address, _) = serve(vec![
        database(),
        (
            read("app"),
            secret(json!({ "listen": "0.0.0.0:8081", UNKNOWN_KEY: "do-not-log" })),
        ),
    ])
    .await;
    let openbao = with_token(address);

    let (result, output) = logged(openbao.load(&MANIFEST)).await;
    let snapshot = result.unwrap();
    assert_eq!(snapshot.report().absent, ["ca_pem", "webhook"]);
    assert_eq!(snapshot.report().unexpected(), 1);

    let warning = output
        .lines()
        .find(|line| line.contains("OpenBao config keys not in manifest were ignored"))
        .unwrap_or_else(|| panic!("no unknown-key warning:\n{output}"));
    assert!(warning.contains(" WARN "), "{warning}");
    assert!(
        warning.contains(&format!("path=secret/{PREFIX}/app unexpected=1")),
        "{warning}"
    );
    let summary = output
        .lines()
        .find(|line| line.contains("OpenBao config loaded"))
        .unwrap_or_else(|| panic!("no summary:\n{output}"));
    assert!(
        summary.contains(
            r#"auth_method="token" domains=2 keys=2 absent=["ca_pem", "webhook"] unexpected=1"#
        ),
        "{summary}"
    );
    for secret in [UNKNOWN_KEY, "do-not-log", DATABASE_URL, "inline-token"] {
        assert!(!output.contains(secret), "{secret} leaked:\n{output}");
    }
}

#[tokio::test]
async fn explicit_null_keeps_a_domain_present_and_the_field_unset() {
    let (address, _) = serve(vec![
        database(),
        (read("app"), secret(json!({ "webhook": null }))),
    ])
    .await;
    let snapshot = with_token(address).load(&MANIFEST).await.unwrap();
    assert_eq!(
        extract(&snapshot),
        Settings {
            database_url: DATABASE_URL.into(),
            listen: None,
            ca_pem: None,
            webhook: None,
        }
    );
    assert_eq!(snapshot.report().absent, ["listen", "ca_pem"]);
}

#[test]
fn the_load_future_can_cross_threads() {
    fn assert_send<T: Send>(_: &T) {}
    let openbao = with_token(Url::parse("http://127.0.0.1:9").unwrap());
    assert_send(&openbao.load(&MANIFEST));
}
