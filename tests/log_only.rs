//! A process that logs through the `log` crate alone, with no `tracing`
//! subscriber. `tracing` forwards events to `log` in such a process. Loading
//! must leave that routing alone, and nothing sensitive may reach `log`.
//!
//! This is its own test binary because the `log` logger is process-wide.

mod support;

use std::sync::Mutex;

use serde_json::json;
use support::{
    DATABASE_URL, MANIFEST, UNKNOWN_KEY, login, read, secret, serve, service_account_token,
    with_kubernetes,
};

static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        RECORDS.lock().unwrap().push(format!(
            "{} {}: {}",
            record.level(),
            record.target(),
            record.args()
        ));
    }

    fn flush(&self) {}
}

#[tokio::test]
async fn a_log_only_process_receives_no_secrets_or_server_messages() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let jwt = service_account_token("service-jwt");
    let mut database = secret(json!({ "database_url": DATABASE_URL, UNKNOWN_KEY: "x" }));
    database.1["warnings"] = json!(["read warning do-not-log"]);
    let (address, seen) = serve(vec![
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

    tracing::info!("probe before the load");
    with_kubernetes(address, "kubernetes", &jwt)
        .load(&MANIFEST)
        .await
        .unwrap_err();
    tracing::info!("probe after the load");

    assert_eq!(seen.lock().unwrap().len(), 4);
    let records = RECORDS.lock().unwrap().join("\n");
    // Events before, during, and after the load all reach `log`: the load does
    // not install a dispatcher of its own.
    for expected in [
        "probe before the load",
        "OpenBao config domain loaded",
        "OpenBao login token revocation failed",
        "probe after the load",
    ] {
        assert!(records.contains(expected), "{expected} missing:\n{records}");
    }
    for secret in [
        DATABASE_URL,
        "do-not-log",
        UNKNOWN_KEY,
        "login-token",
        "service-jwt",
    ] {
        assert!(!records.contains(secret), "{secret} leaked:\n{records}");
    }
}
