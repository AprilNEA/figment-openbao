//! End-to-end loads against a real `bao server -dev`.
//!
//! Ignored by default because they need the `bao` binary on `PATH`:
//!
//! ```sh
//! cargo test --test live -- --ignored
//! ```
//!
//! Each test starts its own in-memory server on a free port, with a private
//! `HOME` so neither the server nor the CLI touches the user's token file.

use std::{
    ffi::OsString,
    fs,
    net::TcpListener,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use figment::Figment;
use figment_openbao::{Auth, Domain, Manifest, OpenBao};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

/// Root token of the throwaway in-memory server; it protects nothing.
const ROOT_TOKEN: &str = "figment-openbao-live-test";
const PREFIX: &str = "dev/live";
const DATABASE_URL: &str = "postgresql://app:do-not-log-password@db/app";

const MANIFEST: Manifest = Manifest::new(&[
    Domain::new("database", &["database_url", "pool"]),
    Domain::new("app", &["listen", "tenant_ids", "mail", "banner"]),
]);

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Settings {
    database_url: String,
    pool: Pool,
    listen: String,
    tenant_ids: Vec<u64>,
    mail: Option<Mail>,
    banner: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Pool {
    max: u32,
    idle_seconds: f64,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Mail {
    api_key: String,
}

struct DevServer {
    child: Child,
    home: tempfile::TempDir,
    address: String,
}

impl DevServer {
    fn start() -> Self {
        let home = tempfile::tempdir().unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let address = format!("http://127.0.0.1:{port}");
        let child = Command::new("bao")
            // Without this flag the dev server overwrites the token helper file.
            .args(["server", "-dev", "-dev-no-store-token"])
            .arg(format!("-dev-root-token-id={ROOT_TOKEN}"))
            .arg(format!("-dev-listen-address=127.0.0.1:{port}"))
            .env_clear()
            .env("PATH", path())
            .env("HOME", home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the `bao` binary must be on PATH");
        let server = Self {
            child,
            home,
            address,
        };
        for _ in 0..100 {
            let status = server.command(ROOT_TOKEN).arg("status").output();
            if status.is_ok_and(|output| output.status.success()) {
                return server;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("`bao server -dev` did not become ready");
    }

    /// The CLI with only the variables it needs, so the caller's `BAO_*` and
    /// `VAULT_*` settings cannot redirect it.
    fn command(&self, token: &str) -> Command {
        let mut command = Command::new("bao");
        command
            .env_clear()
            .env("PATH", path())
            .env("HOME", self.home.path())
            .env("BAO_ADDR", &self.address)
            .env("BAO_TOKEN", token)
            .stdin(Stdio::null());
        command
    }

    fn bao(&self, args: &[&str]) -> String {
        let output = self.command(ROOT_TOKEN).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "bao {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// Write a secret from a file so nested values keep their JSON shape.
    fn put(&self, domain: &str, fields: &Value) {
        self.put_in("", domain, fields);
    }

    /// [`put`](Self::put) into `namespace`; an empty path is the root namespace.
    fn put_in(&self, namespace: &str, domain: &str, fields: &Value) {
        let file = self.home.path().join("payload.json");
        fs::write(&file, fields.to_string()).unwrap();
        self.bao(&[
            "kv",
            "put",
            &format!("-namespace={namespace}"),
            "-mount=secret",
            &format!("{PREFIX}/{domain}"),
            &format!("@{}", file.display()),
        ]);
    }

    fn openbao(&self, token: &str) -> OpenBao {
        OpenBao::new(
            Url::parse(&self.address).unwrap(),
            PREFIX,
            Auth::Token(token.into()),
        )
    }
}

impl Drop for DevServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn path() -> OsString {
    std::env::var_os("PATH").unwrap_or_default()
}

fn database() -> Value {
    json!({
        "database_url": DATABASE_URL,
        "pool": { "max": 20, "idle_seconds": 1.5 },
    })
}

fn unusable(problems: &str) -> String {
    format!("OpenBao config at secret/{PREFIX} is unusable: {problems}")
}

#[tokio::test]
#[ignore = "needs the `bao` binary on PATH"]
async fn a_real_server_round_trips_a_document() {
    // OpenBao itself rounds integers beyond 2^53 (observed on 2.7.2, for writes
    // through the CLI and through raw HTTP alike), so 2^53 is the largest value
    // a secret can hold exactly. Larger identifiers belong in strings.
    let tenant_ids = [1 << 53, 20];
    let server = DevServer::start();
    server.put("database", &database());
    server.put("app", &json!({ "listen": "0.0.0.0:1" }));
    server.put(
        "app",
        &json!({
            "listen": "0.0.0.0:8080",
            "tenant_ids": tenant_ids,
            "mail": null,
            "stray": "do-not-log",
        }),
    );

    let snapshot = server.openbao(ROOT_TOKEN).load(&MANIFEST).await.unwrap();

    let settings: Settings = Figment::from(&snapshot).extract().unwrap();
    assert_eq!(
        settings,
        Settings {
            database_url: DATABASE_URL.into(),
            pool: Pool {
                max: 20,
                idle_seconds: 1.5
            },
            listen: "0.0.0.0:8080".into(),
            tenant_ids: tenant_ids.into(),
            mail: None,
            banner: None,
        }
    );
    let report = snapshot.report();
    let summary: Vec<_> = report
        .domains
        .iter()
        .map(|domain| (domain.name, domain.version, domain.keys, domain.unexpected))
        .collect();
    assert_eq!(summary, [("database", 1, 2, 0), ("app", 2, 3, 1)]);
    assert_eq!(report.absent, ["banner"]);
}

#[tokio::test]
#[ignore = "needs the `bao` binary on PATH"]
async fn missing_and_deleted_secrets_reject_the_load() {
    let server = DevServer::start();
    server.put("database", &database());
    let openbao = server.openbao(ROOT_TOKEN);

    let error = openbao.load(&MANIFEST).await.unwrap_err();
    assert_eq!(error.to_string(), unusable("app: not found (HTTP 404)"));

    server.put(
        "app",
        &json!({ "listen": "0.0.0.0:8080", "tenant_ids": [] }),
    );
    openbao.load(&MANIFEST).await.unwrap();

    // A soft-deleted latest version still has metadata; the server answers 404.
    server.bao(&["kv", "delete", "-mount=secret", &format!("{PREFIX}/app")]);
    let error = openbao.load(&MANIFEST).await.unwrap_err();
    assert_eq!(error.to_string(), unusable("app: not found (HTTP 404)"));

    server.bao(&[
        "kv",
        "undelete",
        "-mount=secret",
        "-versions=1",
        &format!("{PREFIX}/app"),
    ]);
    openbao.load(&MANIFEST).await.unwrap();
}

#[tokio::test]
#[ignore = "needs the `bao` binary on PATH"]
async fn a_token_reads_only_what_its_policy_allows() {
    let server = DevServer::start();
    server.put("database", &database());
    server.put(
        "app",
        &json!({ "listen": "0.0.0.0:8080", "tenant_ids": [] }),
    );
    let policy = server.home.path().join("database-only.hcl");
    fs::write(
        &policy,
        format!(r#"path "secret/data/{PREFIX}/database" {{ capabilities = ["read"] }}"#),
    )
    .unwrap();
    server.bao(&["policy", "write", "database-only", policy.to_str().unwrap()]);
    let token = server.bao(&[
        "token",
        "create",
        "-policy=database-only",
        "-ttl=10m",
        "-field=token",
    ]);
    let token = token.trim();

    let error = server.openbao(token).load(&MANIFEST).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        unusable("app: permission denied (HTTP 403)")
    );
    assert!(!format!("{error:?}").contains(token));

    let error = server
        .openbao("not-a-token")
        .load(&MANIFEST)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        unusable("database: permission denied (HTTP 403); app: permission denied (HTTP 403)")
    );
}

#[tokio::test]
#[ignore = "needs the `bao` binary on PATH"]
async fn a_namespace_selects_its_own_document() {
    const NAMESPACE: &str = "team/billing";
    let app = |listen: &str| json!({ "listen": listen, "tenant_ids": [] });
    let listen = |snapshot: figment_openbao::Snapshot| {
        Figment::from(snapshot)
            .extract::<Settings>()
            .unwrap()
            .listen
    };
    let server = DevServer::start();
    server.put("database", &database());
    server.put("app", &app("root:1"));
    server.bao(&["namespace", "create", "team"]);
    server.bao(&["namespace", "create", "-namespace=team", "billing"]);
    server.bao(&[
        "secrets",
        "enable",
        &format!("-namespace={NAMESPACE}"),
        "-path=secret",
        "kv-v2",
    ]);
    server.put_in(NAMESPACE, "database", &database());
    server.put_in(NAMESPACE, "app", &app("nested:1"));

    // The same mount and prefix hold a different document in each namespace.
    let root = server.openbao(ROOT_TOKEN);
    assert_eq!(listen(root.load(&MANIFEST).await.unwrap()), "root:1");
    let snapshot = root.namespace(NAMESPACE).load(&MANIFEST).await.unwrap();
    assert_eq!(
        snapshot.report().location,
        format!("{NAMESPACE}/secret/{PREFIX}")
    );
    assert_eq!(listen(snapshot), "nested:1");

    // A namespace that does not exist is answered like a missing secret.
    let error = server
        .openbao(ROOT_TOKEN)
        .namespace("team/missing")
        .load(&MANIFEST)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "OpenBao config at team/missing/secret/{PREFIX} is unusable: \
             database: not found (HTTP 404); app: not found (HTTP 404)"
        )
    );

    // A token issued inside the namespace reads there, and nowhere else.
    let policy = server.home.path().join("reader.hcl");
    fs::write(
        &policy,
        format!(r#"path "secret/data/{PREFIX}/*" {{ capabilities = ["read"] }}"#),
    )
    .unwrap();
    server.bao(&[
        "policy",
        "write",
        &format!("-namespace={NAMESPACE}"),
        "reader",
        policy.to_str().unwrap(),
    ]);
    let token = server.bao(&[
        "token",
        "create",
        &format!("-namespace={NAMESPACE}"),
        "-policy=reader",
        "-ttl=10m",
        "-field=token",
    ]);
    let token = token.trim();
    let scoped = server.openbao(token);
    let error = scoped.load(&MANIFEST).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        unusable("database: permission denied (HTTP 403); app: permission denied (HTTP 403)")
    );
    let snapshot = scoped.namespace(NAMESPACE).load(&MANIFEST).await.unwrap();
    assert_eq!(listen(snapshot), "nested:1");
}
