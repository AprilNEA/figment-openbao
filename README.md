# figment-openbao

A [Figment](https://docs.rs/figment) provider that loads startup configuration from [OpenBao](https://openbao.org) KV v2 secrets.

Figment's built-in providers read files, strings, the environment, and serializable values. Its `Provider` trait is synchronous, so a provider cannot make a network request when Figment asks for data. This crate reads the configuration once, asynchronously, and hands Figment an in-memory snapshot to merge like any other provider.

## How configuration is stored

One configuration document is split across a few KV v2 secrets, called domains. Each domain owns some top-level keys of the document, so a database credential and a mail credential can be granted, reviewed, and rotated separately. Values keep their shape: objects, arrays, and scalars.

```text
secret/prod/billing/database   {"database_url": "postgresql://…"}
secret/prod/billing/app        {"listen": "0.0.0.0:8080", "mail": {"api_key": "…"}}
```

Write a domain from a JSON file so nested values are stored as JSON, not as strings:

```sh
bao kv put -mount=secret prod/billing/app @app.json
```

## Usage

```toml
[dependencies]
figment-openbao = "0.1"
```

Declare the layout as a constant, load it at startup, and merge overrides on top:

```rust
use figment::{Figment, providers::Serialized};
use figment_openbao::{Domain, Manifest, OpenBao};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Settings {
    database_url: String,
    listen: String,
    mail: Option<Mail>,
}

#[derive(Deserialize)]
struct Mail {
    api_key: String,
}

/// Command-line and environment overrides, parsed elsewhere.
#[derive(Serialize)]
struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    listen: Option<String>,
}

const MANIFEST: Manifest = Manifest::new(&[
    Domain::new("database", &["database_url"]),
    Domain::new("app", &["listen", "mail"]),
]);

async fn load(overrides: Overrides) -> Result<Settings, Box<dyn std::error::Error>> {
    let mut figment = Figment::new();
    if let Some(openbao) = OpenBao::from_env()? {
        figment = figment.merge(openbao.load(&MANIFEST).await?);
    }
    Ok(figment.merge(Serialized::defaults(overrides)).extract()?)
}
```

`OpenBao::from_env` returns `None` when `BAO_ADDR` is unset, so local runs and tests need no server. Decide in your service whether an unconfigured process may start.

Keep the manifest and the configuration type in step with a unit test. A field added without a domain then fails in CI instead of at startup:

```rust,ignore
#[test]
fn manifest_covers_every_setting() {
    MANIFEST.check::<Settings>().unwrap();
}
```

To build the connection in code instead of from the environment, use `OpenBao::new(address, prefix, auth)` with the `mount`, `ca_file`, and `timeout` setters.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `BAO_ADDR` | Server address, `http` or `https`. Unset means OpenBao is not configured. |
| `BAO_CACERT` | PEM file with additional trusted certificates. |
| `BAO_KV_MOUNT` | KV v2 mount. Defaults to `secret`. |
| `BAO_KV_PATH` | Prefix of this service's secrets, such as `prod/billing`. Required. |
| `BAO_AUTH_METHOD` | `token` (default) or `kubernetes`. |
| `BAO_TOKEN` | Token for the `token` method. |
| `BAO_TOKEN_PATH` | File holding the token. Used when `BAO_TOKEN` is unset. |
| `BAO_K8S_ROLE` | OpenBao role for Kubernetes login. Required for that method. |
| `BAO_K8S_MOUNT` | Kubernetes auth mount. Defaults to `kubernetes`. |
| `BAO_K8S_TOKEN_PATH` | ServiceAccount token file. Defaults to `/var/run/secrets/openbao/token`. |

Values are trimmed, and blank values count as unset. Without `BAO_TOKEN` and `BAO_TOKEN_PATH`, the `token` method reads `$HOME/.vault-token`, where `bao login` stores its token. `BAO_ADDR`, `BAO_CACERT`, and `BAO_TOKEN` have the same meaning as in the `bao` CLI; the other variables belong to this crate. No `VAULT_*` variable is read.

## Authentication

- **Token**: the token is used as is and never revoked. It belongs to the caller.
- **Kubernetes**: the crate logs in with the ServiceAccount token file, reads the document, and revokes the login token. The file is read on every load because the kubelet rotates it. A failed revocation is logged and does not fail the load, since the token still expires with its TTL. Batch tokens cannot be revoked and are left to expire.

The default token path expects a projected ServiceAccount token with a dedicated audience, mounted for this purpose. This avoids handing OpenBao a token that is also valid for the Kubernetes API server:

```yaml
volumes:
  - name: openbao-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: openbao
            expirationSeconds: 600
containers:
  - volumeMounts:
      - name: openbao-token
        mountPath: /var/run/secrets/openbao
        readOnly: true
```

The audience must match the one configured on the OpenBao Kubernetes auth role.

## Load semantics

- **Read once.** A snapshot never contacts OpenBao again. Restart the process to pick up changed secrets.
- **All or nothing.** Every domain must exist and hold at least one key it owns. Any failure rejects the whole load. There is no partial document and no fallback to another source.
- **Keys are owned.** A key stored in the wrong domain rejects the load. Keys are matched to the manifest ASCII case-insensitively and stored under the manifest's spelling; the same key set twice in different case rejects the load.
- **Unknown keys are dropped.** Keys outside the manifest are removed and counted per domain. Their names are not reported, because a pasted credential can end up as a key. A misspelled key therefore shows up as one dropped key plus one absent manifest key.
- **No redirects.** Redirects are not followed, so the token is never sent to an address other than the configured one. Point `BAO_ADDR` at an address that answers directly.
- **Bounded.** Authentication and all reads share one timeout, 10 seconds by default. Revoking the login token gets 2 more seconds, also after a timeout.

`OpenBao::load` must run inside a Tokio runtime with the time driver enabled.

## Logging and redaction

Errors, logs, and `Debug` output never contain configuration values, tokens, or messages returned by the server. Errors name the domain, a fixed failure category, and the HTTP status. Every key name in an error comes from the manifest.

`Snapshot::report` describes the load by name and count only: the version and key count of each domain, the number of dropped keys, and the manifest keys that no secret set. The same facts are emitted as `tracing` events: one `INFO` per domain, one `INFO` summary, and a `WARN` for dropped keys or a failed revocation. Install your subscriber before loading, or log the report yourself afterwards.

## Limits

- **Integers beyond 2^53 are rounded by OpenBao**, not by this crate. On OpenBao 2.7.2, a value such as `9007199254740993` comes back as `9007199254740992`, whether it was written through the CLI or through the HTTP API. Store larger identifiers as strings.
- **A TLS backend is required.** Enable `rustls` (default) or `native-tls`.
- **A CA file must contain a PEM certificate.** A file without one is rejected before any request.

## Cargo features

| Feature | Meaning |
| --- | --- |
| `rustls` (default) | TLS through rustls. |
| `native-tls` | TLS through the platform library. Use with `default-features = false`. |

## Development

The repository includes a [devenv](https://devenv.sh) shell with a stable Rust toolchain:

```sh
devenv shell -- cargo test
```

The tests in `tests/live.rs` run against a real `bao server -dev` and are ignored by default. They need the `bao` binary on `PATH`. Each test starts its own in-memory server on a free port with a private `HOME`, so your token file is not touched:

```sh
devenv shell -- cargo test -- --include-ignored
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
