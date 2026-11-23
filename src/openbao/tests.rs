use std::{collections::HashMap, os::unix::ffi::OsStringExt};

use super::*;

const PREFIX: &str = "dev/billing";

fn parse(vars: &[(&'static str, OsString)]) -> Result<Option<OpenBao>, Error> {
    let vars: HashMap<&str, OsString> = vars.iter().cloned().collect();
    OpenBao::from_lookup(|name| vars.get(name).cloned())
}

fn vars(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, OsString)> {
    pairs
        .iter()
        .map(|(name, value)| (*name, OsString::from(value)))
        .collect()
}

#[test]
fn an_unset_or_blank_address_means_not_configured() {
    assert!(parse(&[]).unwrap().is_none());
    assert!(parse(&vars(&[("BAO_ADDR", "  ")])).unwrap().is_none());
    // Nothing else is inspected, so stray variables cannot fail an unconfigured process.
    assert!(
        parse(&vars(&[("BAO_AUTH_METHOD", "approle")]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn variables_are_trimmed_and_defaulted() {
    let base = [
        ("BAO_ADDR", " https://openbao.example.test:8200 "),
        ("BAO_TOKEN", " inline-token\n"),
    ];
    let parsed = parse(&vars(&[
        base[0],
        base[1],
        ("BAO_KV_PATH", " /dev/billing/ "),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        parsed.address.as_str(),
        "https://openbao.example.test:8200/"
    );
    assert_eq!(parsed.location(), "secret/dev/billing");
    assert!(parsed.ca_file.is_none());
    assert_eq!(parsed.timeout, DEFAULT_TIMEOUT);
    assert!(matches!(parsed.auth, Auth::Token(ref token) if token == "inline-token"));

    let parsed = parse(&vars(&[
        base[0],
        base[1],
        ("BAO_KV_PATH", PREFIX),
        ("BAO_KV_MOUNT", "/kv/"),
        ("BAO_AUTH_METHOD", "token"),
        ("BAO_CACERT", "/etc/openbao/ca.crt"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(parsed.location(), "kv/dev/billing");
    assert_eq!(
        parsed.ca_file.as_deref(),
        Some(Path::new("/etc/openbao/ca.crt"))
    );
}

#[test]
fn invalid_variables_are_named_without_their_values() {
    let base = [
        ("BAO_ADDR", "https://openbao.example.test:8200"),
        ("BAO_TOKEN", "inline-token"),
    ];
    for (name, value, expected) in [
        ("BAO_ADDR", "openbao:8200", "BAO_ADDR is invalid"),
        ("BAO_ADDR", "not a url", "BAO_ADDR is invalid"),
        (
            "BAO_KV_PATH",
            "/",
            "BAO_KV_PATH must be set when BAO_ADDR is set",
        ),
        ("BAO_AUTH_METHOD", "approle", "BAO_AUTH_METHOD is invalid"),
    ] {
        let mut pairs = vec![base[0], base[1], ("BAO_KV_PATH", PREFIX)];
        pairs.retain(|(existing, _)| *existing != name);
        pairs.push((name, value));
        let error = parse(&vars(&pairs)).err().unwrap();
        assert_eq!(error.to_string(), expected);
    }

    let mut non_unicode = vars(&[base[0], ("BAO_KV_PATH", PREFIX)]);
    non_unicode.push(("BAO_TOKEN", OsString::from_vec(vec![0xff])));
    assert!(matches!(
        parse(&non_unicode),
        Err(Error::NotUnicode("BAO_TOKEN"))
    ));
}

#[test]
fn kubernetes_method_requires_a_role_and_defaults_the_rest() {
    let kubernetes = vars(&[
        ("BAO_ADDR", "https://openbao.example.test:8200"),
        ("BAO_KV_PATH", PREFIX),
        ("BAO_AUTH_METHOD", "kubernetes"),
    ]);
    assert!(matches!(
        parse(&kubernetes),
        Err(Error::Missing("BAO_K8S_ROLE"))
    ));

    let mut with_role = kubernetes.clone();
    with_role.extend(vars(&[("BAO_K8S_ROLE", "billing")]));
    let parsed = parse(&with_role).unwrap().unwrap();
    assert!(matches!(
        parsed.auth,
        Auth::Kubernetes { ref mount, ref role, ref jwt_path }
            if mount == DEFAULT_K8S_MOUNT
                && role == "billing"
                && jwt_path == Path::new(DEFAULT_K8S_TOKEN_PATH)
    ));

    with_role.extend(vars(&[
        ("BAO_K8S_MOUNT", "/cluster-a/"),
        ("BAO_K8S_TOKEN_PATH", "/run/token"),
        // A token is not needed, and not read, for the Kubernetes method.
        ("BAO_TOKEN_PATH", "/nonexistent/token"),
    ]));
    let parsed = parse(&with_role).unwrap().unwrap();
    assert!(matches!(
        parsed.auth,
        Auth::Kubernetes { ref mount, ref jwt_path, .. }
            if mount == "cluster-a" && jwt_path == Path::new("/run/token")
    ));
}

#[test]
fn token_falls_back_to_token_path_then_home() {
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().to_str().unwrap();
    let base = [
        ("BAO_ADDR", "http://127.0.0.1:8200"),
        ("BAO_KV_PATH", PREFIX),
    ];

    assert!(matches!(
        parse(&vars(&[base[0], base[1], ("HOME", home_path)])),
        Err(Error::Token("BAO_TOKEN"))
    ));
    fs::write(home.path().join(".vault-token"), "home-token\n").unwrap();
    let parsed = parse(&vars(&[base[0], base[1], ("HOME", home_path)]))
        .unwrap()
        .unwrap();
    assert!(matches!(parsed.auth, Auth::Token(ref token) if token == "home-token"));

    // A named file is authoritative: an unusable one does not fall through to HOME.
    let file = home.path().join("token");
    fs::write(&file, " \n").unwrap();
    let pairs = vars(&[
        base[0],
        base[1],
        ("HOME", home_path),
        ("BAO_TOKEN_PATH", file.to_str().unwrap()),
    ]);
    assert!(matches!(parse(&pairs), Err(Error::Token("BAO_TOKEN_PATH"))));
    fs::write(&file, "file-token").unwrap();
    let parsed = parse(&pairs).unwrap().unwrap();
    assert!(matches!(parsed.auth, Auth::Token(ref token) if token == "file-token"));
}

#[test]
fn debug_output_redacts_the_token_and_address_credentials() {
    let address = Url::parse("https://user:address-password@openbao.example.test:8200/").unwrap();
    let openbao = OpenBao::new(address, "/dev/billing/", Auth::Token("inline-token".into()))
        .mount("/kv/")
        .timeout(Duration::from_secs(3));
    assert_eq!(openbao.location(), "kv/dev/billing");

    let output = format!("{openbao:?}");
    assert!(
        output.contains("https://openbao.example.test:8200"),
        "{output}"
    );
    assert!(output.contains("3s"), "{output}");
    for secret in ["inline-token", "address-password"] {
        assert!(!output.contains(secret), "{output}");
    }
}

#[test]
fn an_empty_prefix_reads_from_the_mount_root() {
    let address = Url::parse("http://127.0.0.1:8200").unwrap();
    let openbao = OpenBao::new(address, "/", Auth::kubernetes("billing"));
    assert_eq!(openbao.location(), "secret");
}
