use tinysocks::config::{Config, DEFAULT_BIND, DEFAULT_MAX_CONNECTIONS, RuntimeOptions};

fn sample_options() -> RuntimeOptions {
    RuntimeOptions {
        bind: "0.0.0.0:2080".to_string(),
        max_connections: 4096,
        username: Some("cli-user".to_string()),
        password: Some("cli-pass".to_string()),
        bypass_ips: vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()],
    }
}

#[test]
fn runtime_options_build_config() {
    let cfg = Config::from_runtime_options(sample_options()).expect("should build config");

    assert_eq!(cfg.server.bind, "0.0.0.0:2080");
    assert_eq!(cfg.server.max_connections, 4096);
    assert_eq!(cfg.auth.username.as_deref(), Some("cli-user"));
    assert_eq!(cfg.auth.password.as_deref(), Some("cli-pass"));
    assert_eq!(cfg.auth.bypass_ips.len(), 2);
    assert_eq!(cfg.auth.bypass_ips[0].prefix_len(), 32);
    assert_eq!(cfg.auth.bypass_ips[1].prefix_len(), 8);
}

#[test]
fn runtime_options_use_cli_defaults() {
    let cfg = Config::from_runtime_options(RuntimeOptions {
        bind: DEFAULT_BIND.to_string(),
        max_connections: DEFAULT_MAX_CONNECTIONS,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        bypass_ips: Vec::new(),
    })
    .expect("should build config");

    assert_eq!(cfg.server.bind, DEFAULT_BIND);
    assert_eq!(cfg.server.max_connections, DEFAULT_MAX_CONNECTIONS);
    assert!(cfg.auth.bypass_ips.is_empty());
}

#[test]
fn runtime_options_reject_missing_credentials() {
    let mut options = sample_options();
    options.bypass_ips.clear();
    options.password = None;

    assert!(Config::from_runtime_options(options).is_err());
}

#[test]
fn runtime_options_allow_bypass_ips_without_credentials() {
    let mut options = sample_options();
    options.username = None;
    options.password = None;

    let cfg = Config::from_runtime_options(options).expect("should build allowlist-only config");
    assert!(cfg.auth.username.is_none());
    assert!(cfg.auth.password.is_none());
    assert_eq!(cfg.auth.bypass_ips.len(), 2);
}

#[test]
fn runtime_options_reject_partial_credentials_even_with_bypass_ips() {
    let mut options = sample_options();
    options.password = None;

    assert!(Config::from_runtime_options(options).is_err());
}

#[test]
fn runtime_options_reject_zero_max_connections() {
    let mut options = sample_options();
    options.max_connections = 0;

    assert!(Config::from_runtime_options(options).is_err());
}

#[test]
fn runtime_options_reject_empty_bind() {
    let cfg = Config::from_runtime_options(RuntimeOptions {
        bind: "".to_string(),
        max_connections: DEFAULT_MAX_CONNECTIONS,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        bypass_ips: Vec::new(),
    });
    assert!(cfg.is_err());
}

#[test]
fn runtime_options_reject_max_connections_above_limit() {
    // MAX_CONNECTIONS_LIMIT is 1_000_000
    let cfg = Config::from_runtime_options(RuntimeOptions {
        bind: DEFAULT_BIND.to_string(),
        max_connections: 2_000_000,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        bypass_ips: Vec::new(),
    });
    assert!(cfg.is_err());
}

#[test]
fn parse_allowlist_ipv6_without_cidr_defaults_to_host() {
    let cfg = Config::from_runtime_options(RuntimeOptions {
        bind: DEFAULT_BIND.to_string(),
        max_connections: DEFAULT_MAX_CONNECTIONS,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        bypass_ips: vec!["::1".to_string()],
    })
    .expect("should build config");
    assert_eq!(cfg.auth.bypass_ips.len(), 1);
    assert_eq!(cfg.auth.bypass_ips[0].prefix_len(), 128);
}
