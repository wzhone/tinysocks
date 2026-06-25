use std::net::IpAddr;

use ipnet::IpNet;
use tinysocks::{
    auth::{http_basic_authorized, ip_authenticate},
    config::AuthConfig,
};

#[test]
fn ip_authenticate_respects_allowlist() {
    let allowlist = vec![
        "127.0.0.1/8".parse::<IpNet>().unwrap(),
        "::1/128".parse::<IpNet>().unwrap(),
    ];

    assert!(ip_authenticate(
        &allowlist,
        "127.0.0.1".parse::<IpAddr>().unwrap()
    ));
    assert!(ip_authenticate(
        &allowlist,
        "::1".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn ip_authenticate_rejects_outside_allowlist() {
    let allowlist = vec!["127.0.0.1/8".parse::<IpNet>().unwrap()];

    assert!(!ip_authenticate(
        &allowlist,
        "192.0.2.1".parse::<IpAddr>().unwrap()
    ));
    assert!(!ip_authenticate(
        &[],
        "127.0.0.1".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn http_basic_authorized_accepts_valid_credentials() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    let header = "Basic dXNlcjpzZWNyZXQ=";

    assert!(http_basic_authorized(Some(header), &auth));
}

#[test]
fn http_basic_authorized_rejects_invalid_credentials() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    let wrong_pass = "Basic dXNlcjp3cm9uZw==";
    let wrong_user = "Basic YWRtaW46c2VjcmV0";

    assert!(!http_basic_authorized(Some(wrong_pass), &auth));
    assert!(!http_basic_authorized(Some(wrong_user), &auth));
}

#[test]
fn http_basic_authorized_rejects_bad_prefix() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };

    assert!(!http_basic_authorized(Some("Bearer abc"), &auth));
}

#[test]
fn http_basic_authorized_rejects_none_header() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    assert!(!http_basic_authorized(None, &auth));
}

#[test]
fn http_basic_authorized_rejects_too_short_header() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    assert!(!http_basic_authorized(Some("Basic"), &auth));
    assert!(!http_basic_authorized(Some(""), &auth));
}

#[test]
fn http_basic_authorized_rejects_bad_base64() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    // Not valid base64
    assert!(!http_basic_authorized(Some("Basic !!!"), &auth));
}

#[test]
fn http_basic_authorized_rejects_no_colon_in_credentials() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    // "justuser" in base64 with no colon
    assert!(!http_basic_authorized(Some("Basic anVzdHVzZXI="), &auth));
}

#[test]
fn http_basic_authorized_rejects_when_auth_has_no_username() {
    let auth = AuthConfig {
        username: None,
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    let header = "Basic dXNlcjpzZWNyZXQ=";
    assert!(!http_basic_authorized(Some(header), &auth));
}

#[test]
fn http_basic_authorized_rejects_when_auth_has_no_password() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: None,
        bypass_ips: Vec::new(),
    };
    let header = "Basic dXNlcjpzZWNyZXQ=";
    assert!(!http_basic_authorized(Some(header), &auth));
}

#[test]
fn http_basic_authorized_accepts_lowercase_basic_prefix() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    let header = "basic dXNlcjpzZWNyZXQ=";
    assert!(http_basic_authorized(Some(header), &auth));
}

#[test]
fn http_basic_authorized_accepts_mixed_case_basic_prefix() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    let header = "BaSiC dXNlcjpzZWNyZXQ=";
    assert!(http_basic_authorized(Some(header), &auth));
}

#[test]
fn http_basic_authorized_with_leading_spaces_in_encoded_part() {
    let auth = AuthConfig {
        username: Some("user".into()),
        password: Some("secret".into()),
        bypass_ips: Vec::new(),
    };
    // "Basic " followed by spaces then the base64-encoded credentials
    let header = "Basic   dXNlcjpzZWNyZXQ=";
    assert!(http_basic_authorized(Some(header), &auth));
}
