//! Authentication helpers shared by SOCKS5 and HTTP proxy flows.
//!
//! The proxy supports username/password authentication for both protocols, and
//! an IP allowlist that can bypass authentication for trusted clients.

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ipnet::IpNet;
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    config::AuthConfig,
    io_timeout::{read_exact_with_timeout, write_all_with_timeout},
};

/// Perform SOCKS5 username/password authentication.
pub async fn basic_authenticate<S>(stream: &mut S, auth: &AuthConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ver = [0u8; 1];
    read_exact_with_timeout(stream, &mut ver, "SOCKS auth version read").await?;

    if ver[0] != 0x01 {
        bail!("SocksError::InvalidProtocol");
    }

    let username = read_string(stream).await?;
    let password = read_string(stream).await?;
    let (expected_user, expected_pass) = match (&auth.username, &auth.password) {
        (Some(username), Some(password)) => (username.as_bytes(), password.as_bytes()),
        _ => bail!("SocksError::AuthUnavailable"),
    };

    if credentials_match(
        expected_user,
        expected_pass,
        username.as_bytes(),
        password.as_bytes(),
    ) {
        write_all_with_timeout(stream, &[0x01, 0x00], "SOCKS auth success reply write").await?;
        return Ok(());
    }

    write_all_with_timeout(stream, &[0x01, 0x01], "SOCKS auth failure reply write").await?;
    bail!("SocksError::AuthFailed");
}

/// Validate HTTP Proxy-Authorization header against configured user using constant-time compares.
/// The header value should include the `Basic` scheme. Returns false on any parsing error.
pub fn http_basic_authorized(auth_header: Option<&str>, auth: &AuthConfig) -> bool {
    let value = match auth_header {
        Some(v) => v,
        None => return false,
    };

    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return false;
    }

    // Check `Basic ` prefix without allocating lowercase copies and without
    // indexing the header as UTF-8 text.
    if !bytes[..5].eq_ignore_ascii_case(b"Basic") || bytes[5] != b' ' {
        return false;
    }

    let encoded = bytes[6..]
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .map_or(&[][..], |start| &bytes[6 + start..]);
    let decoded = match STANDARD.decode(encoded) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let colon_pos = match decoded.iter().position(|&b| b == b':') {
        Some(pos) => pos,
        None => return false,
    };

    let (user_part, rest) = decoded.split_at(colon_pos);
    let pass_part = &rest[1..]; // skip ':'
    let (expected_user, expected_pass) = match (&auth.username, &auth.password) {
        (Some(username), Some(password)) => (username.as_bytes(), password.as_bytes()),
        _ => return false,
    };

    credentials_match(expected_user, expected_pass, user_part, pass_part)
}

/// Read a length-prefixed SOCKS authentication string.
async fn read_string<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0u8; 1];
    read_exact_with_timeout(stream, &mut len, "SOCKS auth string length read").await?;

    let mut buf = vec![0u8; len[0] as usize];
    read_exact_with_timeout(stream, &mut buf, "SOCKS auth string body read").await?;

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Check whether an IP address is allowed to bypass authentication.
pub fn ip_authenticate(allowlist: &[IpNet], ip: IpAddr) -> bool {
    allowlist.iter().any(|net| net.contains(&ip))
}

/// Compare expected and provided credentials in constant time.
fn credentials_match(user: &[u8], pass: &[u8], provided_user: &[u8], provided_pass: &[u8]) -> bool {
    bool::from(user.ct_eq(provided_user) & pass.ct_eq(provided_pass))
}
