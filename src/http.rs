//! Minimal HTTP proxy handling.
//!
//! `httparse` reads raw HTTP/1.x request headers from the TCP stream. URI and
//! authority parsing is delegated to the `http` crate so IPv6, default ports,
//! and path/query handling follow a well-tested parser.

use anyhow::{Context, Result, anyhow, bail};
use http::uri::Authority;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;

use crate::{
    auth::http_basic_authorized,
    config::AuthConfig,
    io_timeout::{flush_with_timeout, read_with_timeout, write_all_with_timeout},
    protocol::PrefixedStream,
    stats::Stats,
};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;

struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body_start: Vec<u8>,
}

/// Handle one HTTP proxy or stats-page request.
pub async fn handle_http_proxy(
    stream: &mut PrefixedStream,
    bypass_auth: bool,
    auth: &AuthConfig,
    copy_buf_size: usize,
    stats: &Stats,
    listener_port: u16,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let mut req = read_http_request(stream).await?;

    if is_stats_request(&req, listener_port) {
        if !bypass_auth && !stats_authorized(&req, auth) {
            stats.inc_auth_failures();
            stats.record_error(format!("stats page authentication failed from {peer}"));
            send_stats_auth_required(stream).await?;
            return Ok(());
        }
        return serve_stats_page(stream, stats).await;
    }

    if !bypass_auth && !http_basic_authorized(get_header(&req.headers, "proxy-authorization"), auth)
    {
        stats.inc_auth_failures();
        stats.record_error(format!("HTTP proxy authentication failed from {peer}"));
        send_proxy_auth_required(stream).await?;
        return Ok(());
    }

    if req.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(stream, &req, copy_buf_size, stats, peer).await
    } else {
        handle_forward(stream, &mut req, copy_buf_size, stats, peer).await
    }
}

/// Read and parse one HTTP request header block.
async fn read_http_request(stream: &mut PrefixedStream) -> Result<HttpRequest> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0u8; 1024];
        let n = read_with_timeout(stream, &mut chunk, "HTTP request header read").await?;
        if n == 0 {
            bail!("HttpError::UnexpectedEof");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADER_SIZE {
            bail!("HttpError::HeaderTooLarge");
        }

        let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut raw_headers);
        match parsed.parse(&buf) {
            Ok(httparse::Status::Complete(header_end)) => {
                let method = parsed
                    .method
                    .ok_or_else(|| anyhow!("HttpError::BadRequest"))?
                    .to_string();
                let target = parsed
                    .path
                    .ok_or_else(|| anyhow!("HttpError::BadRequest"))?
                    .to_string();
                let version = match parsed.version {
                    Some(1) => "HTTP/1.1".to_string(),
                    Some(0) => "HTTP/1.0".to_string(),
                    _ => bail!("HttpError::BadRequest"),
                };

                let mut headers = Vec::with_capacity(parsed.headers.len());
                for header in parsed.headers.iter() {
                    let value = std::str::from_utf8(header.value)
                        .context("HttpError::InvalidHeaderUtf8")?
                        .trim()
                        .to_string();
                    headers.push((header.name.trim().to_string(), value));
                }
                validate_message_framing(&headers)?;

                let body_start = buf[header_end..].to_vec();
                return Ok(HttpRequest {
                    method,
                    target,
                    version,
                    headers,
                    body_start,
                });
            }
            Ok(httparse::Status::Partial) => continue,
            Err(httparse::Error::TooManyHeaders) => bail!("HttpError::TooManyHeaders"),
            Err(_) => bail!("HttpError::BadRequest"),
        }
    }
}

/// Reject ambiguous HTTP request body framing.
fn validate_message_framing(headers: &[(String, String)]) -> Result<()> {
    // This proxy streams bodies without fully decoding HTTP framing. Rejecting
    // ambiguous framing at the edge avoids forwarding requests that different
    // upstream servers could interpret differently.
    let mut content_length: Option<u64> = None;
    let mut has_chunked_transfer_encoding = false;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            for part in value.split(',') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    bail!("HttpError::BadContentLength");
                }
                let parsed = trimmed
                    .parse::<u64>()
                    .map_err(|_| anyhow!("HttpError::BadContentLength"))?;
                if let Some(prev) = content_length {
                    if prev != parsed {
                        // Reject ambiguous Content-Length values to avoid request smuggling.
                        bail!("HttpError::AmbiguousContentLength");
                    }
                } else {
                    content_length = Some(parsed);
                }
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("chunked"))
        {
            has_chunked_transfer_encoding = true;
        }
    }

    // A request must not describe the body length through both CL and TE.
    if has_chunked_transfer_encoding && content_length.is_some() {
        bail!("HttpError::ConflictingLengthHeaders");
    }
    Ok(())
}

/// Find a header value by case-insensitive name.
fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Check whether a request targets the built-in stats page.
fn is_stats_request(req: &HttpRequest, listener_port: u16) -> bool {
    if !req.method.eq_ignore_ascii_case("GET") {
        return false;
    }
    if is_absolute_http_target(&req.target) {
        return false;
    }

    let path = req
        .target
        .split_once('?')
        .map_or(req.target.as_str(), |(path, _)| path);
    if !matches!(path, "/stats") {
        return false;
    }

    let Some(host) = get_header(&req.headers, "host") else {
        return false;
    };
    host_targets_listener_port(host, listener_port)
}

/// Check whether a Host header points at the listener port.
fn host_targets_listener_port(host: &str, listener_port: u16) -> bool {
    host_header_port(host).is_some_and(|port| port == listener_port)
}

/// Extract the port from a Host header value.
fn host_header_port(host: &str) -> Option<u16> {
    let a: Authority = host.trim().parse().ok()?;
    Some(a.port_u16().unwrap_or(80))
}

/// Check Basic credentials for the stats page.
fn stats_authorized(req: &HttpRequest, auth: &AuthConfig) -> bool {
    http_basic_authorized(get_header(&req.headers, "authorization"), auth)
        || http_basic_authorized(get_header(&req.headers, "proxy-authorization"), auth)
}

/// Send a browser-friendly stats authentication challenge.
async fn send_stats_auth_required(stream: &mut PrefixedStream) -> Result<()> {
    write_all_with_timeout(
        stream,
        b"HTTP/1.1 401 Unauthorized\r\n\
          WWW-Authenticate: Basic realm=\"tinysocks stats\"\r\n\
          Content-Length: 0\r\n\
          Connection: close\r\n\r\n",
        "HTTP stats 401 response write",
    )
    .await?;
    Ok(())
}

/// Send the rendered statistics page.
async fn serve_stats_page(stream: &mut PrefixedStream, stats: &Stats) -> Result<()> {
    let body = stats.render_html();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Cache-Control: no-store\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    write_all_with_timeout(stream, response.as_bytes(), "HTTP stats page write").await?;
    Ok(())
}

/// Send an HTTP proxy authentication challenge.
async fn send_proxy_auth_required(stream: &mut PrefixedStream) -> Result<()> {
    write_all_with_timeout(
        stream,
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
          Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
          Content-Length: 0\r\n\
          Connection: close\r\n\r\n",
        "HTTP 407 response write",
    )
    .await?;
    Ok(())
}

/// Handle an HTTP CONNECT tunnel request.
async fn handle_connect(
    stream: &mut PrefixedStream,
    req: &HttpRequest,
    copy_buf_size: usize,
    stats: &Stats,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let (host, port) = parse_connect_target(&req.target)?;
    let target = format_target_endpoint(&host, port);
    let mut outbound = TcpStream::connect(&target)
        .await
        .inspect_err(|err| {
            stats.inc_connect_failures();
            stats.record_error(format!("HTTP CONNECT {target} failed from {peer}: {err}"));
        })
        .context("HttpError::ConnectFailed")?;
    let _ = outbound.set_nodelay(true);

    write_all_with_timeout(
        stream,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        "HTTP CONNECT response write",
    )
    .await?;

    // Forward any bytes that arrived after the CONNECT header (e.g. TLS
    // ClientHello) before entering the tunnel.
    if !req.body_start.is_empty() {
        write_all_with_timeout(
            &mut outbound,
            &req.body_start,
            "HTTP CONNECT upstream pre-write",
        )
        .await?;
        stats.add_tcp_bytes(req.body_start.len() as u64, 0);
    }

    let (up, down) =
        copy_bidirectional_with_sizes(stream, &mut outbound, copy_buf_size, copy_buf_size)
            .await
            .inspect_err(|err| {
                stats.inc_relay_failures();
                stats.record_error(format!(
                    "HTTP CONNECT relay {target} failed from {peer}: {err}"
                ));
            })
            .context("HttpError::RelayFailed")?;
    stats.add_tcp_bytes(up, down);
    Ok(())
}

/// Forward a non-CONNECT HTTP proxy request.
async fn handle_forward(
    stream: &mut PrefixedStream,
    req: &mut HttpRequest,
    copy_buf_size: usize,
    stats: &Stats,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let host_header = get_header(&req.headers, "host").map(|s| s.to_string());
    let (host, port, path) = split_target(&req.target, host_header.as_deref(), 80)?;

    let target = format_target_endpoint(&host, port);
    let mut outbound = TcpStream::connect(&target)
        .await
        .inspect_err(|err| {
            stats.inc_connect_failures();
            stats.record_error(format!(
                "HTTP forward connect {target} failed from {peer}: {err}"
            ));
        })
        .context("HttpError::ConnectFailed")?;
    let _ = outbound.set_nodelay(true);

    let mut request = format!("{} {} {}\r\n", req.method, path, req.version);

    // Drop hop-by-hop and proxy-only headers. Always replace the Host
    // header with the target derived from the request URL to prevent
    // Host header injection (RFC 7230 §5.4).
    let connection_headers = connection_header_names(&req.headers);
    for (name, value) in &req.headers {
        if should_drop_forward_header(name, &connection_headers) {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }

    let host_header = format_host_header(&host, port, 80);
    request.push_str("Host: ");
    request.push_str(&host_header);
    request.push_str("\r\n");

    request.push_str("\r\n");

    let initial_up = request.len() as u64 + req.body_start.len() as u64;

    write_all_with_timeout(
        &mut outbound,
        request.as_bytes(),
        "HTTP upstream request write",
    )
    .await?;
    if !req.body_start.is_empty() {
        write_all_with_timeout(&mut outbound, &req.body_start, "HTTP upstream body write").await?;
    }
    flush_with_timeout(&mut outbound, "HTTP upstream flush").await?;
    stats.add_tcp_bytes(initial_up, 0);

    let (up, down) =
        copy_bidirectional_with_sizes(stream, &mut outbound, copy_buf_size, copy_buf_size)
            .await
            .inspect_err(|err| {
                stats.inc_relay_failures();
                stats.record_error(format!(
                    "HTTP forward relay {target} failed from {peer}: {err}"
                ));
            })
            .context("HttpError::RelayFailed")?;
    stats.add_tcp_bytes(up, down);

    Ok(())
}

/// Return header names listed by all Connection headers.
fn connection_header_names(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

/// Check whether a header must be removed before forwarding.
fn should_drop_forward_header(name: &str, connection_headers: &[String]) -> bool {
    name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || connection_headers
            .iter()
            .any(|header| header.eq_ignore_ascii_case(name))
}

/// Parse a CONNECT authority target into host and port.
fn parse_connect_target(target: &str) -> Result<(String, u16)> {
    let authority = target
        .parse::<Authority>()
        .map_err(|_| anyhow!("HttpError::BadConnectTarget"))?;
    authority_host_port(&authority, 443)
}

/// Split an HTTP request target into host, port, and path.
fn split_target(
    target: &str,
    host_header: Option<&str>,
    default_port: u16,
) -> Result<(String, u16, String)> {
    // Proxy requests normally use absolute-form targets, while origin-form
    // targets rely on the Host header. CONNECT is handled separately.
    if is_absolute_http_target(target) {
        return parse_absolute_target(target);
    }

    let host_header = host_header.ok_or_else(|| anyhow!("HttpError::MissingHost"))?;
    let authority = host_header
        .parse::<Authority>()
        .map_err(|_| anyhow!("HttpError::BadHost"))?;
    let (host, port) = authority_host_port(&authority, default_port)?;
    let path = if target.is_empty() { "/" } else { target };
    Ok((host, port, path.to_string()))
}

/// Parse an absolute-form HTTP target.
fn parse_absolute_target(target: &str) -> Result<(String, u16, String)> {
    let uri = target
        .parse::<http::Uri>()
        .map_err(|_| anyhow!("HttpError::BadRequestTarget"))?;
    let default_port = match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => 80,
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => {
            bail!("HttpError::HttpsNotSupported");
        }
        _ => bail!("HttpError::UnsupportedScheme"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("HttpError::MissingHost"))?;
    let (host, port) = authority_host_port(authority, default_port)?;
    let path = normalize_path_and_query(uri.path_and_query().map(|pq| pq.as_str()));
    Ok((host, port, path))
}

/// Check whether a target is an absolute HTTP or HTTPS URI.
fn is_absolute_http_target(target: &str) -> bool {
    target
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || target
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

/// Extract normalized host and port from an authority.
fn authority_host_port(authority: &Authority, default_port: u16) -> Result<(String, u16)> {
    let host = normalize_host(authority.host());
    if host.is_empty() {
        bail!("HttpError::MissingHost");
    }
    Ok((host, authority.port_u16().unwrap_or(default_port)))
}

/// Remove IPv6 brackets from a host value.
fn normalize_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .to_string()
}

/// Normalize a URI path/query into origin-form.
fn normalize_path_and_query(path_and_query: Option<&str>) -> String {
    match path_and_query {
        Some("") | None => "/".to_string(),
        Some(value) if value.starts_with('?') => format!("/{value}"),
        Some(value) => value.to_string(),
    }
}

/// Format a host and port for `TcpStream::connect`.
fn format_target_endpoint(host: &str, port: u16) -> String {
    format!("{}:{port}", crate::protocol::bracket_ipv6(host))
}

/// Format a Host header value.
fn format_host_header(host: &str, port: u16, default_port: u16) -> String {
    let host = crate::protocol::bracket_ipv6(host);
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, target: &str, host: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), host.to_string())],
            body_start: Vec::new(),
        }
    }

    #[test]
    fn stats_request_accepts_lan_host_on_listener_port() {
        let req = request("GET", "/stats", "192.168.1.10:1080");

        assert!(is_stats_request(&req, 1080));
    }

    #[test]
    fn stats_request_accepts_ipv6_host_on_listener_port() {
        let req = request("GET", "/stats", "[fd00::1]:1080");

        assert!(is_stats_request(&req, 1080));
    }

    #[test]
    fn stats_request_rejects_different_port() {
        let req = request("GET", "/", "192.168.1.10:8080");

        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn stats_request_rejects_absolute_proxy_target() {
        let req = request("GET", "http://example.com/", "192.168.1.10:1080");

        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn split_target_keeps_query_without_slash() {
        let (host, port, path) =
            split_target("http://example.com?token=1", None, 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/?token=1");
    }

    #[test]
    fn split_target_defaults_to_root() {
        let (host, port, path) =
            split_target("http://example.com", None, 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn split_target_supports_ipv6_authority() {
        let (host, port, path) =
            split_target("http://[2001:db8::1]:8080/api", None, 80).expect("should parse");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn split_target_accepts_case_insensitive_scheme() {
        let (host, port, path) =
            split_target("HTTP://example.com:8080/api", None, 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn parse_connect_target_supports_ipv6_authority() {
        let (host, port) = parse_connect_target("[2001:db8::1]:8443").expect("should parse");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
    }

    #[test]
    fn connection_header_names_collects_extensions() {
        let headers = vec![
            ("Connection".to_string(), "Keep-Alive, X-Hop".to_string()),
            ("connection".to_string(), "Another-Hop".to_string()),
        ];

        assert_eq!(
            connection_header_names(&headers),
            vec!["keep-alive", "x-hop", "another-hop"]
        );
    }

    #[test]
    fn should_drop_forward_header_uses_connection_extensions() {
        let connection_headers = vec!["x-hop".to_string()];

        assert!(should_drop_forward_header("X-Hop", &connection_headers));
        assert!(should_drop_forward_header(
            "Connection",
            &connection_headers
        ));
        assert!(should_drop_forward_header("Host", &connection_headers));
        assert!(!should_drop_forward_header(
            "X-End-To-End",
            &connection_headers
        ));
    }

    #[test]
    fn validate_message_framing_accepts_same_content_length_values() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Content-Length".to_string(), "12".to_string()),
            ("Content-Length".to_string(), "12".to_string()),
        ];
        assert!(validate_message_framing(&headers).is_ok());
    }

    #[test]
    fn validate_message_framing_rejects_conflicting_content_length_values() {
        let headers = vec![
            ("Content-Length".to_string(), "12".to_string()),
            ("Content-Length".to_string(), "13".to_string()),
        ];
        assert!(validate_message_framing(&headers).is_err());
    }

    #[test]
    fn validate_message_framing_rejects_conflicting_transfer_encoding_and_content_length() {
        let headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Length".to_string(), "12".to_string()),
        ];
        assert!(validate_message_framing(&headers).is_err());
    }
    #[test]
    fn validate_message_framing_rejects_empty_content_length_value() {
        let headers = vec![("Content-Length".to_string(), "".to_string())];
        assert!(validate_message_framing(&headers).is_err());
    }

    #[test]
    fn is_stats_request_rejects_post() {
        let req = request("POST", "/stats", "127.0.0.1:1080");
        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn is_stats_request_rejects_wrong_path() {
        let req = request("GET", "/health", "127.0.0.1:1080");
        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn is_stats_request_rejects_missing_host_header() {
        let req = HttpRequest {
            method: "GET".to_string(),
            target: "/stats".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body_start: Vec::new(),
        };
        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn is_stats_request_rejects_path_with_query_on_stats_prefix() {
        let req = request("GET", "/stats?refresh=1", "127.0.0.1:1080");
        assert!(is_stats_request(&req, 1080));
    }

    #[test]
    fn is_absolute_http_target_detects_https() {
        assert!(is_absolute_http_target("https://example.com/"));
    }

    #[test]
    fn is_absolute_http_target_detects_http() {
        assert!(is_absolute_http_target("http://example.com/"));
    }

    #[test]
    fn is_absolute_http_target_detects_uppercase() {
        assert!(is_absolute_http_target("HTTP://example.com/"));
        assert!(is_absolute_http_target("HTTPS://example.com/"));
    }

    #[test]
    fn is_absolute_http_target_rejects_origin_form() {
        assert!(!is_absolute_http_target("/path"));
    }

    #[test]
    fn is_absolute_http_target_rejects_short_string() {
        assert!(!is_absolute_http_target("http"));
        assert!(!is_absolute_http_target(""));
    }

    #[test]
    fn is_absolute_http_target_rejects_ftp() {
        assert!(!is_absolute_http_target("ftp://example.com/"));
    }

    #[test]
    fn normalize_host_strips_ipv6_brackets() {
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn normalize_host_passes_through_ipv4() {
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn normalize_host_passes_through_domain() {
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[test]
    fn normalize_path_and_query_defaults_to_root() {
        assert_eq!(normalize_path_and_query(None), "/");
        assert_eq!(normalize_path_and_query(Some("")), "/");
    }

    #[test]
    fn normalize_path_and_query_preserves_path() {
        assert_eq!(normalize_path_and_query(Some("/api")), "/api");
        assert_eq!(normalize_path_and_query(Some("/api/")), "/api/");
    }

    #[test]
    fn normalize_path_and_query_prepends_slash_to_query_only() {
        assert_eq!(normalize_path_and_query(Some("?key=val")), "/?key=val");
    }

    #[test]
    fn format_target_endpoint_ipv4() {
        assert_eq!(format_target_endpoint("127.0.0.1", 8080), "127.0.0.1:8080");
    }

    #[test]
    fn format_target_endpoint_ipv6() {
        assert_eq!(format_target_endpoint("::1", 8080), "[::1]:8080");
    }

    #[test]
    fn format_host_header_default_port_omitted() {
        assert_eq!(format_host_header("example.com", 80, 80), "example.com");
    }

    #[test]
    fn format_host_header_non_default_port_included() {
        assert_eq!(
            format_host_header("example.com", 8080, 80),
            "example.com:8080"
        );
    }

    #[test]
    fn format_host_header_ipv6() {
        assert_eq!(format_host_header("::1", 80, 80), "[::1]");
        assert_eq!(format_host_header("::1", 443, 80), "[::1]:443");
    }

    #[test]
    fn get_header_finds_exact_match() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert_eq!(get_header(&headers, "Host"), Some("example.com"));
    }

    #[test]
    fn get_header_is_case_insensitive() {
        let headers = vec![("host".to_string(), "example.com".to_string())];
        assert_eq!(get_header(&headers, "Host"), Some("example.com"));
        assert_eq!(get_header(&headers, "HOST"), Some("example.com"));
    }

    #[test]
    fn get_header_returns_none_for_missing() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert_eq!(get_header(&headers, "Content-Type"), None);
    }

    #[test]
    fn get_header_returns_none_for_empty_headers() {
        let headers: Vec<(String, String)> = Vec::new();
        assert_eq!(get_header(&headers, "Host"), None);
    }

    #[test]
    fn host_header_port_ipv4_default() {
        assert_eq!(host_header_port("127.0.0.1"), Some(80));
    }

    #[test]
    fn host_header_port_ipv4_explicit() {
        assert_eq!(host_header_port("127.0.0.1:8080"), Some(8080));
    }

    #[test]
    fn host_header_port_ipv6_default() {
        assert_eq!(host_header_port("[::1]"), Some(80));
    }

    #[test]
    fn host_header_port_ipv6_explicit() {
        assert_eq!(host_header_port("[::1]:443"), Some(443));
    }

    #[test]
    fn host_header_port_domain_default() {
        assert_eq!(host_header_port("example.com"), Some(80));
    }

    #[test]
    fn host_header_port_domain_explicit() {
        assert_eq!(host_header_port("example.com:443"), Some(443));
    }

    #[test]
    fn split_target_origin_form_with_host_header() {
        let (host, port, path) =
            split_target("/api/users", Some("example.com:8080"), 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api/users");
    }

    #[test]
    fn split_target_origin_form_default_port() {
        let (host, port, path) =
            split_target("/api", Some("example.com"), 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/api");
    }

    #[test]
    fn split_target_origin_form_empty_path() {
        let (host, port, path) =
            split_target("", Some("example.com:8080"), 80).expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn split_target_missing_host_header() {
        assert!(split_target("/api", None, 80).is_err());
    }

    #[test]
    fn split_target_invalid_host_header() {
        assert!(split_target("/api", Some("bad host"), 80).is_err());
    }

    #[test]
    fn split_target_rejects_https_absolute() {
        assert!(split_target("https://example.com/", None, 443).is_err());
    }

    #[test]
    fn parse_connect_target_ipv4() {
        let (host, port) = parse_connect_target("192.168.1.1:443").expect("should parse");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_domain_default_port() {
        let (host, port) = parse_connect_target("example.com").expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_absolute_target_https_rejected() {
        let err = parse_absolute_target("https://example.com/path").unwrap_err();
        assert!(err.to_string().contains("HttpsNotSupported"));
    }

    #[test]
    fn parse_absolute_target_unsupported_scheme() {
        assert!(parse_absolute_target("ftp://example.com/").is_err());
    }

    #[test]
    fn parse_absolute_target_missing_authority() {
        assert!(parse_absolute_target("http:///path").is_err());
    }

    #[test]
    fn validate_message_framing_allows_chunked_without_content_length() {
        let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert!(validate_message_framing(&headers).is_ok());
    }

    #[test]
    fn validate_message_framing_allows_comma_separated_transfer_encoding() {
        let headers = vec![("Transfer-Encoding".to_string(), "gzip, chunked".to_string())];
        assert!(validate_message_framing(&headers).is_ok());
    }

    #[test]
    fn validate_message_framing_rejects_content_length_with_comma_values() {
        let headers = vec![("Content-Length".to_string(), "12, 13".to_string())];
        assert!(validate_message_framing(&headers).is_err());
    }

    #[test]
    fn should_drop_forward_header_drops_proxy_authorization() {
        assert!(should_drop_forward_header("Proxy-Authorization", &[]));
    }

    #[test]
    fn should_drop_forward_header_drops_proxy_connection() {
        assert!(should_drop_forward_header("Proxy-Connection", &[]));
    }

    #[test]
    fn should_drop_forward_header_drops_keep_alive() {
        assert!(should_drop_forward_header("Keep-Alive", &[]));
    }

    #[test]
    fn should_drop_forward_header_drops_te() {
        assert!(should_drop_forward_header("TE", &[]));
    }

    #[test]
    fn should_drop_forward_header_drops_trailer() {
        assert!(should_drop_forward_header("Trailer", &[]));
    }

    #[test]
    fn should_drop_forward_header_drops_upgrade() {
        assert!(should_drop_forward_header("Upgrade", &[]));
    }
}
