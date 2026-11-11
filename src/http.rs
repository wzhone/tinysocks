//! HTTP proxy handling with per-request authentication and routing.
//!
//! Hyper owns HTTP/1 message boundaries; CONNECT switches to a byte tunnel.

use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, uri::Authority};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    pin::Pin,
    sync::Mutex,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional_with_sizes};
use tokio::net::TcpStream;

use crate::{
    auth::http_basic_authorized,
    config::AuthConfig,
    io_timeout::{IO_TIMEOUT, write_all_with_timeout},
    protocol::PrefixedStream,
    stats::Stats,
};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub struct HttpListener {
    port: u16,
    via: String,
}

impl HttpListener {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            // 每个监听器使用独立标识，避免误拒绝经过其他 TinySocks 的请求。
            via: format!("tinysocks-{:016x}", RandomState::new().hash_one(port)),
        }
    }
}

struct HttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

/// Serve HTTP requests, retaining the connection permit for CONNECT tunnels.
pub async fn handle_http_proxy(
    stream: PrefixedStream,
    bypass_auth: bool,
    auth: &AuthConfig,
    copy_buf_size: usize,
    stats: &Stats,
    listener: &HttpListener,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let tunnel = Mutex::new(None);
    let parts = hyper::server::conn::http1::Builder::new()
        .max_buf_size(MAX_HEADER_SIZE)
        .max_headers(MAX_HEADERS)
        .timer(TokioTimer::new())
        .header_read_timeout(IO_TIMEOUT)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(|req| {
                handle_request(req, bypass_auth, auth, stats, listener, peer, &tunnel)
            }),
        )
        .without_shutdown()
        .await
        .context("HttpError::ConnectionFailed")?;

    let outbound = tunnel
        .lock()
        .map_err(|_| anyhow!("HTTP tunnel lock poisoned"))?
        .take();
    if let Some(mut outbound) = outbound {
        let mut stream = parts.io.into_inner();
        // Hyper 预读的 TLS 数据仍属于隧道，必须先于后续 socket 数据转发。
        write_all_with_timeout(
            &mut outbound,
            &parts.read_buf,
            "HTTP CONNECT upstream pre-write",
        )
        .await?;
        stats.add_tcp_bytes(parts.read_buf.len() as u64, 0);
        let (up, down) =
            copy_bidirectional_with_sizes(&mut stream, &mut outbound, copy_buf_size, copy_buf_size)
                .await
                .inspect_err(|err| {
                    stats.inc_relay_failures();
                    stats.record_error(format!("HTTP CONNECT relay failed from {peer}: {err}"));
                })
                .context("HttpError::RelayFailed")?;
        stats.add_tcp_bytes(up, down);
    }
    Ok(())
}

async fn handle_request(
    mut req: Request<Incoming>,
    bypass_auth: bool,
    auth: &AuthConfig,
    stats: &Stats,
    listener: &HttpListener,
    peer: std::net::SocketAddr,
    tunnel: &Mutex<Option<TcpStream>>,
) -> Result<Response<ProxyBody>> {
    let head = HttpRequest {
        method: req.method().to_string(),
        target: req.uri().to_string(),
        headers: header_pairs(req.headers())?,
    };
    validate_message_framing(&head.headers)?;

    if has_proxy_via(&head.headers, &listener.via) {
        return Ok(local_response(StatusCode::LOOP_DETECTED, ""));
    }
    if stats.is_enabled() && is_stats_request(&head, listener.port) {
        if !bypass_auth && !stats_authorized(&head, auth) {
            stats.inc_auth_failures();
            stats.record_error(format!("stats page authentication failed from {peer}"));
            let mut response = local_response(StatusCode::UNAUTHORIZED, "");
            response.headers_mut().insert(
                "www-authenticate",
                HeaderValue::from_static("Basic realm=\"tinysocks stats\""),
            );
            return Ok(response);
        }
        let mut response = local_response(StatusCode::OK, stats.render_html());
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        return Ok(response);
    }
    if !bypass_auth
        && !http_basic_authorized(get_header(&head.headers, "proxy-authorization"), auth)
    {
        stats.inc_auth_failures();
        stats.record_error(format!("HTTP proxy authentication failed from {peer}"));
        let mut response = local_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED, "");
        response.headers_mut().insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=\"proxy\""),
        );
        return Ok(response);
    }

    let (host, port, path) = if req.method() == http::Method::CONNECT {
        let (host, port) = parse_connect_target(&head.target)?;
        (host, port, String::new())
    } else {
        split_target(&head.target, get_header(&head.headers, "host"), 80)?
    };
    let target = format_target_endpoint(&host, port);
    let outbound = TcpStream::connect(&target)
        .await
        .inspect_err(|err| {
            stats.inc_connect_failures();
            stats.record_error(format!("HTTP connect {target} failed from {peer}: {err}"));
        })
        .context("HttpError::ConnectFailed")?;
    let _ = outbound.set_nodelay(true);

    if req.method() == http::Method::CONNECT {
        *tunnel
            .lock()
            .map_err(|_| anyhow!("HTTP tunnel lock poisoned"))? = Some(outbound);
        return Ok(Response::new(ProxyBody::default()));
    }

    strip_forward_headers(req.headers_mut());
    req.headers_mut()
        .insert("host", format_host_header(&host, port, 80).parse()?);
    let via = format!("{:?} {}", req.version(), listener.via);
    req.headers_mut().append("via", via.parse()?);
    *req.uri_mut() = path.parse()?;

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(HttpStatsStream {
            stream: outbound,
            stats: stats.clone(),
        }))
        .await?;
    let relay_stats = stats.clone();
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            relay_stats.inc_relay_failures();
            relay_stats.record_error(format!(
                "HTTP forward relay {target} failed from {peer}: {err}"
            ));
        }
    });
    let mut response = sender
        .send_request(req)
        .await
        .context("HttpError::RelayFailed")?;
    strip_forward_headers(response.headers_mut());
    Ok(response.map(BodyExt::boxed))
}

fn local_response(status: StatusCode, body: impl Into<Bytes>) -> Response<ProxyBody> {
    let mut response = Response::new(Full::new(body.into()).map_err(|err| match err {}).boxed());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));
    response
}

fn header_pairs(headers: &HeaderMap) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.to_string(),
                std::str::from_utf8(value.as_bytes())
                    .context("HttpError::InvalidHeaderUtf8")?
                    .trim()
                    .to_string(),
            ))
        })
        .collect()
}

fn strip_forward_headers(headers: &mut HeaderMap) {
    let connection_headers = connection_header_names(
        headers
            .iter()
            .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?))),
    );
    let remove: Vec<_> = headers
        .keys()
        .filter(|name| {
            // Hyper 已解码正文，由出站 HTTP 连接重新生成 Transfer-Encoding。
            should_drop_forward_header(name.as_str(), &connection_headers)
                || name.as_str().eq_ignore_ascii_case("transfer-encoding")
        })
        .cloned()
        .collect();
    for name in remove {
        headers.remove(name);
    }
}

struct HttpStatsStream {
    stream: TcpStream,
    stats: Stats,
}

impl AsyncRead for HttpStatsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            self.stats
                .add_tcp_bytes(0, (buf.filled().len() - before) as u64);
        }
        result
    }
}

impl AsyncWrite for HttpStatsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.stats.add_tcp_bytes(n as u64, 0);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Reject ambiguous HTTP request body framing.
fn validate_message_framing(headers: &[(String, String)]) -> Result<()> {
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

fn has_proxy_via(headers: &[(String, String)], via: &str) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("via"))
        .flat_map(|(_, value)| value.split(','))
        .any(|hop| hop.split_whitespace().nth(1) == Some(via))
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

/// Return header names listed by all Connection headers.
fn connection_header_names<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    headers
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

    #[test]
    fn stripping_hop_headers_preserves_non_ascii_response_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-origin", HeaderValue::from_bytes(b"\xff").unwrap());
        headers.insert("connection", HeaderValue::from_static("x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("remove"));
        headers.insert("proxy-authorization", HeaderValue::from_static("secret"));

        strip_forward_headers(&mut headers);

        assert_eq!(headers["x-origin"].as_bytes(), b"\xff");
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-hop"));
        assert!(!headers.contains_key("proxy-authorization"));
    }

    #[test]
    fn proxy_via_detects_own_hop_in_multiple_headers_and_hop_lists() {
        let headers = vec![
            ("Via".to_string(), "1.0 other-proxy".to_string()),
            (
                "vIa".to_string(),
                "HTTP/1.1 tinysocks-own, 1.1 last-proxy".to_string(),
            ),
        ];
        assert!(has_proxy_via(&headers, "tinysocks-own"));
        assert!(!has_proxy_via(&headers, "tinysocks-other"));
        assert!(!has_proxy_via(&headers, "tinysocks"));
    }

    fn request(method: &str, target: &str, host: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            headers: vec![("Host".to_string(), host.to_string())],
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
        let headers = [
            ("Connection".to_string(), "Keep-Alive, X-Hop".to_string()),
            ("connection".to_string(), "Another-Hop".to_string()),
        ];

        assert_eq!(
            connection_header_names(
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
            ),
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
            headers: Vec::new(),
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
