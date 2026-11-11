//! HTTP proxy handling with per-request authentication and routing.
//!
//! Hyper owns HTTP/1 message boundaries; CONNECT switches to a byte tunnel.

use anyhow::{Context, Result, anyhow, bail};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header,
    uri::{Authority, PathAndQuery},
};
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
    if has_proxy_via(req.headers(), &listener.via) {
        return Ok(local_response(StatusCode::LOOP_DETECTED, ""));
    }
    if stats.is_enabled() && is_stats_request(&req, listener.port) {
        if !bypass_auth && !stats_authorized(req.headers(), auth) {
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
        && !http_basic_authorized(
            req.headers()
                .get(header::PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::trim),
            auth,
        )
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

    let authority = request_authority(&req)?;
    let port = authority
        .port_u16()
        .unwrap_or(if req.method() == Method::CONNECT {
            443
        } else {
            80
        });
    let target = format!("{}:{port}", authority.host());
    let outbound = TcpStream::connect(&target)
        .await
        .inspect_err(|err| {
            stats.inc_connect_failures();
            stats.record_error(format!("HTTP connect {target} failed from {peer}: {err}"));
        })
        .context("HttpError::ConnectFailed")?;
    let _ = outbound.set_nodelay(true);

    if req.method() == Method::CONNECT {
        *tunnel
            .lock()
            .map_err(|_| anyhow!("HTTP tunnel lock poisoned"))? = Some(outbound);
        return Ok(Response::new(ProxyBody::default()));
    }

    strip_forward_headers(req.headers_mut());
    let host = if port == 80 {
        authority.host()
    } else {
        &target
    };
    req.headers_mut().insert(header::HOST, host.parse()?);
    let via = format!("{:?} {}", req.version(), listener.via);
    req.headers_mut().append("via", via.parse()?);
    *req.uri_mut() = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"))
        .into();

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

fn strip_forward_headers(headers: &mut HeaderMap) {
    let connection_headers: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_owned())
        .collect();
    for name in connection_headers {
        headers.remove(name.as_str());
    }
    // Hyper 已解码正文，由出站 HTTP 连接重新生成 Transfer-Encoding。
    for name in [
        "proxy-authorization",
        "proxy-connection",
        "host",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "transfer-encoding",
    ] {
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

fn has_proxy_via(headers: &HeaderMap, via: &str) -> bool {
    headers
        .get_all(header::VIA)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|hop| hop.split_whitespace().nth(1) == Some(via))
}

/// Only origin-form GET requests on the listener port serve the local page.
fn is_stats_request<B>(req: &Request<B>, listener_port: u16) -> bool {
    req.method() == Method::GET
        && req.uri().scheme().is_none()
        && req.uri().path() == "/stats"
        && req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()?.trim().parse::<Authority>().ok())
            .is_some_and(|authority| authority.port_u16().unwrap_or(80) == listener_port)
}

fn stats_authorized(headers: &HeaderMap, auth: &AuthConfig) -> bool {
    [header::AUTHORIZATION, header::PROXY_AUTHORIZATION]
        .into_iter()
        .any(|name| {
            http_basic_authorized(
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim),
                auth,
            )
        })
}

/// Prefer the request target; origin-form forwarding falls back to Host.
fn request_authority<B>(req: &Request<B>) -> Result<Authority> {
    if req.method() == Method::CONNECT {
        if req.uri().scheme().is_some() {
            bail!("HttpError::BadConnectTarget");
        }
    } else if req
        .uri()
        .scheme_str()
        .is_some_and(|scheme| scheme != "http")
    {
        bail!("HttpError::UnsupportedScheme");
    }
    let authority = match req.uri().authority() {
        Some(authority) => authority.clone(),
        None if req.method() != Method::CONNECT => req
            .headers()
            .get(header::HOST)
            .context("HttpError::MissingHost")?
            .to_str()?
            .trim()
            .parse::<Authority>()
            .context("HttpError::BadHost")?,
        None => bail!("HttpError::BadConnectTarget"),
    };
    if authority.host().is_empty() {
        bail!("HttpError::MissingHost");
    }
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripping_hop_headers_preserves_origin_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-origin", HeaderValue::from_bytes(b"\xff").unwrap());
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static("Keep-Alive, X-Hop"),
        );
        headers.append(header::CONNECTION, HeaderValue::from_static("Another-Hop"));
        for name in [
            "x-hop",
            "another-hop",
            "proxy-authorization",
            "proxy-connection",
            "host",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "transfer-encoding",
        ] {
            headers.insert(name, HeaderValue::from_static("remove"));
        }
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));

        strip_forward_headers(&mut headers);

        assert_eq!(headers.len(), 2);
        assert_eq!(headers["x-origin"].as_bytes(), b"\xff");
        assert_eq!(headers[header::CONTENT_LENGTH], "4");
    }

    #[test]
    fn proxy_via_detects_own_hop_in_multiple_headers_and_hop_lists() {
        let mut headers = HeaderMap::new();
        headers.append(header::VIA, HeaderValue::from_static("1.0 other-proxy"));
        headers.append(
            header::VIA,
            HeaderValue::from_static("HTTP/1.1 tinysocks-own, 1.1 last-proxy"),
        );
        assert!(has_proxy_via(&headers, "tinysocks-own"));
        assert!(!has_proxy_via(&headers, "tinysocks-other"));
        assert!(!has_proxy_via(&headers, "tinysocks"));
    }

    #[test]
    fn stats_page_requires_origin_form_get_and_listener_port() {
        for (method, target, host, port, expected) in [
            ("GET", "/stats", "192.168.1.10:1080", 1080, true),
            ("GET", "/stats?refresh=1", "[fd00::1]:1080", 1080, true),
            ("GET", "/stats", "example.com", 80, true),
            ("GET", "/stats", " example.com:1080 \t", 1080, true),
            ("GET", "/stats", "example.com:8080", 1080, false),
            ("POST", "/stats", "example.com:1080", 1080, false),
            ("GET", "/stats2222", "example.com:1080", 1080, false),
            (
                "GET",
                "http://example.com:1080/stats",
                "example.com:1080",
                1080,
                false,
            ),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, host)
                .body(())
                .unwrap();
            assert_eq!(
                is_stats_request(&req, port),
                expected,
                "{method} {target} {host}"
            );
        }
        let req = Request::builder().uri("/stats").body(()).unwrap();
        assert!(!is_stats_request(&req, 1080));
    }

    #[test]
    fn targets_use_url_authority_or_origin_form_host() {
        for (method, target, host, expected) in [
            (
                "GET",
                "http://example.com?token=1",
                "wrong.example",
                "example.com",
            ),
            (
                "GET",
                "http://[2001:db8::1]:8080/api",
                "wrong.example",
                "[2001:db8::1]:8080",
            ),
            (
                "GET",
                "HTTP://example.com:8080/api",
                "wrong.example",
                "example.com:8080",
            ),
            ("GET", "/api/users", "example.com:8080", "example.com:8080"),
            (
                "CONNECT",
                "[2001:db8::1]:8443",
                "wrong.example",
                "[2001:db8::1]:8443",
            ),
            ("CONNECT", "example.com", "wrong.example", "example.com"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, host)
                .body(())
                .unwrap();
            assert_eq!(request_authority(&req).unwrap().as_str(), expected);
        }
        for (method, target, host) in [
            ("GET", "https://example.com/", "example.com"),
            ("GET", "ftp://example.com/", "example.com"),
            ("GET", "/api", "bad host"),
            ("CONNECT", "/api", "example.com"),
            ("CONNECT", "http://example.com/", "example.com"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, host)
                .body(())
                .unwrap();
            assert!(request_authority(&req).is_err(), "{method} {target} {host}");
        }
        let req = Request::builder().uri("/api").body(()).unwrap();
        assert!(request_authority(&req).is_err());
    }
}
