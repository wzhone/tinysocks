use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tinysocks::{
    config::{AuthConfig, Config, ServerConfig},
    server::ProxyServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{Duration, sleep, timeout},
};

type Observations = Arc<Mutex<Vec<(&'static str, String, bool, Bytes)>>>;

async fn serve_upstream(listener: TcpListener, label: &'static str, seen: Observations) {
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let seen = seen.clone();
        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|req: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let path = req.uri().to_string();
                            let leaked = req.headers().contains_key("proxy-authorization");
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            seen.lock().unwrap().push((label, path, leaked, body));
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(label))))
                        }
                    }),
                )
                .await
                .unwrap();
        });
    }
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

async fn read_response(stream: &mut TcpStream, status: u16) -> Vec<u8> {
    let head = read_head(stream).await;
    assert!(head.starts_with(&format!("HTTP/1.1 {status} ")), "{head}");
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    body
}

#[tokio::test]
async fn reused_connections_route_authenticate_and_frame_each_request() {
    timeout(Duration::from_secs(10), async {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        let seen = Observations::default();
        let a_task = tokio::spawn(serve_upstream(a, "A", seen.clone()));
        let b_task = tokio::spawn(serve_upstream(b, "B", seen.clone()));

        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let server = ProxyServer::new(Config {
            server: ServerConfig { bind: format!("127.0.0.1:{port}"), max_connections: 16, disable_stats: false },
            auth: AuthConfig { username: Some("user".into()), password: Some("pass".into()), bypass_ips: Vec::new() },
        }).unwrap();
        let (stop, shutdown) = watch::channel(false);
        let server_task = tokio::spawn(async move { server.run(Some(shutdown)).await });
        let mut client = loop {
            if let Ok(client) = TcpStream::connect(("127.0.0.1", port)).await { break client; }
            sleep(Duration::from_millis(10)).await;
        };
        let auth = "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n";

        // 两个请求同批写入，同时覆盖预读正文和请求流水线。
        for (framing, body) in [
            ("Content-Length: 4\r\n", "PING"),
            ("Transfer-Encoding: chunked\r\n", "4\r\nPING\r\n0\r\n\r\n"),
        ] {
            client.write_all(format!(
                "POST http://{a_addr}/first HTTP/1.1\r\nHost: {a_addr}\r\n{auth}{framing}\r\n{body}GET http://{b_addr}/second HTTP/1.1\r\nHost: {b_addr}\r\n{auth}\r\n"
            ).as_bytes()).await.unwrap();
            assert_eq!(read_response(&mut client, 200).await, b"A");
            assert_eq!(read_response(&mut client, 200).await, b"B");
        }
        drop(client);

        for invalid_auth in ["", "Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n"] {
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(format!("GET http://{a_addr}/authenticated HTTP/1.1\r\nHost: {a_addr}\r\n{auth}\r\n").as_bytes()).await.unwrap();
            assert_eq!(read_response(&mut client, 200).await, b"A");
            client.write_all(format!("GET http://{b_addr}/denied HTTP/1.1\r\nHost: {b_addr}\r\n{invalid_auth}\r\n").as_bytes()).await.unwrap();
            assert!(read_response(&mut client, 407).await.is_empty());
        }

        // Expect 握手仍应允许客户端先等 100，再发送正文。
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(format!("POST http://{a_addr}/expect HTTP/1.1\r\nHost: {a_addr}\r\n{auth}Content-Length: 4\r\nExpect: 100-continue\r\n\r\n").as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 100 "));
        client.write_all(b"PING").await.unwrap();
        assert_eq!(read_response(&mut client, 200).await, b"A");
        drop(client);

        let observations = seen.lock().unwrap().clone();
        assert_eq!(observations.len(), 7);
        assert!(observations.iter().all(|(_, _, leaked, _)| !leaked));
        for pair in observations[..4].as_chunks::<2>().0 {
            assert_eq!((&pair[0].0, pair[0].1.as_str(), pair[0].3.as_ref()), (&"A", "/first", b"PING".as_slice()));
            assert_eq!((&pair[1].0, pair[1].1.as_str(), pair[1].3.as_ref()), (&"B", "/second", b"".as_slice()));
        }
        assert!(observations.iter().all(|(_, path, _, _)| path != "/denied"));

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut body = [0; 5];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello");
            stream.write_all(b"world").await.unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n{auth}\r\nhello").as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200 "));
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
        drop(client);
        echo.await.unwrap();

        stop.send(true).unwrap();
        server_task.await.unwrap().unwrap();
        a_task.abort();
        b_task.abort();
    }).await.expect("HTTP regression checks should finish");
}
