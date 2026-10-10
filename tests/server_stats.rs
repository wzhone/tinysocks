use std::process::{Child, Command, Stdio};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, sleep, timeout},
};

struct ProxyProcess(Child);

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn request(port: u16, message: &str) -> String {
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(message.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    })
    .await
    .expect("request should finish")
}

#[tokio::test]
async fn stats_toggle_preserves_authentication_and_proxy_forwarding() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    for (environment, flag, disabled) in [
        (None, false, false),
        (Some("true"), false, true),
        (Some("false"), false, false),
        (Some("false"), true, true),
    ] {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_tinysocks"));
        command
            .args([
                &format!("127.0.0.1:{port}"),
                "--username",
                "user",
                "--password",
                "pass",
            ])
            .env_remove("TINYSOCKS_DISABLE_STATS")
            .env_remove("TINYSOCKS_BYPASS_IP")
            .env_remove("TINYSOCKS_MAX_CONNECTIONS")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(value) = environment {
            command.env("TINYSOCKS_DISABLE_STATS", value);
        }
        if flag {
            command.arg("--disable-stats");
        }
        let _proxy = ProxyProcess(command.spawn().expect("should start proxy"));

        timeout(Duration::from_secs(5), async {
            while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("proxy should listen");

        let response = request(
            port,
            &format!("GET /stats HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with(if disabled {
            "HTTP/1.1 407"
        } else {
            "HTTP/1.1 401"
        }));

        let response = request(
            port,
            &format!(
                "GET /stats?refresh=1 HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with(if disabled {
            "HTTP/1.1 407"
        } else {
            "HTTP/1.1 200"
        }));

        let response = request(
            port,
            &format!(
                "GET /stats?refresh=1 HTTP/1.1\r\nHost: localhost:{port}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with(if disabled {
            "HTTP/1.1 508"
        } else {
            "HTTP/1.1 200"
        }));

        for target in [
            "/stats2222".to_string(),
            format!("http://localhost:{port}/stats2222"),
        ] {
            let response = request(
                port,
                &format!(
                    "GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
                ),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 508"), "{response}");
        }

        let target = format!("http://{upstream_addr}/stats");
        let response = request(
            port,
            &format!("GET {target} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 407"));

        let message = format!(
            "GET {target} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nVia: 1.0 other-proxy\r\n\r\n"
        );
        let forwarding = request(port, &message);
        let serving = async {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let byte = stream.read_u8().await.unwrap();
                headers.push(byte);
            }
            assert!(headers.starts_with(b"GET /stats HTTP/1.1\r\n"));
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.contains("Via: 1.0 other-proxy\r\n"));
            assert!(headers.contains("Via: HTTP/1.1 tinysocks-"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream",
                )
                .await
                .unwrap();
        };
        let (response, ()) = timeout(Duration::from_secs(2), async {
            tokio::join!(forwarding, serving)
        })
        .await
        .expect("forwarding should finish");
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("upstream"));
    }
}
