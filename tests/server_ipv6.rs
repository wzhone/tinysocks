use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{Duration, sleep, timeout},
};

use tinysocks::{
    config::{AuthConfig, Config, ServerConfig},
    server::ProxyServer,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_connect_relays_ipv6_targets() {
    let Ok(upstream) = TcpListener::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        0,
        0,
        0,
    )))
    .await
    else {
        eprintln!("IPv6 loopback is unavailable; skipping test");
        return;
    };
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        stream.write_all(b"world").await.unwrap();
    });

    let Some(proxy_port) = reserve_ipv6_port() else {
        eprintln!("IPv6 loopback is unavailable; skipping test");
        return;
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = ProxyServer::new(Config {
        server: ServerConfig {
            bind: format!("[::1]:{proxy_port}"),
            max_connections: 1024,
        },
        auth: AuthConfig {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            bypass_ips: vec!["::1/128".parse().unwrap()],
        },
    })
    .unwrap();

    let server_task = tokio::spawn(async move { server.run(Some(shutdown_rx)).await });
    wait_for_ipv6_tcp(proxy_port).await;

    let mut client = TcpStream::connect((Ipv6Addr::LOCALHOST, proxy_port))
        .await
        .unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x04];
    request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 22];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);
    assert_eq!(reply[2], 0x00);
    assert_eq!(reply[3], 0x04);

    client.write_all(b"hello").await.unwrap();
    let mut body = [0u8; 5];
    client.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"world");

    let _ = shutdown_tx.send(true);
    let _ = timeout(Duration::from_secs(2), server_task).await.unwrap();
    upstream_task.await.unwrap();
}

fn reserve_ipv6_port() -> Option<u16> {
    std::net::TcpListener::bind("[::1]:0")
        .ok()
        .and_then(|listener| listener.local_addr().ok().map(|addr| addr.port()))
}

async fn wait_for_ipv6_tcp(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect((Ipv6Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not listen on [::1]:{port}");
}
