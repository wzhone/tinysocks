use std::io::ErrorKind;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::{Duration, sleep, timeout},
};

use tinysocks::{
    config::{AuthConfig, Config, ServerConfig},
    server::ProxyServer,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_connections_limits_concurrent_handling() {
    let proxy_port = reserve_local_port();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = ProxyServer::new(Config {
        server: ServerConfig {
            bind: format!("127.0.0.1:{proxy_port}"),
            max_connections: 1,
        },
        auth: AuthConfig {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            bypass_ips: vec!["127.0.0.0/8".parse().unwrap()],
        },
    })
    .unwrap();

    let server_task = tokio::spawn(async move { server.run(Some(shutdown_rx)).await });
    wait_for_tcp(proxy_port).await;

    // First connection fills the semaphore.
    let mut first = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    first.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut first_method = [0u8; 2];
    first.read_exact(&mut first_method).await.unwrap();
    assert_eq!(first_method, [0x05, 0x00]);

    // Server closed the connection; platforms may surface that as RST during
    // connect() (when the kernel RST races ahead of connect completion) or as
    // EOF / RST on the first read.
    match TcpStream::connect(("127.0.0.1", proxy_port)).await {
        Ok(mut second) => {
            second.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut second_method = [0u8; 2];
            match second.read(&mut second_method).await {
                Ok(0) => {}
                Err(err) if err.kind() == ErrorKind::ConnectionReset => {}
                other => panic!("expected EOF or connection reset, got {other:?}"),
            }
        }
        Err(err) if err.kind() == ErrorKind::ConnectionReset => {
            // Connection reset before connect() returned; acceptable.
        }
        other => panic!("expected connect success or ConnectionReset, got {other:?}"),
    }

    // After first connection finishes, a new connection can be served.
    drop(first);

    let mut third = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    third.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut third_method = [0u8; 2];
    timeout(Duration::from_secs(2), third.read_exact(&mut third_method))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(third_method, [0x05, 0x00]);

    let _ = shutdown_tx.send(true);
    let _ = timeout(Duration::from_secs(2), server_task).await.unwrap();
}

fn reserve_local_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_tcp(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            // The probe connection may have consumed a semaphore permit.
            // Yield to let the server release it before tests proceed.
            sleep(Duration::from_millis(100)).await;
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not listen on 127.0.0.1:{port}");
}
