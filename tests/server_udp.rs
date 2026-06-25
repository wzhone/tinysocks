use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::watch,
    time::{Duration, sleep, timeout},
};

use tinysocks::{
    config::{AuthConfig, Config, ServerConfig},
    protocol::{Address, encode_udp_datagram, parse_udp_datagram},
    server::ProxyServer,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_udp_associate_relays_datagrams_and_locks_client_source() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, peer)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo.send_to(&buf[..len], peer).await;
        }
    });

    let proxy_port = reserve_local_port();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = ProxyServer::new(Config {
        server: ServerConfig {
            bind: format!("127.0.0.1:{proxy_port}"),
            max_connections: 1024,
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

    let mut control = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let relay_addr = read_socks_success_reply(&mut control).await;

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = encode_udp_datagram(&Address::from_socket_addr(echo_addr), b"ping").unwrap();
    client_udp.send_to(&request, relay_addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(2), client_udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let response = parse_udp_datagram(&buf[..len]).unwrap().unwrap();
    assert_eq!(response.destination, Address::from_socket_addr(echo_addr));
    assert_eq!(response.payload, b"ping");

    let intruder_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder_udp.send_to(&request, relay_addr).await.unwrap();

    assert!(
        timeout(Duration::from_millis(300), intruder_udp.recv_from(&mut buf))
            .await
            .is_err()
    );

    let _ = shutdown_tx.send(true);
    let _ = timeout(Duration::from_secs(2), server_task).await.unwrap();
    echo_task.abort();
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
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not listen on 127.0.0.1:{port}");
}

async fn read_socks_success_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 0x05);
    assert_eq!(header[1], 0x00);
    assert_eq!(header[2], 0x00);

    match header[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail).await.unwrap();
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(tail[0], tail[1], tail[2], tail[3])),
                u16::from_be_bytes([tail[4], tail[5]]),
            )
        }
        other => panic!("unexpected SOCKS reply address type: {other}"),
    }
}
