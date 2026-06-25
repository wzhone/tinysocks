use tokio::io::{AsyncWriteExt, duplex};

use tinysocks::protocol::{
    Address, Command, encode_udp_datagram, parse_udp_datagram, read_request,
};

#[tokio::test]
async fn read_request_supports_ipv6_connect() {
    let (mut client, mut server) = duplex(64);
    let mut request = vec![0x05, 0x01, 0x00, 0x04];
    request.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    request.extend_from_slice(&443u16.to_be_bytes());

    client.write_all(&request).await.unwrap();
    let request = read_request(&mut server).await.unwrap();

    match request.cmd {
        Command::Connect(Address::V6(ip, port)) => {
            assert_eq!(
                ip,
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            );
            assert_eq!(port, 443);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn read_request_supports_udp_associate() {
    let (mut client, mut server) = duplex(64);
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let request = read_request(&mut server).await.unwrap();

    match request.cmd {
        Command::UdpAssociate(Address::V4(ip, port)) => {
            assert_eq!(ip, [0, 0, 0, 0]);
            assert_eq!(port, 0);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn udp_datagram_round_trips_ipv6_destination() {
    let destination = Address::V6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        5353,
    );
    let packet = encode_udp_datagram(&destination, b"hello").unwrap();
    let decoded = parse_udp_datagram(&packet).unwrap().unwrap();

    assert_eq!(decoded.destination, destination);
    assert_eq!(decoded.payload, b"hello");
}

#[test]
fn udp_datagram_drops_fragments() {
    let packet = [0, 0, 1, 1, 127, 0, 0, 1, 0, 53, b'x'];

    assert!(parse_udp_datagram(&packet).unwrap().is_none());
}

#[test]
fn address_port_ipv4() {
    let addr = Address::V4([127, 0, 0, 1], 8080);
    assert_eq!(addr.port(), 8080);
}

#[test]
fn address_port_ipv6() {
    let addr = Address::V6([0x20; 16], 443);
    assert_eq!(addr.port(), 443);
}

#[test]
fn address_port_domain() {
    let addr = Address::Domain("example.com".to_string(), 8080);
    assert_eq!(addr.port(), 8080);
}

#[test]
fn address_to_target_string_ipv4() {
    let addr = Address::V4([192, 168, 1, 1], 8080);
    assert_eq!(addr.to_target_string(), "192.168.1.1:8080");
}

#[test]
fn address_to_target_string_ipv6() {
    let addr = Address::V6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        443,
    );
    assert_eq!(addr.to_target_string(), "[2001:db8::1]:443");
}

#[test]
fn address_to_target_string_domain() {
    let addr = Address::Domain("example.com".to_string(), 443);
    assert_eq!(addr.to_target_string(), "example.com:443");
}

#[test]
fn udp_datagram_rejects_too_short() {
    assert!(parse_udp_datagram(&[0, 0]).is_err());
    assert!(parse_udp_datagram(&[]).is_err());
}

#[test]
fn udp_datagram_rejects_nonzero_rsv() {
    let packet = [1, 0, 0, 1, 127, 0, 0, 1, 0, 53, b'x'];
    assert!(parse_udp_datagram(&packet).is_err());
    let packet = [0, 1, 0, 1, 127, 0, 0, 1, 0, 53, b'x'];
    assert!(parse_udp_datagram(&packet).is_err());
}

#[test]
fn udp_datagram_parses_ipv4_destination() {
    let packet = [0, 0, 0, 1, 10, 0, 0, 1, 0, 80, b'h', b'e', b'l', b'l', b'o'];
    let decoded = parse_udp_datagram(&packet).unwrap().unwrap();
    assert_eq!(decoded.destination, Address::V4([10, 0, 0, 1], 80));
    assert_eq!(decoded.payload, b"hello");
}

#[test]
fn udp_datagram_parses_domain_destination() {
    let packet = [
        0, 0, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80,
        b'd', b'a', b't', b'a',
    ];
    let decoded = parse_udp_datagram(&packet).unwrap().unwrap();
    assert_eq!(
        decoded.destination,
        Address::Domain("example.com".to_string(), 80)
    );
    assert_eq!(decoded.payload, b"data");
}

#[test]
fn udp_datagram_rejects_invalid_address_type() {
    let packet = [0, 0, 0, 0xFF, 0, 0];
    assert!(parse_udp_datagram(&packet).is_err());
}

#[test]
fn udp_datagram_rejects_zero_length_domain() {
    let packet = [0, 0, 0, 3, 0, 0, 80, b'd'];
    assert!(parse_udp_datagram(&packet).is_err());
}

#[test]
fn encode_udp_datagram_domain_address() {
    let addr = Address::Domain("example.com".to_string(), 80);
    let packet = encode_udp_datagram(&addr, b"hello").unwrap();
    assert_eq!(packet[0], 0);
    assert_eq!(packet[1], 0);
    assert_eq!(packet[2], 0);
    assert_eq!(packet[3], 3); // ATYP domain
    assert_eq!(packet[4], 11); // length
    assert_eq!(&packet[5..16], b"example.com");
    assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 80);
    assert_eq!(&packet[18..], b"hello");
}

#[tokio::test]
async fn handshake_rejects_wrong_version() {
    let (mut client, mut server) = duplex(32);
    client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    let result =
        tinysocks::protocol::handshake(&mut server, tinysocks::protocol::AuthMethod::NoAuth).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn handshake_no_acceptable_method() {
    let (mut client, mut server) = duplex(32);
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let result = tinysocks::protocol::handshake(
        &mut server,
        tinysocks::protocol::AuthMethod::UsernamePassword,
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn read_request_rejects_wrong_version() {
    let (mut client, mut server) = duplex(64);
    client
        .write_all(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    assert!(read_request(&mut server).await.is_err());
}

#[tokio::test]
async fn read_request_rejects_nonzero_rsv() {
    let (mut client, mut server) = duplex(64);
    client
        .write_all(&[0x05, 0x01, 0xFF, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    assert!(read_request(&mut server).await.is_err());
}

#[tokio::test]
async fn read_request_rejects_unsupported_command() {
    let (mut client, mut server) = duplex(64);
    // CMD = 0x02 (BIND)
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    assert!(read_request(&mut server).await.is_err());
}

#[tokio::test]
async fn read_request_rejects_invalid_address_type() {
    let (mut client, mut server) = duplex(64);
    client
        .write_all(&[0x05, 0x01, 0x00, 0xFF, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    assert!(read_request(&mut server).await.is_err());
}

#[tokio::test]
async fn read_request_rejects_zero_length_domain() {
    let (mut client, mut server) = duplex(64);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50])
        .await
        .unwrap();
    assert!(read_request(&mut server).await.is_err());
}

#[tokio::test]
async fn read_request_parses_domain_connect() {
    let (mut client, mut server) = duplex(128);
    let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
    request.extend_from_slice(b"example.com");
    request.extend_from_slice(&80u16.to_be_bytes());

    client.write_all(&request).await.unwrap();
    let req = read_request(&mut server).await.unwrap();

    match req.cmd {
        Command::Connect(Address::Domain(domain, port)) => {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 80);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn udp_datagram_parses_ipv6_destination() {
    let mut packet = vec![0, 0, 0, 4]; // RSV+FRAG = 0,0,0, ATYP=IPv6
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.extend_from_slice(b"tls");

    let decoded = parse_udp_datagram(&packet).unwrap().unwrap();
    assert_eq!(
        decoded.destination,
        Address::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443
        )
    );
    assert_eq!(decoded.payload, b"tls");
}

#[tokio::test]
async fn resolve_socket_addr_ipv6() {
    let addr = Address::V6([0; 16], 8080);
    let socket = addr.resolve_socket_addr().await.unwrap();
    assert_eq!(socket.port(), 8080);
}

#[tokio::test]
async fn resolve_socket_addr_domain_fails_for_bad_host() {
    let addr = Address::Domain("invalid-host-name.test.invalid".to_string(), 80);
    // Should fail because DNS resolution of an invalid host times out or fails.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        addr.resolve_socket_addr(),
    )
    .await;
    // Either times out or returns an error.
    match result {
        Ok(Err(_)) => {} // expected: resolution failed
        Err(_) => {}     // timeout is also acceptable
        Ok(Ok(_)) => panic!("expected resolution failure for bad host"),
    }
}
