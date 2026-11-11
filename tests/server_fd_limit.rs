#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct ProxyProcess(Child);

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn descriptor_exhaustion_does_not_stop_accepting_after_resources_are_freed() {
    let addr: SocketAddr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // 仅限制测试子进程，父进程保留足够的描述符制造并释放连接。
    let mut command = Command::new("sh");
    command
        .args(["-c", "ulimit -n 64 && exec \"$@\"", "tinysocks-fd-test"])
        .arg(env!("CARGO_BIN_EXE_tinysocks"))
        .arg(addr.to_string())
        .args(["--bypass-ip", "127.0.0.1", "--max-connections", "1024"])
        .env_remove("PROXY_USERNAME")
        .env_remove("PROXY_PASSWORD")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut proxy = ProxyProcess(command.spawn().unwrap());
    let stdout = proxy.0.stdout.take().unwrap();
    let (output, lines) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if output.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let startup = lines.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(startup.contains("proxy listening"), "{startup}");

    let mut clients = Vec::new();
    for _ in 0..80 {
        clients.push(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap());
    }
    let error = lines.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(error.contains("Too many open files"), "{error}");
    assert!(proxy.0.try_wait().unwrap().is_none());

    drop(clients);
    let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [0x05, 0x00]);

    drop(client);
    drop(proxy);
    reader.join().unwrap();
}
