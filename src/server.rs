//! Listener and connection dispatch.
//!
//! tinysocks serves SOCKS5 and HTTP proxy traffic on the same TCP port by
//! reading the first byte and replaying it through `PrefixedStream`.

use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};

use crate::{
    auth::ip_authenticate,
    config::{AuthConfig, Config},
    http::{HttpListener, handle_http_proxy},
    io_timeout::read_with_timeout,
    protocol::{PrefixedStream, SOCKS_VERSION},
    socks::handle_socks_proxy,
    stats::Stats,
};

pub struct ProxyServer {
    bind: String,
    max_connections: usize,
    enable_udp: bool,
    auth: AuthConfig,
    stats: Stats,
}

struct ActiveGuard(Stats);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.dec_active_connections();
    }
}

impl ProxyServer {
    /// Create a proxy server with default statistics storage.
    pub fn new(cfg: Config) -> Result<Self> {
        Self::with_stats(cfg, Stats::default())
    }

    /// Create a proxy server with caller-provided statistics storage.
    pub fn with_stats(cfg: Config, stats: Stats) -> Result<Self> {
        cfg.validate()?;
        let Config { server, auth } = cfg;
        Ok(Self {
            bind: server.bind,
            max_connections: server.max_connections,
            enable_udp: server.enable_udp,
            auth,
            stats: if server.disable_stats {
                Stats::disabled()
            } else {
                stats
            },
        })
    }

    async fn accept(&self, listener: &TcpListener) -> (TcpStream, SocketAddr) {
        loop {
            match listener.accept().await {
                Ok(connection) => return connection,
                Err(err) => {
                    let message = format!("listener accept failed: {err}");
                    println!("{message}");
                    self.stats.record_error(message);
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    }

    /// Run the proxy accept loop until shutdown is requested.
    pub async fn run(&self, mut shutdown: Option<watch::Receiver<bool>>) -> Result<()> {
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("Failed to bind {}", self.bind))?;
        let http_listener = Arc::new(HttpListener::new(listener.local_addr()?.port()));
        let limiter = Arc::new(Semaphore::new(self.max_connections));

        println!(
            "SOCKS5/HTTP proxy listening on {} with max_connections={}",
            self.bind, self.max_connections
        );

        loop {
            let (mut stream, peer) = match shutdown.as_mut() {
                Some(shutdown_rx) => tokio::select! {
                    res = self.accept(&listener) => res,
                    _ = shutdown_rx.changed() => break,
                },
                None => self.accept(&listener).await,
            };

            let Ok(permit) = limiter.clone().try_acquire_owned() else {
                self.stats.inc_connection_limit_rejections();
                self.stats
                    .record_error(format!("connection limit rejected from {peer}"));
                // Connection limit reached – cleanly close the accepted socket
                // so the client sees EOF rather than a spurious RST.
                let _ = stream.shutdown().await;
                continue;
            };

            let auth_cfg = self.auth.clone();
            let stats = self.stats.clone();
            let http_listener = http_listener.clone();
            let enable_udp = self.enable_udp;

            stats.inc_total_connections();
            stats.inc_active_connections();

            tokio::spawn(async move {
                let _permit = permit;
                let _guard = ActiveGuard(stats.clone());

                if let Err(err) =
                    handle_connection(stream, peer, &auth_cfg, enable_udp, &stats, &http_listener)
                        .await
                {
                    println!("connection {peer} error: {err}");
                }
            });
        }

        Ok(())
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    auth: &AuthConfig,
    enable_udp: bool,
    stats: &Stats,
    http_listener: &HttpListener,
) -> Result<()> {
    let bypass_auth = ip_authenticate(&auth.bypass_ips, peer.ip());
    stream.set_nodelay(true)?;

    // SOCKS5 以 0x05 开头，HTTP 方法以字母开头；消费的首字节交回协议处理器。
    let mut first = [0u8; 1];
    let read = read_with_timeout(&mut stream, &mut first, "initial protocol read").await?;
    if read == 0 {
        return Ok(());
    }
    let stream = PrefixedStream::new(stream, first[..read].to_vec());

    if first[0] == SOCKS_VERSION {
        stats.inc_socks5_connections();
        handle_socks_proxy(stream, bypass_auth, auth, enable_udp, stats, peer).await
    } else {
        stats.inc_http_connections();
        handle_http_proxy(stream, bypass_auth, auth, stats, http_listener, peer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, ServerConfig};

    fn config(bind: &str) -> Config {
        Config {
            server: ServerConfig {
                bind: bind.to_string(),
                max_connections: 16,
                disable_stats: false,
                enable_udp: false,
            },
            auth: AuthConfig {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                bypass_ips: Vec::new(),
            },
        }
    }

    #[test]
    fn proxy_server_instances_do_not_share_global_auth_state() {
        ProxyServer::new(config("127.0.0.1:0")).expect("first server should build");
        ProxyServer::new(config("127.0.0.1:0")).expect("second server should build");
    }
}
