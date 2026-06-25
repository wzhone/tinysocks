//! Listener and connection dispatch.
//!
//! tinysocks serves SOCKS5 and HTTP proxy traffic on the same TCP port by
//! peeking at the first byte and replaying it through `PrefixedStream`.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Semaphore, watch},
};

use crate::{
    auth::{basic_authenticate, ip_authenticate},
    config::{AuthConfig, Config},
    handler::{handle_connect, handle_udp_associate},
    http::handle_http_proxy,
    io_timeout::read_with_timeout,
    protocol::{AuthMethod, PrefixedStream, SOCKS_VERSION, handshake, read_request},
    stats::Stats,
};

const COPY_BUFFER: usize = 64 * 1024;

pub struct ProxyServer {
    bind: String,
    max_connections: usize,
    auth: AuthConfig,
    stats: Stats,
}

enum ProxyProtocol {
    Socks5,
    Http,
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
            auth,
            stats,
        })
    }

    /// Run the proxy accept loop until shutdown is requested.
    pub async fn run(&self, mut shutdown: Option<watch::Receiver<bool>>) -> Result<()> {
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("Failed to bind {}", self.bind))?;
        let stats_port = listener.local_addr()?.port();
        let limiter = Arc::new(Semaphore::new(self.max_connections));

        println!(
            "SOCKS5/HTTP proxy listening on {} with max_connections={}",
            self.bind, self.max_connections
        );

        loop {
            let (mut stream, peer) = match shutdown.as_mut() {
                Some(shutdown_rx) => tokio::select! {
                    res = listener.accept() => res?,
                    _ = shutdown_rx.changed() => break,
                },
                None => listener.accept().await?,
            };

            let Ok(permit) = limiter.clone().try_acquire_owned() else {
                self.stats.inc_connection_limit_rejections();
                // Connection limit reached – cleanly close the accepted socket
                // so the client sees EOF rather than a spurious RST.
                let _ = stream.shutdown().await;
                continue;
            };

            let auth_cfg = self.auth.clone();
            let stats = self.stats.clone();

            stats.inc_total_connections();
            stats.inc_active_connections();

            tokio::spawn(async move {
                let _permit = permit;

                // Decrement active connections on scope exit.
                struct ActiveGuard(Stats);
                impl Drop for ActiveGuard {
                    // Update the active connection counter when the task exits.
                    fn drop(&mut self) {
                        self.0.dec_active_connections();
                    }
                }
                let _guard = ActiveGuard(stats.clone());

                let r = async {
                    let peer_ip = peer.ip();
                    let bypass_auth = ip_authenticate(&auth_cfg.bypass_ips, peer_ip);
                    stream.set_nodelay(true)?;

                    // SOCKS5 starts with version 0x05. HTTP methods start with
                    // ASCII letters, so the first byte is enough to dispatch.
                    let mut first = [0u8; 1];
                    let read =
                        read_with_timeout(&mut stream, &mut first, "initial protocol read").await?;
                    if read == 0 {
                        return Ok::<(), anyhow::Error>(());
                    }

                    let protocol = if first[0] == SOCKS_VERSION {
                        stats.inc_socks5_connections();
                        ProxyProtocol::Socks5
                    } else {
                        stats.inc_http_connections();
                        ProxyProtocol::Http
                    };
                    let mut stream = PrefixedStream::new(stream, first[..read].to_vec());

                    match protocol {
                        ProxyProtocol::Socks5 => {
                            let method = if bypass_auth {
                                AuthMethod::NoAuth
                            } else {
                                AuthMethod::UsernamePassword
                            };

                            if let Err(err) = handshake(&mut stream, method).await {
                                if !bypass_auth {
                                    stats.inc_auth_failures();
                                }
                                return Err(err);
                            }

                            if !bypass_auth
                                && let Err(err) = basic_authenticate(&mut stream, &auth_cfg).await
                            {
                                stats.inc_auth_failures();
                                return Err(err);
                            }
                            let req = read_request(&mut stream).await?;

                            match req.cmd {
                                crate::protocol::Command::Connect(addr) => {
                                    handle_connect(&mut stream, addr, &stats).await?;
                                }
                                crate::protocol::Command::UdpAssociate(addr) => {
                                    let relay_bind_ip = stream.local_addr()?.ip();
                                    handle_udp_associate(
                                        &mut stream,
                                        peer,
                                        relay_bind_ip,
                                        addr,
                                        &stats,
                                    )
                                    .await?;
                                }
                            }
                        }
                        ProxyProtocol::Http => {
                            handle_http_proxy(
                                &mut stream,
                                bypass_auth,
                                &auth_cfg,
                                COPY_BUFFER,
                                &stats,
                                stats_port,
                            )
                            .await?;
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await;

                if let Err(e) = r {
                    println!("connection {} error: {}", peer, e);
                }
            });
        }

        Ok(())
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
