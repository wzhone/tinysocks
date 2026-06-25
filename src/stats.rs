//! Connection and traffic statistics for the proxy.
//!
//! All counters use atomic operations so the struct can be shared across
//! spawned tasks without locks. The `Stats` handle is cheap to clone.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A cheaply-cloneable handle to the proxy-wide statistics.
#[derive(Clone, Default)]
pub struct Stats(Arc<StatsInner>);

#[derive(Default)]
struct StatsInner {
    // -- connection counters --
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    socks5_connections: AtomicU64,
    http_connections: AtomicU64,

    // -- TCP byte counters --
    tcp_bytes_up: AtomicU64,
    tcp_bytes_down: AtomicU64,

    // -- UDP counters --
    udp_associate_sessions: AtomicU64,
    udp_datagrams_in: AtomicU64,
    udp_datagrams_out: AtomicU64,
    udp_bytes_in: AtomicU64,
    udp_bytes_out: AtomicU64,

    connect_failures: AtomicU64,
}

/// Point-in-time snapshot of all counters (not atomically consistent).
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub socks5_connections: u64,
    pub http_connections: u64,
    pub tcp_bytes_up: u64,
    pub tcp_bytes_down: u64,
    pub udp_associate_sessions: u64,
    pub udp_datagrams_in: u64,
    pub udp_datagrams_out: u64,
    pub udp_bytes_in: u64,
    pub udp_bytes_out: u64,
    pub connect_failures: u64,
}

impl Stats {
    /// Render the current statistics snapshot as an HTML page.
    pub fn render_html(&self) -> String {
        let snapshot = self.snapshot();
        render_template(
            include_str!("../assets/stats.html"),
            &[
                (
                    "{total_connections}",
                    snapshot.total_connections.to_string(),
                ),
                (
                    "{active_connections}",
                    snapshot.active_connections.to_string(),
                ),
                (
                    "{socks5_connections}",
                    snapshot.socks5_connections.to_string(),
                ),
                ("{http_connections}", snapshot.http_connections.to_string()),
                ("{tcp_up}", format_bytes(snapshot.tcp_bytes_up)),
                ("{tcp_down}", format_bytes(snapshot.tcp_bytes_down)),
                (
                    "{udp_associate_sessions}",
                    snapshot.udp_associate_sessions.to_string(),
                ),
                (
                    "{udp_datagrams_out}",
                    snapshot.udp_datagrams_out.to_string(),
                ),
                ("{udp_datagrams_in}", snapshot.udp_datagrams_in.to_string()),
                ("{udp_bytes_out}", format_bytes(snapshot.udp_bytes_out)),
                ("{udp_bytes_in}", format_bytes(snapshot.udp_bytes_in)),
                ("{connect_failures}", snapshot.connect_failures.to_string()),
            ],
        )
    }

    /// Return a point-in-time snapshot of all statistics.
    pub fn snapshot(&self) -> StatsSnapshot {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        StatsSnapshot {
            total_connections: r(&self.0.total_connections),
            active_connections: r(&self.0.active_connections),
            socks5_connections: r(&self.0.socks5_connections),
            http_connections: r(&self.0.http_connections),
            tcp_bytes_up: r(&self.0.tcp_bytes_up),
            tcp_bytes_down: r(&self.0.tcp_bytes_down),
            udp_associate_sessions: r(&self.0.udp_associate_sessions),
            udp_datagrams_in: r(&self.0.udp_datagrams_in),
            udp_datagrams_out: r(&self.0.udp_datagrams_out),
            udp_bytes_in: r(&self.0.udp_bytes_in),
            udp_bytes_out: r(&self.0.udp_bytes_out),
            connect_failures: r(&self.0.connect_failures),
        }
    }

    // -- connection counters --

    /// Increment the total accepted connection counter.
    pub fn inc_total_connections(&self) {
        self.0.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the active connection counter.
    pub fn inc_active_connections(&self) {
        self.0.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active connection counter.
    pub fn dec_active_connections(&self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment the SOCKS5 connection counter.
    pub fn inc_socks5_connections(&self) {
        self.0.socks5_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the HTTP connection counter.
    pub fn inc_http_connections(&self) {
        self.0.http_connections.fetch_add(1, Ordering::Relaxed);
    }

    // -- TCP bytes --

    /// Add proxied TCP byte counts for both directions.
    pub fn add_tcp_bytes(&self, up: u64, down: u64) {
        self.0.tcp_bytes_up.fetch_add(up, Ordering::Relaxed);
        self.0.tcp_bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    // -- UDP --

    /// Increment the UDP ASSOCIATE session counter.
    pub fn inc_udp_associate_sessions(&self) {
        self.0
            .udp_associate_sessions
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the remote-to-client UDP datagram counter.
    pub fn inc_udp_datagrams_in(&self) {
        self.0.udp_datagrams_in.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the client-to-remote UDP datagram counter.
    pub fn inc_udp_datagrams_out(&self) {
        self.0.udp_datagrams_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Add remote-to-client UDP bytes.
    pub fn add_udp_bytes_in(&self, n: u64) {
        self.0.udp_bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Add client-to-remote UDP bytes.
    pub fn add_udp_bytes_out(&self, n: u64) {
        self.0.udp_bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment the outbound connection failure counter.
    pub fn inc_connect_failures(&self) {
        self.0.connect_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Replace stats placeholders in a static HTML template.
fn render_template(template: &str, replacements: &[(&str, String)]) -> String {
    let mut rendered = template.to_string();
    for (token, value) in replacements {
        rendered = rendered.replace(token, value.as_str());
    }
    rendered
}

/// Format a byte count as megabytes with two decimals.
fn format_bytes(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;

    format!("{:.2} MB", bytes as f64 / MB)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_default_on_fresh_stats() {
        let stats = Stats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.total_connections, 0);
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.socks5_connections, 0);
        assert_eq!(snap.http_connections, 0);
        assert_eq!(snap.tcp_bytes_up, 0);
        assert_eq!(snap.tcp_bytes_down, 0);
        assert_eq!(snap.udp_associate_sessions, 0);
        assert_eq!(snap.udp_datagrams_in, 0);
        assert_eq!(snap.udp_datagrams_out, 0);
        assert_eq!(snap.udp_bytes_in, 0);
        assert_eq!(snap.udp_bytes_out, 0);
        assert_eq!(snap.connect_failures, 0);
    }

    #[test]
    fn connection_counters_reflected_in_snapshot() {
        let stats = Stats::default();
        stats.inc_total_connections();
        stats.inc_total_connections();
        stats.inc_active_connections();
        stats.inc_socks5_connections();
        stats.inc_http_connections();
        stats.dec_active_connections();

        let snap = stats.snapshot();
        assert_eq!(snap.total_connections, 2);
        assert_eq!(snap.active_connections, 0, "one inc + one dec = 0");
        assert_eq!(snap.socks5_connections, 1);
        assert_eq!(snap.http_connections, 1);
    }

    #[test]
    fn tcp_bytes_accumulated_in_snapshot() {
        let stats = Stats::default();
        stats.add_tcp_bytes(100, 200);
        stats.add_tcp_bytes(50, 0);

        let snap = stats.snapshot();
        assert_eq!(snap.tcp_bytes_up, 150);
        assert_eq!(snap.tcp_bytes_down, 200);
    }

    #[test]
    fn udp_counters_reflected_in_snapshot() {
        let stats = Stats::default();
        stats.inc_udp_associate_sessions();
        stats.inc_udp_datagrams_in();
        stats.inc_udp_datagrams_in();
        stats.inc_udp_datagrams_out();
        stats.add_udp_bytes_in(512);
        stats.add_udp_bytes_out(1024);

        let snap = stats.snapshot();
        assert_eq!(snap.udp_associate_sessions, 1);
        assert_eq!(snap.udp_datagrams_in, 2);
        assert_eq!(snap.udp_datagrams_out, 1);
        assert_eq!(snap.udp_bytes_in, 512);
        assert_eq!(snap.udp_bytes_out, 1024);
    }

    #[test]
    fn connect_failures_counted() {
        let stats = Stats::default();
        stats.inc_connect_failures();
        stats.inc_connect_failures();
        stats.inc_connect_failures();

        assert_eq!(stats.snapshot().connect_failures, 3);
    }

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0.00 MB");
    }

    #[test]
    fn format_bytes_sub_mb() {
        // 1 byte = 0.00 MB
        assert_eq!(format_bytes(1), "0.00 MB");
        // 512 KB = 0.50 MB
        assert_eq!(format_bytes(512 * 1024), "0.50 MB");
    }

    #[test]
    fn format_bytes_exact_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.00 MB");
    }

    #[test]
    fn format_bytes_fractional_mb() {
        // 1.5 MB
        assert_eq!(format_bytes((1024 * 1024) + (512 * 1024)), "1.50 MB");
    }

    #[test]
    fn format_bytes_large() {
        // ~1 GB
        let one_gb = 1073741824u64;
        assert_eq!(format_bytes(one_gb), "1024.00 MB");
    }

    #[test]
    fn render_template_replaces_all_placeholders() {
        let tmpl = "before {a} middle {b} after";
        let result = render_template(tmpl, &[("{a}", "1".into()), ("{b}", "hello".into())]);
        assert_eq!(result, "before 1 middle hello after");
    }

    #[test]
    fn render_template_keeps_unknown_placeholders() {
        let tmpl = "keep {unknown} as-is";
        let result = render_template(tmpl, &[]);
        assert_eq!(result, "keep {unknown} as-is");
    }

    #[test]
    fn render_html_contains_no_leftover_placeholders() {
        let stats = Stats::default();
        stats.inc_total_connections();
        stats.inc_socks5_connections();
        stats.inc_connect_failures();

        let html = stats.render_html();
        // None of the template placeholders should leak into the output.
        assert!(!html.contains("{total_connections}"));
        assert!(!html.contains("{active_connections}"));
        assert!(!html.contains("{socks5_connections}"));
        assert!(!html.contains("{http_connections}"));
        assert!(!html.contains("{tcp_up}"));
        assert!(!html.contains("{tcp_down}"));
        assert!(!html.contains("{udp_associate_sessions}"));
        assert!(!html.contains("{udp_datagrams_in}"));
        assert!(!html.contains("{udp_datagrams_out}"));
        assert!(!html.contains("{udp_bytes_in}"));
        assert!(!html.contains("{udp_bytes_out}"));
        assert!(!html.contains("{connect_failures}"));
    }

    #[test]
    fn render_html_includes_counter_values() {
        let stats = Stats::default();
        stats.inc_total_connections();
        stats.inc_total_connections();
        stats.inc_http_connections();

        let html = stats.render_html();
        assert!(html.contains(">2<"), "total_connections value");
        assert!(html.contains(">1<"), "http_connections value");
        assert!(html.contains(">0<"), "HTTP connections should be 0");
    }
}
