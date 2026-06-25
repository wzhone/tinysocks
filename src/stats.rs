//! Connection and traffic statistics for the proxy.
//!
//! Most counters use atomic operations so the struct can be shared across
//! spawned tasks without locks. Recent errors use a small mutex-protected
//! ring buffer because writes only happen on failure paths.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_RECENT_ERRORS: usize = 100;
const MAX_ERROR_MESSAGE_CHARS: usize = 240;

/// A cheaply-cloneable handle to the proxy-wide statistics.
#[derive(Clone, Default)]
pub struct Stats(Arc<StatsInner>);

struct StatsInner {
    started_at: Instant,

    // -- connection counters --
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    socks5_connections: AtomicU64,
    http_connections: AtomicU64,
    connection_limit_rejections: AtomicU64,

    // -- TCP byte counters --
    tcp_bytes_up: AtomicU64,
    tcp_bytes_down: AtomicU64,

    // -- UDP counters --
    udp_associate_sessions: AtomicU64,
    udp_bytes_in: AtomicU64,
    udp_bytes_out: AtomicU64,

    connect_failures: AtomicU64,
    auth_failures: AtomicU64,
    relay_failures: AtomicU64,
    recent_errors: Mutex<VecDeque<RecentError>>,
}

struct RecentError {
    unix_seconds: u64,
    message: String,
}

impl Default for StatsInner {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            total_connections: AtomicU64::default(),
            active_connections: AtomicU64::default(),
            socks5_connections: AtomicU64::default(),
            http_connections: AtomicU64::default(),
            connection_limit_rejections: AtomicU64::default(),
            tcp_bytes_up: AtomicU64::default(),
            tcp_bytes_down: AtomicU64::default(),
            udp_associate_sessions: AtomicU64::default(),
            udp_bytes_in: AtomicU64::default(),
            udp_bytes_out: AtomicU64::default(),
            connect_failures: AtomicU64::default(),
            auth_failures: AtomicU64::default(),
            relay_failures: AtomicU64::default(),
            recent_errors: Mutex::new(VecDeque::with_capacity(MAX_RECENT_ERRORS)),
        }
    }
}

/// Point-in-time snapshot of all counters (not atomically consistent).
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub socks5_connections: u64,
    pub http_connections: u64,
    pub connection_limit_rejections: u64,
    pub tcp_bytes_up: u64,
    pub tcp_bytes_down: u64,
    pub udp_associate_sessions: u64,
    pub udp_bytes_in: u64,
    pub udp_bytes_out: u64,
    pub connect_failures: u64,
    pub auth_failures: u64,
    pub relay_failures: u64,
}

impl Stats {
    /// Render the current statistics snapshot as an HTML page.
    pub fn render_html(&self) -> String {
        let snapshot = self.snapshot();
        let total_traffic = snapshot
            .tcp_bytes_up
            .saturating_add(snapshot.tcp_bytes_down)
            .saturating_add(snapshot.udp_bytes_in)
            .saturating_add(snapshot.udp_bytes_out);
        render_template(
            include_str!("../assets/stats.html"),
            &[
                ("{uptime}", format_duration(snapshot.uptime_seconds)),
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
                (
                    "{connection_limit_rejections}",
                    snapshot.connection_limit_rejections.to_string(),
                ),
                ("{total_traffic}", format_bytes(total_traffic)),
                ("{tcp_up}", format_bytes(snapshot.tcp_bytes_up)),
                ("{tcp_down}", format_bytes(snapshot.tcp_bytes_down)),
                (
                    "{udp_associate_sessions}",
                    snapshot.udp_associate_sessions.to_string(),
                ),
                ("{udp_bytes_out}", format_bytes(snapshot.udp_bytes_out)),
                ("{udp_bytes_in}", format_bytes(snapshot.udp_bytes_in)),
                ("{connect_failures}", snapshot.connect_failures.to_string()),
                ("{auth_failures}", snapshot.auth_failures.to_string()),
                ("{relay_failures}", snapshot.relay_failures.to_string()),
                ("{recent_errors}", self.render_recent_errors()),
            ],
        )
    }

    /// Return a point-in-time snapshot of all statistics.
    pub fn snapshot(&self) -> StatsSnapshot {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        StatsSnapshot {
            uptime_seconds: self.0.started_at.elapsed().as_secs(),
            total_connections: r(&self.0.total_connections),
            active_connections: r(&self.0.active_connections),
            socks5_connections: r(&self.0.socks5_connections),
            http_connections: r(&self.0.http_connections),
            connection_limit_rejections: r(&self.0.connection_limit_rejections),
            tcp_bytes_up: r(&self.0.tcp_bytes_up),
            tcp_bytes_down: r(&self.0.tcp_bytes_down),
            udp_associate_sessions: r(&self.0.udp_associate_sessions),
            udp_bytes_in: r(&self.0.udp_bytes_in),
            udp_bytes_out: r(&self.0.udp_bytes_out),
            connect_failures: r(&self.0.connect_failures),
            auth_failures: r(&self.0.auth_failures),
            relay_failures: r(&self.0.relay_failures),
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

    /// Increment the connection-limit rejection counter.
    pub fn inc_connection_limit_rejections(&self) {
        self.0
            .connection_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
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

    /// Increment the authentication failure counter.
    pub fn inc_auth_failures(&self) {
        self.0.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the relay failure counter.
    pub fn inc_relay_failures(&self) {
        self.0.relay_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one recent error message for display on the stats page.
    pub fn record_error(&self, message: impl Into<String>) {
        let unix_seconds = current_unix_seconds();
        let message = truncate_error_message(&normalize_error_message(&message.into()));
        let error = RecentError {
            unix_seconds,
            message,
        };

        let mut errors = self
            .0
            .recent_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if errors.len() == MAX_RECENT_ERRORS {
            errors.pop_front();
        }
        errors.push_back(error);
    }

    /// Render recent errors as table rows.
    fn render_recent_errors(&self) -> String {
        let errors = self
            .0
            .recent_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if errors.is_empty() {
            return "<tr><td class=\"empty-value\">No recent errors</td></tr>".to_string();
        }

        errors
            .iter()
            .rev()
            .map(|error| {
                format!(
                    "<tr><td class=\"error-message\"><time class=\"error-time\" data-unix-seconds=\"{}\"></time>{}</td></tr>",
                    error.unix_seconds,
                    escape_html(&error.message)
                )
            })
            .collect()
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

/// Format a duration in seconds for compact display.
fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;

    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m {seconds:02}s")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

/// Return the current Unix timestamp in seconds.
fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Collapse control whitespace so recent error rows stay one line per event.
fn normalize_error_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Limit one recent error entry to a bounded display size.
fn truncate_error_message(message: &str) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_CHARS {
        return message.to_string();
    }

    if let Some((end, _)) = message.char_indices().nth(MAX_ERROR_MESSAGE_CHARS) {
        let mut truncated = String::with_capacity(end + 3);
        truncated.push_str(&message[..end]);
        truncated.push_str("...");
        return truncated;
    }

    message.to_string()
}

/// Escape text before embedding it into the stats HTML.
fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_default_on_fresh_stats() {
        let stats = Stats::default();
        let snap = stats.snapshot();
        assert!(snap.uptime_seconds < 5);
        assert_eq!(snap.total_connections, 0);
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.socks5_connections, 0);
        assert_eq!(snap.http_connections, 0);
        assert_eq!(snap.connection_limit_rejections, 0);
        assert_eq!(snap.tcp_bytes_up, 0);
        assert_eq!(snap.tcp_bytes_down, 0);
        assert_eq!(snap.udp_associate_sessions, 0);
        assert_eq!(snap.udp_bytes_in, 0);
        assert_eq!(snap.udp_bytes_out, 0);
        assert_eq!(snap.connect_failures, 0);
        assert_eq!(snap.auth_failures, 0);
        assert_eq!(snap.relay_failures, 0);
    }

    #[test]
    fn connection_counters_reflected_in_snapshot() {
        let stats = Stats::default();
        stats.inc_total_connections();
        stats.inc_total_connections();
        stats.inc_active_connections();
        stats.inc_socks5_connections();
        stats.inc_http_connections();
        stats.inc_connection_limit_rejections();
        stats.dec_active_connections();

        let snap = stats.snapshot();
        assert_eq!(snap.total_connections, 2);
        assert_eq!(snap.active_connections, 0, "one inc + one dec = 0");
        assert_eq!(snap.socks5_connections, 1);
        assert_eq!(snap.http_connections, 1);
        assert_eq!(snap.connection_limit_rejections, 1);
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
        stats.add_udp_bytes_in(512);
        stats.add_udp_bytes_out(1024);

        let snap = stats.snapshot();
        assert_eq!(snap.udp_associate_sessions, 1);
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
    fn auth_failures_counted() {
        let stats = Stats::default();
        stats.inc_auth_failures();
        stats.inc_auth_failures();

        assert_eq!(stats.snapshot().auth_failures, 2);
    }

    #[test]
    fn relay_failures_counted() {
        let stats = Stats::default();
        stats.inc_relay_failures();

        assert_eq!(stats.snapshot().relay_failures, 1);
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
    fn format_duration_compacts_seconds() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(65), "1m 05s");
        assert_eq!(format_duration(3_661), "1h 01m 01s");
        assert_eq!(format_duration(90_061), "1d 01h 01m 01s");
    }

    #[test]
    fn truncate_error_message_keeps_short_messages() {
        assert_eq!(truncate_error_message("short error"), "short error");
    }

    #[test]
    fn truncate_error_message_counts_chars_not_bytes() {
        let message = "错".repeat(MAX_ERROR_MESSAGE_CHARS);
        assert_eq!(truncate_error_message(&message), message);
    }

    #[test]
    fn truncate_error_message_truncates_at_char_boundary() {
        let message = format!("{}tail", "错".repeat(MAX_ERROR_MESSAGE_CHARS));
        assert_eq!(
            truncate_error_message(&message),
            format!("{}...", "错".repeat(MAX_ERROR_MESSAGE_CHARS))
        );
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
        stats.inc_auth_failures();
        stats.inc_relay_failures();

        let html = stats.render_html();
        // None of the template placeholders should leak into the output.
        assert!(!html.contains("{uptime}"));
        assert!(!html.contains("{total_connections}"));
        assert!(!html.contains("{active_connections}"));
        assert!(!html.contains("{socks5_connections}"));
        assert!(!html.contains("{http_connections}"));
        assert!(!html.contains("{connection_limit_rejections}"));
        assert!(!html.contains("{total_traffic}"));
        assert!(!html.contains("{tcp_up}"));
        assert!(!html.contains("{tcp_down}"));
        assert!(!html.contains("{udp_associate_sessions}"));
        assert!(!html.contains("{udp_bytes_in}"));
        assert!(!html.contains("{udp_bytes_out}"));
        assert!(!html.contains("{connect_failures}"));
        assert!(!html.contains("{auth_failures}"));
        assert!(!html.contains("{relay_failures}"));
        assert!(!html.contains("{recent_errors}"));
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

    #[test]
    fn recent_errors_render_newest_first_and_escape_html() {
        let stats = Stats::default();
        stats.record_error("first error");
        stats.record_error("relay <bad> & \"quoted\"");

        let html = stats.render_html();
        let newest = html.find("relay &lt;bad&gt; &amp; &quot;quoted&quot;");
        let oldest = html.find("first error");

        assert!(newest.is_some(), "escaped newest error should render");
        assert!(oldest.is_some(), "oldest error should render");
        assert!(newest < oldest, "newest errors render first");
    }

    #[test]
    fn recent_errors_are_bounded() {
        let stats = Stats::default();
        for i in 0..(MAX_RECENT_ERRORS + 1) {
            stats.record_error(format!("error {i}"));
        }

        let html = stats.render_html();
        assert!(!html.contains("error 0"));
        assert!(html.contains("error 100"));
    }
}
