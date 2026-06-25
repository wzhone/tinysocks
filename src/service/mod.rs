use anyhow::Result;
#[cfg(not(windows))]
use anyhow::bail;
use tinysocks::{
    config::{Config, RuntimeOptions},
    server::ProxyServer,
};

pub(crate) const DEFAULT_SERVICE_NAME: &str = "tinysocks";
pub(crate) const SERVICE_DESCRIPTION: &str = "SOCKS5/HTTP tinysocks service";

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{install, uninstall};
#[cfg(windows)]
pub(crate) use windows::{install, run_as_service, uninstall};

#[cfg(all(not(target_os = "linux"), not(windows)))]
/// Report that service installation is unsupported on this platform.
pub(crate) fn install(_options: &RuntimeOptions) -> Result<()> {
    bail!("service installation is only supported on Linux systemd and Windows.");
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
/// Report that service removal is unsupported on this platform.
pub(crate) fn uninstall() -> Result<()> {
    bail!("service removal is only supported on Linux systemd and Windows.");
}

#[cfg(not(windows))]
/// Report that Windows service mode is unavailable on this platform.
pub(crate) fn run_as_service(_options: RuntimeOptions) -> Result<()> {
    bail!("Service mode is only supported on Windows.");
}

/// Run the proxy in the foreground.
pub(crate) async fn run_foreground(runtime_options: RuntimeOptions) -> Result<()> {
    let cfg = Config::from_runtime_options(runtime_options)?;
    let server = ProxyServer::new(cfg)?;
    server.run(None).await
}

#[cfg(any(windows, test))]
/// Build runtime CLI arguments from service options.
pub(crate) fn runtime_args(options: &RuntimeOptions) -> Result<Vec<String>> {
    // Services store the full runtime CLI so install-time behavior matches the
    // process that starts after boot.
    Config::from_runtime_options(options.clone())?;

    let mut args = vec![
        options.bind.clone(),
        "--max-connections".to_string(),
        options.max_connections.to_string(),
    ];
    if let (Some(username), Some(password)) = (&options.username, &options.password) {
        args.push("--username".to_string());
        args.push(username.clone());
        args.push("--password".to_string());
        args.push(password.clone());
    }
    if !options.bypass_ips.is_empty() {
        args.push("--bypass-ip".to_string());
        args.push(options.bypass_ips.join(","));
    }
    Ok(args)
}

#[cfg(test)]
/// Build the Linux foreground service command arguments.
pub(crate) fn foreground_service_args(options: &RuntimeOptions) -> Result<Vec<String>> {
    let mut args = vec!["run".to_string()];
    args.extend(runtime_args(options)?);
    Ok(args)
}

#[cfg(any(windows, test))]
/// Build the Windows service command arguments.
pub(crate) fn windows_service_args(options: &RuntimeOptions) -> Result<Vec<String>> {
    let mut args = vec!["--run-service".to_string()];
    args.extend(runtime_args(options)?);
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_options() -> RuntimeOptions {
        RuntimeOptions {
            bind: "0.0.0.0:1080".to_string(),
            max_connections: 2048,
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            bypass_ips: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
        }
    }

    #[test]
    fn foreground_service_args_include_run_and_runtime_options() {
        let args = foreground_service_args(&sample_options()).expect("should build args");

        assert_eq!(
            args,
            vec![
                "run",
                "0.0.0.0:1080",
                "--max-connections",
                "2048",
                "--username",
                "admin",
                "--password",
                "secret",
                "--bypass-ip",
                "127.0.0.0/8,::1/128",
            ]
        );
    }

    #[test]
    fn windows_service_args_include_run_service_and_runtime_options() {
        let args = windows_service_args(&sample_options()).expect("should build args");

        assert_eq!(
            args,
            vec![
                "--run-service",
                "0.0.0.0:1080",
                "--max-connections",
                "2048",
                "--username",
                "admin",
                "--password",
                "secret",
                "--bypass-ip",
                "127.0.0.0/8,::1/128",
            ]
        );
    }
}
