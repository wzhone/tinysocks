use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tinysocks::config::{Config, RuntimeOptions};

use super::{DEFAULT_SERVICE_NAME, SERVICE_DESCRIPTION};

const DEFAULT_LINUX_BIN_DIR: &str = "/usr/local/bin";
const DEFAULT_LINUX_CONFIG_DIR: &str = "/etc/tinysocks";
const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// Return the installed Linux binary path for a service name.
fn installed_bin_path(service_name: &str) -> PathBuf {
    Path::new(DEFAULT_LINUX_BIN_DIR).join(service_name)
}

/// Return the systemd environment file path for a service name.
fn env_file_path(service_name: &str) -> PathBuf {
    Path::new(DEFAULT_LINUX_CONFIG_DIR).join(format!("{service_name}.env"))
}

/// Return the systemd unit path for a service name.
fn unit_path(service_name: &str) -> PathBuf {
    Path::new(SYSTEMD_UNIT_DIR).join(format!("{service_name}.service"))
}

/// Quote one shell argument for a systemd ExecStart line.
fn quote_arg(arg: &str) -> String {
    if arg.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@' | '=' | ',')
    }) {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    for c in arg.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Quote one value for a systemd EnvironmentFile.
fn quote_env_value(value: &str) -> Result<String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("service environment values cannot contain NUL or newline characters");
    }

    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

/// Build a protected environment file for secret runtime options.
fn build_env_file(options: &RuntimeOptions) -> Result<Option<String>> {
    let (Some(username), Some(password)) = (&options.username, &options.password) else {
        return Ok(None);
    };

    Ok(Some(format!(
        "TINYSOCKS_USERNAME={}\nTINYSOCKS_PASSWORD={}\n",
        quote_env_value(username)?,
        quote_env_value(password)?
    )))
}

/// Build Linux service command arguments without credentials.
fn linux_service_args(options: &RuntimeOptions) -> Result<Vec<String>> {
    Config::from_runtime_options(options.clone())?;

    let mut args = vec![
        "run".to_string(),
        options.bind.clone(),
        "--max-connections".to_string(),
        options.max_connections.to_string(),
    ];
    if !options.bypass_ips.is_empty() {
        args.push("--bypass-ip".to_string());
        args.push(options.bypass_ips.join(","));
    }
    Ok(args)
}

/// Build the systemd unit file contents.
fn build_unit(
    installed_bin: &Path,
    env_file: Option<&Path>,
    options: &RuntimeOptions,
) -> Result<String> {
    if options.username.is_some() && env_file.is_none() {
        bail!("credentialed Linux services require a private EnvironmentFile");
    }

    let mut command = vec![quote_arg(&installed_bin.display().to_string())];
    command.extend(
        linux_service_args(options)?
            .into_iter()
            .map(|arg| quote_arg(&arg)),
    );
    let exec_start = command.join(" ");
    let environment_file = env_file
        .map(|path| {
            format!(
                "EnvironmentFile={}\n",
                quote_arg(&path.display().to_string())
            )
        })
        .unwrap_or_default();

    Ok(format!(
        "[Unit]\n\
         Description={SERVICE_DESCRIPTION}\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=nobody\n\
         {environment_file}\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    ))
}

/// Install and start the Linux systemd service.
pub(crate) fn install(options: &RuntimeOptions) -> Result<()> {
    Config::from_runtime_options(options.clone())?;

    let service_name = DEFAULT_SERVICE_NAME;
    let installed_bin = installed_bin_path(service_name);
    let env_path = env_file_path(service_name);
    let unit_path = unit_path(service_name);
    let current_exe = std::env::current_exe().context("Failed to locate current executable")?;

    if let Some(parent) = installed_bin.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create install directory {}", parent.display()))?;
    }
    if installed_bin.exists()
        && current_exe.canonicalize().ok() == installed_bin.canonicalize().ok()
    {
        println!("Binary is already installed at {}", installed_bin.display());
    } else {
        fs::copy(&current_exe, &installed_bin).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                current_exe.display(),
                installed_bin.display()
            )
        })?;
    }
    fs::set_permissions(&installed_bin, fs::Permissions::from_mode(0o755)).with_context(|| {
        format!(
            "Failed to set executable permissions on {}",
            installed_bin.display()
        )
    })?;

    let env_file = build_env_file(options)?;
    let unit_env_path = env_file.as_ref().map(|_| env_path.as_path());
    if let Some(env_file) = env_file {
        if let Some(parent) = env_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create service config directory {}",
                    parent.display()
                )
            })?;
        }
        fs::write(&env_path, env_file).with_context(|| {
            format!("Failed to write service environment {}", env_path.display())
        })?;
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "Failed to set private permissions on {}",
                env_path.display()
            )
        })?;
    }

    let unit = build_unit(&installed_bin, unit_env_path, options)?;
    fs::write(&unit_path, unit)
        .with_context(|| format!("Failed to write systemd unit {}", unit_path.display()))?;

    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", service_name])?;
    run_systemctl(&["start", service_name])?;

    println!(
        "Installed service '{}' using {}",
        service_name,
        installed_bin.display()
    );
    Ok(())
}

/// Run a systemctl command and fail on non-zero status.
fn run_systemctl(args: &[&str]) -> Result<()> {
    use std::process::Command as ProcessCommand;

    let status = ProcessCommand::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run systemctl {}", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} failed with {}", args.join(" "), status);
    }
    Ok(())
}

/// Stop, disable, and remove the Linux systemd service.
pub(crate) fn uninstall() -> Result<()> {
    let service_name = DEFAULT_SERVICE_NAME;
    let installed_bin = installed_bin_path(service_name);
    let env_path = env_file_path(service_name);
    let unit_path = unit_path(service_name);

    run_systemctl_best_effort(&["stop", service_name]);
    run_systemctl_best_effort(&["disable", service_name]);

    match fs::remove_file(&unit_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to remove systemd unit {}", unit_path.display()));
        }
    }

    run_systemctl(&["daemon-reload"])?;

    match fs::remove_file(&installed_bin) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to remove {}", installed_bin.display()));
        }
    }

    match fs::remove_file(&env_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("Failed to remove {}", env_path.display()));
        }
    }

    println!("Uninstalled service '{}'", service_name);
    Ok(())
}

/// Run a systemctl command while ignoring any failure.
fn run_systemctl_best_effort(args: &[&str]) {
    let _ = std::process::Command::new("systemctl").args(args).status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinysocks::config::RuntimeOptions;

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
    fn systemd_unit_uses_installed_binary_and_runtime_options() {
        let unit = build_unit(
            Path::new("/usr/local/bin/tinysocks"),
            Some(Path::new("/etc/tinysocks/tinysocks.env")),
            &sample_options(),
        )
        .expect("should build unit");

        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("User=nobody"));
        assert!(unit.contains("EnvironmentFile=/etc/tinysocks/tinysocks.env"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/tinysocks run 0.0.0.0:1080 --max-connections 2048 --bypass-ip 127.0.0.0/8,::1/128"
        ));
        assert!(!unit.contains("secret"));
    }

    #[test]
    fn quote_arg_quotes_spaces() {
        assert_eq!(
            quote_arg("/path with space/tinysocks"),
            "\"/path with space/tinysocks\""
        );
    }

    #[test]
    fn env_file_contains_quoted_credentials() {
        let mut options = sample_options();
        options.password = Some("quote\"slash\\".to_string());

        let env = build_env_file(&options)
            .expect("should build env file")
            .expect("credentials should produce env file");

        assert_eq!(
            env,
            "TINYSOCKS_USERNAME=\"admin\"\nTINYSOCKS_PASSWORD=\"quote\\\"slash\\\\\"\n"
        );
    }

    #[test]
    fn env_file_rejects_newlines() {
        let mut options = sample_options();
        options.password = Some("bad\nsecret".to_string());

        assert!(build_env_file(&options).is_err());
    }
}
