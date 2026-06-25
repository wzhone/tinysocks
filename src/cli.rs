use clap::{ArgAction, Parser, Subcommand};
use tinysocks::config::{DEFAULT_BIND, DEFAULT_MAX_CONNECTIONS, RuntimeOptions};

const BUILD_VERSION: &str = match option_env!("TINYSOCKS_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "tinysocks",
    version = BUILD_VERSION,
    about = "SOCKS5 and HTTP proxy server"
)]
pub struct Cli {
    #[arg(
        global = true,
        value_name = "BIND ADDR",
        default_value = DEFAULT_BIND,
        env = "TINYSOCKS_BIND"
    )]
    bind: String,

    #[arg(
        short,
        long,
        global = true,
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_CONNECTIONS,
        env = "TINYSOCKS_MAX_CONNECTIONS"
    )]
    max_connections: usize,

    #[arg(
        short,
        long,
        global = true,
        value_name = "NAME",
        env = "TINYSOCKS_USERNAME"
    )]
    username: Option<String>,

    #[arg(
        short,
        long,
        global = true,
        value_name = "PASSWORD",
        env = "TINYSOCKS_PASSWORD"
    )]
    password: Option<String>,

    #[arg(
        long = "bypass-ip",
        global = true,
        value_name = "IP_OR_CIDR",
        action = ArgAction::Set,
        value_delimiter = ',',
        env = "TINYSOCKS_BYPASS_IP"
    )]
    bypass_ips: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Convert parsed CLI arguments into runtime options.
    pub fn runtime_options(&self) -> RuntimeOptions {
        RuntimeOptions {
            bind: self.bind.clone(),
            max_connections: self.max_connections,
            username: self.username.clone(),
            password: self.password.clone(),
            bypass_ips: self.bypass_ips.clone(),
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    Install,
    Uninstall,
    #[command(name = "winsvc", hide = true)]
    Winsvc,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_ip_accepts_comma_separated_values() {
        let cli = Cli::try_parse_from([
            "tinysocks",
            "--username",
            "admin",
            "--password",
            "secret",
            "--bypass-ip",
            "127.0.0.1,192.168.1.1",
        ])
        .expect("should parse CLI");

        let options = cli.runtime_options();
        assert_eq!(options.bypass_ips, vec!["127.0.0.1", "192.168.1.1"]);
    }

    #[test]
    fn bypass_ip_rejects_repeated_values() {
        assert!(
            Cli::try_parse_from([
                "tinysocks",
                "--username",
                "admin",
                "--password",
                "secret",
                "--bypass-ip",
                "127.0.0.1",
                "--bypass-ip",
                "192.168.1.1",
            ])
            .is_err()
        );
    }

    #[test]
    fn default_run_accepts_bind_without_subcommand() {
        let cli = Cli::try_parse_from([
            "tinysocks",
            "127.0.0.1:2080",
            "--username",
            "admin",
            "--password",
            "secret",
        ])
        .expect("should parse CLI");

        let options = cli.runtime_options();
        assert_eq!(options.bind, "127.0.0.1:2080");
        assert!(cli.command.is_none());
    }

    #[test]
    fn install_accepts_command_after_global_options() {
        let cli = Cli::try_parse_from([
            "tinysocks",
            "127.0.0.1:2081",
            "--username",
            "admin",
            "--password",
            "secret",
            "install",
        ])
        .expect("should parse CLI");

        let options = cli.runtime_options();
        assert_eq!(options.bind, "127.0.0.1:2081");
        assert!(matches!(cli.command, Some(Command::Install)));
    }

    #[test]
    fn winsvc_accepts_bind_after_hidden_subcommand() {
        let cli = Cli::try_parse_from([
            "tinysocks",
            "winsvc",
            "127.0.0.1:2082",
            "--username",
            "admin",
            "--password",
            "secret",
        ])
        .expect("should parse CLI");

        let options = cli.runtime_options();
        assert_eq!(options.bind, "127.0.0.1:2082");
        assert!(matches!(cli.command, Some(Command::Winsvc)));
    }

    #[test]
    fn service_name_is_not_a_cli_argument() {
        assert!(
            Cli::try_parse_from(["tinysocks", "--service-name", "other", "uninstall"]).is_err()
        );
    }
}
