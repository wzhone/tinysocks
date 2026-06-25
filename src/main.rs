mod cli;
mod service;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

#[tokio::main(flavor = "multi_thread")]
/// Parse CLI arguments and dispatch the selected command.
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime_options = cli.runtime_options();

    match cli.command {
        Some(Command::Install) => service::install(&runtime_options),
        Some(Command::Uninstall) => service::uninstall(),
        Some(Command::Winsvc) => service::run_as_service(runtime_options),
        None => service::run_foreground(runtime_options).await,
    }
}
