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

    if cli.run_service {
        return service::run_as_service(runtime_options);
    }

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => service::run_foreground(runtime_options).await,
        Command::Install => service::install(&runtime_options),
        Command::Uninstall => service::uninstall(),
    }
}
