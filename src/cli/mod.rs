pub mod commands;

use anyhow::Result;
use clap::{crate_description, crate_version, Parser, Subcommand};

use crate::config::get_config;

#[derive(Parser)]
#[command(
    about = crate_description!(),
    version = crate_version!(),
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Test if a domain would be blocked by the blacklist")]
    Check(commands::check::CheckArgs),
    #[command(about = "Display configuration")]
    Config,
    #[command(about = "Start the DNS listener")]
    Start(commands::start::StartArgs),
    #[command(about = "Resolve a domain name")]
    Resolve(commands::resolve::ResolveArgs),
}

pub async fn start() -> Result<()> {
    let args = Cli::parse();
    let config = get_config()?;

    match args.command {
        Commands::Check(args) => commands::check::execute(args).await,
        Commands::Config => commands::config::execute(&config).await,
        Commands::Start(args) => commands::start::execute(args, &config).await,
        Commands::Resolve(args) => commands::resolve::execute(args, &config).await,
    }
}
