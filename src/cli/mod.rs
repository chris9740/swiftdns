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
    Demo(commands::demo::DemoArgs),
    #[command(about = "Start the DNS listener")]
    Start(commands::start::StartArgs),
    #[command(about = "Resolve a domain name")]
    Resolve(commands::resolve::ResolveArgs),
    #[command(about = "Display configuration")]
    Status,
}

pub async fn start() -> Result<()> {
    let args = Cli::parse();
    let config = get_config()?;

    match args.command {
        Commands::Demo(args) => commands::demo::execute(args).await,
        Commands::Start(args) => commands::start::execute(args, &config).await,
        Commands::Resolve(args) => commands::resolve::execute(args, &config).await,
        Commands::Status => commands::status::execute(&config).await,
    }
}
