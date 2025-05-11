pub mod args;
pub mod commands;

use anyhow::Result;
use clap::{crate_description, crate_version, Parser, Subcommand};

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
    #[command(about = "Check DNS resolver health and performance")]
    Check(commands::check::CheckArgs),
    #[command(about = "Start the DNS listener")]
    Start(commands::start::StartArgs),
    #[command(about = "Resolve a domain name")]
    Resolve(commands::resolve::ResolveArgs),
    #[command(about = "List all filters", name = "filters")]
    ListFilters,
}

pub async fn start() -> Result<()> {
    let args = Cli::parse();
    let mut config = crate::config::get_config()?;

    crate::filter::migrate_filters()?;

    match args.command {
        Commands::Check(args) => commands::check::execute(args, &mut config).await,
        Commands::Start(args) => commands::start::execute(args, &mut config).await,
        Commands::Resolve(args) => commands::resolve::execute(args, &mut config).await,
        Commands::ListFilters => commands::filters::execute().await,
    }
}
