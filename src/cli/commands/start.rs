use anyhow::Result;
use clap::Args;
use std::net::SocketAddr;

use crate::{config::SwiftConfig, listener};

#[derive(Args)]
pub struct StartArgs {
    #[arg(
        help = "Specify the address for the DNS client to listen on",
        long = "address",
        short = 'a',
        value_parser = clap::value_parser!(SocketAddr)
    )]
    address: Option<SocketAddr>,
}

pub async fn execute(args: StartArgs, config: &SwiftConfig) -> Result<()> {
    let addr = args.address.unwrap_or(config.address);

    listener::start(&addr, config).await
}
