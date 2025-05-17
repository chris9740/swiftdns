use anyhow::Result;
use clap::Args;
use std::net::SocketAddr;

use crate::{
    config::{Scope, SwiftConfig},
    listener,
};

#[derive(Args)]
pub struct StartArgs {
    #[arg(
        help = "Specify the address for the DNS client to listen on",
        long = "address",
        short = 'a',
        value_parser = clap::value_parser!(SocketAddr)
    )]
    address: Option<SocketAddr>,

    #[arg(
        help = "Specify the scope of the DNS server",
        long = "scope",
        short = 's',
        value_parser = clap::value_parser!(Scope)
    )]
    scope: Option<Scope>,
}

pub async fn execute(args: StartArgs, config: &SwiftConfig) -> Result<()> {
    let mut config = config.clone();
    let addr = args.address.unwrap_or(config.address);

    if let Some(scope) = args.scope {
        config.scope = Some(scope);
    }

    listener::start(&addr, &config).await
}
