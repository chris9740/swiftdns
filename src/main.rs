use dns::resolver::RecordType;
use domain::Domain;

use serde::Deserialize;

#[macro_use]
mod macros;

mod cli;
mod cache;
mod config;
mod dns;
mod domain;
mod filter;
mod http;
mod listener;

#[tokio::main]
async fn main() {
    cli::parse_args().await;
}
