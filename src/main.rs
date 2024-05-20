use anyhow::Result;
use swiftdns::cli;

#[tokio::main]
async fn main() -> Result<()> {
    cli::start().await
}
