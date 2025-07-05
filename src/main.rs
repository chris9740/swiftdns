use anyhow::Result;
use std::{io::ErrorKind, process};
use swiftdns::cli;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .without_time()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    if let Err(err) = cli::start().await {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            if io_err.kind() == ErrorKind::BrokenPipe {
                process::exit(0);
            }
        }
        return Err(err);
    }
    Ok(())
}
