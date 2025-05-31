use anyhow::Result;
use std::{io::ErrorKind, process};
use swiftdns::cli;
#[cfg(feature = "tracing")]
use tracing::level_filters::LevelFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
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
