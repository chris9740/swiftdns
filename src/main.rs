use anyhow::Result;
use std::{io::ErrorKind, process};
use swiftdns::cli;

#[tokio::main]
async fn main() -> Result<()> {
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
