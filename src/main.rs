use swiftdns::cli;

#[tokio::main]
async fn main() {
    cli::start().await;
}
