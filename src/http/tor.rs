pub fn proxy(address: &str) -> reqwest::Proxy {
    reqwest::Proxy::all(format!("socks5h://{address}"))
        .unwrap_or_else(|_| {
            error!("Invalid socket address was provided ({address})");
        })
}

pub async fn validate_client_proxy(client: &reqwest::Client) {
    let connectivity_check_url = "https://check.torproject.org";

    let res = client
        .get(connectivity_check_url)
        .send()
        .await
        .unwrap_or_else(|_| {
            error!("Could not connect to {connectivity_check_url}");
        });

    let text = res
        .text()
        .await
        .unwrap_or_else(|_| {
            error!("Could not read response from {connectivity_check_url}")
        });

    let is_connected = text.contains("Congratulations. This browser is configured to use Tor.");

    if !is_connected {
        error!("Unsuccessful connection to Tor. Integrity and correctness assertion failed, exiting.");
    }
}
