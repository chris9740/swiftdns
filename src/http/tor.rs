pub fn proxy() -> reqwest::Proxy {
    reqwest::Proxy::all("socks5h://127.0.0.1:9050")
        .expect("Could not find tor proxy at 127.0.0.1:9050")
}

pub async fn validate_client_proxy(client: &reqwest::Client) {
    let res = client
        .get("https://check.torproject.org")
        .send()
        .await
        .expect("Could not connect to https://check.torproject.org");

    let text = res
        .text()
        .await
        .expect("Should be able to get text from response body");

    let is_tor = text.contains("Congratulations. This browser is configured to use Tor.");

    assert!(is_tor, "did not successfully connect to tor");
}
