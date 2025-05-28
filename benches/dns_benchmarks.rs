use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, str::FromStr};
use swiftdns::{
    config::{ResolverConfig, SwiftConfig, TorConfig},
    dns::{message_types::DnsJsonQuestion, record_types::SupportedRecordType},
    domain::Domain,
    http::Client,
};

fn mock_dns_resolver_setup() -> (Client, SwiftConfig) {
    let config = SwiftConfig {
        resolver: ResolverConfig {
            url: "https://dns.swiftdns.mock/dns-query?name={name}&type={type}".to_string(),
            bootstrap_ips: None,
        },
        tor: TorConfig {
            enabled: false,
            address: None,
        },
        ..Default::default()
    };

    std::env::set_var("SWIFTDNS_TEST_MODE", "1");
    let client =
        tokio_test::block_on(Client::connect(&config)).expect("Failed to create mock client");

    (client, config)
}

fn dns_resolve_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (mut client, config) = mock_dns_resolver_setup();

    c.bench_function("resolve_a_record", |b| {
        b.iter(|| {
            rt.block_on(async {
                let domain = black_box(Domain::from_str("example.com").unwrap());

                swiftdns::dns::resolver::resolve(
                    &mut client,
                    &config,
                    &DnsJsonQuestion {
                        name: domain.name().to_string(),
                        qtype: SupportedRecordType::A.value(),
                        dnssec: None,
                    },
                )
                .await
                .expect("DNS resolution failed")
            })
        });
    });
}

criterion_group!(dns_benches, dns_resolve_benchmark);
criterion_main!(dns_benches);
