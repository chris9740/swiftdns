use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, str::FromStr, time::Duration};
use swiftdns::{
    config::{ResolverConfig, SwiftConfig, TorConfig},
    dns::{
        message_types::DnsJsonQuestion,
        resolver::{DnsRecordType, QueryType},
    },
    domain::Domain,
    http::Client,
};

fn setup() -> (tokio::runtime::Runtime, SwiftConfig) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let config = SwiftConfig {
        resolver: ResolverConfig {
            url: "https://dns.cloudflare.com/dns-query?name={name}&type={type}".to_string(),
            bootstrap_ips: None,
        },
        tor: TorConfig {
            enabled: false,
            address: None,
        },
        ..Default::default()
    };

    (rt, config)
}

fn e2e_dns_benchmark(c: &mut Criterion) {
    if std::env::var("CI").is_ok() {
        return;
    }

    let (rt, config) = setup();
    let common_domains = ["example.com", "gurka.se"];
    let mut group = c.benchmark_group("e2e_dns_resolution");

    let mut client = rt.block_on(Client::connect(&config)).unwrap();

    for domain in &common_domains {
        rt.block_on(async {
            let domain = Domain::from_str(domain).unwrap();
            let _ = swiftdns::dns::resolver::resolve(
                &mut client,
                &config,
                &DnsJsonQuestion {
                    name: domain.name().to_string(),
                    qtype: QueryType::new(DnsRecordType::A).unwrap().value(),
                },
            )
            .await;
        });
    }

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    for domain in &common_domains {
        group.bench_with_input(
            format!("resolve_{}", domain.replace('.', "_")),
            domain,
            |b, domain| {
                b.iter(|| {
                    rt.block_on(async {
                        let domain = Domain::from_str(black_box(*domain)).unwrap();

                        swiftdns::dns::resolver::resolve(
                            &mut client,
                            &config,
                            &DnsJsonQuestion {
                                name: domain.name().to_string(),
                                qtype: QueryType::new(DnsRecordType::A).unwrap().value(),
                            },
                        )
                        .await
                        .expect("DNS resolution failed")
                    })
                })
            },
        );

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    group.bench_function("full_cli_resolve_netflix", |b| {
        b.iter(|| {
            use std::process::Command;

            let output = Command::new("target/release/swiftdns")
                .arg("resolve")
                .arg("netflix.com")
                .output()
                .expect("Failed to execute command");

            assert!(output.status.success());
            black_box(output)
        })
    });

    group.finish();
}

criterion_group!(
    name = dns_e2e_benches;
    config = Criterion::default().sample_size(10);
    targets = e2e_dns_benchmark
);
criterion_main!(dns_e2e_benches);
