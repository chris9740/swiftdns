use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, str::FromStr};
use swiftdns::Domain;

fn domain_parsing_benchmark(c: &mut Criterion) {
    c.bench_function("parse_simple_domain", |b| {
        b.iter(|| {
            Domain::from_str(black_box("example.com")).unwrap();
        })
    });

    c.bench_function("parse_unicode_domain", |b| {
        b.iter(|| {
            Domain::from_str(black_box("münich.de")).unwrap();
        })
    });

    c.bench_function("parse_punycode_domain", |b| {
        b.iter(|| {
            Domain::from_str(black_box("xn--hlsa-loa.se")).unwrap();
        })
    });
}

fn domain_conversion_benchmark(c: &mut Criterion) {
    let unicode_domain = Domain::from_str("münich.de").unwrap();
    let punycode_domain = Domain::from_str("xn--hlsa-loa.se").unwrap();

    c.bench_function("domain_to_unicode", |b| {
        b.iter(|| {
            black_box(punycode_domain.to_unicode());
        })
    });

    c.bench_function("domain_name", |b| {
        b.iter(|| {
            black_box(unicode_domain.name());
        })
    });
}

criterion_group!(
    domain_benches,
    domain_parsing_benchmark,
    domain_conversion_benchmark
);
criterion_main!(domain_benches);
