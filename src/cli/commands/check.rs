use anyhow::Result;
use clap::Args;
use colored::Colorize;
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use std::io::stdout;
use std::{str::FromStr as _, time::Instant};

use crate::{
    config::SwiftConfig,
    dns::{message_types::DnsJsonQuestion, record_types::SupportedRecordType, resolver},
    domain::Domain,
    http::Client,
};

#[derive(Args)]
pub struct CheckArgs {
    #[arg(
        long = "tor",
        help = "Include Tor connectivity test",
        action = clap::ArgAction::SetTrue
    )]
    tor: bool,
}

pub struct DomainTestResult {
    domain: String,
    status: TestStatus,
    response_time: Option<u128>,
    answer_count: usize,
    min_ttl: Option<u32>,
    first_answer: Option<String>,
}

impl DomainTestResult {
    pub fn format(&self) -> String {
        let time = self
            .response_time
            .map(|t| format!("{:>4}ms", t))
            .unwrap_or_else(|| "    -".to_string());
        let ttl = self
            .min_ttl
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());
        let first = self.first_answer.as_deref().unwrap_or("-");
        format!(
            "{:<20} {:>6}   {:>2} ans    ttl={:<3}   {}",
            self.domain, time, self.answer_count, ttl, first
        )
    }
}

enum TestStatus {
    Success,
    Error,
}

impl TestStatus {
    fn color(&self) -> Color {
        match self {
            TestStatus::Success => Color::Rgb {
                r: 100,
                g: 170,
                b: 100,
            },
            TestStatus::Error => Color::Rgb {
                r: 170,
                g: 100,
                b: 100,
            },
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            TestStatus::Success => "✓",
            TestStatus::Error => "✗",
        }
    }
}

pub async fn execute(args: CheckArgs, config: &SwiftConfig) -> Result<()> {
    println!(); // Empty line at the beginning

    let test_domains = [
        "duckduckgo.com",
        "bitwarden.com",
        "torproject.org",
        "signal.org",
        "tutanota.com",
    ];

    let mut client = Client::connect(config).await?;
    let resolver_url = url::Url::parse(&config.resolver.url)?;

    let mut header_url = resolver_url.clone();
    header_url.set_query(None);
    header_url.set_fragment(None);

    print_resolver_header(header_url.as_ref())?;
    test_resolver(&mut client, &test_domains, config).await?;

    if args.tor {
        println!();
        test_tor(config).await?;
    }

    println!();

    Ok(())
}

fn print_resolver_header(resolver_url: &str) -> Result<()> {
    let mut stdout = stdout();

    execute!(
        stdout,
        SetForegroundColor(Color::Grey),
        Print("  "),
        Print(format!("DNS Resolver Test - {}\n\n", resolver_url).underline()),
        ResetColor
    )?;

    execute!(
        stdout,
        SetForegroundColor(Color::Grey),
        Print(format!(
            "  {:<24} {:<7} {:<8} {:<9} {:<15}\n",
            "Domain", "Time", "Answers", "TTL", "First Result"
        )),
        Print("  "),
        Print("─".repeat(66)),
        Print("\n"),
        ResetColor
    )?;

    Ok(())
}

async fn test_resolver(client: &mut Client, domains: &[&str], config: &SwiftConfig) -> Result<()> {
    let mut stdout = stdout();
    let mut total_time = 0u128;
    let mut successful = 0;
    let total = domains.len();

    for d in domains {
        let domain = Domain::from_str(d)?;
        let start = Instant::now();
        let raw = resolver::resolve(
            client,
            config,
            &DnsJsonQuestion {
                name: domain.to_string(),
                qtype: SupportedRecordType::A.value(),
                dnssec: None,
            },
        )
        .await;

        let result = match raw {
            Ok(res) if res.status == 0 => {
                let elapsed = start.elapsed().as_millis();
                total_time += elapsed;
                successful += 1;

                let answer_count = res.answer.len();
                let min_ttl = res.answer.iter().map(|r| r.ttl).min();
                let first = res.answer.first().map(|r| r.data.clone());

                DomainTestResult {
                    domain: domain.to_string(),
                    response_time: Some(elapsed),
                    answer_count,
                    min_ttl,
                    first_answer: first,
                    status: TestStatus::Success,
                }
            }
            Ok(res) => {
                let elapsed = start.elapsed().as_millis();
                DomainTestResult {
                    domain: domain.to_string(),
                    response_time: Some(elapsed),
                    answer_count: res.answer.len(),
                    min_ttl: res.answer.iter().map(|r| r.ttl).min(),
                    first_answer: res.answer.first().map(|r| r.data.clone()),
                    status: TestStatus::Error,
                }
            }
            Err(_) => DomainTestResult {
                domain: domain.to_string(),
                response_time: None,
                answer_count: 0,
                min_ttl: None,
                first_answer: None,
                status: TestStatus::Error,
            },
        };

        execute!(
            stdout,
            Print("  "),
            SetForegroundColor(result.status.color()),
            Print(result.status.icon()),
            Print(" "),
            SetForegroundColor(Color::Grey),
            Print(result.format()),
            ResetColor,
            Print("\n"),
        )?;
    }

    let avg_time = if successful > 0 {
        total_time / successful as u128
    } else {
        0
    };

    execute!(
        stdout,
        Print("\n"),
        SetForegroundColor(Color::Grey),
        Print(format!(
            "  ▶ {}/{} successful queries ({}%), average response time: {}ms\n",
            successful,
            total,
            (successful as f64 / total as f64 * 100.0) as u32,
            avg_time
        )),
        ResetColor
    )?;

    Ok(())
}

async fn test_tor(config: &SwiftConfig) -> Result<()> {
    let mut config = config.clone();
    config.tor.enabled = true;

    let mut client = Client::connect(&config).await?;
    let mut stdout = stdout();

    execute!(
        stdout,
        SetForegroundColor(Color::Grey),
        Print(" Tor Connectivity Test\n\n".bold()),
        ResetColor
    )?;

    execute!(
        stdout,
        SetForegroundColor(Color::Grey),
        Print(format!(
            "  {:<24} {:<7} {:<8} {:<9} {:<15}\n",
            "Domain", "Time", "Answers", "TTL", "First Result"
        )),
        Print("  "),
        Print("─".repeat(66)),
        Print("\n"),
        ResetColor
    )?;

    let start = Instant::now();
    let test_domain = Domain::from_str("torproject.org")?;

    match resolver::resolve(
        &mut client,
        &config,
        &DnsJsonQuestion {
            name: test_domain.to_string(),
            qtype: SupportedRecordType::A.value(),
            dnssec: None,
        },
    )
    .await
    {
        Ok(res) if res.status == 0 => {
            let elapsed = start.elapsed().as_millis();
            let result = DomainTestResult {
                domain: test_domain.to_string(),
                status: TestStatus::Success,
                response_time: Some(elapsed),
                answer_count: res.answer.len(),
                min_ttl: res.answer.iter().map(|r| r.ttl).min(),
                first_answer: res.answer.first().map(|r| r.data.clone()),
            };

            execute!(
                stdout,
                Print("  "),
                SetForegroundColor(result.status.color()),
                Print(result.status.icon()),
                Print(" "),
                SetForegroundColor(Color::Grey),
                Print(result.format()),
                ResetColor,
                Print("\n"),
            )?;

            execute!(
                stdout,
                Print("\n"),
                SetForegroundColor(Color::Grey),
                Print("  ▶ Tor connectivity test successful\n"),
                ResetColor
            )?;
        }
        Ok(res) => {
            let elapsed = start.elapsed().as_millis();
            let result = DomainTestResult {
                domain: test_domain.to_string(),
                status: TestStatus::Error,
                response_time: Some(elapsed),
                answer_count: res.answer.len(),
                min_ttl: res.answer.iter().map(|r| r.ttl).min(),
                first_answer: res.answer.first().map(|r| r.data.clone()),
            };

            execute!(
                stdout,
                Print("  "),
                SetForegroundColor(result.status.color()),
                Print(result.status.icon()),
                Print(" "),
                SetForegroundColor(Color::Grey),
                Print(result.format()),
                ResetColor,
                Print("\n"),
            )?;

            execute!(
                stdout,
                Print("\n"),
                SetForegroundColor(Color::Red),
                Print("  ●"),
                SetForegroundColor(Color::Grey),
                Print(" Tor connectivity test failed"),
                ResetColor
            )?;
        }
        Err(e) => {
            let result = DomainTestResult {
                domain: test_domain.to_string(),
                status: TestStatus::Error,
                response_time: None,
                answer_count: 0,
                min_ttl: None,
                first_answer: None,
            };

            execute!(
                stdout,
                Print("  "),
                SetForegroundColor(result.status.color()),
                Print(result.status.icon()),
                Print(" "),
                SetForegroundColor(Color::Grey),
                Print(result.format()),
                ResetColor,
                Print("\n"),
            )?;

            let error_str = e.to_string();
            let message = categorize_tor_error(&error_str);

            execute!(
                stdout,
                Print("\n"),
                SetForegroundColor(Color::Red),
                Print("  ●"),
                SetForegroundColor(Color::Grey),
                Print(format!(" {}", message)),
                ResetColor
            )?;
        }
    }

    Ok(())
}

fn categorize_tor_error(error: &str) -> &'static str {
    if error.contains("Proxy server unreachable") || error.contains("connection refused") {
        "The Tor service does not appear to be running. Start the Tor service with 'sudo systemctl start tor'."
    } else if error.contains("connection timed out") || error.contains("timeout") {
        "The connection to the Tor network timed out. This could indicate network issues or an overloaded Tor network."
    } else if error.contains("socks connect error") {
        "There was an error connecting to the Tor SOCKS proxy. Verify your Tor configuration is correct."
    } else if error.contains("unexpected status") || error.contains("protocol error") {
        "There was a protocol error when communicating with the Tor proxy. This could indicate a configuration issue."
    } else if error.contains("DNS") || error.contains("name resolution") {
        "The Tor proxy was unable to resolve the DNS name. This could indicate Tor network issues."
    } else {
        "An unknown error occurred when attempting to connect to the Tor network."
    }
}
