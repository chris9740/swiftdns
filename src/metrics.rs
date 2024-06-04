use std::fmt::Display;

use anyhow::Result;
use clap::ValueEnum;
use csv::Writer;
use indexmap::IndexMap;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;

pub struct DnsQueryLog {
    pub domain: String,
    pub cached: bool,
    pub blacklisted: bool,
}

pub fn log_query(conn: &Connection, query: DnsQueryLog) -> Result<()> {
    let timestamp = chrono::Local::now().timestamp();
    
    conn.execute(
        "INSERT INTO dns_queries (domain, timestamp, cached, blacklisted) VALUES (?1, ?2, ?3, ?4)",
        params![query.domain, timestamp, query.cached, query.blacklisted],
    )?;

    Ok(())
}

#[derive(Debug, Serialize)]
pub struct DomainStats {
    total_queries: usize,
    cache_hits: usize,
    blacklist_hits: usize,
}

pub fn compile_analytics(conn: &Connection) -> Result<DomainAnalytics> {
    let mut stmt = conn.prepare(
        "SELECT domain, COUNT(*) as total_queries, SUM(cached) as cache_hits, SUM(blacklisted) as blacklist_hits
        FROM dns_queries
        GROUP BY domain
        ORDER BY MAX(timestamp) DESC"
    )?;

    let domain_iter = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            DomainStats {
                total_queries: row.get(1)?,
                cache_hits: row.get(2)?,
                blacklist_hits: row.get(3)?,
            },
        ))
    })?;

    let mut domains: IndexMap<String, DomainStats> = IndexMap::new();
    for domain in domain_iter {
        let (domain_name, stats) = domain?;
        domains.insert(domain_name, stats);
    }

    Ok(DomainAnalytics { domains })
}

#[derive(Clone, Deserialize, ValueEnum)]
pub enum Format {
    Json,
    Csv,
}

impl Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::Csv => "csv",
            Self::Json => "json",
        })
    }
}

#[derive(Debug)]
pub struct DomainAnalytics {
    domains: IndexMap<String, DomainStats>,
}

impl DomainAnalytics {
    pub fn reverse(&mut self) {
        self.domains.reverse();
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        to_string_pretty(&self.domains)
    }

    pub fn to_csv(&self) -> Result<String> {
        let mut wtr = Writer::from_writer(vec![]);
        wtr.write_record(["Domain", "Total Queries", "Cache Hits", "Blacklist Hits"])?;

        for (domain, stats) in &self.domains {
            wtr.write_record([
                domain,
                &stats.total_queries.to_string(),
                &stats.cache_hits.to_string(),
                &stats.blacklist_hits.to_string(),
            ])?;
        }

        wtr.flush()?;
        Ok(String::from_utf8(wtr.into_inner()?)?.trim().to_string())
    }
}
