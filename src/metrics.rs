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

#[derive(Debug, Serialize, PartialEq)]
pub struct DomainStats {
    total_queries: usize,
    cache_hits: usize,
    blacklist_hits: usize,
}

/// This function compiles analytics from the DNS queries log.
/// The `DomainStats` struct contains the total number of queries, cache hits, and blacklist hits.
///
/// # Arguments
/// * `conn` - A reference to a `rusqlite::Connection` object.
/// * `search` - An optional string to filter the analytics by domain name.
///
/// # Errors
/// This function returns an error if the SQL query fails.
///
/// # Returns
/// A `Result` containing a `DomainAnalytics` struct.
pub fn compile_analytics(conn: &Connection, search: Option<&str>) -> Result<DomainAnalytics> {
    let mut query = String::from(
        "SELECT domain, COUNT(*) as total_queries, SUM(cached) as cache_hits, SUM(blacklisted) as blacklist_hits \
        FROM dns_queries "
    );

    let mut parameters: Vec<&dyn rusqlite::ToSql> = Vec::new();

    let search_param: String;

    if let Some(search) = search {
        query.push_str("WHERE domain LIKE ?1 ");
        search_param = format!("%{}%", search);
        parameters.push(&search_param);
    }

    query.push_str("GROUP BY domain ORDER BY MAX(timestamp) DESC");

    let mut stmt = conn.prepare(&query)?;

    let domain_iter = stmt.query_map(&*parameters, |row| {
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
        write!(
            f,
            "{}",
            match self {
                Self::Csv => "csv",
                Self::Json => "json",
            }
        )
    }
}

#[derive(Debug)]
pub struct DomainAnalytics {
    domains: IndexMap<String, DomainStats>,
}

impl DomainAnalytics {
    /// Reverse the order of the domains in the analytics.
    pub fn reverse(&mut self) {
        self.domains.reverse();
    }

    /// Convert the analytics to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        to_string_pretty(&self.domains)
    }

    /// Convert the analytics to a CSV string.
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

#[cfg(test)]
mod tests {
    use crate::db::setup_db;

    use super::*;

    #[test]
    fn test_domain_analytics_to_json() {
        let conn = initialize_db_with_data();
        let analytics = compile_analytics(&conn, None).unwrap();
        let json = analytics.to_json().unwrap();

        let expected_json = r#"{
  "signal.org": {
    "total_queries": 3,
    "cache_hits": 2,
    "blacklist_hits": 0
  },
  "instagram.com": {
    "total_queries": 3,
    "cache_hits": 0,
    "blacklist_hits": 3
  }
}"#;

        assert_eq!(json, expected_json);
    }

    #[test]
    fn test_domain_analytics_to_csv() {
        let conn = initialize_db_with_data();
        let analytics = compile_analytics(&conn, None).unwrap();

        let csv = analytics.to_csv().unwrap();
        let expected_csv = "Domain,Total Queries,Cache Hits,Blacklist Hits\n\
signal.org,3,2,0\n\
instagram.com,3,0,3";

        assert_eq!(csv, expected_csv);
    }

    fn initialize_db_with_data() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        setup_db(&conn).unwrap();

        let queries = vec![
            DnsQueryLog {
                domain: "signal.org".to_string(),
                cached: false,
                blacklisted: false,
            },
            DnsQueryLog {
                domain: "instagram.com".to_string(),
                cached: false,
                blacklisted: true,
            },
            DnsQueryLog {
                domain: "signal.org".to_string(),
                cached: true,
                blacklisted: false,
            },
            DnsQueryLog {
                domain: "instagram.com".to_string(),
                cached: false,
                blacklisted: true,
            },
            DnsQueryLog {
                domain: "signal.org".to_string(),
                cached: true,
                blacklisted: false,
            },
            DnsQueryLog {
                domain: "instagram.com".to_string(),
                cached: false,
                blacklisted: true,
            },
        ];

        for query in queries {
            log_query(&conn, query).unwrap();
        }

        conn
    }
}
