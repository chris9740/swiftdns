use std::io::Write;

use anyhow::Result;
use clap::Args;

use crate::{
    db::create_conn,
    metrics::{self, Format},
};

#[derive(Args)]
pub struct MetricsArgs {
    #[arg(
        long = "format",
        short = 'f',
        help = "The desired output format",
        default_value_t = Format::Json
    )]
    pub format: Format,

    #[arg(
        long = "reverse",
        short = 'r',
        help = "Reverse the order of the output",
        action = clap::ArgAction::SetTrue
    )]
    pub reverse: bool,

    #[arg(
        long = "search",
        short = 's',
        help = "Filter the output by domain name"
    )]
    pub search: Option<String>,
}

pub async fn execute(args: MetricsArgs) -> Result<()> {
    let conn = create_conn()?;
    let mut analytics = metrics::compile_analytics(&conn, args.search.as_deref())?;

    if args.reverse {
        analytics.reverse();
    }

    let output = match args.format {
        Format::Csv => analytics.to_csv()?,
        Format::Json => analytics.to_json()?,
    };

    let mut lock = std::io::stdout().lock();
    lock.write_all(output.as_bytes())?;
    lock.write(b"\n")?;
    lock.flush()?;

    Ok(())
}
