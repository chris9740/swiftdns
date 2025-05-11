use anyhow::Result;
use clap::Args;
use colored::Colorize;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use crate::filter;

#[derive(Args)]
pub struct FiltersArgs {}

pub async fn execute() -> Result<()> {
    let mut filters = filter::load_filters()?;
    filters.sort_by_key(|filter| filter.pathname.clone());

    println!("{}", "Filters".bold());

    for (index, filter) in filters.iter().enumerate() {
        let path = Path::new(&filter.pathname);
        let relative_path = path
            .iter()
            .skip_while(|&component| component != OsStr::new("filters"))
            .skip(1)
            .collect::<PathBuf>();

        let filter_name = relative_path
            .file_stem()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| relative_path.to_string_lossy());

        let mut v: Vec<char> = filter_name.chars().collect();
        v[0] = v[0].to_uppercase().next().unwrap();
        let filter_name = v.into_iter().collect::<String>();

        println!(
            " {}) {} ({})",
            index + 1,
            filter_name,
            relative_path.display().to_string().italic()
        );
    }

    Ok(())
}
