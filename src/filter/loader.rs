use std::{fs, path::Path};

use crate::filter::{
    types::{FilterData, FilterError, FilterPattern},
    FilterContext,
};

pub fn scan_dir<P>(path: P) -> Result<Vec<(String, String)>, FilterError>
where
    P: AsRef<Path>,
{
    path.as_ref()
        .read_dir()?
        .filter_map(Result::ok)
        .filter(|entry| {
            let path = entry.path();
            path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("list"))
                    .unwrap_or(false)
        })
        .map(|entry| {
            let filename = entry.file_name().to_string_lossy().to_string();
            let contents = fs::read_to_string(entry.path())?;
            Ok((filename, contents))
        })
        .collect()
}

pub fn populate_filter_context(
    filter: &mut FilterContext,
    files: Vec<(String, String)>,
) -> Result<(), FilterError> {
    filter.filters.clear();
    filter.whitelist.clear();

    for (filename, contents) in files {
        let is_whitelist = filename == "whitelist.list";
        let mut blacklist_data = (!is_whitelist).then(FilterData::default);

        let mut line_number = 0;
        for pattern in contents.lines().map(|l| l.trim()) {
            line_number += 1;

            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }

            let filter_pattern = parse_pattern(pattern, &filename, line_number);

            if is_whitelist {
                filter.whitelist.push(filter_pattern);
            } else {
                blacklist_data.as_mut().unwrap().add_pattern(filter_pattern);
            }
        }

        if let Some(data) = blacklist_data {
            filter.filters.push(data);
        }
    }

    Ok(())
}

fn parse_pattern(pattern: &str, filename: &str, line_number: usize) -> FilterPattern {
    if let Some(exact_domain) = pattern.strip_prefix('^') {
        FilterPattern::Exact {
            pattern: pattern.to_string(),
            filename: filename.to_string(),
            line_number,
            exact_domain: exact_domain.to_string(),
        }
    } else if pattern.contains('*') {
        FilterPattern::Wildcard {
            pattern: pattern.to_string(),
            filename: filename.to_string(),
            line_number,
        }
    } else {
        FilterPattern::Domain {
            pattern: pattern.to_string(),
            filename: filename.to_string(),
            line_number,
        }
    }
}
