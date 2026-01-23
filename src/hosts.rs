use crate::domain::DnsName;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader},
    net::IpAddr,
};

pub fn parse_hosts_file() -> io::Result<HashMap<DnsName, Vec<IpAddr>>> {
    let file = File::open("/etc/hosts")?;
    parse_hosts(BufReader::new(file))
}

pub fn parse_hosts<R: BufRead>(reader: R) -> io::Result<HashMap<DnsName, Vec<IpAddr>>> {
    let mut m: HashMap<DnsName, Vec<IpAddr>> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        // Split on comment character - first part is always the content ("127.0.0.1 localhost")
        let line = line.split('#').next().unwrap_or("").trim();

        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip: IpAddr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        for &name in &parts[1..] {
            if let Ok(dn) = name.parse::<DnsName>() {
                m.entry(dn).or_default().push(ip);
            }
        }
    }

    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_hosts_basic() {
        let hosts_content = "127.0.0.1 localhost\n192.168.1.1 router.local router";
        let cursor = Cursor::new(hosts_content);
        let hosts = parse_hosts(cursor).unwrap();

        assert_eq!(hosts.len(), 3);
        assert_eq!(
            hosts.get(&"localhost".parse().unwrap()),
            Some(&vec!["127.0.0.1".parse().unwrap()])
        );
        assert_eq!(
            hosts.get(&"router.local".parse().unwrap()),
            Some(&vec!["192.168.1.1".parse().unwrap()])
        );
        assert_eq!(
            hosts.get(&"router".parse().unwrap()),
            Some(&vec!["192.168.1.1".parse().unwrap()])
        );
    }
}
