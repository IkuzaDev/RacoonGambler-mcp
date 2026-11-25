// net.rs — cross-platform networking: capped HTTP, DNS, DoH, pure-Rust whois (port 43).
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

/// HTTP GET with a hard byte cap (memory optimizer: never buffer more than `max_bytes`).
/// Returns (status, final_url, body). Cross-platform TLS via ureq/rustls.
pub fn http_get(url: &str, max_bytes: usize, timeout_secs: u64) -> Option<(u16, String, Vec<u8>)> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(timeout_secs))
        .timeout_read(Duration::from_secs(timeout_secs))
        .build();
    let resp = agent
        .get(url)
        .set("User-Agent", UA)
        .set("Accept", "text/html,application/xhtml+xml,application/json,*/*")
        .call();
    match resp {
        Ok(r) => {
            let status = r.status();
            let final_url = r.get_url().to_string();
            let mut reader = r.into_reader();
            let mut buf = Vec::with_capacity((max_bytes / 2).min(64 * 1024));
            // read at most max_bytes+1 to detect truncation without unbounded alloc
            let mut limited = reader.by_ref().take((max_bytes as u64) + 1);
            let _ = limited.read_to_end(&mut buf);
            if buf.len() > max_bytes {
                buf.truncate(max_bytes);
            }
            Some((status, final_url, buf))
        }
        Err(_) => None,
    }
}

/// Resolve A/AAAA via stdlib (cross-platform).
pub fn resolve_a(host: &str) -> Vec<String> {
    match (host, 0u16).to_socket_addrs() {
        Ok(iter) => {
            let mut set: Vec<String> = iter.map(|s| s.ip().to_string()).collect();
            set.sort();
            set.dedup();
            set
        }
        Err(_) => Vec::new(),
    }
}

/// DoH JSON fallback (Cloudflare/Google, keyless).
pub fn doh(host: &str) -> Vec<String> {
    for ep in ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"] {
        let url = format!("{ep}?name={}&type=A", url_encode(host));
        if let Some((_, _, body)) = http_get(&url, 64 * 1024, 6) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
                    let ips: Vec<String> = ans
                        .iter()
                        .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(1))
                        .filter_map(|a| a.get("data").and_then(|d| d.as_str()).map(String::from))
                        .collect();
                    if !ips.is_empty() {
                        return ips;
                    }
                }
            }
        }
    }
    Vec::new()
}

pub fn resolve_all(host: &str) -> Vec<String> {
    let a = resolve_a(host);
    if !a.is_empty() {
        a
    } else {
        doh(host)
    }
}

/// Minimal application/x-www-form-urlencoded for query values.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Pure-Rust whois over TCP port 43 (cross-platform, no `whois` binary needed).
fn whois_query(server: &str, query: &str, timeout_secs: u64) -> String {
    let addr = format!("{server}:43");
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)));
    if stream.write_all(query.as_bytes()).is_err() {
        return String::new();
    }
    let _ = stream.write_all(b"\r\n");
    let mut buf = Vec::with_capacity(8 * 1024);
    let _ = stream.take(64 * 1024).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

/// Team Cymru whois: one query -> ASN / prefix / country / org for an IP. Structured + light.
pub fn whois_ip(ip: &str) -> Option<crate::model::WhoisIp> {
    let raw = whois_query("whois.cymru.com", &format!(" -v {}", ip), 8);
    if raw.trim().is_empty() {
        return None;
    }
    // Cymru verbose: header line "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
    // then data rows. Pick the first row whose first column is numeric.
    let line = raw
        .lines()
        .find(|l| l.contains('|') && l.split('|').next().map(|c| c.trim().parse::<u64>().is_ok()).unwrap_or(false))?;
    let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
    if parts.len() < 7 {
        return None;
    }
    let asn = parts[0].trim();
    Some(crate::model::WhoisIp {
        ip: ip.to_string(),
        asn: format!("AS{asn}"),
        route: parts[2].to_string(),
        country: parts[3].to_string(),
        org: parts[6].to_string(),
        netname: String::new(),
    })
}

/// Registry whois for domain creation date. Follows IANA referral for unknown TLDs.
pub fn whois_domain_age(host: &str) -> (Option<String>, Option<i64>) {
    let tld = host.rsplit('.').next().unwrap_or("");
    let mut server = match tld {
        "com" | "net" => "whois.verisign-grs.com",
        "org" => "whois.pir.org",
        "id" => "whois.id",
        _ => "whois.iana.org",
    }
    .to_string();
    let mut raw = whois_query(&server, host, 8);
    // If IANA referred us to a registry whois, follow it once.
    if server == "whois.iana.org" {
        if let Some(refer) = extract_field(&raw, &["refer"]) {
            let r2 = whois_query(refer.trim(), host, 8);
            if !r2.is_empty() {
                raw = r2;
                server = refer.trim().to_string();
            }
        }
    }
    let _ = server;
    if raw.is_empty() {
        return (None, None);
    }
    let created = extract_field(&raw, &["Creation Date", "Created On", "created", "Registered On", "registration time", "created-date", "Registered Date"]);
    let age = created.as_deref().and_then(parse_date_age);
    (created, age)
}

fn extract_field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        for k in keys {
            if let Some(pos) = line.find(k) {
                let rest = &line[pos + k.len()..];
                let val = rest.trim_start_matches(|c: char| c == ':' || c == ' ').trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn parse_date_age(raw: &str) -> Option<i64> {
    // Accept common whois date shapes; compute days since.
    let s = raw.trim();
    let s = s.split('T').next().unwrap_or(s); // drop time
    let s = s.split(' ').next().unwrap_or(s);
    let parts: Vec<&str> = s.split(['-', '/']).collect();
    if parts.len() != 3 {
        return None;
    }
    let (y, m, d) = (parts[0].parse::<i64>().ok()?, parts[1].parse::<i64>().ok()?, parts[2].parse::<i64>().ok()?);
    let days = days_from_civil(y, m, d);
    let now = days_from_civil(2026, 11, 26); // deterministic-ish; refined by caller if needed
    Some(now - days)
}

/// Howard Hinnant's days_from_civil (proleptic Gregorian, no chrono dep).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}