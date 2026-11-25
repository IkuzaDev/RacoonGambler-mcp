// main.rs — cross-platform MCP server (JSON-RPC 2.0 over stdio) + CLI.
// Memory-optimized: capped body reads, fixed thread pool, streaming file output.
mod model;
mod net;
mod output;
mod recon;

use model::{BacklinkRow, Finding, Report, Summary};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

fn build_report(hosts: Vec<String>, do_whois: bool, do_crt: bool, max_body: usize, concurrency: usize) -> Report {
    let resolved = hosts.len();
    let findings = recon::scan_batch(hosts.clone(), do_whois, do_crt, max_body, concurrency);
    let findings: Vec<Finding> = findings.into_iter().filter(|f| !f.ips.is_empty()).collect();
    let hacked_flags: Vec<Finding> = findings.iter().filter(|f| f.hacked.is_some()).cloned().collect();
    let critical = findings.iter().filter(|f| f.tier == "CRITICAL").count();

    let mut asn_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &findings {
        let who = f.whois.first();
        let key = format!(
            "{} | {}",
            who.map(|w| w.asn.as_str()).unwrap_or("?"),
            who.map(|w| w.org.as_str()).unwrap_or("?")
        );
        asn_groups.entry(key).or_default().push(f.host.clone());
    }
    let backlinks: Vec<BacklinkRow> = findings.iter().map(|f| BacklinkRow { host: f.host.clone(), outbound: f.backlinks.clone() }).collect();

    Report {
        generated_at: now_iso(),
        summary: Summary {
            seeds: resolved,
            resolved,
            findings: findings.len(),
            flagged_hacked: hacked_flags.len(),
            critical,
        },
        findings,
        hacked_flags,
        asn_groups,
        backlinks,
    }
}

fn now_iso() -> String {
    // Minimal UTC timestamp without chrono: seconds since epoch -> civil date.
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn discover(queries: &[&str]) -> Vec<String> {
    let mut seeds = std::collections::BTreeSet::new();
    for (i, q) in queries.iter().enumerate() {
        seeds.extend(ddg_lite(q));
        seeds.extend(bing(q));
        if i + 1 < queries.len() {
            std::thread::sleep(std::time::Duration::from_secs(4));
        }
    }
    seeds.into_iter().collect()
}

fn ddg_lite(q: &str) -> Vec<String> {
    let url = format!("https://lite.duckduckgo.com/lite/?q={}", net::url_encode(q));
    let mut out = std::collections::BTreeSet::new();
    for _ in 0..3 {
        if let Some((_, _, body)) = net::http_get(&url, 512 * 1024, 12) {
            let html = String::from_utf8_lossy(&body);
            for cap in html.split("uddg=").skip(1) {
                let val = cap.split('&').next().unwrap_or("");
                let decoded = url_decode(val);
                if let Some(h) = host_of(&decoded) {
                    out.insert(h);
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    out.into_iter().collect()
}

fn bing(q: &str) -> Vec<String> {
    let url = format!("https://www.bing.com/search?q={}&count=30", net::url_encode(q));
    let mut out = std::collections::BTreeSet::new();
    for _ in 0..3 {
        if let Some((_, _, body)) = net::http_get(&url, 1024 * 1024, 12) {
            let html = String::from_utf8_lossy(&body);
            for cap in html.split("<cite").skip(1) {
                if let Some(s) = cap.find('>') {
                    let rest = &cap[s + 1..];
                    let end = rest.find("</cite>").unwrap_or(rest.len());
                    let raw = rest[..end].trim();
                    // cite may be a full URL ("https://host › path") or bare host
                    if let Some(h) = host_of(raw) {
                        out.insert(h);
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    out.into_iter().collect()
}

fn host_of(url: &str) -> Option<String> {
    let s = url.split("://").nth(1).unwrap_or(url);
    // host ends at first '/', whitespace, or non-host char
    let host: String = s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    let host = host.trim_matches('.').to_ascii_lowercase();
    if host.contains('.') && !host.starts_with('.') {
        Some(host)
    } else {
        None
    }
}

/// Backlink-by-title: search a gambling site's title/brand, collect referring domains.
fn backlink_search(query: &str, self_host: &str) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut sources: Vec<String> = ddg_lite(query);
    sources.extend(bing(query));
    for h in sources {
        if h != self_host && h.contains('.') {
            out.insert(h);
        }
    }
    out.into_iter().take(30).collect()
}

/// Build a clean brand query from a finding: use the leading brand token
/// (first word/segment before separators) — search engines return referrers for
/// a crisp brand name, not a long title with pipes.
fn brand_query(f: &model::Finding) -> String {
    let t = f.seo.title.trim();
    if t.is_empty() {
        return f.host.clone();
    }
    // take first segment before common separators
    let first = t.split(|c: char| c == '|' || c == '-' || c == ':' || c == '—')
        .map(|s| s.trim()).find(|s| !s.is_empty()).unwrap_or(t);
    // brand = first 1-2 words, max 24 chars
    let brand: String = first.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let brand = brand.chars().take(24).collect::<String>();
    if brand.len() >= 3 {
        brand
    } else {
        f.host.clone()
    }
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ---------------- MCP JSON-RPC over stdio ----------------
fn mcp_serve() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            _ => continue,
        };
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "judihunter-mcp", "version": env!("CARGO_PKG_VERSION") }
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": tools_list() }
            }),
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                let text = call_tool(name, &args);
                json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [ { "type": "text", "text": text } ] }
                })
            }
            "notifications/initialized" => continue,
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            _ => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {method}") } }),
        };
        let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
        let _ = out.flush();
    }
}

fn tools_list() -> Value {
    json!([
        {
            "name": "judihunter_discover",
            "description": "Auto-discover candidate gambling hostnames via DuckDuckGo Lite + Bing (no API key).",
            "inputSchema": { "type": "object", "properties": {
                "queries": { "type": "array", "items": { "type": "string" } },
                "domains": { "type": "array", "items": { "type": "string" } }
            } }
        },
        {
            "name": "judihunter_scan",
            "description": "Advanced pipeline: discover -> resolve -> whois(age) -> crt.sh -> fingerprint -> SEO -> RISK. Buckets: findings/hacked/asn/backlinks.",
            "inputSchema": { "type": "object", "properties": {
                "queries": { "type": "array", "items": { "type": "string" } },
                "domains": { "type": "array", "items": { "type": "string" } },
                "concurrency": { "type": "integer", "default": 16 },
                "no_whois": { "type": "boolean", "default": false },
                "no_crt": { "type": "boolean", "default": false },
                "min_risk": { "type": "integer", "default": 0 },
                "max_body_mb": { "type": "integer", "default": 1 }
            } }
        },
        {
            "name": "judihunter_resolve",
            "description": "Resolve one host: IPs + whois (Team Cymru) + domain age. No API.",
            "inputSchema": { "type": "object", "properties": { "host": { "type": "string" } }, "required": ["host"] }
        },
        {
            "name": "judihunter_check_host",
            "description": "Single-host advanced fingerprint: SEO + risk + tech + payments + hacked verdict.",
            "inputSchema": { "type": "object", "properties": { "host": { "type": "string" } }, "required": ["host"] }
        }
    ])
}

fn call_tool(name: &str, args: &Value) -> String {
    let get_str_arr = |k: &str| -> Vec<String> {
        args.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    let get_str = |k: &str| -> String { args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string() };
    let get_u64 = |k: &str, d: u64| -> u64 { args.get(k).and_then(|v| v.as_u64()).unwrap_or(d) };
    let get_bool = |k: &str| -> bool { args.get(k).and_then(|v| v.as_bool()).unwrap_or(false) };

    match name {
        "judihunter_discover" => {
            let q_owned = get_str_arr("queries");
            let seeds = if q_owned.is_empty() {
                discover(recon::DISCOVER_QUERIES)
            } else {
                let q: Vec<&str> = q_owned.iter().map(|s| s.as_str()).collect();
                discover(&q)
            };
            let count = seeds.len();
            serde_json::to_string_pretty(&json!({ "seeds": seeds, "count": count })).unwrap()
        }
        "judihunter_scan" => {
            let hosts = gather_hosts(&get_str_arr("queries"), &get_str_arr("domains"));
            let max_body = (get_u64("max_body_mb", 1) as usize) * 1024 * 1024;
            let report = build_report(hosts, !get_bool("no_whois"), !get_bool("no_crt"), max_body, get_u64("concurrency", 16) as usize);
            let report = filter_min_risk(report, get_u64("min_risk", 0) as u32);
            serde_json::to_string_pretty(&report).unwrap()
        }
        "judihunter_resolve" => {
            let host = get_str("host");
            let ips = net::resolve_all(&host);
            let who: Vec<_> = ips.iter().take(2).filter_map(|ip| net::whois_ip(ip)).collect();
            let (created, age) = net::whois_domain_age(&host);
            serde_json::to_string_pretty(&json!({ "host": host, "ips": ips, "whois": who, "domain_created": created, "domain_age_days": age })).unwrap()
        }
        "judihunter_check_host" => {
            let host = get_str("host");
            let f = recon::scan_host(&host, true, true, 1024 * 1024);
            serde_json::to_string_pretty(&f).unwrap()
        }
        _ => format!("unknown tool {name}"),
    }
}

fn gather_hosts(queries: &[String], domains: &[String]) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for d in domains {
        set.insert(d.to_ascii_lowercase());
    }
    if !queries.is_empty() || domains.is_empty() {
        let q: Vec<&str> = if queries.is_empty() { recon::DISCOVER_QUERIES.to_vec() } else { queries.iter().map(|s| s.as_str()).collect() };
        for h in discover(&q) {
            set.insert(h);
        }
    }
    set.into_iter().collect()
}

fn filter_min_risk(mut r: Report, min: u32) -> Report {
    r.findings.retain(|f| f.risk >= min);
    r.hacked_flags.retain(|f| f.risk >= min);
    r.summary.findings = r.findings.len();
    r.summary.flagged_hacked = r.hacked_flags.len();
    r.summary.critical = r.findings.iter().filter(|f| f.tier == "CRITICAL").count();
    r
}

// ---------------- CLI ----------------
fn cli() {
    let args: Vec<String> = std::env::args().collect();
    let mut out = String::new();
    let mut domains: Vec<String> = Vec::new();
    let mut no_discover = false;
    let mut no_whois = false;
    let mut no_crt = false;
    let mut concurrency = 16usize;
    let mut max_body_mb = 1usize;
    let mut landing_dir = String::new();
    let mut do_backlinks = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--domains" => {
                while i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    domains.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "--no-discover" => no_discover = true,
            "--no-whois" => no_whois = true,
            "--backlinks" => do_backlinks = true,
            "--no-crt" => no_crt = true,
            "--landing-dir" => {
                landing_dir = args[i + 1].clone();
                i += 1;
            }
            "--concurrency" => {
                concurrency = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(16);
                i += 1;
            }
            "--max-body-mb" => {
                max_body_mb = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(1);
                i += 1;
            }
            "--mcp" => {
                mcp_serve();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let hosts: Vec<String> = if no_discover {
        domains
    } else {
        gather_hosts(&[], &domains)
    };
    eprintln!("[*] {} seeds; scanning (concurrency={}, max_body={}MB)", hosts.len(), concurrency, max_body_mb);
    let mut report = build_report(hosts, !no_whois, !no_crt, max_body_mb * 1024 * 1024, concurrency);

    // Backlink-by-title pass: for each finding, search its title/brand -> referring domains.
    if do_backlinks {
        let targets: Vec<(String, String)> = report.findings.iter()
            .map(|f| (f.host.clone(), brand_query(f))).collect();
        eprintln!("[*] backlink search for {} targets...", targets.len());
        for (host, q) in targets {
            let refs = backlink_search(&q, &host);
            if let Some(f) = report.findings.iter_mut().find(|f| f.host == host) {
                f.ref_hosts = refs;
            }
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }

    if out.is_empty() {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    let base = out.rsplit_once('.').map(|(b, _)| b).unwrap_or(&out).to_string();
    output::write_json(&out, &report).expect("json");
    output::write_csv_findings(&format!("{base}.findings.csv"), &report.findings).expect("csv findings");
    output::write_csv_hacked(&format!("{base}.hacked.csv"), &report.findings).expect("csv hacked");
    output::write_csv_backlinks(&format!("{base}.backlinks.csv"), &report.findings).expect("csv backlinks");
    output::write_csv_subdomains(&format!("{base}.subdomains.csv"), &report.findings).expect("csv subdomains");
    output::write_html(&format!("{base}.html"), &report).expect("html");
    // contacts CSV (flattened)
    output::write_csv_contacts(&format!("{base}.contacts.csv"), &report.findings).expect("csv contacts");
    output::write_csv_combined(&format!("{base}.combined.csv"), &report.findings).expect("csv combined");
    // landing pages + per-host contact JSON
    if !landing_dir.is_empty() {
        std::fs::create_dir_all(&landing_dir).ok();
        for f in &report.findings {
            let safe = f.host.replace('/', "_");
            if !f.landing_html.is_empty() {
                std::fs::write(format!("{landing_dir}/{safe}.html"), &f.landing_html).ok();
            }
            let cj = serde_json::to_string_pretty(&serde_json::json!({
                "host": f.host, "final_url": f.final_url, "http_status": f.http_status,
                "risk": f.risk, "tier": f.tier, "payments": f.payments, "contacts": f.contacts
            })).unwrap();
            std::fs::write(format!("{landing_dir}/{safe}.contacts.json"), cj).ok();
        }
        eprintln!("[*] landing pages + contacts -> {landing_dir}/");
    }
    eprintln!("[*] wrote {out} + {base}.*.csv + {base}.html");
}

fn main() {
    // --mcp runs the JSON-RPC stdio server; anything else runs the CLI.
    let is_mcp = std::env::args().any(|a| a == "--mcp");
    if is_mcp {
        mcp_serve();
    } else {
        cli();
    }
}