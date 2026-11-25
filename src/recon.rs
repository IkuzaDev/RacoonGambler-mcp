// recon.rs — analysis + orchestration (memory-optimized, bounded concurrency).
use crate::model::*;
use crate::net;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const GAMBLE_KW: &[&str] = &[
    "slot", "situs judi", "bandar", "togel", "judi online", "casino", "toto",
    "poker", "domino", "capsa", "sportsbook", "parlay", "maxwin", "gacor",
    "rtp slot", "rtp live", "deposit pulsa", "wd gampang", "bonus new member",
    "judi bola", "togel hk", "togel sgp", "togel sdy", "live casino", "slot88",
    "pragmatic", "pgsoft", "habanero", "sbobet", "maxbet", "daftar togel",
    "situs toto", "bandar togel", "judi slot", "pasti maxwin", "gampang menang",
];

pub const DISCOVER_QUERIES: &[&str] = &[
    "bandar togel online indonesia",
    "situs judi slot gacor maxwin",
    "judi online terpercaya 2026",
    "situs toto togel terbesar",
    "daftar situs judi resmi indonesia",
    "slot deposit pulsa tanpa potongan",
];

const PAY_PATTERNS: &[(&str, &str)] = &[
    ("DANA", "dana"),
    ("OVO", "ovo"),
    ("GoPay", "gopay"),
    ("QRIS", "qris"),
    ("Pulsa/Telkomsel", "pulsa"),
    ("Bank BCA", "bca"),
    ("Bank Mandiri", "mandiri"),
    ("Bank BRI", "bri"),
    ("Bitcoin/USDT", "usdt"),
    ("LinkAja", "linkaja"),
    ("ShopeePay", "shopeepay"),
];

const TECH_PATTERNS: &[(&str, &str)] = &[
    ("WordPress", "wp-content"),
    ("WooCommerce", "woocommerce"),
    ("jQuery", "jquery"),
    ("Bootstrap", "bootstrap"),
    ("React", "react"),
    ("Cloudflare", "cloudflare"),
    ("GoogleAnalytics", "gtag("),
    ("FontAwesome", "font-awesome"),
];

const LEGIT_HINT: &[&str] = &[
    "berita", "news", "sekolah", "school", "komunitas", "community", "blog",
    "toko", "shop", "organisasi", "desa", "village", "masjid", "klinik",
    "clinic", "univ", "universitas", "college", "academy", "yayasan",
    "portal", "magazine", "jurnal",
];

// tiny regex-free matchers (avoid heavy regex dep; memory + compile friendly)
fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn count_ci(hay: &str, needle: &str) -> usize {
    let h = hay.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    if n.is_empty() {
        return 0;
    }
    h.matches(&n as &str).count()
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_title(html: &str) -> String {
    let l = html.to_ascii_lowercase();
    if let Some(s) = l.find("<title") {
        let after = &html[s..];
        if let Some(gt) = after.find('>') {
            let rest = &after[gt + 1..];
            if let Some(end) = rest.to_ascii_lowercase().find("</title>") {
                return strip_tags(&rest[..end]).chars().take(200).collect();
            }
        }
    }
    String::new()
}

fn extract_h1(html: &str) -> Vec<String> {
    let l = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(s) = l[start..].find("<h1") {
        let s = start + s;
        if let Some(gt) = html[s..].find('>') {
            let content_start = s + gt + 1;
            if let Some(e) = l[content_start..].find("</h1>") {
                out.push(strip_tags(&html[content_start..content_start + e]).chars().take(120).collect::<String>());
                start = content_start + e + 5;
                if out.len() >= 5 {
                    break;
                }
                continue;
            }
        }
        break;
    }
    out
}

fn extract_outbound(host: &str, html: &str) -> Vec<String> {
    let l = html.to_ascii_lowercase();
    let mut set = std::collections::BTreeSet::new();
    let mut i = 0;
    while let Some(p) = l[i..].find("href=\"http") {
        let p = i + p + 6;
        if let Some(q) = l[p..].find('"') {
            let url = &html[p..p + q];
            if let Some(h) = host_of(url) {
                if h != host && !h.is_empty() {
                    set.insert(h);
                }
            }
            i = p + q;
        } else {
            break;
        }
    }
    set.into_iter().take(30).collect()
}

fn host_of(url: &str) -> Option<String> {
    let s = url.split("://").nth(1).unwrap_or(url);
    let host = s.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
    if host.contains('.') {
        Some(host.to_string())
    } else {
        None
    }
}

pub fn seo_analyze(host: &str, html: &str) -> Seo {
    let title = extract_title(html);
    let h1 = extract_h1(html);
    let text = strip_tags(html);
    let words = text.split_whitespace().count().max(1);
    let mut kw_hits: Vec<String> = GAMBLE_KW.iter().filter(|k| contains_ci(html, k)).map(|k| k.to_string()).collect();
    kw_hits.sort();
    kw_hits.dedup();
    let kw_count: usize = GAMBLE_KW.iter().map(|k| count_ci(html, k)).sum();
    let density = 100.0 * kw_count as f64 / words as f64;

    let mut score: u32 = 0;
    score += (kw_hits.len() as u32 * 6).min(40);
    score += (density as u32 * 8).min(20);
    if h1.iter().any(|h| GAMBLE_KW.iter().any(|k| contains_ci(h, k))) {
        score += 15;
    }
    if GAMBLE_KW.iter().any(|k| contains_ci(&title, k)) {
        score += 10;
    }
    if kw_count >= 25 {
        score += 10;
    }
    if words < 400 && !kw_hits.is_empty() {
        score += 5;
    }
    score = score.min(100);
    let outbound = extract_outbound(host, html);
    Seo {
        title,
        h1,
        wordcount: words,
        kw_hits,
        kw_density_pct: (density * 100.0).round() / 100.0,
        seo_score: score,
        doorwayish: words < 400 && score >= 50,
        outbound_hosts: outbound,
    }
}

pub fn fingerprint(html: &str) -> Tech {
    let tech: Vec<String> = TECH_PATTERNS.iter().filter(|(_, p)| contains_ci(html, p)).map(|(n, _)| n.to_string()).collect();
    let generator = String::new();
    Tech { tech, generator }
}

pub fn payments_contacts(html: &str) -> PaymentsContacts {
    let payments: Vec<String> = PAY_PATTERNS.iter().filter(|(_, p)| contains_ci(html, p)).map(|(n, _)| n.to_string()).collect();
    let mut contacts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut add = |k: &str, mut v: Vec<String>| {
        v.sort();
        v.dedup();
        if !v.is_empty() {
            contacts.insert(k.into(), v.into_iter().take(8).collect());
        }
    };
    add("telegram", find_all(html, "t.me/"));
    add("whatsapp", find_digits_after(html, "wa.me/"));
    add("whatsapp", find_digits_after(html, "api.whatsapp.com/send?phone="));
    add("email", find_emails(html));
    add("phone_id", find_phone_id(html));
    add("facebook", find_all(html, "facebook.com/"));
    add("instagram", find_all(html, "instagram.com/"));
    add("youtube", find_all(html, "youtube.com/@"));
    add("youtube", find_all(html, "youtube.com/channel/"));
    add("tiktok", find_all(html, "tiktok.com/@"));
    add("twitter", find_all(html, "twitter.com/"));
    add("twitter", find_all(html, "x.com/"));
    PaymentsContacts { payments, contacts }
}

/// Indonesian phone numbers: +62 / 08xx, 8-15 digits.
fn find_phone_id(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '+' || c.is_ascii_digit() {
            let start = i;
            let mut j = i;
            if bytes[j] as char == '+' {
                j += 1;
            }
            while j < bytes.len() && (bytes[j] as char).is_ascii_digit() {
                j += 1;
            }
            let tok = &html[start..j];
            let digits = tok.trim_start_matches('+');
            if (digits.starts_with("62") && digits.len() >= 10 && digits.len() <= 15)
                || (digits.starts_with('0') && digits.len() >= 9 && digits.len() <= 14)
            {
                out.push(tok.to_string());
            }
            i = j.max(start + 1);
        } else {
            i += 1;
        }
    }
    out
}

fn find_all(html: &str, marker: &str) -> Vec<String> {
    let l = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = l[i..].find(marker) {
        let p = i + p + marker.len();
        let rest: String = html[p..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').take(32).collect();
        if !rest.is_empty() {
            out.push(rest);
        }
        i = p;
    }
    out
}

fn find_digits_after(html: &str, marker: &str) -> Vec<String> {
    let l = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = l[i..].find(marker) {
        let p = i + p + marker.len();
        let digits: String = html[p..].chars().take_while(|c| c.is_ascii_digit()).take(15).collect();
        if digits.len() >= 8 {
            out.push(digits);
        }
        i = p;
    }
    out
}

fn find_emails(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in html.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"' || c == '\'') {
        if tok.contains('@') && tok.contains('.') && tok.len() < 64 {
            out.push(tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '@' && c != '.').to_string());
        }
    }
    out
}

pub fn crt_subdomains(host: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q={}&output=json", net::url_encode(&format!(".{host}")));
    let mut out = std::collections::BTreeSet::new();
    if let Some((_, _, body)) = net::http_get(&url, 2 * 1024 * 1024, 15) {
        if let Ok(entries) = serde_json::from_slice::<serde_json::Value>(&body) {
            if let Some(arr) = entries.as_array() {
                for e in arr {
                    if let Some(nv) = e.get("name_value").and_then(|v| v.as_str()) {
                        for line in nv.lines() {
                            let l = line.trim().trim_start_matches("*.").to_ascii_lowercase();
                            if l.ends_with(host) && l.matches('.').count() >= 2 {
                                out.insert(l);
                            }
                        }
                    }
                }
            }
        }
    }
    out.into_iter().take(40).collect()
}

pub fn risk_score(f: &Finding) -> u32 {
    let mut r = (f.seo.seo_score as f64) * 0.45;
    if let Some(age) = f.domain_age_days {
        if age < 90 {
            r += 20.0;
        } else if age < 365 {
            r += 12.0;
        }
    }
    if !f.payments.is_empty() {
        r += (f.payments.len() as f64 * 3.0).min(15.0);
    }
    if f.hacked.is_some() {
        r += 15.0;
    }
    if f.seo.doorwayish {
        r += 8.0;
    }
    if f.sibling_count >= 3 {
        r += 7.0;
    }
    r.min(100.0).round() as u32
}

pub fn tier(score: u32) -> String {
    match score {
        80.. => "CRITICAL",
        60..=79 => "HIGH",
        40..=59 => "MEDIUM",
        _ => "LOW",
    }
    .into()
}

fn hacked_verdict(host: &str, seo: &Seo) -> Option<Hacked> {
    if seo.seo_score < 40 {
        return None;
    }
    let legit = LEGIT_HINT.iter().any(|k| contains_ci(host, k) || contains_ci(&seo.title, k));
    if legit && seo.kw_hits.len() >= 2 {
        return Some(Hacked {
            flag: "website ini mungkin telah di retas".into(),
            reason: format!("legit-looking host, SEO {}, markers {:?}", seo.seo_score, &seo.kw_hits[..seo.kw_hits.len().min(6)]),
            confidence: if seo.seo_score >= 70 { "high" } else { "medium" }.into(),
        });
    }
    None
}

/// Scan one host. `max_body` caps HTML buffering (memory optimizer).
pub fn scan_host(host: &str, do_whois: bool, do_crt: bool, max_body: usize) -> Finding {
    let mut f = Finding::default();
    f.host = host.to_string();
    f.ips = net::resolve_all(host);
    if do_whois {
        for ip in f.ips.iter().take(2) {
            if let Some(w) = net::whois_ip(ip) {
                f.whois.push(w);
            }
        }
        let (created, age) = net::whois_domain_age(host);
        f.domain_created = created;
        f.domain_age_days = age;
    }
    if do_crt {
        f.crt_subdomains = crt_subdomains(host);
        f.sibling_count = f.crt_subdomains.len();
    }
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{host}/");
        if let Some((status, final_url, body)) = net::http_get(&url, max_body, 10) {
            let html = String::from_utf8_lossy(&body);
            f.http_status = Some(status);
            f.final_url = Some(final_url);
            f.redirect = vec![url.clone()];
            f.landing_html = html.to_string();
            f.seo = seo_analyze(host, &html);
            f.tech = fingerprint(&html);
            let pc = payments_contacts(&html);
            f.payments = pc.payments;
            f.contacts = pc.contacts;
            f.hacked = hacked_verdict(host, &f.seo);
            f.backlinks = f.seo.outbound_hosts.clone();
            break;
        }
    }
    f.risk = risk_score(&f);
    f.tier = tier(f.risk);
    f
}

/// Bounded-concurrency batch scan. Memory optimizer: results streamed to caller,
/// work distributed via atomic index over a fixed thread set (no per-task task bloat).
pub fn scan_batch(hosts: Vec<String>, do_whois: bool, do_crt: bool, max_body: usize, concurrency: usize) -> Vec<Finding> {
    let hosts = Arc::new(hosts);
    let idx = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(std::sync::Mutex::new(Vec::with_capacity(hosts.len())));
    let nthreads = concurrency.max(1).min(hosts.len().max(1));
    let mut handles = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let hosts = Arc::clone(&hosts);
        let idx = Arc::clone(&idx);
        let results = Arc::clone(&results);
        handles.push(std::thread::spawn(move || loop {
            let i = idx.fetch_add(1, Ordering::Relaxed);
            if i >= hosts.len() {
                break;
            }
            let f = scan_host(&hosts[i], do_whois, do_crt, max_body);
            results.lock().unwrap().push(f);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut v = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    v.sort_by(|a, b| b.risk.cmp(&a.risk));
    v
}