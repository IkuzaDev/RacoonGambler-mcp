// output.rs — JSON + CSV + HTML report generation (streaming writes).
use crate::model::{BacklinkRow, Finding, Report, Summary};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};

pub fn write_json(path: &str, report: &Report) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, report)?;
    w.flush()
}

pub fn write_csv_findings(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,risk,tier,ips,http_status,seo_score,domain_age_days,sibling_count,payments,tech,kw_hits,hacked,org,asn,country")?;
    for fnd in findings {
        let who = fnd.whois.first();
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            esc(&fnd.host),
            fnd.risk,
            esc(&fnd.tier),
            esc(&fnd.ips.join(";")),
            fnd.http_status.map_or("".into(), |v| v.to_string()),
            fnd.seo.seo_score,
            fnd.domain_age_days.map_or("".into(), |v| v.to_string()),
            fnd.sibling_count,
            esc(&fnd.payments.join(";")),
            esc(&fnd.tech.tech.join(";")),
            esc(&fnd.seo.kw_hits.join(";")),
            fnd.hacked.as_ref().map(|_| "YES").unwrap_or("-"),
            who.map(|w| esc(&w.org)).unwrap_or_default(),
            who.map(|w| esc(&w.asn)).unwrap_or_default(),
            who.map(|w| esc(&w.country)).unwrap_or_default(),
        )?;
    }
    Ok(())
}

pub fn write_csv_hacked(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,flag,confidence,risk,reason")?;
    for fnd in findings {
        if let Some(h) = &fnd.hacked {
            writeln!(w, "{},{},{},{},{}", csv(&fnd.host), csv(&h.flag), csv(&h.confidence), fnd.risk, csv(&h.reason))?;
        }
    }
    Ok(())
}

/// CSV-safe field: wrap in quotes, double internal quotes.
fn csv(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn write_csv_contacts(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,channel,value")?;
    for fnd in findings {
        for (ch, vals) in &fnd.contacts {
            for v in vals {
                writeln!(w, "{},{},{}", csv(&fnd.host), csv(ch), csv(v))?;
            }
        }
    }
    Ok(())
}

/// Single combined CSV: one row per host with all key fields + contacts + ref_hosts.
pub fn write_csv_combined(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,risk,tier,http_status,final_url,ips,asn,org,country,domain_age_days,seo_score,payments,tech,contacts,ref_hosts,hacked")?;
    for fnd in findings {
        let who = fnd.whois.first();
        let contacts: Vec<String> = fnd.contacts.iter()
            .map(|(k, v)| format!("{k}={}", v.join("|"))).collect();
        writeln!(
            w, "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv(&fnd.host), fnd.risk, csv(&fnd.tier),
            fnd.http_status.map_or("".into(), |v| v.to_string()),
            csv(fnd.final_url.as_deref().unwrap_or("")),
            csv(&fnd.ips.join(";")),
            csv(who.map(|w| w.asn.as_str()).unwrap_or("")),
            csv(who.map(|w| w.org.as_str()).unwrap_or("")),
            csv(who.map(|w| w.country.as_str()).unwrap_or("")),
            fnd.domain_age_days.map_or("".into(), |v| v.to_string()),
            fnd.seo.seo_score,
            csv(&fnd.payments.join(";")),
            csv(&fnd.tech.tech.join(";")),
            csv(&contacts.join(" ")),
            csv(&fnd.ref_hosts.join(";")),
            fnd.hacked.as_ref().map(|_| "YES").unwrap_or("-"),
        )?;
    }
    Ok(())
}

pub fn write_csv_backlinks(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,outbound")?;
    for fnd in findings {
        writeln!(w, "{},{}", esc(&fnd.host), esc(&fnd.backlinks.join(";")))?;
    }
    Ok(())
}

pub fn write_csv_subdomains(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    writeln!(w, "host,crt_subdomains,tls_sans,sibling_count")?;
    for fnd in findings {
        writeln!(w, "{},{},{},{}", esc(&fnd.host), esc(&fnd.crt_subdomains.join(";")), esc(&fnd.tls_sans.join(";")), fnd.sibling_count)?;
    }
    Ok(())
}

pub fn write_html(path: &str, report: &Report) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    let rows: String = report.findings.iter().map(|fnd| html_row(fnd)).collect();
    let ts = &report.generated_at;
    write!(
        w,
        r#"<!doctype html><html><head><meta charset="utf-8">
<title>Judi Recon — Advanced Report</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--fg:#c9d1d9;--mut:#8b949e;--acc:#58a6ff;--red:#f85149;--org:#ffa657}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}}
.wrap{{max-width:1280px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--mut);margin-bottom:20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.card{{background:var(--card);border:1px solid #30363d;border-radius:8px;padding:14px 18px;min-width:120px}}
.card b{{font-size:24px;display:block;color:var(--acc)}}.card span{{color:var(--mut);font-size:12px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:12px}}
th{{background:#1f2630;color:var(--mut);position:sticky;top:0}}
.mono{{font-family:ui-monospace,monospace;color:#9ecbff}}
.tier{{padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700}}
.CRITICAL{{background:#3d1418;color:var(--red)}}.HIGH{{background:#3a2a10;color:var(--org)}}
.MEDIUM{{background:#1f2f10;color:#7ee787}}.LOW{{background:#1c2128;color:var(--mut)}}
.flag{{color:var(--red);font-weight:700}}
tr:hover{{background:#1b2230}}
</style></head><body><div class="wrap">
<h1>🎰 Judi Recon — Advanced Report</h1>
<div class="sub">generated {ts} · operator red-team · read-only</div>
<div class="cards">
<div class="card"><b>{seeds}</b><span>seeds</span></div>
<div class="card"><b>{resolved}</b><span>resolved</span></div>
<div class="card"><b>{findings}</b><span>findings</span></div>
<div class="card"><b style="color:var(--red)">{hacked}</b><span>hacked</span></div>
<div class="card"><b style="color:var(--org)">{critical}</b><span>critical</span></div>
</div>
<table><thead><tr><th>host</th><th>risk</th><th>ip</th><th>seo</th><th>age(d)</th>
<th>siblings</th><th>payments</th><th>tech</th><th>geo/asn</th><th>flag</th></tr></thead>
<tbody>{rows}</tbody></table>
</div></body></html>"#,
        seeds = report.summary.seeds,
        resolved = report.summary.resolved,
        findings = report.summary.findings,
        hacked = report.summary.flagged_hacked,
        critical = report.summary.critical,
        rows = rows
    )
}

fn html_row(f: &Finding) -> String {
    let who = f.whois.first();
    let geo = format!("{} {}", who.map(|w| w.country.as_str()).unwrap_or("?"), who.map(|w| w.asn.as_str()).unwrap_or(""));
    let hacked_html = f.hacked.as_ref().map(|_| r#"<td class="flag">HACKED</td>"#).unwrap_or(r#"<td>-</td>"#);
    format!(
        r#"<tr>
<td class="mono">{host}</td>
<td><span class="tier {tier}">{tier}</span> <b>{risk}</b></td>
<td class="mono">{ip}</td>
<td>{seo}</td>
<td>{age}</td>
<td>{sib}</td>
<td>{pay}</td>
<td>{tech}</td>
<td class="mono">{geo}</td>
{hacked}
</tr>"#,
        host = esc(&f.host),
        tier = esc(&f.tier),
        risk = f.risk,
        ip = esc(&f.ips.iter().take(2).cloned().collect::<Vec<_>>().join(", ")),
        seo = f.seo.seo_score,
        age = f.domain_age_days.map_or("?".into(), |v| v.to_string()),
        sib = f.sibling_count,
        pay = esc(&f.payments.join(", ")),
        tech = esc(&f.tech.tech.join(", ")),
        geo = esc(&geo),
        hacked = hacked_html
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}