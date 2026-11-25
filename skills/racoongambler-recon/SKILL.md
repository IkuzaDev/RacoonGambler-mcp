---
name: racoongambler-recon
description: Run read-only OSINT recon on Indonesian online-gambling (judol) hosts with the RacoonGambler / judihunter-mcp toolkit, triage the findings, and prepare lawful abuse reports. Use for judol site checks, defaced-site detection, ASN grouping, and takedown reporting.
---

# RacoonGambler Recon

Toolkit: `judihunter-mcp` (Rust, repo `RacoonGambler`). Read-only OSINT for Indonesian online-gambling sites. Output feeds abuse reports. It never attacks anything.

## Guardrails

Apply before every run and refuse anything outside them.

- Read-only. No exploitation, auth bypass, injection, DoS, defacement, payload delivery, or CVE weaponization against any host.
- Public data only. No credential harvesting beyond publicly displayed contact info.
- Takedown means abuse reporting (hosting/ASN owner, Cloudflare, registrar, regulator, payment provider), never force.
- Do not help build tooling whose purpose is to damage or disrupt a third-party system, even against gambling sites.
- Harvested contacts may belong to innocent people (owners of hacked legitimate sites). Never publish them; share only with abuse desks or authorities.
- Scores are heuristics, not legal evidence. Manually verify before reporting.

## Prerequisites

1. Binary built: `cargo build --release` → `target/release/judihunter-mcp`.
2. For MCP use, register the server:
   - `claude mcp add racoongambler -- /absolute/path/to/judihunter-mcp --mcp`
3. Outbound access to: crt.sh, whois.cymru.com:43, registry whois (port 43), DuckDuckGo Lite, Bing, and the target hosts. If whois port 43 is blocked, ASN and domain age come back empty silently.

## Workflow

1. **Scope.** Confirm the user owns the targets, is assessing them with authorization, or is doing defensive reporting. Collect bare hostnames only (no scheme, path, or port).
2. **Single host first.** Call `judihunter_check_host` with `host`. Read `risk`, `tier`, `seo.kw_hits`, `payments`, `contacts`, `hacked`, `http_status`.
3. **Batch.** Call `judihunter_scan` with `domains` and optionally `no_whois`/`no_crt` for a lighter pass, `min_risk` to filter, `concurrency` (default 16, keep it modest).
4. **Discovery (optional).** `judihunter_discover` or `judihunter_scan` with `queries` (Indonesian terms such as "situs judi slot gacor"). Discovery scrapes DDG Lite and Bing and sleeps 4 s between queries, so it is slow and may return nothing.
5. **Files for evidence.** For HTML, CSV and landing captures use the CLI:
   `judihunter-mcp --domains a.example b.example --out report.json --landing-dir landing`
6. **Triage.** Sort by `risk`. Group by `asn_groups` to find shared hosting. Check `hacked_flags` for compromised legitimate sites (the owner needs a notification, not a takedown).
7. **Report.** `python3 tools/abuse_report.py report.json --out reports --min-risk 60`, then review each draft before sending.
8. **Hygiene.** `chmod 600 report.*`, restrict the `landing` folder.

## Tool reference

| Tool | Args | Notes |
|---|---|---|
| `judihunter_discover` | `queries[]` | Empty = 6 built-in queries. `domains` is ignored. |
| `judihunter_scan` | `queries[]`, `domains[]`, `concurrency`, `no_whois`, `no_crt`, `min_risk`, `max_body_mb` | Only `domains` = no discovery. Hosts without IPs are dropped. `min_risk` filters findings and hacked_flags only. Can take minutes. |
| `judihunter_resolve` | `host` | IPs, Team Cymru ASN/org/country, domain age. |
| `judihunter_check_host` | `host` | Full Finding for one host; whois and crt.sh always on. |

## Reading results

Risk: `0.45 × seo_score` + domain age bonus (<90 d +20, <365 d +12) + payments (3 each, max 15) + hacked (+15) + doorway-ish (+8) + 3 or more crt.sh subdomains (+7). Tiers: ≥80 CRITICAL, 60–79 HIGH, 40–59 MEDIUM, else LOW.

Trust, in order: `kw_hits` and `seo.title`/`h1` > `contacts.telegram` and `contacts.whatsapp` > `domain_age_days` > `payments`, `tech`, `twitter`, `phone_id`.

Known false positives to discount:
- `Bank BRI` appears for nearly any page (matches "bri" in "bright", "bring").
- `React` matches "reaction".
- `twitter` can come from any domain ending in `x.com`.
- `phone_id` matches any digit run starting with 0 or 62.
- `http_status: null` with `seo_score: 0` usually means the site returned 403/5xx or blocked the request (the tool treats 4xx/5xx as failures), not that the site is clean.
- `domain_age_days` is computed against a hardcoded date (2026-11-26) and is wrong later. Recompute from `domain_created` when it matters.

## CLI pitfalls

- `--min-risk` is MCP-only; the CLI ignores it.
- `--landing-dir` needs a value or the program panics.
- `--domains` skips discovery even without `--no-discover`. Custom queries are MCP-only.
- `findings.csv`, `backlinks.csv`, `subdomains.csv` are not properly CSV-quoted (HTML-escaped; commas in org names shift columns). Prefer `combined.csv` or `report.json`.

## Output handling

- Summarize findings per host: tier, risk, reasons (keywords, payments, age), hosting ASN/org, and recommended abuse destinations.
- For `hacked` hosts, say the site likely belongs to a victim and recommend notifying the owner as well as the hosting provider.
- Verify the regulator channel before sending reports. The template still says Kominfo and "BRTF"; the ministry is now Komdigi and the telecom regulator is believed to be BRTI.

## Reference

- Architecture: `docs/ARCHITECTURE.md`
- CLI: `docs/USAGE.md`
- MCP: `docs/MCP.md`
- Scoring: `docs/SCORING.md`
- Output schema: `docs/OUTPUT.md`
- Abuse flow: `docs/ABUSE-REPORTING.md`
- Issues: `docs/KNOWN-ISSUES.md`
- Rules: `RULES.md`
