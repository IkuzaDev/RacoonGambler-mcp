#!/usr/bin/env python3
"""
abuse_report.py — generate ready-to-send abuse/takedown reports from a judi_recon report.json.

The lawful way to take down a gambling site is abuse reporting, not attacking it.
This reads findings and emits per-host reports addressed to:
  - hosting / origin provider (from whois ASN org)
  - Cloudflare abuse (if fronted)
  - domain registrar (from whois)
  - Indonesian regulator (Kominfo / BRTF) aduan konten
  - payment processors used (merchant abuse)

Stdlib only. No network calls. Output: markdown files + a combined bundle.

Usage:
  python3 abuse_report.py report.json --out reports/
"""
import argparse
import json
import os
import re

KOMINFO = "https://aduankonten.id/ (Kominfo) / BRTF aduan telekomunikasi"
CLOUDFLARE = "https://abuse.cloudflare.com/"


def registrar_from_whois(whois_list):
    for w in whois_list or []:
        org = (w.get("org") or w.get("netname") or "").strip()
        if org:
            return org
    return "unknown (check whois)"


def hosting_targets(f):
    """Return list of (label, detail) abuse destinations for a finding."""
    out = []
    who = (f.get("whois") or [{}])[0]
    asn = who.get("asn", "?")
    org = who.get("org") or who.get("netname") or "?"
    cc = who.get("country", "?")
    out.append(("Hosting / origin (ASN owner)", f"{asn} — {org} ({cc}). Find abuse contact via whois -h whois.cymru.com or the ASN's abuse-c."))
    if "CLOUDFLARE" in org.upper() or f.get("ips") and any(ip.startswith(("104.", "172.67.")) for ip in f.get("ips", [])):
        out.append(("Cloudflare (CDN front)", CLOUDFLARE))
    out.append(("Domain registrar", f"Registrar abuse contact (whois {f['host']})."))
    out.append(("Regulator (ID)", KOMINFO))
    for p in f.get("payments", []):
        out.append(("Payment processor", f"{p} — report merchant/gambling abuse to the provider."))
    return out


def render(f):
    s = f.get("seo") or {}
    lines = []
    lines.append(f"# Abuse / Takedown Report — {f['host']}")
    lines.append("")
    lines.append(f"- **Risk tier:** {f.get('tier')} ({f.get('risk')}/100)")
    lines.append(f"- **Final URL:** {f.get('final_url') or 'https://' + f['host'] + '/'}")
    lines.append(f"- **HTTP status:** {f.get('http_status')}")
    lines.append(f"- **IPs:** {', '.join(f.get('ips', [])[:4])}")
    who = (f.get("whois") or [{}])[0]
    lines.append(f"- **ASN / org:** {who.get('asn','?')} — {who.get('org') or who.get('netname') or '?'} ({who.get('country','?')})")
    lines.append(f"- **Domain age:** {f.get('domain_age_days')} days (created {f.get('domain_created')})")
    lines.append(f"- **SEO/gambling score:** {s.get('seo_score')}/100")
    if f.get("payments"):
        lines.append(f"- **Payment methods advertised:** {', '.join(f['payments'])}")
    if f.get("contacts"):
        lines.append("- **Public contact channels:**")
        for ch, vals in f["contacts"].items():
            lines.append(f"  - {ch}: {', '.join(vals[:5])}")
    if f.get("hacked"):
        lines.append(f"- **NOTE:** {f['hacked']['flag']} — {f['hacked']['reason']}")
    lines.append("")
    lines.append("## Why this is reportable")
    lines.append("This site advertises online gambling (slot/togel/casino/judi) and payment methods "
                 "commonly used for illegal gambling in Indonesia. Online gambling is prohibited under "
                 "Indonesian law (KUHP / UU ITE). Requesting review and takedown under applicable "
                 "content rules and the provider's Acceptable Use Policy.")
    lines.append("")
    lines.append("## Where to send this report")
    for label, detail in hosting_targets(f):
        lines.append(f"- **{label}:** {detail}")
    lines.append("")
    lines.append("## Evidence")
    lines.append(f"- Landing page capture: landing/{f['host']}.html")
    lines.append(f"- Contacts: report.contacts.csv (filter host={f['host']})")
    lines.append(f"- Screenshot: capture landing/{f['host']}.html in a browser, timestamp WIB.")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--min-risk", type=int, default=0)
    args = ap.parse_args()
    data = json.load(open(args.report))
    os.makedirs(args.out, exist_ok=True)
    findings = [f for f in data.get("findings", []) if f.get("risk", 0) >= args.min_risk]
    bundle = ["# Abuse Report Bundle", ""]
    for f in findings:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", f["host"])
        txt = render(f)
        open(os.path.join(args.out, f"{safe}.md"), "w").write(txt)
        bundle.append(txt)
        bundle.append("\n---\n")
    open(os.path.join(args.out, "_bundle.md"), "w").write("\n".join(bundle))
    print(f"wrote {len(findings)} reports to {args.out}/ (+ _bundle.md)")


if __name__ == "__main__":
    main()