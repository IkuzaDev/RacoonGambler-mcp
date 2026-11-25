# RULES — Judi Recon Toolkit

## Scope (what this toolkit does)
Read-only OSINT & reconnaissance against Indonesian online-gambling hosts:
- Auto-discover candidate hosts (public search engines)
- Resolve IPs, ASN/org/country (Team Cymru whois, DoH)
- Enumerate subdomains (crt.sh, TLS SAN)
- Fingerprint: SEO score, risk tier, tech stack, payment methods
- Harvest **public** contact channels (Telegram/WhatsApp/email/phone/social)
- Capture **public** landing-page HTML
- Group by hosting/ASN

## Hard rules
1. **READ-ONLY.** No exploitation, no auth-bypass, no DoS, no deface, no payload delivery, no CVE weaponization against any host.
2. **Public data only.** Everything collected is served publicly to any visitor. No credential theft, no bypass of access controls.
3. **No third-party takedown by force.** This toolkit does not attack, degrade, or destroy targets. Takedown happens ONLY via lawful channels (hosting abuse desk, Cloudflare abuse, Kominfo/BTRF, law enforcement).
4. **Authorized use.** Run only against targets you are authorized to assess, or for defensive/awareness/reporting purposes.
5. **Evidence hygiene.** Collected data is for reporting/awareness. Store under `chmod 600`, share only with intended recipients.
6. **Rate discipline.** Discovery throttled; respect target capacity. No aggressive scanning.

## What "takedown" means here (lawful path)
The effective way to remove a gambling site is **abuse reporting**, not attacking it:
- Hosting/origin provider abuse contact (from whois / ASN owner)
- Cloudflare abuse (if fronted) — abuse@cloudflare.com / abuse form
- Indonesian regulator: Kominfo / BRTF (Badan Regulasi Telekomunikasi) aduan konten
- Payment processors used (DANA/OVO/GoPay/bank) — report merchant abuse
- Domain registrar abuse (from whois)

`tools/abuse_report.py` generates ready-to-send reports from findings. That is the supported "take down" mechanism.

## Out of scope (will NOT build)
- CVE exploit / PoC weaponization against non-owned hosts
- Auth bypass, injection, RCE, deface, DoS/DDoS
- Credential harvesting beyond public contact info
- Any tool whose purpose is to damage, disrupt, or destroy a third-party system