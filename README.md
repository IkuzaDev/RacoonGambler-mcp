# 🦝 RacoonGambler

**Read-only OSINT & recon toolkit for Indonesian online-gambling (judol) sites. Find, fingerprint, and report them through lawful abuse channels.**

Satu binary Rust, tanpa API key, lintas platform. Bisa dipakai sebagai CLI atau sebagai MCP server (JSON-RPC 2.0 over stdio) supaya bisa dipanggil langsung dari Claude atau MCP client lain.

> Nama paket/binary di dalam kode tetap `judihunter-mcp` (nama asli proyeknya). `RacoonGambler` adalah nama repo.

---

## Apa yang dikerjakan

| Tahap | Detail |
|---|---|
| Discovery | Cari kandidat host judol lewat DuckDuckGo Lite dan Bing, tanpa API key |
| Resolve | A/AAAA lewat resolver sistem, fallback DoH (Cloudflare, Google) |
| Hosting intel | IP → ASN / org / negara / prefix via Team Cymru whois (port 43) |
| Umur domain | Whois registry (`.com/.net` Verisign, `.org` PIR, `.id` whois.id, TLD lain via IANA referral) |
| Subdomain | crt.sh (maks 40) |
| Fingerprint | Skor SEO judol, tech stack, metode pembayaran (DANA, OVO, GoPay, QRIS, bank, dll.) |
| Kontak publik | Telegram, WhatsApp, email, nomor telepon ID, Facebook, Instagram, YouTube, TikTok, X/Twitter |
| Deteksi defacement | Flag "website ini mungkin telah di retas" untuk situs yang kelihatan sah tapi penuh keyword judol |
| Risk scoring | Skor 0–100 + tier `LOW / MEDIUM / HIGH / CRITICAL` |
| Pengelompokan | Group per ASN/hosting, outbound link (backlinks), referring host |
| Laporan | JSON, 6 CSV, dashboard HTML gelap, capture landing page |
| Takedown | `tools/abuse_report.py` membuat draf laporan abuse siap kirim |

## Yang TIDAK dilakukan

Tidak ada exploit, auth bypass, injection, DoS, deface, atau pengambilan kredensial. Semua data yang dikumpulkan adalah data yang disajikan publik ke setiap pengunjung. Penindakan hanya lewat jalur resmi (abuse desk hosting, Cloudflare, registrar, regulator, payment provider). Aturan lengkap ada di [RULES.md](RULES.md).

---

## Quick start

### Build

```bash
cargo build --release
```

Binary ada di `target/release/judihunter-mcp` (Windows: `judihunter-mcp.exe`), sekitar 1,8 MB. Profil release memakai `opt-level = "z"`, LTO, `panic = "abort"`, dan strip.

### Cek satu host

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"judihunter_check_host","arguments":{"host":"example.com"}}}' | ./target/release/judihunter-mcp --mcp
```

### Scan lewat CLI

```bash
./target/release/judihunter-mcp --no-discover --domains a.example b.example --out report.json --landing-dir landing
```

Hasil: `report.json`, enam file CSV, `report.html`, dan folder `landing/`.

### Buat laporan abuse

```bash
python3 tools/abuse_report.py report.json --out reports --min-risk 60
```

---

## Pakai sebagai MCP server

Claude Code:

```bash
claude mcp add racoongambler -- /absolute/path/to/judihunter-mcp --mcp
```

Claude Desktop atau client lain yang membaca JSON config:

```json
{
  "mcpServers": {
    "racoongambler": {
      "command": "/absolute/path/to/judihunter-mcp",
      "args": ["--mcp"]
    }
  }
}
```

| Tool | Argumen | Fungsi |
|---|---|---|
| `judihunter_discover` | `queries[]` | Cari kandidat hostname |
| `judihunter_scan` | `queries[]`, `domains[]`, `concurrency`, `no_whois`, `no_crt`, `min_risk`, `max_body_mb` | Pipeline penuh, hasil berupa report JSON |
| `judihunter_resolve` | `host` | IP + ASN/org + umur domain |
| `judihunter_check_host` | `host` | Fingerprint satu host |

Detail protokol dan semantik argumen: [docs/MCP.md](docs/MCP.md).

---

## Scoring singkat

```
risk = 0.45 × seo_score
     + bonus umur domain   (< 90 hari: +20, < 365 hari: +12)
     + bonus pembayaran    (3 per metode, maks 15)
     + 15 bila ada flag "retas"
     + 8  bila doorway-ish (< 400 kata dan seo_score ≥ 50)
     + 7  bila subdomain di crt.sh ≥ 3
     dibatasi 0–100
```

Tier: `≥ 80` CRITICAL, `60–79` HIGH, `40–59` MEDIUM, selain itu LOW. Rumus lengkap: [docs/SCORING.md](docs/SCORING.md).

---

## Struktur repo

```
RacoonGambler/
├── Cargo.toml
├── src/
│   ├── main.rs        CLI, MCP server, discovery
│   ├── recon.rs       analisis, scoring, orkestrasi scan
│   ├── net.rs         HTTP, DNS/DoH, whois port 43
│   ├── model.rs       struct data (serde)
│   └── output.rs      JSON, CSV, HTML
├── tools/
│   └── abuse_report.py
├── skills/
│   └── racoongambler-recon/SKILL.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── USAGE.md
│   ├── MCP.md
│   ├── SCORING.md
│   ├── OUTPUT.md
│   ├── ABUSE-REPORTING.md
│   └── KNOWN-ISSUES.md
└── RULES.md
```

## Dokumentasi

- [Arsitektur & alur data](docs/ARCHITECTURE.md)
- [Panduan CLI](docs/USAGE.md)
- [MCP server](docs/MCP.md)
- [Scoring & heuristik](docs/SCORING.md)
- [Skema output](docs/OUTPUT.md)
- [Alur pelaporan abuse](docs/ABUSE-REPORTING.md)
- [Known issues](docs/KNOWN-ISSUES.md) — baca ini sebelum mengandalkan hasil scan
- [Skill untuk Claude](skills/racoongambler-recon/SKILL.md)

## Penggunaan yang bertanggung jawab

- Jalankan hanya untuk tujuan defensif, awareness, dan pelaporan, atau terhadap target yang berwenang kamu assess.
- Hasil scan adalah indikator heuristik, bukan bukti hukum. Verifikasi manual sebelum melapor.
- Kontak yang terkumpul bisa milik orang tak bersalah (misalnya pemilik situs yang diretas). Jangan dipublikasikan; kirim hanya ke abuse desk atau pihak berwenang.
- Simpan output dengan `chmod 600`.
- Jaga rate: discovery sudah di-throttle, jangan menaikkan `--concurrency` secara agresif.

## Lisensi

Belum ditentukan. Tambahkan file `LICENSE` sebelum repo dipublikasikan.
