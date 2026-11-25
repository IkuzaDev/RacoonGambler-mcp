# Arsitektur

Satu crate Rust (`judihunter-mcp` 0.2.0, edition 2021) dengan empat dependensi: `serde`, `serde_json`, `ureq` (rustls + gzip, tanpa default features), dan `url`. Tidak ada regex, tidak ada async runtime, tidak ada chrono. Semua parsing HTML dan whois dibuat manual.

## Modul

| File | Tanggung jawab |
|---|---|
| `src/main.rs` | Entry point, parser argumen CLI, MCP server, discovery (DDG Lite + Bing), backlink search, `build_report` |
| `src/recon.rs` | Keyword/pola, analisis SEO, fingerprint, ekstraksi kontak, crt.sh, risk score, `scan_host`, `scan_batch` |
| `src/net.rs` | `http_get` dengan batas byte, resolve DNS, DoH, whois TCP port 43, parsing tanggal |
| `src/model.rs` | `Finding`, `Report`, `Summary`, `Seo`, `Tech`, `Hacked`, `WhoisIp`, `BacklinkRow` |
| `src/output.rs` | Penulis JSON, 6 CSV, dan HTML |

`main()` memeriksa apakah ada argumen `--mcp` di mana pun; jika ada, jalankan `mcp_serve()`, jika tidak jalankan `cli()`.

## Alur pipeline

```
seed host
   │
   ▼
discover()  ── DDG Lite + Bing, jeda 4 dtk antar query
   │
   ▼
scan_batch()  ── thread pool tetap, indeks atomik
   │
   ▼  per host: scan_host()
   ├─ resolve_all()        stdlib → fallback DoH
   ├─ whois_ip()           Team Cymru, maks 2 IP pertama
   ├─ whois_domain_age()   registry whois
   ├─ crt_subdomains()     crt.sh, maks 40
   ├─ http_get()           https dulu, lalu http
   ├─ seo_analyze()
   ├─ fingerprint()
   ├─ payments_contacts()
   ├─ hacked_verdict()
   └─ risk_score() + tier()
   │
   ▼
build_report()  ── buang host tanpa IP, bentuk hacked_flags, asn_groups, backlinks
   │
   ▼
(opsional) backlink pass  ── --backlinks
   │
   ▼
output::*  ── JSON, CSV, HTML, landing pages
```

## Discovery

- **DuckDuckGo Lite**: `https://lite.duckduckgo.com/lite/?q=<query>`. Hostname diambil dari parameter `uddg=` pada hasil.
- **Bing**: `https://www.bing.com/search?q=<query>&count=30`. Hostname diambil dari elemen `<cite>`.
- Tiap mesin dicoba sampai 3 kali (jeda 2 dtk) sampai ada hasil.
- Antar query ada jeda 4 detik.
- Query bawaan (`recon::DISCOVER_QUERIES`): enam query berbahasa Indonesia seputar togel, slot gacor, judi online, situs toto, dan deposit pulsa.

Karena memakai scraping HTML publik tanpa API, hasil discovery bergantung pada format halaman mesin pencari dan bisa kosong bila diblokir atau format berubah.

## Konkurensi

`scan_batch` membuat `min(concurrency, jumlah_host)` thread. Tiap thread mengambil indeks host berikutnya dari `AtomicUsize` sampai habis, lalu hasil didorong ke `Mutex<Vec<Finding>>`. Setelah semua thread selesai, hasil diurutkan menurun berdasarkan `risk`. Default `concurrency` adalah 16.

Whois, crt.sh, dan fetch HTTP dilakukan sinkron di dalam thread masing-masing, jadi satu host lambat hanya menahan satu thread.

## Batas memori

- `http_get` membaca paling banyak `max_bytes + 1` byte lewat `Read::take`, lalu memotong ke `max_bytes`. Default body halaman 1 MB (`--max-body-mb`).
- Respons whois dibatasi 64 KB, crt.sh 2 MB, DoH 64 KB, DDG 512 KB, Bing 1 MB.
- Penulisan file memakai `BufWriter`.
- HTML landing page disimpan di `Finding.landing_html` (di-skip saat serialisasi JSON) untuk semua host sampai laporan selesai, jadi pemakaian memori puncak kira-kira `jumlah_host × max_body`.

## Resolusi jaringan

| Kebutuhan | Cara |
|---|---|
| DNS | `ToSocketAddrs` (resolver sistem), fallback DoH JSON `cloudflare-dns.com/dns-query` lalu `dns.google/resolve` |
| ASN/org/negara | Query `" -v <ip>"` ke `whois.cymru.com:43`, ambil baris pertama dengan kolom ASN numerik |
| Umur domain | Whois registry sesuai TLD, ikuti `refer` dari IANA satu kali |
| Subdomain | `https://crt.sh/?q=.<host>&output=json` |
| User-Agent | Chrome 124 di Windows (konstanta `net::UA`) |

## MCP server

Loop sinkron membaca baris dari stdin, mem-parse JSON, dan menulis satu baris respons ke stdout. Tidak ada concurrency antar request: pemanggilan `tools/call` yang lama (misalnya `judihunter_scan`) memblokir request berikutnya sampai selesai. Lihat [MCP.md](MCP.md).
