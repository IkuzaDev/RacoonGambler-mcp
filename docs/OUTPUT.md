# Skema output

Dengan `--out report.json`, nama dasar (`report`) diturunkan dengan membuang ekstensi terakhir. File yang ditulis:

| File | Isi |
|---|---|
| `report.json` | Objek `Report` lengkap |
| `report.findings.csv` | Ringkasan per host, urut risk |
| `report.hacked.csv` | Hanya host dengan flag "retas" |
| `report.contacts.csv` | `host,channel,value` (satu baris per kontak) |
| `report.backlinks.csv` | `host,outbound` |
| `report.subdomains.csv` | `host,crt_subdomains,tls_sans,sibling_count` |
| `report.combined.csv` | Satu baris per host dengan semua field penting |
| `report.html` | Dashboard gelap, urut risk |
| `<landing-dir>/<host>.html` | HTML landing page (hanya dengan `--landing-dir`) |
| `<landing-dir>/<host>.contacts.json` | `host, final_url, http_status, risk, tier, payments, contacts` |

Daftar ini juga mencakup `combined.csv`, yang tidak tercantum di dokumentasi asli.

## `Report`

```json
{
  "generated_at": "2026-11-26T02:30:00+00:00",
  "summary": { "seeds": 0, "resolved": 0, "findings": 0, "flagged_hacked": 0, "critical": 0 },
  "findings": [],
  "hacked_flags": [],
  "asn_groups": { "AS13335 | CLOUDFLARENET, US": ["host1", "host2"] },
  "backlinks": [ { "host": "host1", "outbound": ["t.me", "wa.me"] } ]
}
```

- `asn_groups`: kunci berbentuk `"<ASN> | <org>"` (atau `?` bila tidak ada whois), nilai daftar host.
- `hacked_flags`: salinan `Finding` yang punya `hacked`.
- `landing_html` tidak pernah masuk JSON.

## `Finding`

| Field | Tipe | Keterangan |
|---|---|---|
| `host` | string | Host seperti yang diberikan |
| `ips` | string[] | A/AAAA hasil resolve |
| `whois` | object[] | Maks 2 entri: `ip, netname, org, country, asn, route` (`netname` selalu kosong) |
| `http_status` | int / null | Status respons sukses pertama |
| `final_url` | string / null | URL akhir setelah redirect |
| `redirect` | string[] | Berisi URL yang diminta saja, bukan rantai redirect |
| `domain_created` | string / null | Teks mentah tanggal dari whois |
| `domain_age_days` | int / null | Lihat [KNOWN-ISSUES.md](KNOWN-ISSUES.md) soal tanggal acuan |
| `crt_subdomains` | string[] | Maks 40 |
| `tls_sans` | string[] | Selalu kosong (belum diimplementasi) |
| `sibling_count` | int | Panjang `crt_subdomains` |
| `tech` | object | `{tech: string[], generator: string}` |
| `payments` | string[] | Label metode pembayaran |
| `contacts` | object | channel → nilai (maks 8 per channel) |
| `seo` | object | `title, h1[], wordcount, kw_hits[], kw_density_pct, seo_score, doorwayish, outbound_hosts[]` |
| `risk` | int | 0–100 |
| `tier` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `hacked` | object / null | `{flag, reason, confidence}` |
| `backlinks` | string[] | Sama dengan `seo.outbound_hosts` |
| `ref_hosts` | string[] | Terisi hanya dengan `--backlinks` |

Host yang gagal di-fetch tetap punya `seo` kosong dan `risk` hanya dari faktor non-konten (umur domain, subdomain). Pada `judihunter_scan` dan CLI, host tanpa IP dibuang sepenuhnya.

## Kolom CSV

`findings.csv`:
`host,risk,tier,ips,http_status,seo_score,domain_age_days,sibling_count,payments,tech,kw_hits,hacked,org,asn,country`

`combined.csv`:
`host,risk,tier,http_status,final_url,ips,asn,org,country,domain_age_days,seo_score,payments,tech,contacts,ref_hosts,hacked`

Pemisah nilai ganda di dalam sel: `;` (`ips`, `payments`, dst.), dan di kolom `contacts` format `channel=nilai1|nilai2` dipisah spasi.

Pembungkus kutip CSV yang benar hanya dipakai di `hacked.csv`, `contacts.csv`, dan `combined.csv`. Tiga CSV lain memakai escape HTML; lihat [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## Dashboard HTML

Satu halaman statis, tema gelap, tanpa JavaScript dan tanpa dependensi eksternal. Menampilkan kartu ringkasan (seeds, resolved, findings, hacked, critical) dan tabel: host, risk + tier, IP, seo, umur (hari), siblings, payments, tech, negara + ASN, flag.

## Izin file

Output berisi kontak dan HTML target. Setelah scan:

```bash
chmod 600 report.* && chmod -R go-rwx landing
```
