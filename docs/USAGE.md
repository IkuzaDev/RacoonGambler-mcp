# Panduan CLI

Binary: `target/release/judihunter-mcp`. Tanpa `--mcp`, program berjalan sebagai CLI.

```bash
BIN=./target/release/judihunter-mcp
```

## Flag

| Flag | Argumen | Efek |
|---|---|---|
| `--out` | path | Tulis `JSON` ke path itu dan file turunan lain di sebelahnya. Tanpa flag ini, JSON dicetak ke stdout |
| `--domains` | satu atau lebih host | Daftar host. Membaca nilai sampai bertemu argumen yang diawali `--` |
| `--no-discover` | - | Lewati discovery, pakai hanya `--domains` |
| `--no-whois` | - | Lewati whois IP dan umur domain |
| `--no-crt` | - | Lewati crt.sh |
| `--backlinks` | - | Setelah scan, cari referring host per temuan lewat DDG + Bing |
| `--landing-dir` | path | Simpan HTML landing page dan JSON kontak per host |
| `--concurrency` | angka | Jumlah thread, default 16 |
| `--max-body-mb` | angka | Batas ukuran body halaman, default 1 |
| `--mcp` | - | Jalankan sebagai MCP server |

Argumen yang tidak dikenal diabaikan tanpa peringatan. Termasuk `--min-risk`, yang hanya berlaku di MCP (lihat [KNOWN-ISSUES.md](KNOWN-ISSUES.md)).

## Perilaku pemilihan host

`main.cli()` memanggil `gather_hosts([], domains)` bila `--no-discover` tidak ada. Akibatnya:

| Kombinasi | Hasil |
|---|---|
| Tanpa `--domains`, tanpa `--no-discover` | Discovery dengan 6 query bawaan |
| `--domains ...` (dengan atau tanpa `--no-discover`) | Hanya host yang diberikan, discovery dilewati |
| `--no-discover` tanpa `--domains` | Nol host |

Query kustom tidak bisa diberikan lewat CLI. Untuk itu pakai MCP (`judihunter_discover` atau `judihunter_scan` dengan `queries`).

## Contoh

Scan daftar domain sendiri, semua output ke folder kerja:

```bash
$BIN --domains a.example b.example --out report.json --landing-dir landing
```

Cepat, tanpa whois dan crt.sh:

```bash
$BIN --domains a.example --no-whois --no-crt --out quick.json
```

Discovery otomatis dengan query bawaan plus pencarian backlink:

```bash
$BIN --backlinks --out report.json
```

Batasi memori dan thread:

```bash
$BIN --domains a.example b.example --concurrency 8 --max-body-mb 2 --out report.json
```

Cetak JSON ke stdout dan saring dengan `jq`:

```bash
$BIN --domains a.example | jq '.findings[] | {host, risk, tier}'
```

Log progres ditulis ke stderr, jadi stdout aman untuk di-pipe.

## Waktu eksekusi

Discovery memakai jeda 4 detik antar query ditambah retry, jadi enam query bawaan butuh paling sedikit sekitar 20 detik sebelum scan dimulai. Setiap host bisa memakan puluhan detik bila whois atau crt.sh lambat (timeout 8 dtk per query whois, 15 dtk crt.sh, 10 dtk HTTP per skema).

## Setelah scan

Lihat [OUTPUT.md](OUTPUT.md) untuk isi file, dan [ABUSE-REPORTING.md](ABUSE-REPORTING.md) untuk membuat laporan.
