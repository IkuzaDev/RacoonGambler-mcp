# MCP server

Transport: JSON-RPC 2.0 lewat stdio, satu pesan JSON per baris. Protocol version yang diumumkan: `2024-11-05`. Server memakai nama `judihunter-mcp` dan versi dari `Cargo.toml`.

## Menjalankan

```bash
./target/release/judihunter-mcp --mcp
```

Konfigurasi client:

```bash
claude mcp add racoongambler -- /absolute/path/to/judihunter-mcp --mcp
```

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

## Method yang didukung

| Method | Respons |
|---|---|
| `initialize` | `protocolVersion`, `capabilities: {tools: {}}`, `serverInfo` |
| `notifications/initialized` | Tidak ada respons |
| `ping` | `result: {}` |
| `tools/list` | Empat tool |
| `tools/call` | `result.content[0].text` berisi JSON pretty-print |
| lainnya | Error `-32601 method not found` |

Perilaku yang perlu diketahui:

- Baris kosong dan JSON yang tidak valid diabaikan, tanpa respons.
- Tool tidak dikenal mengembalikan hasil sukses biasa dengan teks `unknown tool <nama>` (bukan error JSON-RPC dan tanpa `isError`).
- Notifikasi lain selain `notifications/initialized` yang tidak dikenal akan dijawab dengan error `-32601` dengan `id: null`.
- Server memproses satu request pada satu waktu.

## Handshake

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"judihunter_check_host","arguments":{"host":"example.com"}}}
```

## Tools

### `judihunter_discover`

Cari kandidat hostname lewat DDG Lite + Bing.

| Argumen | Tipe | Keterangan |
|---|---|---|
| `queries` | string[] | Query kustom. Kosong = 6 query bawaan |
| `domains` | string[] | Ada di schema tetapi **diabaikan** oleh tool ini |

Hasil: `{"seeds": [...], "count": N}`.

### `judihunter_scan`

Pipeline penuh: discovery, resolve, whois, crt.sh, fingerprint, SEO, risk.

| Argumen | Tipe | Default | Keterangan |
|---|---|---|---|
| `queries` | string[] | - | Query discovery |
| `domains` | string[] | - | Host yang di-scan langsung |
| `concurrency` | integer | 16 | Jumlah thread |
| `no_whois` | boolean | false | Lewati whois |
| `no_crt` | boolean | false | Lewati crt.sh |
| `min_risk` | integer | 0 | Buang temuan dengan risk di bawah nilai ini |
| `max_body_mb` | integer | 1 | Batas body halaman |

Pemilihan host:

| `queries` | `domains` | Perilaku |
|---|---|---|
| kosong | kosong | Discovery dengan query bawaan |
| kosong | terisi | Hanya `domains`, tanpa discovery |
| terisi | apa saja | Discovery dengan `queries`, digabung dengan `domains` |

Hasil: objek `Report` (lihat [OUTPUT.md](OUTPUT.md)). Catatan:

- Host yang tidak punya IP dibuang dari `findings`.
- `min_risk` memfilter `findings` dan `hacked_flags`, serta menghitung ulang `summary`. `asn_groups` dan `backlinks` tidak ikut difilter.
- `summary.seeds` dan `summary.resolved` sama-sama berisi jumlah host masukan, bukan jumlah yang benar-benar ter-resolve.
- Panggilan ini bisa memakan waktu beberapa menit. Naikkan timeout di client MCP bila perlu, atau pakai `domains` + `no_whois`/`no_crt` untuk scan ringan.

### `judihunter_resolve`

| Argumen | Tipe | Wajib |
|---|---|---|
| `host` | string | ya |

Hasil: `host`, `ips`, `whois` (maks 2 entri, dari IP pertama), `domain_created`, `domain_age_days`.

### `judihunter_check_host`

| Argumen | Tipe | Wajib |
|---|---|---|
| `host` | string | ya |

Menjalankan `scan_host` dengan whois dan crt.sh selalu aktif dan batas body 1 MB. Hasil: satu objek `Finding` lengkap. Tidak ada filter "harus punya IP", dan `host` diteruskan apa adanya ke URL, jadi `host:port` tetap dapat di-fetch meski DNS-nya tidak ter-resolve.

## Penggunaan yang disarankan lewat Claude

1. `judihunter_check_host` untuk memeriksa satu domain mencurigakan.
2. `judihunter_scan` dengan `domains` untuk batch yang sudah kamu pegang.
3. Jalankan CLI dengan `--out` dan `--landing-dir` bila butuh file bukti dan laporan abuse.

Skill siap pakai ada di [`skills/racoongambler-recon/SKILL.md`](../skills/racoongambler-recon/SKILL.md).
