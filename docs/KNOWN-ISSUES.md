# Known issues

Daftar ini hasil membaca source dan menjalankan binary (build release, Rust 1.97) terhadap halaman uji lokal. Item bertanda ✅ sudah direproduksi langsung.

## Bug dan ketidaksesuaian

| # | Masalah | Dampak | Lokasi |
|---|---|---|---|
| 1 ✅ | `--min-risk` tidak diparse di CLI (argumen asing diabaikan) | Dokumentasi asli menyarankan `--min-risk 60` di CLI, tetapi tidak ada efek. Hanya MCP `judihunter_scan` yang mendukungnya | `main.rs` `cli()` |
| 2 ✅ | `--landing-dir` tanpa nilai memicu panic `index out of bounds` | Crash | `main.rs` `cli()` |
| 3 ✅ | `--domains` tanpa `--no-discover` tetap melewati discovery | Tidak bisa menggabungkan domain sendiri dengan discovery lewat CLI; query kustom juga tidak bisa dipakai di CLI | `main.rs` `gather_hosts` |
| 4 | `findings.csv`, `backlinks.csv`, `subdomains.csv` memakai `esc()` (escape HTML) bukan kutip CSV | Nilai berisi koma (mis. nama org Team Cymru seperti `CLOUDFLARENET, US`) menggeser kolom; `&` menjadi `&amp;`. Pakai `combined.csv`, `contacts.csv`, `hacked.csv` yang benar atau parse JSON | `output.rs` |
| 5 | Umur domain dihitung terhadap tanggal tetap 2026-11-26 | `domain_age_days` dan bonus risk menjadi salah seiring waktu | `net.rs` `parse_date_age` |
| 6 | `tls_sans` tidak pernah diisi | RULES.md menyebut "TLS SAN" sebagai sumber subdomain, padahal hanya crt.sh yang dipakai | `recon.rs` |
| 7 ✅ | Respons HTTP 4xx/5xx dianggap gagal (`ureq` mengembalikan error) | Situs di balik Cloudflare challenge (403) atau yang menolak User-Agent menghasilkan `http_status: null`, `seo_score: 0`, tanpa kontak | `net.rs` `http_get` |
| 8 ✅ | Input host dengan skema (`https://x.com`) tidak dinormalisasi | URL menjadi `https://https://x.com/` dan fetch gagal. Berikan hostname polos | `recon.rs` `scan_host` |
| 9 | Umur domain di-query dengan host mentah, bukan domain terdaftar | Subdomain, `host:port`, atau `co.id` bisa menghasilkan umur kosong | `net.rs` `whois_domain_age` |
| 10 | Format tanggal whois hanya `YYYY-MM-DD` / `YYYY/MM/DD` | Format lain (mis. `01-Mar-2010`) menghasilkan umur kosong | `net.rs` `parse_date_age` |
| 11 | `summary.seeds` dan `summary.resolved` sama-sama = jumlah host masukan | Bukan jumlah host yang benar-benar ter-resolve | `main.rs` `build_report` |
| 12 | `judihunter_discover` mengabaikan argumen `domains` walau ada di schema | Tidak berdampak, hanya menyesatkan | `main.rs` `call_tool` |
| 13 | `redirect` hanya berisi URL yang diminta | Bukan rantai redirect; pakai `final_url` | `recon.rs` |
| 14 | Tool MCP tidak dikenal mengembalikan sukses dengan teks, bukan error | Client sulit membedakan | `main.rs` |
| 15 | Tiga import tidak terpakai di `output.rs` (`BacklinkRow`, `Summary`, `BTreeMap`) | Warning compiler | `output.rs` |
| 16 | `landing_html` disimpan di memori untuk semua host sampai laporan selesai | Memori puncak ≈ jumlah host × `max_body_mb` walau `--landing-dir` tidak dipakai | `recon.rs`, `model.rs` |

## Akurasi heuristik (false positive)

Pencocokan memakai substring pada HTML mentah, jadi:

- **`bri`** (Bank BRI) cocok dengan kata Inggris umum seperti *bright*, *bridge*, *bring*, *brief*. Hampir semua halaman akan terdeteksi "Bank BRI". ✅
- **`react`** (tech React) cocok dengan *reaction*, *reactive*. ✅
- **`x.com/`** (Twitter) cocok dengan domain berakhiran `x.com`, mis. `dropbox.com/foo` terbaca sebagai akun Twitter `foo`. ✅
- **`bca`** cocok dengan *webcam*; **`ovo`** dengan *novo*; **`dana`** dengan nama orang atau tempat.
- **`bandar`** cocok dengan *Bandar Lampung* dan *bandar udara*; **`pragmatic`**, **`slot`** ("time slot"), **`domino`** ("Domino's"), **`toto`** (merek) muncul di konten sah.
- Karena keyword dicari di HTML mentah, script dan atribut ikut dihitung.
- `LEGIT_HINT` juga substring (`shop`, `blog`, `news`, `univ`, `portal`), sehingga situs judi yang kebetulan memakai kata itu di title bisa diberi flag "retas".
- `phone_id` menangkap rangkaian digit apa pun yang berawalan `0` atau `62` dengan panjang cocok (ID produk, timestamp), dan nomor WhatsApp juga muncul ganda di `whatsapp` dan `phone_id`. ✅

Perlakukan `payments`, `tech`, `hacked`, dan `contacts` sebagai petunjuk yang harus diverifikasi manual, terutama sebelum melapor.

## Keterbatasan operasional

- **Discovery rapuh.** Parsing HTML DDG Lite dan Bing tanpa API; format berubah atau pemblokiran bot membuat hasil kosong.
- **Jejak ke pihak ketiga.** "Read-only" terhadap target, tetapi hostname dan IP dikirim ke crt.sh, Team Cymru, registry whois, mesin pencari, dan (saat fallback) Cloudflare/Google DoH. Target sendiri menerima request HTTP biasa dengan User-Agent yang menyamar sebagai Chrome.
- **Port 43.** Whois memakai TCP port 43 langsung; jaringan yang memblokirnya membuat ASN dan umur domain kosong tanpa pesan error.
- **Tanpa retry cerdas.** Satu timeout per langkah; kegagalan ditelan diam-diam menjadi data kosong.
- **Tanpa uji otomatis.** Repo belum punya test suite.

## Saran perbaikan (belum diimplementasi)

1. Parse `--min-risk` di CLI dan beri error untuk flag tidak dikenal.
2. Ganti `esc()` dengan `csv()` di tiga CSV tersisa.
3. Ambil tanggal sekarang dari `SystemTime` (fungsi `civil_from_days` sudah ada di `main.rs`).
4. Gunakan pencocokan dengan batas kata (word boundary) untuk `bri`, `react`, `bca`, `ovo`, `dana`, dan normalisasi domain untuk `x.com/`.
5. Terima respons 4xx/5xx sebagai konten (ambil body dari `Error::Status`).
6. Normalisasi input host (buang skema, path, port, huruf kecil).
