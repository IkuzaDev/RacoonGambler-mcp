# Scoring & heuristik

Semua logika ada di `src/recon.rs`. Tidak ada machine learning: murni pencocokan substring tanpa membedakan huruf besar/kecil.

## 1. Keyword judol (`GAMBLE_KW`)

36 keyword, antara lain: `slot`, `situs judi`, `bandar`, `togel`, `judi online`, `casino`, `toto`, `poker`, `domino`, `capsa`, `sportsbook`, `parlay`, `maxwin`, `gacor`, `rtp slot`, `rtp live`, `deposit pulsa`, `wd gampang`, `bonus new member`, `judi bola`, `togel hk/sgp/sdy`, `live casino`, `slot88`, `pragmatic`, `pgsoft`, `habanero`, `sbobet`, `maxbet`, `daftar togel`, `situs toto`, `bandar togel`, `judi slot`, `pasti maxwin`, `gampang menang`.

Pencocokan dilakukan pada **HTML mentah** (termasuk atribut dan script), bukan hanya teks yang terlihat.

## 2. `seo_score` (0–100)

| Komponen | Poin |
|---|---|
| Jumlah keyword unik yang cocok | `min(jumlah × 6, 40)` |
| Kepadatan keyword | `min(int(density%) × 8, 20)` |
| Ada keyword di salah satu `<h1>` | +15 |
| Ada keyword di `<title>` | +10 |
| Total kemunculan keyword ≥ 25 | +10 |
| Kata < 400 dan ada keyword | +5 |

- `density = 100 × total_kemunculan / jumlah_kata`, dengan jumlah kata dihitung dari HTML setelah tag dibuang (isi `<script>` dan `<style>` ikut terhitung).
- Pembulatan `int(density)` memotong desimal, jadi density di bawah 1% tidak memberi poin dan density ≥ 3% sudah mencapai batas 20.
- `doorwayish = true` bila jumlah kata < 400 **dan** `seo_score ≥ 50`.

## 3. `risk` (0–100)

```
risk = 0.45 × seo_score
     + umur domain:     < 90 hari → +20,  < 365 hari → +12
     + pembayaran:      min(3 × jumlah_metode, 15)
     + hacked != null   → +15
     + doorwayish       → +8
     + sibling_count ≥ 3 → +7
risk = round(min(risk, 100))
```

`sibling_count` = jumlah subdomain dari crt.sh (maks 40). Jika whois gagal, `domain_age_days` kosong dan bonus umur tidak diberikan.

### Tier

| Risk | Tier |
|---|---|
| ≥ 80 | `CRITICAL` |
| 60–79 | `HIGH` |
| 40–59 | `MEDIUM` |
| < 40 | `LOW` |

### Contoh terverifikasi

Halaman uji dengan judul "Slot Gacor Maxwin | Bandar Togel", 11 keyword unik, 14 kemunculan total, 35 kata (density 40%), `<h1>` berisi keyword, 6 metode pembayaran:

```
seo_score = 40 (keyword) + 20 (density) + 15 (h1) + 10 (title) + 0 (kemunculan 14 < 25) + 5 (< 400 kata)
          = 90
```

Hasil aktual tool: `seo_score = 90`, `doorwayish = true`, `risk = 64`, tier `HIGH`:

```
0.45 × 90 = 40.5
+ pembayaran min(6 × 3, 15) = 15
+ doorwayish = 8
= 63.5 → 64
```

(Umur domain dan subdomain tidak tersedia pada host uji lokal.)

## 4. Verdict "retas" (`hacked_verdict`)

Flag `website ini mungkin telah di retas` diberikan bila **semua** terpenuhi:

1. `seo_score ≥ 40`
2. Host atau title mengandung salah satu `LEGIT_HINT`: `berita`, `news`, `sekolah`, `school`, `komunitas`, `community`, `blog`, `toko`, `shop`, `organisasi`, `desa`, `village`, `masjid`, `klinik`, `clinic`, `univ`, `universitas`, `college`, `academy`, `yayasan`, `portal`, `magazine`, `jurnal`
3. Minimal 2 keyword judol unik cocok

`confidence` = `high` bila `seo_score ≥ 70`, selain itu `medium`. Alasan (`reason`) memuat skor dan maksimal 6 keyword.

Ini heuristik kasar untuk menangkap injeksi konten judol pada situs sah (sekolah, desa, berita). Pencocokan memakai substring sehingga bisa meleset; lihat [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## 5. Metode pembayaran (`PAY_PATTERNS`)

Substring yang dicari di HTML: `dana`, `ovo`, `gopay`, `qris`, `pulsa`, `bca`, `mandiri`, `bri`, `usdt`, `linkaja`, `shopeepay`, dipetakan ke label seperti `DANA`, `OVO`, `Bank BRI`, `Bitcoin/USDT`.

## 6. Tech stack (`TECH_PATTERNS`)

Substring: `wp-content` (WordPress), `woocommerce`, `jquery`, `bootstrap`, `react`, `cloudflare`, `gtag(` (Google Analytics), `font-awesome`. Field `generator` selalu kosong.

## 7. Ekstraksi kontak

| Channel | Pola |
|---|---|
| `telegram` | handle setelah `t.me/` |
| `whatsapp` | digit (≥ 8) setelah `wa.me/` atau `api.whatsapp.com/send?phone=` |
| `email` | token berisi `@` dan `.`, panjang < 64 |
| `phone_id` | rangkaian digit berawalan `62` (10–15 digit) atau `0` (9–14 digit), `+` opsional |
| `facebook`, `instagram` | handle setelah `facebook.com/`, `instagram.com/` |
| `youtube` | setelah `youtube.com/@` atau `youtube.com/channel/` |
| `tiktok` | setelah `tiktok.com/@` |
| `twitter` | setelah `twitter.com/` atau `x.com/` |

Setiap channel diurutkan, di-dedup, dan dibatasi 8 nilai.

## 8. Outbound hosts (`backlinks`)

Semua `href="http...` ke host lain, dibatasi 30 host unik, disimpan di `seo.outbound_hosts` dan `backlinks`. Dengan `--backlinks`, `ref_hosts` berisi host pencari balik (maks 30) dari DDG + Bing memakai query merek hasil turunan `<title>`.
