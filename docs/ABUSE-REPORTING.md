# Alur pelaporan abuse

Penindakan dilakukan **hanya** lewat pelaporan ke pihak yang berwenang atas infrastruktur, bukan dengan menyerang situs. Ini aturan inti toolkit (lihat [RULES.md](../RULES.md)).

## Alur

```
scan  →  triage manual  →  generate draf  →  review  →  kirim
```

1. **Scan** dengan `--out report.json --landing-dir landing`.
2. **Triage manual.** Buka `report.html`, urut dari risk tertinggi. Buka landing page yang tersimpan di browser (jangan di mesin yang sensitif) dan pastikan memang konten judi. Skor adalah heuristik, bukan bukti.
3. **Generate draf:**

   ```bash
   python3 tools/abuse_report.py report.json --out reports --min-risk 60
   ```

4. **Review.** Edit draf, lengkapi kontak abuse tujuan, tambahkan screenshot bertimestamp WIB.
5. **Kirim** ke tujuan yang relevan di bawah.

## `tools/abuse_report.py`

Hanya library standar Python 3, tidak melakukan panggilan jaringan.

| Argumen | Default | Keterangan |
|---|---|---|
| `report` | - | Path `report.json` hasil scan |
| `--out` | `reports` | Folder keluaran |
| `--min-risk` | 0 | Hanya buat laporan untuk risk ≥ nilai ini |

Keluaran:

- `reports/<host>.md`: satu laporan per host (karakter selain `[A-Za-z0-9._-]` diganti `_`)
- `reports/_bundle.md`: gabungan semua laporan

Isi tiap laporan: tier dan risk, URL akhir, status HTTP, IP, ASN/org/negara, umur domain, skor SEO, metode pembayaran, kanal kontak publik, catatan "retas" bila ada, alasan laporan, daftar tujuan pengiriman, dan daftar bukti.

## Tujuan pelaporan

| Tujuan | Sumber kontak |
|---|---|
| Hosting / pemilik ASN | Abuse contact dari whois ASN (`whois -h whois.cymru.com`, atau `abuse-c` di RIR) |
| Cloudflare (jika di depan origin) | https://abuse.cloudflare.com/ |
| Registrar domain | Abuse contact di whois domain |
| Regulator Indonesia | Template memakai https://aduankonten.id/ dan "BRTF aduan telekomunikasi" |
| Payment provider | Kanal merchant abuse masing-masing (DANA, OVO, GoPay, bank) |

Deteksi Cloudflare di skrip: nama org mengandung `CLOUDFLARE`, atau IP berawalan `104.` / `172.67.`. Awalan `104.` mencakup blok yang tidak seluruhnya milik Cloudflare, jadi periksa ulang.

## Verifikasi sebelum mengirim

- **Nama regulator.** Template masih menyebut Kominfo dan "BRTF". Kominfo sudah menjadi Komdigi, dan lembaga regulasi telekomunikasinya setahuku bernama BRTI (kemungkinan "BRTF" adalah typo). Cek kanal aduan terbaru di situs resminya sebelum mengirim.
- **Dasar hukum.** Paragraf "Why this is reportable" menyebut KUHP dan UU ITE secara umum. Sesuaikan atau konsultasikan ke pihak hukum bila laporan dikirim ke penegak hukum.
- **Bahasa.** Template berbahasa Inggris, cocok untuk hosting global dan Cloudflare. Untuk regulator atau bank lokal, terjemahkan ke Bahasa Indonesia.
- **Kontak pihak ketiga.** Jangan mencantumkan nomor atau email yang terkumpul di laporan publik. Pada situs sah yang diretas, kontak itu bisa milik korban.
