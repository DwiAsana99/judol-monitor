# SPEC: Judol Monitor

Sistem pemantauan infeksi judol (judi online) / webshell / cloaking pada banyak web app di beberapa VPS,
dengan agent per-VPS yang mengirim (push) hasil scan ke server pusat, dashboard, dan alert Telegram.

> Dokumen ini adalah spesifikasi untuk dilanjutkan di Claude Code lokal. Sudah ada **implementasi referensi**
> (`judol-monitor.zip`: `agent/` + `server/`) yang lulus tes end-to-end dengan data tiruan.
> Tugas di Claude Code: pasang, uji pada data asli, kurangi false positive, dan kerjakan backlog di bagian 12.

---

## 1. Latar belakang & tujuan

- Pemilik mengelola beberapa web app di VPS: **Laravel, WordPress (PHP), FastAPI, Moodle (elearning, prioritas tinggi), SLiMS (perpustakaan)**.
- Gejala: setiap ada notifikasi "claim owner" di Google Search Console berarti situs disusupi judol
  (penyusup memasang token verifikasi Google, lalu menyuntikkan halaman/link judol, biasanya dengan cloaking).
- Menghapus index bisa lewat Search Console, tetapi **file dan database yang terinfeksi harus ditelusuri**.

**Tujuan**
1. Menemukan file dan konten terindikasi judol/webshell/backdoor di semua web app, dari satu tempat.
2. Mendeteksi cloaking (konten judol yang hanya tampil ke Google) dari luar.
3. Memberi alert Telegram hanya untuk temuan **baru atau berubah** (bukan mengulang yang lama).
4. Melacak token/file verifikasi Google yang mencurigakan (indikator claim owner).
5. Memeriksa database Moodle dan SLiMS (tempat injeksi konten).

**Bukan tujuan**: pembersihan otomatis (semua komponen **read-only** terhadap web app), antivirus penuh, WAF.

## 2. Prinsip desain (wajib dipertahankan)

- **Read-only**: agent tidak pernah mengubah/menghapus file web app. Pembersihan dilakukan manusia.
- **Push, bukan pull**: VPS hanya membuka koneksi keluar. Pusat tidak menyimpan kredensial SSH ke VPS
  (jika pusat dibobol, VPS tidak ikut terbuka).
- **Minim data sensitif**: agent hanya mengirim metadata (path, aturan, skor, sha256, ukuran, mtime).
  Potongan kode hanya dikirim jika `send_snippets=true`.
- **Agent tanpa dependensi** (stdlib Python 3.8+) supaya mudah dipasang di VPS mana pun.
- **Alert berbasis perubahan**: identitas temuan = `(app, path)`; berubah jika `sha256` berubah.
- Bahasa UI dan pesan: **Indonesia**.

## 3. Arsitektur

```
 VPS-1..N                                   Server pusat
┌──────────────────────┐   HTTPS POST     ┌────────────────────────────────────────┐
│ agent.py (cron 6 jam)│ ───────────────▶ │ FastAPI  /api/report  (Bearer token)   │
│  └ scan_judol.py     │  JSON metadata   │  ├ SQLite (hosts, apps, findings, ...) │
│  (baca file saja)    │                  │  ├ Dashboard (HTTP Basic + CSRF)       │
└──────────────────────┘                  │  ├ Scheduler: probe cloaking, stale    │
                                          │  └ Alert → Telegram Bot API            │
 Internet ◀── probe.py: fetch URL dengan 4 identitas (normal, dari Google,          │
              Googlebot, HP dari Google) lalu bandingkan                             │
                                          └────────────────────────────────────────┘
```

Struktur repo:
```
judol-monitor/
  agent/  scan_judol.py  agent.py  agent.example.json  db_check_moodle.sql  db_check_slims.sql
  server/ app.py  probe.py  requirements.txt
  README.md
```
Server mengimpor `scan_judol` (untuk `JUDOL_RE`, `FANCY_RE`) dari `../agent` atau `$SCANNER_DIR`.

## 4. Komponen

### 4.1 `scan_judol.py` (scanner, bisa dipakai mandiri via CLI)
API utama: `scan_tree(root, since=0, min_score=3, include_vendor=False, profile="generic") -> (results, google, total_files)`
- `results[]`: `{score, level, file(relatif), mtime, size, sha256, hits[(rule, weight, line, desc)]}`
- `google[]`: `{type: "file-html"|"meta-tag", file, token, mtime}`
- Level dari skor: `>=10 HIGH`, `>=5 MEDIUM`, sisanya `LOW`. Hanya file dengan `skor >= min_score` yang dilaporkan.
- Yang dilewati default: `.git .svn .hg node_modules vendor .next __pycache__ .cache venv .venv site-packages .idea`. File > 5 MB tidak dibaca isinya.
- CLI: `python scan_judol.py PATH... [--since N] [--min-score N] [--include-vendor] [--out csv] [--json file] [--known-tokens file]`

**Kategori deteksi (skor = jumlah bobot aturan yang cocok)**
| Kategori | Contoh | Bobot |
|---|---|---|
| Kata kunci judol (slot gacor, togel, rtp, maxwin, sbobet, dst.) | bobot naik menurut jumlah kata berbeda: `min(3+2*(n-1), 12)` | 3–12 |
| Huruf unicode "fancy" (𝗦𝗟𝗢𝗧) ≥3 kali | | 4 |
| Eksekusi berbahaya PHP | `eval(base64_decode…)`, `eval($_POST…)`, `preg_replace /e`, `create_function`, fungsi dinamis dari input | 5–10 |
| Eksekusi berbahaya Python | `exec(base64.b64decode…)`, `os.system/subprocess` dengan input request | 6–9 |
| Obfuscation | base64 panjang, blob hex, `chr()` beruntun, JS `_0x…`, `eval(atob())` | 3–7 |
| Cloaking di kode | deteksi UA bot/Googlebot, referer Google/Bing; `.htaccess` RewriteCond UA/referer | 6–7 |
| Include/redirect luar | `include 'http…'`, `header('Location: http…')`, meta refresh, JS redirect | 2–8 |
| Link/iframe tersembunyi | `display:none`, `left:-9999px`, iframe 0x0 | 5–6 |
| Nama/lokasi mencurigakan | PHP di folder upload/media/cache; file tersembunyi `.x.php`; `x.php.jpg`; nama shell (`shell`, `cmd`, `wso`, dst.) ; nama pendek huruf kecil ≤3 (`a.php`) | 4–6 |
| Persistensi | `auto_prepend_file`, `AddType application/x-httpd-php .jpg` | 6–9 |
| Baris sangat panjang di PHP (>3000 char) | | 3 |

**Profil per aplikasi (`profile_checks`)**
- `laravel`: PHP selain `public/index.php` di `public/` (7); `.env`/`phpinfo.php` di `public/` (10).
- `wordpress`: file di `mu-plugins` (4); PHP di `wp-content/uploads` (6); PHP menyamar gambar di theme/plugin (6).
- `moodle`: PHP non-inti di root (6); PHP di `moodledata/cache/sessions/filedir/temp` (9); PHP di `pix/fonts/img` (6); `config.php` memuat `eval/base64_decode/gzinflate/http` (10).
- `slims`: PHP di `images/ files/ repository/ uploads/` (8); `sysconfig.local.inc.php` memuat fungsi mencurigakan (10).
- `fastapi`: skrip `.py/.sh/.pl/…` di folder upload/static (6) + aturan Python di atas.
- Semua profil: skrip (`.py .sh .pl .cgi .jsp .asp .aspx`) di folder upload (6).

**Artefak verifikasi Google**: cari file `google[0-9a-f]{16}.html` dan `<meta name="google-site-verification" content=…>`.

### 4.2 `agent.py`
- Config JSON (`agent.example.json`): `server_url, token, host_name, send_snippets(false), min_score(3), apps[{name,type,path,include_vendor}]`.
- Tipe: `laravel|wordpress|moodle|slims|fastapi|generic`.
- Alur: scan tiap app → bangun payload → `POST {server_url}/api/report` dengan `Authorization: Bearer <token>`; retry 3x untuk error jaringan (tidak retry untuk 4xx).
- `--dry-run` mencetak payload tanpa mengirim. Exit code 0 jika HTTP 200.
- Path pada payload relatif terhadap root app dan memakai `/`.

**Payload**
```json
{"host":"vps-1","agent_version":1,"scan_started":1790000000,"duration_sec":12.3,
 "apps":[{"name":"elearning","type":"moodle","files_scanned":18234,"error":null,
   "findings":[{"file":"pix/icon.php","score":16,"level":"HIGH","mtime":"2026-09-26 10:44","size":158,
     "sha256":"…","hits":[{"rule":"eval-request","weight":10,"line":1,"desc":"…"}]}],
   "google":[{"type":"meta-tag","file":"theme/head.html","token":"…"}]}]}
```

### 4.3 Server pusat (`app.py`, FastAPI + SQLite)
**CLI**: `add-host NAME` (cetak token sekali; simpan hanya sha256-nya), `rotate-token NAME`, `list-hosts`, `run --host --port`.

**Env**: `DASH_USER, DASH_PASS` (wajib), `DB_PATH, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_API, ALERT_MIN_LEVEL(HIGH), STALE_HOURS(26), PROBE_INTERVAL_MIN(360), PUBLIC_URL, DISABLE_SCHEDULER`.

**Endpoint**
| Method | Path | Auth | Fungsi |
|---|---|---|---|
| POST | `/api/report` | Bearer token host | terima laporan agent (maks 8 MB); `payload.host` harus = nama host pemilik token |
| GET | `/` | Basic | ikhtisar host/app, hitungan temuan baru per level, token Google belum diverifikasi, situs probe, 15 alert terakhir |
| GET | `/app/{id}` | Basic | rincian temuan + token Google |
| POST | `/finding/{id}/ack` | Basic+CSRF | tandai aman (mengikat `ack_sha = sha256` saat ini) |
| POST | `/google/{id}/known` | Basic+CSRF | tandai token sah |
| POST | `/site/add`, `/site/{id}/delete`, `/probe/run` | Basic+CSRF | kelola & jalankan probe |

**Model data (SQLite)**: `hosts(name, token_hash, last_report, last_ip, stale_alerted)`, `apps(host_id, name, type, files_scanned, last_scan, error)`,
`findings(app_id, file, sha256, level, score, hits(json), mtime, size, first_seen, last_seen, status, ack_sha)` unik `(app_id,file)`,
`google_tokens(app_id, type, file, token, first_seen, last_seen, status)` unik `(app_id,file,token)`,
`sites(name, url, last_probe, status, detail(json), last_alert_hash)`, `alerts(ts, text, sent, note)`, `meta(csrf)`.

**Aturan status temuan (inti logika)** dalam `process_report`:
- Belum ada → insert `new`, alert.
- `ack` dan `sha256 == ack_sha` → tetap `ack`, tidak alert.
- `new` dan sha sama → tidak alert.
- sha berubah (termasuk yang sudah `ack`), atau `resolved` muncul lagi → `new` (ack dicabut), alert ("ISI BERUBAH"/"muncul lagi").
- Ada di DB tapi tak ada di laporan → `resolved`.
- Token Google: baru → `unverified` + alert; hilang → `gone`; muncul lagi → `unverified`.
- **Laporan pertama sebuah app** → satu pesan ringkasan (jumlah temuan, HIGH, token), bukan satu alert per file.
- Alert temuan hanya untuk level ≥ `ALERT_MIN_LEVEL`; token Google baru selalu di-alert.
- Watchdog: host tidak melapor > `STALE_HOURS` → alert sekali (reset saat lapor lagi).

**Telegram**: `sendMessage` polos (tanpa parse_mode), maksimal 4000 karakter, dikirim di thread terpisah; hasil (sent/note) dicatat di tabel `alerts` dan tampil di dashboard. Jika env belum diisi, alert tetap tercatat dengan catatan "belum dikonfigurasi".

### 4.4 `probe.py` (deteksi cloaking dari luar)
- Ambil URL dengan 4 varian: `normal`, `google_referer` (Referer google.com), `googlebot` (UA Googlebot), `mobile_google` (UA Android + Referer Google).
- Redirect diikuti manual (maks 6) supaya domain tujuan terlihat; jika domain tujuan tak terjangkau, tetap dianggap redirect (status 0).
- Isu **HIGH**: kata judol terlihat oleh pengunjung biasa; kata judol/huruf fancy hanya muncul di varian tertentu; varian dialihkan ke domain lain (abaikan `www.`); redirect JS/meta ke domain lain hanya di varian tertentu.
- Isu **MEDIUM**: judul beda dan ukuran halaman selisih > 60% dari varian normal.
- Status `ok|alert|error`; alert hanya jika himpunan isu berubah (hash `last_alert_hash`).

### 4.5 Skrip SQL (read-only, hanya SELECT)
- `db_check_moodle.sql`: `mdl_config` (`additionalhtmlhead/topofbody/footer`, pola script/iframe/eval), `mdl_config_plugins` (tema: customcss/scss/footnote), konten kursus/label/page/forum/profil, block HTML, admin & user baru 30 hari, plugin terpasang terbaru. Awalan `mdl_` disesuaikan dengan `$CFG->prefix`.
- `db_check_slims.sql`: `biblio` (title/notes), `content`, `setting`, `user` (admin terbaru), `member`. Kolom `groups` memakai backtick.

## 5. Keamanan
- Token agent: `secrets.token_urlsafe(32)`, disimpan hanya sebagai sha256; satu token per host; bisa dirotasi.
- Dashboard: HTTP Basic (`compare_digest`) + CSRF token (disimpan di `meta`) pada semua POST; semua keluaran HTML di-`escape`.
- Server wajib di belakang **nginx + HTTPS**; port aplikasi hanya `127.0.0.1`. Tambahkan rate limit di nginx untuk `/api/report` dan `/`.
- Agent berjalan sebagai user non-root dengan izin baca saja; `agent.json` `chmod 600`.
- Data di server pusat = peta celah keamanan: batasi akses, backup DB terenkripsi.
- Probe hanya menerima URL `http/https` yang ditambahkan admin (belum ada blokir IP privat, lihat backlog).

## 6. Deployment (ringkas)
- Server: `pip install -r server/requirements.txt`, systemd + `EnvironmentFile`, nginx reverse proxy + Let's Encrypt.
- Agent: salin `agent/` ke `/opt/judol-agent/`, isi `agent.json`, uji `--dry-run`, cron `0 */6 * * *` (user non-root).
- Telegram: buat bot via @BotFather, ambil `chat.id` dari `getUpdates`.
- Detail lengkap ada di `README.md` repo.

## 7. Pengujian yang sudah lulus (harus tetap lulus)
1. Token salah / tanpa auth → 401. CSRF salah → 403.
2. Laporan pertama 4 app (moodle, slims, laravel, fastapi) → 4 pesan ringkasan; laporan identik kedua → **0 alert**.
3. Ubah isi file HIGH → alert "ISI BERUBAH"; file dihapus → `resolved`.
4. `ack` lalu scan ulang → tidak ada alert; `ack` terikat ke sha256.
5. Situs uji yang melakukan cloaking (Googlebot → konten slot, referer Google → 302 ke domain lain) → alert HIGH untuk googlebot, google_referer, mobile_google; situs bersih → `ok`.
6. `Tag.php`/`Ok.php` (kelas Laravel) dan `config.php` sah **tidak** kena aturan "nama mencurigakan"; `public/.env` = HIGH.

## 8. Format hasil yang diharapkan pada temuan (contoh)
`[HIGH] pix/icon.php — ISI BERUBAH (eval-request,moodle-php-in-assets)`; pesan alert selalu memuat host/app, level, path, aturan, dan tautan dashboard bila `PUBLIC_URL` diisi.

## 9. Prioritas & konteks bisnis
- **Moodle (elearning) paling penting** → pertimbangkan interval scan lebih rapat dan `ALERT_MIN_LEVEL=MEDIUM` untuk app ini.
- Perpustakaan = SLiMS; VPS lain: Laravel, WordPress, FastAPI.

## 10. Batasan yang diketahui
- Deteksi berbasis pola: ada false positive (mitigasi: ack per hash) dan malware baru bisa lolos.
- Tidak ada verifikasi checksum core (WordPress/Moodle/SLiMS).
- Injeksi yang hanya ada di DB tidak terdeteksi oleh agent (hanya lewat skrip SQL manual).
- Agent memindai isi file penuh tiap siklus (bisa berat di app besar).

## 11. Yang perlu dilakukan pertama kali di Claude Code lokal
1. Ekstrak zip, jalankan tes bagian 7 ulang (buat fixture di `tests/`; gunakan pytest + server uji lokal seperti `cloak.py` di bagian 4.4).
2. Pasang server dan agent di lingkungan nyata; jalankan agent dengan `--dry-run` pada tiap app dan **tinjau false positive** (terutama Moodle plugin pihak ketiga, WordPress plugin, template SLiMS).
3. Sesuaikan aturan/bobot berdasarkan hasil nyata; catat pengecualian sah lewat mekanisme ack atau allowlist (backlog).

## 12. Backlog (urut prioritas)
1. **Uji unit/integrasi** (pytest) untuk `scan_tree`, `process_report` (semua transisi status), `probe_url`; CI.
2. **Allowlist global** per path/pola/sha256 (mis. plugin Moodle sah) selain ack per temuan; impor daftar hash sah.
3. **Baseline integritas file**: hash seluruh file inti (`index.php`, `.htaccess`, `config.php`, `wp-config.php`, `sysconfig.local.inc.php`) dan alert jika berubah tanpa deploy; opsi `wp core verify-checksums` / hash rilis Moodle & SLiMS.
4. **Scan inkremental** (cache mtime+sha di agent) supaya cepat pada app besar; opsi `since` untuk scan penuh mingguan + inkremental harian.
5. **Agent untuk pemeriksaan DB** terjadwal (Moodle/SLiMS/WordPress) dengan koneksi read-only, hasilnya ikut dikirim ke pusat (tanpa menyimpan kredensial di pusat).
6. **Pemeriksaan log web server**: pola akses ke webshell (POST ke file di uploads), user-agent Googlebot palsu, lonjakan URL judol/sitemap aneh.
7. **Cek indeks Google**: pantau `site:domain slot|togel|gacor` (Search Console API atau pencarian) dan bandingkan sitemap dengan yang sah.
8. **Search Console API**: ambil daftar owner/verified users dan tandai yang tidak ada di daftar sah; hitung URL terindeks baru yang mencurigakan.
9. Blokir SSRF pada probe (tolak IP privat/loopback kecuali di allowlist), rate limit dan lockout login dashboard, dukungan multi-user + 2FA.
10. Ganti `@app.on_event("startup")` ke lifespan (deprecation FastAPI); bersihkan kondisi `lang` yang redundan pada profil Moodle di `profile_checks`.
11. Notifikasi alternatif (email/webhook), ringkasan harian, halaman riwayat/diff per file, ekspor CSV.
12. Paket instalasi: `install.sh`/Dockerfile untuk server, unit systemd + timer untuk agent (Windows Task Scheduler bila perlu).

## 13. Kriteria selesai (Definition of Done)
- Semua tes bagian 7 otomatis dan hijau di CI.
- Agent terpasang di semua VPS, laporan masuk terjadwal, tidak ada VPS berstatus "tidak lapor".
- Semua temuan awal sudah ditinjau: dibersihkan atau di-ack dengan alasan; token Google tak dikenal sudah dihapus dan owner di Search Console dibersihkan.
- Alert Telegram terverifikasi diterima untuk: temuan HIGH baru, token Google baru, cloaking terdeteksi, host tidak melapor.
