# Judol Monitor

Agent di tiap VPS memindai file web app, lalu **mengirim (push)** hasilnya ke server pusat.
Server pusat menampilkan dashboard, mendeteksi temuan baru/berubah, memantau cloaking dari luar,
dan mengirim alert ke Telegram. Semua bersifat read-only terhadap web app (tidak ada yang dihapus/diubah).

```
agent/   -> dipasang di setiap VPS (Python 3.8+, tanpa library tambahan)
server/  -> dipasang di 1 server pusat (Python 3.9+, fastapi + uvicorn + python-multipart)
```

## 1. Server pusat

```bash
pip install fastapi uvicorn python-multipart
cd server
python3 app.py add-host vps-1          # SIMPAN token yang tampil (sekali saja); satu token per VPS
export DASH_USER=admin DASH_PASS='password-panjang'
export TELEGRAM_BOT_TOKEN=123:ABC TELEGRAM_CHAT_ID=-100123456
export PUBLIC_URL=https://monitor.contoh.ac.id      # opsional, untuk tautan di pesan
python3 app.py run --host 127.0.0.1 --port 8000
```

- Pasang di belakang **nginx + HTTPS** (Let's Encrypt). Jangan buka port 8000 langsung ke internet.
- Agar IP asli VPS tercatat (`last_ip`), nginx wajib mengirim header IP klien. Uvicorn hanya mempercayai
  header ini dari alamat di `FORWARDED_ALLOW_IPS` (default `127.0.0.1,::1`):
  ```
  location / {
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Forwarded-Proto $scheme;
  }
  ```
- Bot Telegram: buat lewat @BotFather (dapat token), kirim satu pesan ke bot, lalu buka
  `https://api.telegram.org/bot<TOKEN>/getUpdates` untuk melihat `chat.id`.
- Opsi lain: `ALERT_MIN_LEVEL` (HIGH/MEDIUM/LOW), `STALE_HOURS` (default 26), `PROBE_INTERVAL_MIN` (default 360), `DB_PATH`.
- Contoh systemd: `/etc/systemd/system/judol-monitor.service`
  ```
  [Service]
  WorkingDirectory=/opt/judol-monitor/server
  EnvironmentFile=/etc/judol-monitor.env      # berisi DASH_USER=..., DASH_PASS=..., TELEGRAM_...
  ExecStart=/usr/bin/python3 app.py run --port 8000
  Restart=always
  User=judol
  ```

### 1b. Server pusat via Docker

Jalankan dari root repo (image ikut menyalin `agent/scan_judol.py` yang dipakai `probe.py`):
```bash
cp server/.env.example server/.env        # isi DASH_PASS, TELEGRAM_*, PUBLIC_URL
docker compose up -d --build
docker compose exec server python app.py add-host vps-1   # SIMPAN token yang tampil
docker compose exec server python app.py list-hosts
docker compose logs -f
```
- Port hanya terbuka di `127.0.0.1:8000`; pasang nginx + HTTPS di depannya seperti biasa (konfigurasi di atas).
- Dari host, koneksi masuk ke container lewat gateway bridge `172.30.0.1` (subnet dipatok di compose),
  jadi `FORWARDED_ALLOW_IPS=172.30.0.1`. Jika subnet diubah atau nginx juga dijalankan di Docker, sesuaikan nilai ini.
- Database SQLite ada di volume `judol-data` (`/data/monitor.db`). Backup: `docker compose cp server:/data/monitor.db ./backup.db`.
- Container berjalan sebagai user non-root `judol`.

### 1c. Pengembangan lokal (venv)
```bash
cd server
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux/macOS: .venv/bin/python
```

## 2. Agent di tiap VPS

1. Salin folder `agent/` ke VPS di luar web root, mis. `/opt/judol-agent/`.
2. `cp agent.example.json agent.json`, isi `server_url`, `token` (dari `add-host`), dan daftar app.
   Tipe yang dikenal: `laravel`, `wordpress`, `moodle`, `slims`, `fastapi`, `generic`.
3. Uji: `python3 agent.py --config agent.json --dry-run` (hanya cetak, tidak mengirim), lalu tanpa `--dry-run`.
4. Jadwalkan (cron, tiap 6 jam) dengan user non-root yang hanya punya izin **baca**:
   `0 */6 * * * judol /usr/bin/python3 /opt/judol-agent/agent.py --config /opt/judol-agent/agent.json >> /var/log/judol-agent.log 2>&1`
5. `chmod 600 agent.json` (berisi token).

Secara default agent hanya mengirim metadata (path, aturan, skor, hash), bukan potongan kode.
Set `"send_snippets": true` jika ingin potongan kode ikut terkirim.

## 3. Probe cloaking (dari luar)

Di dashboard, tambahkan URL situs (mis. beranda elearning & perpustakaan). Server mengambilnya sebagai
pengunjung biasa, dari Google, sebagai Googlebot, dan HP dari Google, lalu membandingkan. Kata judol yang
hanya muncul untuk Googlebot/pengunjung Google, atau redirect ke domain lain, memicu alert.

## 4. Pemeriksaan database (Moodle & SLiMS)

Banyak injeksi judol tersimpan di DB, bukan di file. Jalankan (read-only, hanya SELECT):
```
mysql -u USER -p DB_MOODLE < agent/db_check_moodle.sql > hasil_moodle.txt
mysql -u USER -p DB_SLIMS  < agent/db_check_slims.sql  > hasil_slims.txt
```
Untuk Moodle, periksa terutama `additionalhtmlhead/topofbody/footer` dan pengaturan tema. Ini titik injeksi klasik.
Sesuaikan awalan tabel `mdl_` dengan `$CFG->prefix`.

## Alur kerja saat ada alert
1. Buka dashboard, tinjau temuan HIGH. Jika sah, klik **tandai aman** (terikat ke hash isi file; jika file berubah, alert muncul lagi).
2. Token Google yang tidak dikenal: hapus file/meta-nya, lalu un-verify owner di Search Console.
3. Tutup celah masuknya (update Moodle/SLiMS/plugin, ganti password admin/FTP/DB, cek user admin baru, cek cron).

## Batasan
- Deteksi berbasis pola: bisa ada false positive (ditangani lewat "tandai aman") dan malware baru bisa lolos.
- Scan tidak membandingkan dengan checksum resmi core WordPress/Moodle; untuk itu pakai `wp core verify-checksums` atau bandingkan dengan rilis resmi.
- `vendor/`, `node_modules/`, `venv/` dilewati default (set `"include_vendor": true` per app untuk ikut dipindai).
