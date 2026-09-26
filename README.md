# Judol Monitor — Server Pusat

Server pusat untuk Judol Monitor. Agent di tiap VPS memindai file web app (read-only) lalu **mengirim (push)**
hasilnya ke server ini. Server menampilkan dashboard, mendeteksi temuan baru/berubah, memantau cloaking
dari luar, dan mengirim alert ke Telegram.

Agent tidak ada di repo ini; agent dipasang terpisah di tiap VPS dan mengirim laporan ke `POST /api/report`.

```
app.py            FastAPI + SQLite: API agent, dashboard, scheduler, alert Telegram, CLI
probe.py          deteksi cloaking dari luar (4 identitas: normal, referer Google, Googlebot, HP dari Google)
scan_judol.py     salinan scanner agent; dipakai probe.py untuk pola kata judol (JUDOL_RE, FANCY_RE)
```

> `scan_judol.py` adalah salinan dari agent. Jika aturan kata judol di agent diubah, perbarui juga file ini.

## Menjalankan dengan Docker (disarankan)

```bash
cp .env.example .env                  # isi DASH_PASS, TELEGRAM_*, PUBLIC_URL
docker compose up -d --build
docker compose exec server python app.py add-host vps-1   # SIMPAN token yang tampil (sekali saja); satu token per VPS
docker compose exec server python app.py list-hosts
docker compose logs -f
```

- Port hanya terbuka di `127.0.0.1:8000`; publik lewat nginx + HTTPS (lihat di bawah).
- Database SQLite ada di volume `judol-data` (`/data/monitor.db`). Backup: `docker compose cp server:/data/monitor.db ./backup.db`.
- Container berjalan sebagai user non-root `judol`.
- Dari host, koneksi masuk ke container lewat gateway bridge `172.30.0.1` (subnet dipatok di compose), jadi
  `FORWARDED_ALLOW_IPS=172.30.0.1`. Jika subnet diubah atau nginx juga dijalankan di Docker, sesuaikan nilai ini.

## Menjalankan tanpa Docker (venv)

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt       # Windows: .venv/Scripts/python
.venv/bin/python app.py add-host vps-1
export DASH_USER=admin DASH_PASS='password-panjang'
.venv/bin/python app.py run --host 127.0.0.1 --port 8000
```

Contoh systemd: `/etc/systemd/system/judol-monitor.service`
```
[Service]
WorkingDirectory=/opt/judol-monitor
EnvironmentFile=/etc/judol-monitor.env      # berisi DASH_USER=..., DASH_PASS=..., TELEGRAM_...
ExecStart=/opt/judol-monitor/.venv/bin/python app.py run --port 8000
Restart=always
User=judol
```

## Konfigurasi (env)

| Variabel | Keterangan |
|---|---|
| `DASH_USER`, `DASH_PASS` | wajib; login dashboard (HTTP Basic) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | tujuan alert; jika kosong, alert hanya dicatat |
| `PUBLIC_URL` | opsional, untuk tautan dashboard di pesan alert |
| `ALERT_MIN_LEVEL` | `HIGH` (default) / `MEDIUM` / `LOW` |
| `STALE_HOURS` | default 26; host tidak melapor lebih lama → alert |
| `PROBE_INTERVAL_MIN` | default 360; interval probe cloaking |
| `DB_PATH` | lokasi SQLite (Docker: `/data/monitor.db`) |
| `FORWARDED_ALLOW_IPS` | IP proxy yang dipercaya mengirim `X-Forwarded-For` (default `127.0.0.1,::1`) |

Bot Telegram: buat lewat @BotFather (dapat token), kirim satu pesan ke bot, lalu buka
`https://api.telegram.org/bot<TOKEN>/getUpdates` untuk melihat `chat.id`.

## nginx + HTTPS

Jangan buka port 8000 langsung ke internet. Pasang nginx + Let's Encrypt di depannya. Agar IP asli VPS
tercatat (`last_ip`), nginx wajib mengirim `X-Forwarded-For $remote_addr`.

Config siap pakai untuk `monju.dwiputraasana.my.id` (HTTPS, redirect HTTP, rate limit, allowlist opsional):
[deploy/nginx/monju.dwiputraasana.my.id.conf](deploy/nginx/monju.dwiputraasana.my.id.conf).

Pemasangan di server (Debian/Ubuntu, DNS sudah mengarah ke server):
```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo ufw allow 80,443/tcp                          # jika memakai ufw; buka juga di firewall provider
sudo certbot certonly --nginx -d monju.dwiputraasana.my.id
sudo cp deploy/nginx/monju.dwiputraasana.my.id.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```
Perpanjangan sertifikat berjalan otomatis lewat timer certbot. Di agent, isi
`"server_url": "https://monju.dwiputraasana.my.id"`.

## Probe cloaking

Di dashboard, tambahkan URL situs (mis. beranda elearning & perpustakaan). Server mengambilnya sebagai
pengunjung biasa, dari Google, sebagai Googlebot, dan HP dari Google, lalu membandingkan. Kata judol yang
hanya muncul untuk Googlebot/pengunjung Google, atau redirect ke domain lain, memicu alert.

## Alur kerja saat ada alert
1. Buka dashboard, tinjau temuan HIGH. Jika sah, klik **tandai aman** (terikat ke hash isi file; jika file berubah, alert muncul lagi).
2. Token Google yang tidak dikenal: hapus file/meta-nya, lalu un-verify owner di Search Console.
3. Tutup celah masuknya (update Moodle/SLiMS/plugin, ganti password admin/FTP/DB, cek user admin baru, cek cron).
