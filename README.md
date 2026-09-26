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

## Alert Telegram

Server mengirim alert lewat bot Telegram ke satu chat: chat pribadi atau grup (disarankan grup, agar
beberapa admin ikut menerima).

### 1. Buat bot
1. Di Telegram, buka **@BotFather** → kirim `/newbot`.
2. Isi nama bot (bebas, mis. `Judol Monitor`) dan username (harus diakhiri `bot`, mis. `judol_monitor_bot`).
3. BotFather membalas dengan token, bentuknya `123456789:AAH...`. Ini `TELEGRAM_BOT_TOKEN`.
   Token = kunci penuh bot; jangan dibagikan atau di-commit.

### 2. Dapatkan chat ID
**Chat pribadi**: buka bot yang baru dibuat, tekan **Start** (atau kirim pesan apa saja).

**Grup**: buat grup, tambahkan bot sebagai anggota, lalu kirim satu pesan di grup yang menyebut bot,
mis. `/start@judol_monitor_bot`.

Lalu jalankan (di VPS server atau di mana saja):
```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
```
Angka setelah `"id":` adalah `TELEGRAM_CHAT_ID`:
- chat pribadi: angka positif, mis. `123456789`;
- grup: angka negatif, mis. `-1001234567890` (sertakan tanda minus).

Jika hasilnya kosong, kirim pesan lagi ke bot/grup lalu ulangi. `getUpdates` hanya menyimpan pesan
yang belum lama.

### 3. Uji kirim pesan
```bash
curl -s "https://api.telegram.org/bot<TOKEN>/sendMessage" -d chat_id=<CHAT_ID> -d text="Tes Judol Monitor"
```
Harus muncul `"ok":true` dan pesan masuk di Telegram. Jika `chat not found`: chat ID salah, atau bot
belum di-Start / belum masuk grup.

### 4. Pasang di server
```bash
cd /opt/judol-monitor
nano .env        # isi TELEGRAM_BOT_TOKEN=... dan TELEGRAM_CHAT_ID=...
docker compose up -d --force-recreate
```
`--force-recreate` wajib: `.env` hanya dibaca saat container dibuat.

### 5. Verifikasi
Alert berikutnya akan terkirim: laporan pertama sebuah app yang memiliki temuan atau token Google
(app bersih tidak memicu pesan), temuan baru/berubah, token Google baru, host tidak melapor, atau cloaking.
Status tiap alert tampil di dashboard bagian alert terakhir: terkirim, atau catatan kegagalan seperti
`Telegram belum dikonfigurasi` / `gagal: HTTP Error 400`.

Opsional: atur `ALERT_MIN_LEVEL=MEDIUM` agar temuan MEDIUM juga dikirim (disarankan untuk Moodle,
lihat prioritas di SPEC). Token Google baru selalu dikirim, apa pun levelnya.

## nginx + HTTPS

Jangan buka port 8000 langsung ke internet. Pasang nginx + Let's Encrypt di depannya. Agar IP asli VPS
tercatat (`last_ip`), nginx wajib mengirim `X-Forwarded-For $remote_addr`.

Config untuk `monju.dwiputraasana.my.id` dipasang dalam dua tahap, karena config HTTPS merujuk file
sertifikat yang belum ada sebelum certbot berhasil (`nginx -t` gagal: `cannot load certificate`):
- [deploy/nginx/1-http.conf](deploy/nginx/1-http.conf): HTTP saja + jalur ACME, untuk meminta sertifikat.
- [deploy/nginx/2-https.conf](deploy/nginx/2-https.conf): HTTPS, redirect HTTP, rate limit, allowlist opsional.

Keduanya dipasang ke file yang sama, `/etc/nginx/conf.d/monju.dwiputraasana.my.id.conf`
(jangan aktifkan keduanya bersamaan). Langkah di server (Debian/Ubuntu, DNS sudah mengarah ke server,
container sudah jalan):

```bash
# 0. Paket + firewall (buka juga port 80/443 di panel firewall provider)
sudo apt install nginx certbot
sudo ufw allow 80,443/tcp                          # jika memakai ufw

# 1. Tahap HTTP
sudo mkdir -p /var/www/certbot
sudo cp deploy/nginx/1-http.conf /etc/nginx/conf.d/monju.dwiputraasana.my.id.conf
sudo nginx -t && sudo systemctl reload nginx
curl -I http://monju.dwiputraasana.my.id/          # dari luar server; harus 401 (minta login dashboard)

# 2. Minta sertifikat
sudo certbot certonly --webroot -w /var/www/certbot -d monju.dwiputraasana.my.id \
     --deploy-hook "systemctl reload nginx"

# 3. Tahap HTTPS
sudo cp deploy/nginx/2-https.conf /etc/nginx/conf.d/monju.dwiputraasana.my.id.conf
sudo nginx -t && sudo systemctl reload nginx
curl -I https://monju.dwiputraasana.my.id/         # harus 401
```

Jika langkah 1 atau 2 gagal, periksa:
- `curl -I` dari luar tidak tersambung: port 80 masih tertutup di ufw atau firewall provider.
- `nginx -t` mengeluh `conflicting server name` / `duplicate zone`: ada config lama untuk domain ini
  (mis. di `/etc/nginx/sites-enabled/`); hapus yang lama.
- certbot `unauthorized` / 404 pada `/.well-known/acme-challenge/`: DNS belum mengarah ke server ini, atau
  domain lewat proxy (mis. Cloudflare oranye) yang mengubah respons.

Perpanjangan sertifikat berjalan otomatis lewat timer certbot (memakai webroot yang sama; nginx di-reload
lewat `--deploy-hook`). Di agent, isi `"server_url": "https://monju.dwiputraasana.my.id"` setelah tahap 3 selesai.

## Probe cloaking

Di dashboard, tambahkan URL situs (mis. beranda elearning & perpustakaan). Server mengambilnya sebagai
pengunjung biasa, dari Google, sebagai Googlebot, dan HP dari Google, lalu membandingkan. Kata judol yang
hanya muncul untuk Googlebot/pengunjung Google, atau redirect ke domain lain, memicu alert.

## Alur kerja saat ada alert
1. Buka dashboard, tinjau temuan HIGH. Jika sah, klik **tandai aman** (terikat ke hash isi file; jika file berubah, alert muncul lagi).
2. Token Google yang tidak dikenal: hapus file/meta-nya, lalu un-verify owner di Search Console.
3. Tutup celah masuknya (update Moodle/SLiMS/plugin, ganti password admin/FTP/DB, cek user admin baru, cek cron).
