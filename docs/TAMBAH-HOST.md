# Menambah host (VPS baru)

Satu VPS = satu host = satu token. Jalankan di **server pusat**.

## 1. Buat token

```bash
cd /opt/judol-monitor
docker compose exec server python app.py add-host moodle-vps
```

Hasil:
```
Host: moodle-vps
Token (simpan sekarang, tidak akan ditampilkan lagi):
AbCdEf...
```

- Salin token. Token hanya tampil **sekali**.
- Nama host (`moodle-vps`) dipakai lagi di `agent.json` sebagai `host_name`. Harus sama persis.

## 2. Pasang agent di VPS tersebut

Ikuti panduan pasang agent (mis. `PASANG-AGENT-MOODLE.md`), isi `host_name` dan `token` dari langkah 1.

## 3. Cek host sudah melapor

```bash
docker compose exec server python app.py list-hosts
```
```
moodle-vps           lapor terakhir: 2m lalu  ip: 203.0.113.10
```
Jika `lapor terakhir: -`, agent belum berhasil mengirim.

## Perintah lain

| Keperluan | Perintah |
|---|---|
| Lihat semua host | `docker compose exec server python app.py list-hosts` |
| Token hilang / bocor | `docker compose exec server python app.py rotate-token moodle-vps` lalu ganti `token` di `agent.json` VPS itu |
