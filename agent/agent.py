#!/usr/bin/env python3
"""
agent.py - Agent scan judol untuk dipasang di setiap VPS.

Menjalankan scan_judol pada tiap web app di config, lalu MENGIRIM (push) hasilnya
ke server pusat lewat HTTPS. Tidak membuka port, tidak mengubah/menghapus file.
Hanya butuh Python 3.8+ (tanpa library tambahan).

  python3 agent.py --config agent.json            # scan + kirim
  python3 agent.py --config agent.json --dry-run  # scan saja, cetak payload (tidak dikirim)
"""
import argparse, json, os, socket, sys, time, urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_judol  # noqa: E402


def build_payload(cfg):
    started = time.time()
    send_snip = bool(cfg.get("send_snippets", False))
    apps_out = []
    for app in cfg["apps"]:
        path = app["path"]
        if not os.path.isdir(path):
            apps_out.append({"name": app["name"], "type": app.get("type", "generic"),
                             "error": "folder tidak ditemukan: " + path,
                             "findings": [], "google": [], "files_scanned": 0})
            continue
        results, google, total = scan_judol.scan_tree(
            path, min_score=int(cfg.get("min_score", 3)),
            include_vendor=bool(app.get("include_vendor", False)),
            profile=app.get("type", "generic"))
        findings = []
        for r in results:
            hits = []
            for name, w, line, desc in r["hits"]:
                if not send_snip and " | " in desc:
                    desc = desc.split(" | ", 1)[0]  # buang potongan kode, kirim metadata saja
                hits.append({"rule": name, "weight": w, "line": line, "desc": desc[:300]})
            findings.append({"file": r["file"].replace("\\", "/"), "score": r["score"], "level": r["level"],
                             "mtime": r["mtime"], "size": r["size"], "sha256": r["sha256"], "hits": hits})
        g_out = [{"type": g["type"], "file": g["file"].replace("\\", "/"), "token": g["token"]} for g in google]
        apps_out.append({"name": app["name"], "type": app.get("type", "generic"),
                         "files_scanned": total, "findings": findings, "google": g_out})
    return {"host": cfg.get("host_name") or socket.gethostname(),
            "agent_version": 1, "scan_started": int(started),
            "duration_sec": round(time.time() - started, 1), "apps": apps_out}


def send(cfg, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(cfg["server_url"].rstrip("/") + "/api/report", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + cfg["token"],
                                          "User-Agent": "judol-agent/1"})
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]  # 401/403 dsb: jangan diulang
        except Exception as e:  # jaringan: coba lagi
            last = e
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("gagal mengirim laporan: %s" % last)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="agent.json")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    with open(a.config, encoding="utf-8") as f:
        cfg = json.load(f)
    payload = build_payload(cfg)
    n = sum(len(x["findings"]) for x in payload["apps"])
    if a.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    code, text = send(cfg, payload)
    print("[%s] %d app, %d temuan -> server: HTTP %s %s" % (time.strftime("%F %T"), len(payload["apps"]), n, code, text[:200]))
    sys.exit(0 if code == 200 else 1)


if __name__ == "__main__":
    main()
