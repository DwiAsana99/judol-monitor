#!/usr/bin/env python3
"""
Server pusat monitor judol.

  python3 app.py add-host vps-1          # buat host + token (token tampil SEKALI)
  python3 app.py list-hosts
  python3 app.py rotate-token vps-1
  DASH_USER=admin DASH_PASS=... python3 app.py run --host 127.0.0.1 --port 8000

Env: DASH_USER, DASH_PASS (wajib), DB_PATH, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
     ALERT_MIN_LEVEL (HIGH|MEDIUM|LOW, default HIGH), STALE_HOURS (default 26),
     PROBE_INTERVAL_MIN (default 360), PUBLIC_URL (untuk tautan di pesan Telegram)
"""
import argparse, contextlib, hashlib, hmac, html, json, os, secrets, sqlite3, sys, threading, time
import urllib.parse, urllib.request

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import probe

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.db"))
LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
MAX_BODY = 8 * 1024 * 1024
LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS hosts(id INTEGER PRIMARY KEY, name TEXT UNIQUE, token_hash TEXT UNIQUE,
  created INTEGER, last_report INTEGER, last_ip TEXT, stale_alerted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY, host_id INTEGER, name TEXT, type TEXT,
  files_scanned INTEGER DEFAULT 0, last_scan INTEGER, error TEXT, recent TEXT, UNIQUE(host_id, name));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, app_id INTEGER, file TEXT, sha256 TEXT, level TEXT,
  score INTEGER, hits TEXT, mtime TEXT, size INTEGER, first_seen INTEGER, last_seen INTEGER,
  status TEXT, ack_sha TEXT, investigation TEXT, followup TEXT, note_by TEXT, note_at INTEGER, UNIQUE(app_id, file));
CREATE TABLE IF NOT EXISTS google_tokens(id INTEGER PRIMARY KEY, app_id INTEGER, type TEXT, file TEXT, token TEXT,
  first_seen INTEGER, last_seen INTEGER, status TEXT, UNIQUE(app_id, file, token));
CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY, name TEXT, url TEXT UNIQUE, added INTEGER,
  last_probe INTEGER, status TEXT, detail TEXT, last_alert_hash TEXT);
CREATE TABLE IF NOT EXISTS watch_files(id INTEGER PRIMARY KEY, app_id INTEGER, file TEXT, sha256 TEXT, size INTEGER,
  mtime INTEGER, first_seen INTEGER, last_seen INTEGER, changed_at INTEGER, status TEXT, UNIQUE(app_id, file));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts INTEGER, text TEXT, sent INTEGER DEFAULT 0, note TEXT);
"""


@contextlib.contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)
        # DB lama: tambah kolom yang belum ada
        for table, add in (("findings", (("investigation", "TEXT"), ("followup", "TEXT"), ("note_by", "TEXT"), ("note_at", "INTEGER"))),
                           ("apps", (("recent", "TEXT"),))):
            cols = {r[1] for r in c.execute("PRAGMA table_info(%s)" % table)}
            for col, typ in add:
                if col not in cols:
                    c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
        if not c.execute("SELECT 1 FROM meta WHERE k='csrf'").fetchone():
            c.execute("INSERT INTO meta VALUES('csrf', ?)", (secrets.token_hex(32),))


def csrf_token():
    with conn() as c:
        return c.execute("SELECT v FROM meta WHERE k='csrf'").fetchone()[0]


def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


# ---------------------------------------------------------------- Telegram / alert
def alert(text):
    with conn() as c:
        aid = c.execute("INSERT INTO alerts(ts,text) VALUES(?,?)", (int(time.time()), text)).lastrowid
    threading.Thread(target=_send_telegram, args=(aid, text), daemon=True).start()


def _send_telegram(aid, text):
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    ok, note = 0, ""
    if not tok or not chat:
        note = "Telegram belum dikonfigurasi (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)"
    else:
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": "true"}).encode()
            url = os.environ.get("TELEGRAM_API", "https://api.telegram.org") + "/bot%s/sendMessage" % tok
            with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=20) as r:
                ok = 1 if r.status == 200 else 0
                note = "HTTP %s" % r.status
        except Exception as e:
            note = "gagal: " + str(e)[:150]
    with conn() as c:
        c.execute("UPDATE alerts SET sent=?, note=? WHERE id=?", (ok, note, aid))


def link(path=""):
    base = os.environ.get("PUBLIC_URL", "").rstrip("/")
    return (base + path) if base else ""


# ---------------------------------------------------------------- pemrosesan laporan
def process_report(host, payload):
    now = int(time.time())
    min_level = LEVELS.get(os.environ.get("ALERT_MIN_LEVEL", "HIGH").upper(), 3)
    alerts = []
    with LOCK, conn() as c:
        c.execute("UPDATE hosts SET last_report=?, stale_alerted=0 WHERE id=?", (now, host["id"]))
        for a in (payload.get("apps") or [])[:50]:
            name = str(a.get("name", ""))[:80] or "app"
            typ = str(a.get("type", "generic"))[:20]
            row = c.execute("SELECT id FROM apps WHERE host_id=? AND name=?", (host["id"], name)).fetchone()
            first = row is None
            if first:
                app_id = c.execute("INSERT INTO apps(host_id,name,type,files_scanned,last_scan,error) VALUES(?,?,?,?,?,?)",
                                   (host["id"], name, typ, int(a.get("files_scanned", 0)), now, a.get("error"))).lastrowid
            else:
                app_id = row["id"]
                c.execute("UPDATE apps SET type=?, files_scanned=?, last_scan=?, error=? WHERE id=?",
                          (typ, int(a.get("files_scanned", 0)), now, a.get("error"), app_id))
            if a.get("error"):
                alerts.append("⚠️ %s/%s: agent gagal scan: %s" % (host["name"], name, str(a["error"])[:150]))
                continue

            # ---- temuan file
            existing = {r["file"]: r for r in c.execute("SELECT * FROM findings WHERE app_id=?", (app_id,))}
            seen, new_items, resolved = set(), [], 0
            for f in (a.get("findings") or [])[:3000]:
                file = str(f.get("file", ""))[:500]
                sha = str(f.get("sha256", ""))[:64]
                level = f.get("level") if f.get("level") in LEVELS else "LOW"
                score = int(f.get("score", 0))
                hits = json.dumps((f.get("hits") or [])[:30], ensure_ascii=False)[:8000]
                mtime, size = str(f.get("mtime", ""))[:20], int(f.get("size", 0))
                seen.add(file)
                r = existing.get(file)
                rules = ",".join(h.get("rule", "?") for h in (f.get("hits") or [])[:4])
                if r is None:
                    c.execute("INSERT INTO findings(app_id,file,sha256,level,score,hits,mtime,size,first_seen,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?,?,'new')",
                              (app_id, file, sha, level, score, hits, mtime, size, now, now))
                    new_items.append((level, file, score, rules, "baru"))
                elif r["status"] == "ack" and r["ack_sha"] == sha:
                    c.execute("UPDATE findings SET last_seen=?, level=?, score=?, hits=? WHERE id=?", (now, level, score, hits, r["id"]))
                elif r["status"] == "new" and r["sha256"] == sha:
                    c.execute("UPDATE findings SET last_seen=?, level=?, score=?, hits=? WHERE id=?", (now, level, score, hits, r["id"]))
                else:
                    why = "muncul lagi" if r["status"] == "resolved" else "ISI BERUBAH"
                    c.execute("UPDATE findings SET sha256=?, level=?, score=?, hits=?, mtime=?, size=?, last_seen=?, status='new', ack_sha=NULL WHERE id=?",
                              (sha, level, score, hits, mtime, size, now, r["id"]))
                    new_items.append((level, file, score, rules, why))
            for file, r in existing.items():
                if file not in seen and r["status"] != "resolved":
                    c.execute("UPDATE findings SET status='resolved', last_seen=? WHERE id=?", (now, r["id"]))
                    resolved += 1

            # ---- token verifikasi Google
            gex = {(r["file"], r["token"]): r for r in c.execute("SELECT * FROM google_tokens WHERE app_id=?", (app_id,))}
            gseen, new_g = set(), []
            for g in (a.get("google") or [])[:500]:
                key = (str(g.get("file", ""))[:500], str(g.get("token", ""))[:200])
                gseen.add(key)
                r = gex.get(key)
                if r is None:
                    c.execute("INSERT INTO google_tokens(app_id,type,file,token,first_seen,last_seen,status) VALUES(?,?,?,?,?,?,'unverified')",
                              (app_id, str(g.get("type", ""))[:20], key[0], key[1], now, now))
                    new_g.append(key)
                else:
                    if r["status"] == "gone":
                        c.execute("UPDATE google_tokens SET status='unverified', last_seen=? WHERE id=?", (now, r["id"]))
                        new_g.append(key)
                    else:
                        c.execute("UPDATE google_tokens SET last_seen=? WHERE id=?", (now, r["id"]))
            for key, r in gex.items():
                if key not in gseen and r["status"] != "gone":
                    c.execute("UPDATE google_tokens SET status='gone' WHERE id=?", (r["id"],))

            # ---- file inti (hash) & file kode yang baru berubah; agent lama tidak mengirim keduanya
            changed_w = process_watch(c, app_id, a["watch"], now) if isinstance(a.get("watch"), list) else []
            if isinstance(a.get("recent"), dict):
                rc = a["recent"]
                files = [{"file": str(x.get("file", ""))[:500], "mtime": int(x.get("mtime", 0)), "ctime": int(x.get("ctime", 0)),
                          "size": int(x.get("size", 0))} for x in (rc.get("files") or [])[:300] if isinstance(x, dict)]
                c.execute("UPDATE apps SET recent=? WHERE id=?",
                          (json.dumps({"days": int(rc.get("days", 7)), "total": int(rc.get("total", len(files))), "files": files}), app_id))

            # ---- susun pesan
            url = link("/app/%d" % app_id)
            head = "%s / %s" % (host["name"], name)
            if first:
                high = sum(1 for x in new_items if x[0] == "HIGH")
                msg = "🆕 Laporan pertama %s: %d temuan (%d HIGH), %d token/file verifikasi Google.%s" % (
                    head, len(new_items), high, len(new_g), ("\n" + url) if url else "")
                if new_items or new_g:
                    alerts.append(msg)
                    top = [x for x in sorted(new_items, key=lambda x: -x[2]) if LEVELS[x[0]] >= min_level][:5]
                    if top:
                        alerts[-1] += "\n" + "\n".join("• [%s] %s (%s)" % (x[0], x[1], x[3]) for x in top)
            else:
                lines = ["• [%s] %s — %s (%s)" % (x[0], x[1], x[4], x[3]) for x in sorted(new_items, key=lambda x: -x[2])
                         if LEVELS[x[0]] >= min_level][:10]
                lines += ["• Token Google baru: %s di %s → cek apakah owner sah" % (k[1][:40], k[0]) for k in new_g[:5]]
                lines += ["• File inti %s: %s" % (why, f) for f, why in changed_w[:10]]
                if len(changed_w) > 10:
                    lines.append("• ... dan %d file inti lain berubah" % (len(changed_w) - 10))
                if lines:
                    alerts.append("🚨 %s: temuan baru\n%s%s" % (head, "\n".join(lines), ("\n" + url) if url else ""))
    for m in alerts:
        alert(m)
    return {"apps": len(payload.get("apps") or []), "alerts": len(alerts)}


def process_watch(c, app_id, watch, now):
    """Bandingkan hash file inti dengan laporan sebelumnya. Laporan pertama = baseline (tanpa alert).
    Mengembalikan [(file, alasan)] untuk file yang baru / BERUBAH / hilang / muncul lagi."""
    wex = {r["file"]: r for r in c.execute("SELECT * FROM watch_files WHERE app_id=?", (app_id,))}
    baseline = not wex
    seen, changed = set(), []
    for w in watch[:2000]:
        if not isinstance(w, dict):
            continue
        file, sha = str(w.get("file", ""))[:500], str(w.get("sha256", ""))[:64]
        size, mt = int(w.get("size", 0)), int(w.get("mtime", 0))
        seen.add(file)
        r = wex.get(file)
        if r is None:
            c.execute("INSERT INTO watch_files(app_id,file,sha256,size,mtime,first_seen,last_seen,changed_at,status) VALUES(?,?,?,?,?,?,?,?,?)",
                      (app_id, file, sha, size, mt, now, now, None if baseline else now, "ok" if baseline else "new"))
            if not baseline:
                changed.append((file, "baru"))
        elif r["sha256"] != sha or r["status"] == "gone":
            c.execute("UPDATE watch_files SET sha256=?, size=?, mtime=?, last_seen=?, changed_at=?, status='changed' WHERE id=?",
                      (sha, size, mt, now, now, r["id"]))
            changed.append((file, "muncul lagi" if r["status"] == "gone" else "BERUBAH"))
        else:
            c.execute("UPDATE watch_files SET last_seen=? WHERE id=?", (now, r["id"]))
    for file, r in wex.items():
        if file not in seen and r["status"] != "gone":
            c.execute("UPDATE watch_files SET status='gone', changed_at=? WHERE id=?", (now, r["id"]))
            changed.append((file, "hilang"))
    return changed


# ---------------------------------------------------------------- probe & watchdog
def run_probes(only_id=None):
    with conn() as c:
        sites = [dict(r) for r in c.execute("SELECT * FROM sites" + (" WHERE id=%d" % only_id if only_id else ""))]
    for s in sites:
        try:
            r = probe.probe_url(s["url"])
        except Exception as e:
            r = {"status": "error", "issues": [], "error": str(e)[:200], "detail": {}}
        sig = hashlib.sha256(json.dumps(sorted(x[1] for x in r["issues"])).encode()).hexdigest() if r["issues"] else ""
        with conn() as c:
            row = c.execute("SELECT last_alert_hash FROM sites WHERE id=?", (s["id"],)).fetchone()
            c.execute("UPDATE sites SET last_probe=?, status=?, detail=?, last_alert_hash=? WHERE id=?",
                      (int(time.time()), r["status"], json.dumps(r, ensure_ascii=False), sig, s["id"]))
        if r["status"] == "alert" and sig != (row["last_alert_hash"] or ""):
            alert("🚨 Probe cloaking %s (%s)\n%s%s" % (s["name"], s["url"],
                  "\n".join("• [%s] %s" % (lv, tx) for lv, tx in r["issues"][:8]), ("\n" + link("/")) if link("/") else ""))


def check_stale():
    limit = float(os.environ.get("STALE_HOURS", "26")) * 3600
    now = int(time.time())
    with conn() as c:
        rows = c.execute("SELECT * FROM hosts WHERE last_report IS NOT NULL AND stale_alerted=0 AND ? - last_report > ?", (now, limit)).fetchall()
        for r in rows:
            c.execute("UPDATE hosts SET stale_alerted=1 WHERE id=?", (r["id"],))
    for r in rows:
        alert("⏰ Host %s tidak melapor > %s jam. Agent mati, cron berhenti, atau VPS bermasalah?" % (r["name"], os.environ.get("STALE_HOURS", "26")))


def scheduler():
    interval = float(os.environ.get("PROBE_INTERVAL_MIN", "360")) * 60
    last_probe = 0
    while True:
        try:
            check_stale()
            if time.time() - last_probe >= interval:
                run_probes()
                last_probe = time.time()
        except Exception as e:
            print("scheduler error:", e, file=sys.stderr)
        time.sleep(60)


# ---------------------------------------------------------------- web
app = FastAPI(title="Judol Monitor", docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()


def admin(cred: HTTPBasicCredentials = Depends(security)):
    u, p = os.environ.get("DASH_USER"), os.environ.get("DASH_PASS")
    if not u or not p:
        raise HTTPException(503, "DASH_USER/DASH_PASS belum di-set")
    if not (secrets.compare_digest(cred.username.encode(), u.encode()) and secrets.compare_digest(cred.password.encode(), p.encode())):
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return cred.username


def check_csrf(tok):
    if not hmac.compare_digest(tok or "", csrf_token()):
        raise HTTPException(403, "CSRF")


@app.on_event("startup")
def _startup():
    init_db()
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        threading.Thread(target=scheduler, daemon=True).start()


@app.post("/api/report")
async def api_report(request: Request):
    auth = request.headers.get("authorization", "")
    tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not tok:
        raise HTTPException(401, "token diperlukan")
    with conn() as c:
        host = c.execute("SELECT * FROM hosts WHERE token_hash=?", (hash_token(tok),)).fetchone()
        if host:
            c.execute("UPDATE hosts SET last_ip=? WHERE id=?", (request.client.host if request.client else "", host["id"]))
    if not host:
        raise HTTPException(401, "token tidak valid")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "payload terlalu besar")
    try:
        payload = json.loads(body)
        assert isinstance(payload, dict)
    except Exception:
        raise HTTPException(400, "JSON tidak valid")
    if str(payload.get("host", host["name"])) != host["name"]:
        raise HTTPException(403, "nama host tidak cocok dengan token")
    return JSONResponse(await run_in_threadpool(process_report, dict(host), payload))


E = html.escape
CSS = """<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#ddd;--hi:#c62828;--md:#e08a00;--ok:#2e7d32;--card:#f6f6f6}
@media(prefers-color-scheme:dark){:root{--bg:#141414;--fg:#e8e8e8;--mut:#999;--line:#333;--card:#1e1e1e}}
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px;max-width:1200px;margin:auto}
table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600}a{color:inherit}code{background:var(--card);padding:1px 4px;border-radius:3px;word-break:break-all}
.p{padding:1px 8px;border-radius:10px;color:#fff;font-size:12px}.HIGH,.alert{background:var(--hi)}.MEDIUM{background:var(--md)}.LOW,.ok,.gone,.resolved{background:var(--ok)}.new,.unverified{background:var(--md)}.changed,.beda{background:var(--hi)}.ack,.known,.error{background:#607d8b}
input,button,textarea{font:inherit;padding:4px 8px}textarea{width:100%;box-sizing:border-box;background:var(--bg);color:var(--fg);border:1px solid var(--line)}
tr.f td{border-bottom:0}.note{white-space:pre-wrap;margin:2px 0 6px}details summary{cursor:pointer;color:var(--mut)}label{display:block;margin:4px 0}button{cursor:pointer}small{color:var(--mut)}form{display:inline}
</style>"""


def page(title, body):
    return HTMLResponse("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>%s</title>%s%s" % (E(title), CSS, body))


def ago(ts):
    if not ts:
        return "-"
    d = int(time.time()) - int(ts)
    return "%dm lalu" % (d // 60) if d < 3600 else ("%dj lalu" % (d // 3600) if d < 172800 else "%dh lalu" % (d // 86400))


def pill(s):
    return "<span class='p %s'>%s</span>" % (E(s), E(s))


@app.get("/", response_class=HTMLResponse)
def index(_: str = Depends(admin)):
    tok = csrf_token()
    out = ["<h1>Monitor Judol</h1>", "<h2>Host & aplikasi</h2><table><tr><th>Host</th><th>Aplikasi</th><th>Tipe</th><th>Lapor terakhir</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>Token Google ?</th></tr>"]
    stale = float(os.environ.get("STALE_HOURS", "26")) * 3600
    with conn() as c:
        for h in c.execute("SELECT * FROM hosts ORDER BY name"):
            apps = c.execute("SELECT * FROM apps WHERE host_id=? ORDER BY name", (h["id"],)).fetchall()
            old = h["last_report"] and time.time() - h["last_report"] > stale
            hs = "%s%s" % (E(h["name"]), " " + pill("alert") + " <small>tidak lapor</small>" if old else "")
            if not apps:
                out.append("<tr><td>%s</td><td colspan=7><small>belum ada laporan</small></td></tr>" % hs)
            for a in apps:
                cnt = {r[0]: r[1] for r in c.execute("SELECT level,COUNT(*) FROM findings WHERE app_id=? AND status='new' GROUP BY level", (a["id"],))}
                gu = c.execute("SELECT COUNT(*) FROM google_tokens WHERE app_id=? AND status='unverified'", (a["id"],)).fetchone()[0]
                out.append("<tr><td>%s</td><td><a href='/app/%d'>%s</a>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    hs, a["id"], E(a["name"]), (" " + pill("error")) if a["error"] else "", E(a["type"] or ""), ago(h["last_report"]),
                    cnt.get("HIGH", 0) or "-", cnt.get("MEDIUM", 0) or "-", cnt.get("LOW", 0) or "-", gu or "-"))
                hs = ""
        out.append("</table><h2>Probe cloaking (dari luar)</h2><table><tr><th>Situs</th><th>URL</th><th>Dicek</th><th>Status</th><th>Detail</th><th></th></tr>")
        for s in c.execute("SELECT * FROM sites ORDER BY name"):
            d = json.loads(s["detail"]) if s["detail"] else {}
            det = "<br>".join("[%s] %s" % (E(lv), E(tx)) for lv, tx in d.get("issues", [])) or E(d.get("error", ""))
            out.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td><form method=post action='/site/%d/delete'><input type=hidden name=csrf value='%s'><button>hapus</button></form></td></tr>" % (
                E(s["name"]), E(s["url"]), ago(s["last_probe"]), pill(s["status"] or "-") if s["status"] else "-", det, s["id"], tok))
        out.append("</table><form method=post action='/site/add'><input type=hidden name=csrf value='%s'><input name=name placeholder='nama' required> <input name=url placeholder='https://situs.ac.id/' size=36 required> <button>Tambah situs</button></form> "
                   "<form method=post action='/probe/run'><input type=hidden name=csrf value='%s'><button>Jalankan probe sekarang</button></form>" % (tok, tok))
        out.append("<h2>Alert terakhir</h2><table><tr><th>Waktu</th><th>Pesan</th><th>Telegram</th></tr>")
        for r in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 15"):
            out.append("<tr><td>%s</td><td><pre style='margin:0;white-space:pre-wrap'>%s</pre></td><td>%s <small>%s</small></td></tr>" % (
                time.strftime("%d-%m %H:%M", time.localtime(r["ts"])), E(r["text"]), "✔" if r["sent"] else "✘", E(r["note"] or "")))
        out.append("</table>")
    return page("Monitor Judol", "".join(out))


@app.get("/app/{app_id}", response_class=HTMLResponse)
def app_page(app_id: int, _: str = Depends(admin)):
    tok = csrf_token()
    with conn() as c:
        a = c.execute("SELECT apps.*, hosts.name AS host FROM apps JOIN hosts ON hosts.id=apps.host_id WHERE apps.id=?", (app_id,)).fetchone()
        if not a:
            raise HTTPException(404)
        out = ["<p><a href='/'>← kembali</a></p><h1>%s / %s <small>(%s)</small></h1><p>%d file diperiksa · scan terakhir %s</p>" % (
            E(a["host"]), E(a["name"]), E(a["type"] or ""), a["files_scanned"], ago(a["last_scan"]))]
        out.append("<h2>Temuan file</h2><table><tr><th>Level</th><th>File</th><th>Skor</th><th>Diubah</th><th>Aturan</th><th>Status</th><th></th></tr>")
        rows = c.execute("SELECT * FROM findings WHERE app_id=? AND status!='resolved' ORDER BY (status='ack'), score DESC", (app_id,)).fetchall()
        for f in rows:
            hits = "<br>".join("<b>%s</b> %s%s" % (E(h.get("rule", "")), E(h.get("desc", "")[:160]), (" <small>(baris %s)</small>" % h["line"]) if h.get("line") else "") for h in json.loads(f["hits"] or "[]"))
            btn = "<form method=post action='/finding/%d/ack'><input type=hidden name=csrf value='%s'><button title='Tandai aman untuk isi file saat ini'>tandai aman</button></form>" % (f["id"], tok) if f["status"] == "new" else ""
            out.append("<tr class=f id='f%d'><td>%s</td><td><code>%s</code><br><small>sha256 %s · %s B</small></td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                f["id"], pill(f["level"]), E(f["file"]), E(f["sha256"][:12]), f["size"], f["score"], E(f["mtime"] or ""), hits, pill(f["status"]), btn))
            out.append("<tr><td></td><td colspan=6>%s</td></tr>" % note_block(f, tok))
        if not rows:
            out.append("<tr><td colspan=7><small>tidak ada temuan aktif</small></td></tr>")
        out.append("</table>")
        gt = c.execute("SELECT * FROM google_tokens WHERE app_id=? AND status!='gone' ORDER BY status, first_seen DESC", (app_id,)).fetchall()
        out.append("<h2>Verifikasi Google ditemukan di file</h2><p><small>Cocokkan dengan Search Console → Settings → Ownership verification. Yang tidak dikenal = kemungkinan dipasang penyusup: hapus token/file-nya lalu un-verify owner tsb.</small></p>"
                   "<table><tr><th>Tipe</th><th>File</th><th>Token</th><th>Pertama terlihat</th><th>Status</th><th></th></tr>")
        for g in gt:
            btn = "<form method=post action='/google/%d/known'><input type=hidden name=csrf value='%s'><button>tandai sah</button></form>" % (g["id"], tok) if g["status"] == "unverified" else ""
            out.append("<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                E(g["type"]), E(g["file"]), E(g["token"]), ago(g["first_seen"]), pill(g["status"]), btn))
        if not gt:
            out.append("<tr><td colspan=6><small>tidak ada</small></td></tr>")
        out.append("</table>")
        out.append(watch_section(c, app_id))
        out.append(recent_section(a["recent"]))
        nres = c.execute("SELECT COUNT(*) FROM findings WHERE app_id=? AND status='resolved'", (app_id,)).fetchone()[0]
        out.append("<p><small>%d temuan lama sudah hilang/bersih (resolved).</small></p>" % nres)
    return page("%s/%s" % (a["host"], a["name"]), "".join(out))


def fmt_ts(ts):
    return time.strftime("%d-%m-%Y %H:%M", time.localtime(ts)) if ts else "-"


def watch_section(c, app_id):
    """File inti yang pernah berubah/baru/hilang sejak baseline; yang tidak berubah hanya dihitung."""
    rows = c.execute("SELECT * FROM watch_files WHERE app_id=? AND status!='ok' ORDER BY changed_at DESC", (app_id,)).fetchall()
    n_ok = c.execute("SELECT COUNT(*) FROM watch_files WHERE app_id=? AND status='ok'", (app_id,)).fetchone()[0]
    if not rows and not n_ok:
        return ""
    out = ["<h2>File inti dipantau</h2><p><small>index.php, config.php, .htaccess, .user.ini, robots.txt, sitemap.xml, cron, dll. "
           "Dibandingkan dengan sha256 laporan sebelumnya. %d file tidak berubah sejak baseline.</small></p>" % n_ok]
    if rows:
        out.append("<table><tr><th>File</th><th>Status</th><th>Terdeteksi</th><th>mtime file</th><th>sha256</th></tr>")
        for w in rows:
            out.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
                E(w["file"]), pill(w["status"]), fmt_ts(w["changed_at"]), fmt_ts(w["mtime"]), E((w["sha256"] or "")[:12])))
        out.append("</table>")
    return "".join(out)


def recent_section(raw):
    """Daftar file kode yang mtime/ctime-nya baru berubah, dari laporan terakhir agent."""
    if not raw:
        return ""
    r = json.loads(raw)
    files = r.get("files", [])
    out = ["<h2>File kode berubah %d hari terakhir</h2><p><small>%d file (ditampilkan %d terbaru). ctime = waktu perubahan inode, "
           "tidak bisa dimundurkan dengan <code>touch</code>; tanda <b>beda</b> = ctime &gt; 1 hari lebih baru dari mtime "
           "(mtime mungkin dipalsukan).</small></p>" % (r.get("days", 7), r.get("total", len(files)), len(files))]
    if files:
        rows = "".join("<tr><td><code>%s</code></td><td>%s</td><td>%s%s</td><td>%s</td></tr>" % (
            E(f["file"]), fmt_ts(f["mtime"]), fmt_ts(f["ctime"]),
            " " + pill("beda") if f["ctime"] - f["mtime"] > 86400 else "", f["size"]) for f in files)
        table = "<table><tr><th>File</th><th>mtime</th><th>ctime</th><th>Ukuran</th></tr>%s</table>" % rows
        out.append(table if len(files) <= 20 else "<details><summary>tampilkan %d file</summary>%s</details>" % (len(files), table))
    return "".join(out)


def note_block(f, tok):
    """Catatan hasil investigasi & tindak lanjut untuk satu temuan, plus form untuk mengubahnya."""
    inv, fu = f["investigation"] or "", f["followup"] or ""
    shown = ""
    if inv or fu:
        shown = "<b>Hasil investigasi:</b><div class=note>%s</div><b>Tindak lanjut:</b><div class=note>%s</div><small>dicatat %s oleh %s</small>" % (
            E(inv) or "<small>-</small>", E(fu) or "<small>-</small>",
            time.strftime("%d-%m-%Y %H:%M", time.localtime(f["note_at"])) if f["note_at"] else "-", E(f["note_by"] or "-"))
    form = ("<details><summary>%s</summary><form method=post action='/finding/%d/note' style='display:block'>"
            "<input type=hidden name=csrf value='%s'>"
            "<label>Hasil investigasi<textarea name=investigation rows=3 maxlength=4000>%s</textarea></label>"
            "<label>Tindak lanjut<textarea name=followup rows=3 maxlength=4000>%s</textarea></label>"
            "<button>Simpan catatan</button></form></details>") % (
        "ubah catatan" if shown else "catat hasil investigasi & tindak lanjut", f["id"], tok, E(inv), E(fu))
    return shown + form


@app.post("/finding/{fid}/note")
def finding_note(fid: int, investigation: str = Form(""), followup: str = Form(""), csrf: str = Form(""), user: str = Depends(admin)):
    check_csrf(csrf)
    with conn() as c:
        f = c.execute("SELECT app_id FROM findings WHERE id=?", (fid,)).fetchone()
        if not f:
            raise HTTPException(404)
        c.execute("UPDATE findings SET investigation=?, followup=?, note_by=?, note_at=? WHERE id=?",
                  (investigation.strip()[:4000], followup.strip()[:4000], user, int(time.time()), fid))
    return RedirectResponse("/app/%d#f%d" % (f["app_id"], fid), 303)


@app.post("/finding/{fid}/ack")
def ack(fid: int, csrf: str = Form(""), _: str = Depends(admin)):
    check_csrf(csrf)
    with conn() as c:
        f = c.execute("SELECT app_id, sha256 FROM findings WHERE id=?", (fid,)).fetchone()
        if not f:
            raise HTTPException(404)
        c.execute("UPDATE findings SET status='ack', ack_sha=? WHERE id=?", (f["sha256"], fid))
    return RedirectResponse("/app/%d" % f["app_id"], 303)


@app.post("/google/{gid}/known")
def google_known(gid: int, csrf: str = Form(""), _: str = Depends(admin)):
    check_csrf(csrf)
    with conn() as c:
        g = c.execute("SELECT app_id FROM google_tokens WHERE id=?", (gid,)).fetchone()
        if not g:
            raise HTTPException(404)
        c.execute("UPDATE google_tokens SET status='known' WHERE id=?", (gid,))
    return RedirectResponse("/app/%d" % g["app_id"], 303)


@app.post("/site/add")
def site_add(name: str = Form(...), url: str = Form(...), csrf: str = Form(""), _: str = Depends(admin)):
    check_csrf(csrf)
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise HTTPException(400, "URL harus http/https")
    with conn() as c:
        c.execute("INSERT OR IGNORE INTO sites(name,url,added) VALUES(?,?,?)", (name[:80], url[:300], int(time.time())))
    return RedirectResponse("/", 303)


@app.post("/site/{sid}/delete")
def site_del(sid: int, csrf: str = Form(""), _: str = Depends(admin)):
    check_csrf(csrf)
    with conn() as c:
        c.execute("DELETE FROM sites WHERE id=?", (sid,))
    return RedirectResponse("/", 303)


@app.post("/probe/run")
def probe_run(csrf: str = Form(""), _: str = Depends(admin)):
    check_csrf(csrf)
    threading.Thread(target=run_probes, daemon=True).start()
    return RedirectResponse("/", 303)


# ---------------------------------------------------------------- CLI
def cli():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("add-host", "rotate-token"):
        sub.add_parser(n).add_argument("name")
    sub.add_parser("list-hosts")
    r = sub.add_parser("run")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    init_db()
    if a.cmd in ("add-host", "rotate-token"):
        token = secrets.token_urlsafe(32)
        with conn() as c:
            if a.cmd == "add-host":
                c.execute("INSERT INTO hosts(name,token_hash,created) VALUES(?,?,?)", (a.name, hash_token(token), int(time.time())))
            else:
                if not c.execute("UPDATE hosts SET token_hash=? WHERE name=?", (hash_token(token), a.name)).rowcount:
                    sys.exit("host tidak ada")
        print("Host: %s\nToken (simpan sekarang, tidak akan ditampilkan lagi):\n%s" % (a.name, token))
    elif a.cmd == "list-hosts":
        with conn() as c:
            for h in c.execute("SELECT * FROM hosts ORDER BY name"):
                print("%-20s lapor terakhir: %s  ip: %s" % (h["name"], ago(h["last_report"]), h["last_ip"] or "-"))
    else:
        if not os.environ.get("DASH_USER") or not os.environ.get("DASH_PASS"):
            sys.exit("Set DASH_USER dan DASH_PASS dulu.")
        import uvicorn
        uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    cli()
