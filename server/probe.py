"""
probe.py - Deteksi CLOAKING dari luar: ambil URL yang sama dengan identitas berbeda
(pengunjung biasa, datang dari Google, Googlebot, HP dari Google) lalu bandingkan.
Tidak butuh akses ke VPS. Hanya stdlib + scan_judol (untuk daftar kata kunci judol).
"""
import os, re, sys, urllib.request, urllib.error, urllib.parse

_here = os.path.dirname(os.path.abspath(__file__))
for p in (_here, os.path.join(_here, "..", "agent"), os.environ.get("SCANNER_DIR", "")):
    if p and os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)
import scan_judol  # noqa: E402

UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_MOBILE = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
UA_GBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
VARIANTS = [
    ("normal", UA_NORMAL, None),
    ("google_referer", UA_NORMAL, "https://www.google.com/"),
    ("googlebot", UA_GBOT, None),
    ("mobile_google", UA_MOBILE, "https://www.google.com/"),
]
MAX_BODY = 1_500_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def fetch(url, ua, referer=None, timeout=20):
    cur = url
    hops = []
    for _ in range(6):
        headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                   "Accept-Language": "id-ID,id;q=0.9,en;q=0.8"}
        if referer:
            headers["Referer"] = referer
        req = urllib.request.Request(cur, headers=headers)
        loc = None
        try:
            r = _opener.open(req, timeout=timeout)
            status, body = r.status, r.read(MAX_BODY)
        except urllib.error.HTTPError as e:
            status, body, loc = e.code, e.read(MAX_BODY), e.headers.get("Location")
        except Exception:
            if hops:  # sudah dialihkan ke domain lain yang tak terjangkau: pengalihan itu sendiri sudah bukti
                return {"status": 0, "final_url": cur, "hops": hops, "body": ""}
            raise
        if 300 <= status < 400 and loc:
            cur = urllib.parse.urljoin(cur, loc)
            hops.append(cur)
            continue
        return {"status": status, "final_url": cur, "hops": hops,
                "body": body.decode("utf-8", errors="ignore")}
    return {"status": 310, "final_url": cur, "hops": hops, "body": ""}


def _host(u):
    h = (urllib.parse.urlparse(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _title(b):
    m = re.search(r"<title[^>]*>(.*?)</title>", b, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _kw(b):
    return {m.group(0).lower() for m in scan_judol.JUDOL_RE.finditer(b)}


def _js_redirect_hosts(b):
    hosts = set()
    for m in re.finditer(r"(?:location(?:\.href|\.replace)?\s*(?:=|\()\s*|http-equiv=['\"]?refresh['\"]?[^>]*?url=)['\"]?(https?://[^'\"\s>)]+)", b, re.I):
        hosts.add(_host(m.group(1)))
    return hosts


def probe_url(url):
    """Kembalikan dict: status ('ok'|'alert'|'error'), issues [(HIGH|MEDIUM, teks)], detail per varian."""
    site_host = _host(url)
    res = {}
    for name, ua, ref in VARIANTS:
        try:
            res[name] = fetch(url, ua, ref)
        except Exception as e:
            res[name] = {"error": str(e)[:150]}
    base = res.get("normal", {})
    if "error" in base:
        return {"status": "error", "issues": [], "error": "tidak bisa diakses: " + base["error"], "detail": {}}

    issues = []
    k0 = _kw(base["body"])
    if k0:
        issues.append(("HIGH", "Konten judol terlihat oleh pengunjung biasa: " + ", ".join(sorted(k0)[:6])))
    if len(scan_judol.FANCY_RE.findall(base["body"])) >= 3:
        issues.append(("HIGH", "Huruf unicode 'fancy' bergaya spam SLOT terlihat oleh pengunjung biasa"))
    base_host = _host(base["final_url"])
    base_js = _js_redirect_hosts(base["body"]) - {"", site_host, base_host}

    detail = {"normal": {"status": base["status"], "final": base["final_url"], "title": _title(base["body"]), "len": len(base["body"])}}
    for name, _, _ in VARIANTS[1:]:
        v = res.get(name, {})
        if "error" in v:
            detail[name] = {"error": v["error"]}
            continue
        detail[name] = {"status": v["status"], "final": v["final_url"], "title": _title(v["body"]), "len": len(v["body"])}
        kv = _kw(v["body"]) - k0
        if kv:
            issues.append(("HIGH", "CLOAKING (%s): kata judol hanya muncul untuk varian ini: %s" % (name, ", ".join(sorted(kv)[:6]))))
        if len(scan_judol.FANCY_RE.findall(v["body"])) >= 3 and len(scan_judol.FANCY_RE.findall(base["body"])) < 3:
            issues.append(("HIGH", "CLOAKING (%s): huruf 'fancy' spam SLOT hanya untuk varian ini" % name))
        vh = _host(v["final_url"])
        if vh and vh != base_host and vh != site_host:
            issues.append(("HIGH", "CLOAKING (%s): diarahkan ke domain lain: %s" % (name, vh)))
        extra_js = _js_redirect_hosts(v["body"]) - {"", site_host, base_host} - base_js
        if extra_js:
            issues.append(("HIGH", "CLOAKING (%s): redirect JS/meta ke %s hanya untuk varian ini" % (name, ", ".join(sorted(extra_js)[:3]))))
        lb, lv = len(base["body"]), len(v["body"])
        if abs(lv - lb) / max(lb, 1) > 0.6 and _title(v["body"]) != _title(base["body"]):
            issues.append(("MEDIUM", "Halaman untuk %s sangat berbeda (judul & ukuran): '%s' vs '%s'" % (name, _title(v["body"]), _title(base["body"]))))
    return {"status": "alert" if issues else "ok", "issues": issues, "detail": detail}
