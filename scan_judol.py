#!/usr/bin/env python3
"""
scan_judol.py - Scanner read-only untuk mencari indikasi injeksi judol (judi online),
webshell, backdoor, dan cloaking pada folder web app.

Tidak mengubah/menghapus file apa pun. Hanya membaca dan membuat laporan.

Contoh:
  python scan_judol.py /var/www/html
  python scan_judol.py D:\\web\\app1 --since 30 --out laporan.csv
  python scan_judol.py /var/www --min-score 4 --json laporan.json
  python scan_judol.py /var/www/app --include-vendor      # ikut scan node_modules/vendor
"""
import argparse, csv, json, os, re, sys, time
from collections import defaultdict

TEXT_EXT = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc",
    ".html", ".htm", ".shtml", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".vue",
    ".css", ".xml", ".txt", ".json", ".htaccess", ".ini", ".user.ini",
    ".py", ".pl", ".cgi", ".sh", ".asp", ".aspx", ".jsp", ".blade.php",
    ".twig", ".tpl", ".env", ".yml", ".yaml", ".conf", ".sql", ".md",
}
SKIP_DIRS_DEFAULT = {".git", ".svn", ".hg", "node_modules", "vendor", ".next",
                     "__pycache__", ".cache", "venv", ".venv", "site-packages", ".idea"}
MAX_SIZE = 5 * 1024 * 1024  # 5 MB per file

# ---------- Kata kunci judol ----------
JUDOL_TERMS = [
    "slot gacor", "slot online", "slot88", "slot777", "situs slot", "slot demo",
    "rtp slot", "rtp live", "gacor", "maxwin", "max win", "togel", "sbobet",
    "judi online", "judi bola", "judi slot", "agen judi", "situs judi",
    "bandar togel", "bandar slot", "bandar bola", "pragmatic play",
    "scatter hitam", "link alternatif", "daftar slot", "casino online",
    "poker online", "joker123", "gates of olympus", "mahjong ways",
    "sweet bonanza", "bocoran slot", "pola slot", "deposit pulsa",
    "deposit dana", "bonus new member", "anti rungkad", "toto macau",
    "hk pools", "judol", "slot thailand", "slot zeus", "bola tangkas",
    "sabung ayam", "live casino", "situs toto", "bo slot", "akun pro",
    "slot receh", "slot pulsa", "slot gampang menang", "wd cepat",
]
JUDOL_RE = re.compile("|".join(re.escape(t) for t in JUDOL_TERMS), re.I)

# Huruf "fancy" unicode (𝗦𝗟𝗢𝗧, 𝐒𝐋𝐎𝐓) yang sering dipakai spammer
FANCY_RE = re.compile("[\U0001D400-\U0001D7FF\uFF21-\uFF3A\uFF41-\uFF5A]{4,}")

# ---------- Rule: (nama, regex, bobot, deskripsi) ----------
RULES = [
    ("eval-decode", re.compile(r"\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode|convert_uudecode)\s*\(", re.I), 9,
     "eval() + decode: pola obfuscation malware klasik"),
    ("eval-request", re.compile(r"\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)", re.I), 10,
     "Eksekusi kode dari input user (backdoor/webshell)"),
    ("preg-e", re.compile(r"preg_replace\s*\(\s*['\"].*/[a-z]*e[a-z]*['\"]", re.I), 8,
     "preg_replace modifier /e (eksekusi kode)"),
    ("create-function", re.compile(r"\bcreate_function\s*\(", re.I), 5, "create_function (sering dipakai backdoor)"),
    ("dyn-func-request", re.compile(r"\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", re.I), 6,
     "Pemanggilan fungsi dinamis dari input user"),
    ("base64-long", re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), 3, "String base64 sangat panjang"),
    ("hex-blob", re.compile(r"(\\x[0-9a-fA-F]{2}){25,}"), 5, "Blob hex escape (obfuscation)"),
    ("chr-concat", re.compile(r"(chr\(\s*\d+\s*\)\s*\.\s*){8,}", re.I), 6, "String dibangun dari chr() beruntun"),
    ("js-obfus", re.compile(r"(String\.fromCharCode\((\s*\d+\s*,){15,}|_0x[0-9a-f]{4,}\s*=\s*\[)", re.I), 4,
     "JS obfuscation (fromCharCode/_0x...)"),
    ("js-eval-atob", re.compile(r"\b(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(", re.I), 7,
     "JS eval(atob(..)) / unescape"),
    ("cloak-ua-google", re.compile(r"(HTTP_USER_AGENT|navigator\.userAgent|getenv\(\s*['\"]HTTP_USER_AGENT)[^;\n]{0,150}(googlebot|bingbot|yandex|baiduspider|bot|crawl|spider)", re.I), 7,
     "Cloaking: deteksi user-agent bot mesin pencari"),
    ("cloak-ua-google2", re.compile(r"(googlebot|bingbot)[^;\n]{0,150}(HTTP_USER_AGENT|strpos|stripos|preg_match)", re.I), 6,
     "Cloaking: pengecekan googlebot"),
    ("cloak-referer", re.compile(r"(HTTP_REFERER|document\.referrer)[^;\n]{0,120}(google|bing|yahoo)", re.I), 6,
     "Cloaking/redirect berdasar referer search engine"),
    ("remote-include", re.compile(r"\b(include|require)(_once)?\s*\(?\s*['\"]?https?://", re.I), 8, "include/require dari URL luar"),
    ("file-get-remote", re.compile(r"(file_get_contents|curl_exec|fopen)\s*\([^)]{0,80}https?://[^)]{0,120}\)", re.I), 3,
     "Ambil konten dari URL luar (cek apakah sah)"),
    ("redirect-header", re.compile(r"header\s*\(\s*['\"]\s*Location\s*:\s*https?://", re.I), 3, "Redirect header ke domain luar"),
    ("meta-refresh", re.compile(r"<meta[^>]+http-equiv=['\"]?refresh['\"]?[^>]+url=https?://", re.I), 4, "Meta refresh ke domain luar"),
    ("js-redirect", re.compile(r"(window\.|document\.)?location(\.href|\.replace)?\s*(=|\()\s*['\"]https?://", re.I), 2, "Redirect JS ke domain luar"),
    ("hidden-links", re.compile(r"<(div|span|p|ul)[^>]+style=['\"][^'\"]*(display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px|text-indent\s*:\s*-\d{3,}px)[^'\"]*['\"][^>]*>\s*(<a\s|<ul|<li)", re.I), 6,
     "Link tersembunyi (teknik spam SEO)"),
    ("iframe-hidden", re.compile(r"<iframe[^>]+(width=['\"]?[01]['\"]?|height=['\"]?[01]['\"]?|display\s*:\s*none)", re.I), 5, "iframe tersembunyi"),
    ("webshell-name", re.compile(r"\b(c99shell|r57shell|b374k|wso\s*shell|FilesMan|WSOsetcookie|alfa\s*team|indoxploit|gel4y|mini\s*shell|priv8|Kuda\s*Shell|hacked\s*by|Gecko\s*shell|Marijuana\s*shell)\b", re.I), 10,
     "Nama/tanda webshell dikenal"),
    ("htaccess-rewrite-bot", re.compile(r"RewriteCond\s+%\{HTTP_USER_AGENT\}[^\n]*(google|bing|yahoo|bot)", re.I), 7,
     ".htaccess: rewrite berdasar user-agent bot"),
    ("htaccess-referer", re.compile(r"RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(google|bing|yahoo)", re.I), 6,
     ".htaccess: rewrite berdasar referer search engine"),
    ("prepend", re.compile(r"(auto_prepend_file|auto_append_file)\s*[=\s]", re.I), 6, "auto_prepend/append_file (persistensi malware)"),
    ("add-handler", re.compile(r"AddType\s+application/x-httpd-php\s+\.(jpg|jpeg|png|gif|txt|ico|css)", re.I), 9,
     "File gambar/teks dieksekusi sebagai PHP"),
    ("py-exec-decode", re.compile(r"\b(exec|eval)\s*\(\s*(base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads)", re.I), 9,
     "Python exec/eval + decode (obfuscation malware)"),
    ("py-cmd-request", re.compile(r"\b(os\.system|subprocess\.(run|call|Popen|check_output))\s*\([^)\n]{0,120}(request\.|params|query|form|body)", re.I), 6,
     "Python: eksekusi perintah dari input request"),
    ("wp-admin-create", re.compile(r"wp_create_user\s*\(|wp_insert_user\s*\(", re.I), 3, "Pembuatan user WP lewat kode (cek apakah sah)"),
]

SUSPECT_NAME_RE = re.compile(r"(^\.[a-z0-9_-]+\.php$|^(wp-)?(tmp|temp|shell|cmd|x|up|wso|mini|small|alfa|dropper|backdoor)\d*\.php$|\.(php|phtml)\.(jpg|png|gif|txt|ico|pdf)$|\.(jpg|png|gif|ico|txt)\.php$)", re.I)
SUSPECT_SHORT_RE = re.compile(r"^[a-z0-9]{1,3}\.php$")  # huruf kecil saja: kelas Laravel (Tag.php, Job.php) tidak terkena
UPLOAD_DIR_RE = re.compile(r"(^|[\\/])(uploads?|images?|img|media|files?|assets|storage|public[\\/]storage|cache|tmp|temp|repository|filedir|moodledata|localcache)([\\/]|$)", re.I)
PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"}
GOOGLE_HTML_RE = re.compile(r"^google[0-9a-f]{16}\.html$", re.I)
GOOGLE_META_RE = re.compile(r"<meta[^>]+name=['\"]google-site-verification['\"][^>]+content=['\"]([^'\"]+)['\"]|<meta[^>]+content=['\"]([^'\"]+)['\"][^>]+name=['\"]google-site-verification['\"]", re.I)


def ext_of(name):
    low = name.lower()
    if low.endswith(".blade.php"):
        return ".php"
    return os.path.splitext(low)[1] if "." in low else ""


def is_text_candidate(name):
    low = name.lower()
    if low in (".htaccess", ".user.ini", "php.ini", "robots.txt", "ads.txt"):
        return True
    return ext_of(name) in TEXT_EXT


def snippet(text, start, end, width=110):
    s = max(0, start - 20)
    e = min(len(text), max(end, start) + width)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def scan_file(path, rel, root_args, findings_g):
    """Return (score, hits list) for one file."""
    hits = []
    name = os.path.basename(path)
    ext = ext_of(name)
    try:
        st = os.stat(path)
    except OSError:
        return 0, hits, st_dummy()
    score = 0

    # 1) Nama / lokasi mencurigakan
    if ext in PHP_EXT and UPLOAD_DIR_RE.search(rel):
        hits.append(("php-in-upload", 6, 0, "File PHP di folder upload/media/cache (biasanya tidak seharusnya ada)"))
        score += 6
    if SUSPECT_NAME_RE.search(name) or SUSPECT_SHORT_RE.search(name):
        hits.append(("suspect-name", 4, 0, "Nama file mencurigakan: " + name))
        score += 4
    if name.startswith(".") and ext in PHP_EXT:
        hits.append(("hidden-php", 5, 0, "File PHP tersembunyi (diawali titik)"))
        score += 5

    if st.st_size > MAX_SIZE or not is_text_candidate(name):
        return score, hits, st

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return score, hits, st

    # 2) Verifikasi Google (untuk pelacakan claim owner)
    if GOOGLE_HTML_RE.match(name):
        findings_g.append({"type": "file-html", "file": rel, "token": name, "mtime": st.st_mtime})
    for m in GOOGLE_META_RE.finditer(text):
        findings_g.append({"type": "meta-tag", "file": rel, "token": m.group(1) or m.group(2), "mtime": st.st_mtime,
                           "line": text.count("\n", 0, m.start()) + 1})

    # 3) Rule regex
    for rname, rx, w, desc in RULES:
        m = rx.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            hits.append((rname, w, line, desc + " | " + snippet(text, m.start(), m.end())))
            score += w

    # 4) Kata kunci judol
    terms = {}
    first = None
    for m in JUDOL_RE.finditer(text):
        t = m.group(0).lower()
        terms[t] = terms.get(t, 0) + 1
        if first is None:
            first = m
    if terms:
        distinct = len(terms)
        w = min(3 + 2 * (distinct - 1), 12)
        line = text.count("\n", 0, first.start()) + 1
        hits.append(("judol-keyword", w, line,
                     f"{distinct} kata judol: " + ", ".join(f"{k}({v})" for k, v in list(terms.items())[:8])
                     + " | " + snippet(text, first.start(), first.end())))
        score += w
    if len(FANCY_RE.findall(text)) >= 3:
        m = FANCY_RE.search(text)
        hits.append(("fancy-unicode", 4, text.count("\n", 0, m.start()) + 1,
                     "Huruf unicode 'fancy' berulang (gaya spam SLOT): " + snippet(text, m.start(), m.end())))
        score += 4

    # 5) Baris super panjang di file kode (minified malware)
    if ext in PHP_EXT:
        longest = max((len(l) for l in text.split("\n")), default=0)
        if longest > 3000 and not re.search(r"\.min\.", name):
            hits.append(("long-line", 3, 0, f"Ada baris sepanjang {longest} karakter di file PHP"))
            score += 3

    # 6) File .txt/.html/.xml tak lazim berisi banyak link luar
    if ext in {".html", ".htm", ".txt", ".xml"}:
        ext_links = re.findall(r"https?://(?!localhost)[^\s\"'<>]+", text)
        if len(ext_links) >= 40 and JUDOL_RE.search(text):
            hits.append(("many-links", 4, 0, f"{len(ext_links)} URL luar + kata judol"))
            score += 4
    return score, hits, st


class _S:
    st_mtime = 0
    st_size = 0


def st_dummy():
    return _S()


def level(score):
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


SCRIPT_EXT_UPLOAD = {".py", ".sh", ".pl", ".cgi", ".jsp", ".asp", ".aspx"}


def profile_checks(rel, name, ext, profile):
    """Pemeriksaan tambahan berdasar jenis aplikasi: laravel | wordpress | fastapi | generic."""
    hits = []
    rel_n = rel.replace("\\", "/").lower()
    if ext in SCRIPT_EXT_UPLOAD and UPLOAD_DIR_RE.search(rel):
        hits.append(("script-in-upload", 6, 0, "File skrip (%s) di folder upload/static" % ext))
    if profile == "laravel":
        if rel_n.startswith("public/") and ext in PHP_EXT and rel_n != "public/index.php":
            hits.append(("laravel-extra-php", 7, 0, "File PHP tambahan di public/ (Laravel hanya butuh index.php)"))
        if rel_n.startswith("public/") and name.lower() in (".env", "env.txt", ".env.bak", "phpinfo.php"):
            hits.append(("laravel-exposed", 10, 0, "File sensitif terekspos di public/"))
    elif profile == "wordpress":
        if "/mu-plugins/" in "/" + rel_n and ext in PHP_EXT:
            hits.append(("wp-mu-plugin", 4, 0, "File di mu-plugins (sering dipakai untuk persistensi malware): cek keabsahan"))
        if rel_n.startswith("wp-content/uploads/") and ext in PHP_EXT:
            hits.append(("wp-php-uploads", 6, 0, "PHP di wp-content/uploads"))
        if re.match(r"^(wp-content/)?(themes|plugins)/[^/]+/[^/]+\.(ico|png|jpg)\.php$", rel_n):
            hits.append(("wp-fake-image", 6, 0, "File PHP menyamar sebagai gambar"))
    elif profile == "moodle":
        parts = rel_n.split("/")
        core_top = {"index.php", "config.php", "config-dist.php", "version.php", "file.php", "pluginfile.php",
                    "draftfile.php", "tokenpluginfile.php", "r.php", "brokenfile.php", "help.php", "install.php",
                    "lib.php", "mdlversion.php"}
        if len(parts) == 1 and ext in PHP_EXT and rel_n not in core_top:
            hits.append(("moodle-unknown-top-php", 6, 0, "File PHP di root Moodle yang bukan bagian inti: cek keabsahan"))
        if parts[0] in ("moodledata", "localcache", "sessions", "filedir", "temp", "trashdir", "cache", "lang") and ext in PHP_EXT \
                and parts[0] != "lang":
            hits.append(("moodle-php-in-data", 9, 0, "PHP di dalam moodledata/cache (seharusnya tidak ada)"))
        if any(p in ("pix", "fonts", "img", "images") for p in parts[:-1]) and ext in PHP_EXT:
            hits.append(("moodle-php-in-assets", 6, 0, "PHP di folder aset (pix/fonts/img)"))
        if name.lower() == "config.php" and len(parts) == 1:
            try:
                with open(os.path.join(profile_checks.root, rel), "r", encoding="utf-8", errors="ignore") as f:
                    t = f.read(200000)
                if re.search(r"(eval|base64_decode|gzinflate|file_get_contents\s*\(\s*['\"]http|curl_exec)", t, re.I):
                    hits.append(("moodle-config-tampered", 10, 0, "config.php Moodle memuat fungsi mencurigakan (eval/base64/http)"))
            except OSError:
                pass
    elif profile == "slims":
        parts = rel_n.split("/")
        if parts[0] in ("images", "files", "repository", "uploads") and ext in PHP_EXT:
            hits.append(("slims-php-in-upload", 8, 0, "PHP di images/files/repository SLiMS (jalur upload umum untuk webshell)"))
        if name.lower() in ("sysconfig.local.inc.php",):
            try:
                with open(os.path.join(profile_checks.root, rel), "r", encoding="utf-8", errors="ignore") as f:
                    t = f.read(200000)
                if re.search(r"(eval|base64_decode|gzinflate|file_get_contents\s*\(\s*['\"]http|curl_exec)", t, re.I):
                    hits.append(("slims-config-tampered", 10, 0, "sysconfig.local.inc.php memuat fungsi mencurigakan"))
            except OSError:
                pass
    elif profile == "fastapi":
        if ext in {".html", ".htm"} and re.search(r"(^|/)(static|public|media)/", rel_n):
            pass  # dicek lewat kata kunci judol
    return hits


def scan_tree(root, since=0, min_score=3, include_vendor=False, profile="generic"):
    """Scan satu folder. Mengembalikan (results, google_findings, total_files).
    Path pada hasil relatif terhadap root. Setiap result memuat sha256 file."""
    import hashlib
    root = os.path.abspath(root)
    profile_checks.root = root
    cutoff = time.time() - since * 86400 if since else 0
    results, google, total = [], [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_vendor:
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS_DEFAULT]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            total += 1
            try:
                st0 = os.stat(full)
            except OSError:
                continue
            if cutoff and st0.st_mtime < cutoff:
                if GOOGLE_HTML_RE.match(fn):
                    google.append({"type": "file-html", "file": rel, "token": fn, "mtime": st0.st_mtime})
                continue
            score, hits, st = scan_file(full, rel, None, google)
            ext = ext_of(fn)
            for h in profile_checks(rel, fn, ext, profile):
                hits.append(h)
                score += h[1]
            if score >= min_score and hits:
                try:
                    with open(full, "rb") as f:
                        sha = hashlib.sha256(f.read(MAX_SIZE * 2)).hexdigest()
                except OSError:
                    sha = ""
                results.append({"score": score, "level": level(score), "file": rel,
                                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                                "size": st.st_size, "sha256": sha, "hits": hits})
    return results, google, total


def main():
    ap = argparse.ArgumentParser(description="Scanner read-only indikasi judol/webshell/cloaking")
    ap.add_argument("path", nargs="+", help="folder root web app (boleh lebih dari satu)")
    ap.add_argument("--since", type=int, default=0, help="hanya file yang diubah N hari terakhir")
    ap.add_argument("--min-score", type=int, default=3, help="skor minimum untuk ditampilkan (default 3)")
    ap.add_argument("--include-vendor", action="store_true", help="ikut scan node_modules/vendor/.git")
    ap.add_argument("--out", help="simpan laporan CSV")
    ap.add_argument("--json", help="simpan laporan JSON")
    ap.add_argument("--known-tokens", help="file teks berisi token google-site-verification/HTML yang SAH (satu per baris)")
    args = ap.parse_args()

    known = set()
    if args.known_tokens and os.path.isfile(args.known_tokens):
        with open(args.known_tokens, encoding="utf-8") as f:
            known = {l.strip() for l in f if l.strip()}

    results, google_findings, total = [], [], 0
    for root_arg in args.path:
        r, g, t = scan_tree(root_arg, since=args.since, min_score=args.min_score,
                            include_vendor=args.include_vendor)
        base = os.path.abspath(root_arg)
        for x in r:
            x["file"] = os.path.join(base, x["file"])
        for x in g:
            x["file"] = os.path.join(os.path.basename(base), x["file"])
        results += r
        google_findings += g
        total += t
    results.sort(key=lambda r: -r["score"])

    print(f"\n=== Selesai: {total} file diperiksa, {len(results)} file mencurigakan ===\n")
    for r in results:
        print(f"[{r['level']:6}] skor {r['score']:>3}  {r['file']}  (diubah {r['mtime']}, {r['size']} B)")
        for name, w, line, desc in r["hits"]:
            loc = f"baris {line}" if line else "-"
            print(f"      - {name} (+{w}, {loc}): {desc[:230]}")
        print()

    if google_findings:
        print("=== Artefak verifikasi Google (cek terhadap daftar owner di Search Console) ===")
        print("Search Console > Settings > Ownership verification: lihat semua owner & metode verifikasi.")
        print("Yang tidak Anda kenal = kemungkinan dipasang penyusup. Hapus token/file-nya lalu un-verify owner tsb.\n")
        for g in google_findings:
            tag = "SAH?" if g["token"] in known else "CEK "
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(g["mtime"]))
            print(f"  [{tag}] {g['type']:9} {g['file']}  token={g['token']}  (diubah {when})")
        print()

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["level", "score", "file", "mtime", "size", "rule", "weight", "line", "detail"])
            for r in results:
                for name, wt, line, desc in r["hits"]:
                    w.writerow([r["level"], r["score"], r["file"], r["mtime"], r["size"], name, wt, line, desc])
        print(f"CSV disimpan: {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"files": results, "google_verification": google_findings}, f, ensure_ascii=False, indent=2)
        print(f"JSON disimpan: {args.json}")


if __name__ == "__main__":
    main()
