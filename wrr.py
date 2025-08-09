# Rebuilding wer_web_pro.py using your provided scaffold,
# now WITH WHOIS and DNS sections integrated and wired up.

from textwrap import dedent
from pathlib import Path

code = dedent(r'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WeR-Web Pro (Safe) — Improved scanner based on your #2
- Concurrency (thread pool)
- Single requests.Session with retries
- ScopeGuard (allowlist by domain/CIDR) + --i-am-authorized flag
- Smarter SECRET FILES, CRAWL, and JS scanning
- WHOIS & DNS lookups
- Optional active checks (SQLi/XSS/LFI) only with --enable-active
- Logs to stdout and to a file

USAGE:
  python wer_web_pro.py --url https://target.tld --allow-domain target.tld --i-am-authorized --enable-active

DISCLAIMER:
  This tool is ONLY for authorized security testing with explicit written consent.
  Do NOT use on third-party assets without permission.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

# ------------------ Console colors (fallback-safe) ------------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _F: RESET = ''; RED=''; GREEN=''; YELLOW=''; CYAN=''; MAGENTA=''
    class _S: BRIGHT=''; NORMAL=''
    Fore, Style = _F(), _S()

# ------------------ Scope Guard ------------------
class ScopeGuard:
    def __init__(self, allowed_cidrs=None, allowed_domains=None):
        self.allowed_nets = [ipaddress.ip_network(c, strict=False) for c in (allowed_cidrs or [])]
        self.allowed_domains = [d.lower().lstrip(".") for d in (allowed_domains or [])]

    def normalize_host(self, target: str) -> str:
        # strip scheme, port, path if present
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/", 1)[0]
        if ":" in target:
            target = target.split(":", 1)[0]
        return target

    def is_allowed(self, target: str) -> bool:
        host = self.normalize_host(target)
        # IP check
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self.allowed_nets) if self.allowed_nets else False
        except ValueError:
            # Hostname check
            host_l = host.lower()
            return any(host_l == d or host_l.endswith("." + d) for d in self.allowed_domains)

# ------------------ Session factory ------------------
def make_session(ua="Mozilla/5.0 (compatible; WeR-Web-Pro/1.0)"):
    s = requests.Session()
    s.headers.update({"User-Agent": ua})
    adapter = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=2)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

# ------------------ Helpers ------------------
def rate_limiter(max_per_min=300):
    interval = 60.0 / max_per_min if max_per_min > 0 else 0
    last = [0.0]
    def wait():
        now = time.time()
        delta = now - last[0]
        if delta < interval:
            time.sleep(interval - delta)
        last[0] = time.time()
    return wait

def mutate_query(url, param, new_value):
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    if param not in q: 
        return None
    q[param] = [new_value]
    new_q = urlencode(q, doseq=True)
    return urlunparse((u.scheme,u.netloc,u.path,u.params,new_q,u.fragment))

def same_host_and_port(a, b):
    ua, ub = urlparse(a), urlparse(b)
    pa = ua.port or (80 if ua.scheme=="http" else 443 if ua.scheme=="https" else None)
    pb = ub.port or (80 if ub.scheme=="http" else 443 if ub.scheme=="https" else None)
    return ua.hostname == ub.hostname and pa == pb

# ------------------ BANNER ------------------
BANNER = r"""
***********************************************************************
*  LEGAL & ETHICS WARNING (IMPORTANT):                                *
*  This tool is ONLY for authorized pentesting with written consent.  *
*  DO NOT use it on third-party networks/sites without permission!    *
***********************************************************************
"""

# ------------------ Scans ------------------
def host_info(session, url, logger):
    logger.info(Fore.CYAN + "[HOST INFO]")
    host = urlparse(url).hostname
    if not host:
        logger.error(Fore.RED + "Invalid URL")
        return
    try:
        ip = socket.gethostbyname(host)
        logger.info(f"IP: {ip}")
    except Exception as e:
        logger.warning(Fore.YELLOW + f"IP lookup failed: {e}")

def port_scan(host, ports, timeout=0.7, threads=128, logger=None):
    logger and logger.info(Fore.CYAN + "[PORT SCAN]")
    open_ports = []
    def try_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, p))
                if res == 0:
                    return p
        except Exception:
            return None
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for p, r in zip(ports, ex.map(try_port, ports)):
            if r:
                open_ports.append(r)
                logger and logger.info(Fore.RED + f"Open port: {r}")
    return sorted(open_ports)

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    # Optional modern:
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

def sec_headers(session, url, logger):
    logger.info(Fore.CYAN + "\n[SECURITY HEADERS]")
    try:
        r = session.get(url, timeout=5, allow_redirects=True)
        lowered = {k.lower(): v for k, v in r.headers.items()}
        for h in SEC_HEADERS:
            if h in lowered:
                logger.info(Fore.GREEN + f"{h}: {lowered[h]}")
            else:
                logger.warning(Fore.YELLOW + f"{h.upper()}: MISSING")
    except Exception as e:
        logger.error(Fore.RED + f"Header check failed: {e}")

SECRET_PATHS = [
    ".env",".git/HEAD","config.php","wp-config.php","backup.sql","db.sql","dump.sql","database.sql",
    "config.json","settings.py","id_rsa","private.key",".htpasswd",".htaccess","composer.json",
    "composer.lock","phpinfo.php","admin/config.php",".DS_Store","backup.zip","site_backup.tar.gz",
    "logs/error.log","logs/access.log"
]
PREFIXES = ["", "backup/","backups/","old/","_old/","tmp/","storage/","public/","config/","admin/",".git/"]

def guess_roots(base_url):
    u = urlparse(base_url)
    root = f"{u.scheme}://{u.netloc}/"
    roots = {root}
    path = u.path.strip("/")
    if path:
        first = path.split("/")[0]
        if first:
            roots.add(urljoin(root, first + "/"))
    return list(roots)

def is_interesting_status(sc):
    return sc in (200,206,301,302,303,307,308,401,403)

def secret_files(session, base_url, logger, timeout=4, threads=64):
    logger.info(Fore.CYAN + "\n[SECRET FILES]")
    roots = guess_roots(base_url)
    candidates = []
    for root in roots:
        for pref in PREFIXES:
            for p in SECRET_PATHS:
                candidates.append(urljoin(urljoin(root, pref), p))
    seen = list(dict.fromkeys(candidates))  # preserve order, unique

    def check(url):
        try:
            h = session.head(url, allow_redirects=True, timeout=timeout)
        except Exception:
            h = None
        if h is not None and is_interesting_status(h.status_code):
            try:
                r = session.get(url, allow_redirects=True, timeout=timeout, stream=True)
                ct = r.headers.get("Content-Type","")
                cl = r.headers.get("Content-Length")
                return (url, r.status_code, ct, cl)
            except Exception as e:
                return (url, "ERR", str(e), None)
        return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(check, seen):
            if res:
                found.append(res)
                url, sc, ct, cl = res
                logger.warning(Fore.RED + f"Possible secret: {url} [{sc}] CT={ct} CL={cl}")
    if not found:
        logger.info(Fore.GREEN + "No obvious secret files")
    return found

def js_scan(session, base_url, logger, timeout=5, threads=32):
    logger.info(Fore.CYAN + "\n[JS SCAN]")
    try:
        r = session.get(base_url, timeout=timeout)
    except Exception as e:
        logger.error(Fore.RED + f"Failed to load base page: {e}")
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    scripts = [urljoin(r.url, s['src']) for s in soup.find_all("script", src=True)]
    patterns = [r"api[_-]?key",r"token",r"secret",r"passwd|password"]
    rx = re.compile("|".join(patterns), re.I)
    def fetch(u):
        try:
            res = session.get(u, timeout=timeout)
            if rx.search(res.text or ""):
                return u
        except Exception:
            pass
        return None
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for got in ex.map(fetch, scripts):
            if got:
                hits.append(got)
                logger.warning(Fore.RED + f"Sensitive data in: {got}")
    if not hits:
        logger.info(Fore.GREEN + "No obvious secrets in JS includes")
    return hits

def cms_detect(session, url, logger):
    logger.info(Fore.CYAN + "\n[CMS DETECTION]")
    try:
        r = session.get(url, timeout=5)
        t = r.text.lower()
        if "wp-content" in t or "/wp-includes/" in t: 
            logger.info("WordPress detected")
            return "wordpress"
        if "joomla" in t:
            logger.info("Joomla detected")
            return "joomla"
        if "drupal" in t:
            logger.info("Drupal detected")
            return "drupal"
        logger.info(Fore.GREEN + "No CMS detected")
    except Exception as e:
        logger.error(Fore.RED + f"CMS check failed: {e}")
    return None

def dir_listing(session, base_url, logger, timeout=4):
    logger.info(Fore.CYAN + "\n[DIRECTORY LISTING]")
    paths = ["uploads/","images/","files/","backup/","data/","logs/","static/","media/"]
    def check(p):
        full = urljoin(base_url, p)
        try:
            r = session.get(full, timeout=timeout)
            txt = (r.text or "").lower()
            if "index of /" in txt or re.search(r"<title>\s*index of", txt):
                return ("open", full)
            # Heuristic: many links + last modified column-like
            links = re.findall(r"<a\s+href=", txt)
            if len(links) > 20 and ("parent directory" in txt or "last modified" in txt):
                return ("maybe", full)
        except Exception as e:
            return ("err", f"{full}: {e}")
        return None
    results = []
    for p in paths:
        res = check(p)
        if res:
            results.append(res)
            kind, msg = res
            if kind == "open":
                logger.warning(Fore.RED + f"Open dir: {msg}")
            elif kind == "maybe":
                logger.warning(Fore.YELLOW + f"Possible listing: {msg}")
            else:
                logger.info(Fore.YELLOW + msg)
    if not results:
        logger.info(Fore.GREEN + "No obvious directory listings")
    return results

def crawl(session, base_url, logger, depth=2, max_links=300, timeout=4):
    logger.info(Fore.CYAN + "\n[CRAWL]")
    seen, out = set(), []
    q = deque([(base_url,0)])
    while q and len(out) < max_links:
        url,d = q.popleft()
        u,_ = urldefrag(url)
        if u in seen or d > depth: 
            continue
        seen.add(u)
        try:
            r = session.get(u, timeout=timeout)
        except Exception as e:
            logger.info(Fore.YELLOW + f"Crawl error {u}: {e}")
            continue
        final = r.url
        out.append(final)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(final, a["href"])
            if same_host_and_port(link, base_url):
                q.append((link, d+1))
    logger.info(f"Collected {len(out)} page(s)")
    return out

# ------------------ WHOIS & DNS ------------------
def whois_lookup(host, logger):
    logger.info(Fore.CYAN + "\n[WHOIS]")
    try:
        import whois  # python-whois
    except Exception as e:
        logger.info(Fore.YELLOW + "python-whois not installed. Install: pip install python-whois")
        return {}
    try:
        w = whois.whois(host)
        def norm(x):
            if isinstance(x, (list, tuple)):
                return [str(i) for i in x]
            return str(x)
        data = {
            "domain_name": norm(w.domain_name),
            "registrar": norm(w.registrar),
            "creation_date": norm(w.creation_date),
            "expiration_date": norm(w.expiration_date),
            "updated_date": norm(w.updated_date),
            "name_servers": norm(w.name_servers),
            "status": norm(w.status),
            "org": norm(getattr(w, "org", None)),
            "country": norm(getattr(w, "country", None)),
            "emails": norm(getattr(w, "emails", None)),
        }
        for k, v in data.items():
            if v and v != "None":
                logger.info(f"{k}: {v}")
        return data
    except Exception as e:
        logger.info(Fore.YELLOW + f"WHOIS lookup failed: {e}")
        return {}

def dns_records(host, logger, timeout=3.0):
    logger.info(Fore.CYAN + "\n[DNS RECORDS]")
    try:
        import dns.resolver  # dnspython
    except Exception:
        logger.info(Fore.YELLOW + "dnspython not installed. Install: pip install dnspython")
        return {}
    recs = {}
    rtypes = ["A","AAAA","MX","TXT","NS","SOA","CAA"]
    for rtype in rtypes:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=timeout, raise_on_no_answer=False)
            vals = []
            if answers:
                for r in answers:
                    vals.append(str(r).strip())
            if vals:
                recs[rtype] = vals
                logger.info(f"{rtype}: {', '.join(vals[:10])}" + (" ..." if len(vals) > 10 else ""))
        except Exception:
            pass
    if not recs:
        logger.info(Fore.GREEN + "No DNS records found or resolver blocked")
    return recs

# ------------------ Active checks (optional) ------------------
def sqli_scan(session, links, logger, timeout=5):
    logger.info(Fore.CYAN + "\n[SQL INJECTION SCAN]")
    payloads = ["' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
    found = []
    for link in links:
        u = urlparse(link)
        if not u.query:
            continue
        params = parse_qs(u.query, keep_blank_values=True)
        for p in params:
            for pay in payloads:
                test_url = mutate_query(link, p, pay)
                if not test_url: 
                    continue
                try:
                    r = session.get(test_url, timeout=timeout)
                    low = (r.text or "").lower()
                    if any(e in low for e in ["sql syntax","mysql","pdo","syntax error","sql error"]):
                        logger.warning(Fore.RED + f"SQLi: {test_url}")
                        found.append(test_url)
                        break
                except Exception as e:
                    logger.info(Fore.YELLOW + f"SQLi check error: {e}")
    if not found:
        logger.info(Fore.GREEN + "No obvious SQLi")
    return found

def xss_scan(session, links, logger, timeout=5):
    logger.info(Fore.CYAN + "\n[XSS SCAN]")
    payload = "<script>alert(1337)</script>"
    found = []
    for link in links:
        u = urlparse(link)
        if not u.query:
            continue
        params = parse_qs(u.query, keep_blank_values=True)
        for p in params:
            test_url = mutate_query(link, p, payload)
            if not test_url:
                continue
            try:
                r = session.get(test_url, timeout=timeout)
                if payload in (r.text or ""):
                    logger.warning(Fore.RED + f"XSS: {test_url}")
                    found.append(test_url)
                    break
            except Exception as e:
                logger.info(Fore.YELLOW + f"XSS check error: {e}")
    if not found:
        logger.info(Fore.GREEN + "No obvious reflected XSS")
    return found

def lfi_scan(session, links, logger, timeout=5):
    logger.info(Fore.CYAN + "\n[LFI/RFI SCAN]")
    payloads = ["../../../../etc/passwd","../../../../wp-config.php"]
    found = []
    for link in links:
        u = urlparse(link)
        if not u.query:
            continue
        params = parse_qs(u.query, keep_blank_values=True)
        for p in params:
            if any(x in p.lower() for x in ["file","path","include","page","template","action"]):
                for pay in payloads:
                    test_url = mutate_query(link, p, pay)
                    if not test_url:
                        continue
                    try:
                        r = session.get(test_url, timeout=timeout)
                        txt = (r.text or "")
                        if "root:x:" in txt or "DB_PASSWORD" in txt:
                            logger.warning(Fore.RED + f"LFI: {test_url}")
                            found.append(test_url)
                            break
                    except Exception as e:
                        logger.info(Fore.YELLOW + f"LFI check error: {e}")
    if not found:
        logger.info(Fore.GREEN + "No obvious LFI/RFI")
    return found

# ------------------ Runner ------------------
def main():
    print(BANNER, file=sys.stderr)

    ap = argparse.ArgumentParser(description="WeR-Web Pro (Safe) — Discovery & Active Checks (opt-in)")
    ap.add_argument("--url", required=True, help="Base URL, e.g. https://target.tld/")
    ap.add_argument("--ports", default="21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2082,2083,3306,3389,5432,5900,6379,8080,8081,8443,9200,10000")
    ap.add_argument("--threads", type=int, default=64, help="Thread pool size for parallel tasks")
    ap.add_argument("--depth", type=int, default=2, help="Crawl depth")
    ap.add_argument("--max-links", type=int, default=300, help="Max links to crawl")
    ap.add_argument("--rate-limit", type=int, default=300, help="Max HTTP requests per minute (approx)")
    ap.add_argument("--allow-domain", action="append", default=[], help="Allowed domain suffix(es) (repeatable)")
    ap.add_argument("--allow-cidr", action="append", default=[], help="Allowed CIDR(s) for IP targets (repeatable)")
    ap.add_argument("--i-am-authorized", action="store_true", help="You assert you are authorized to test this target")
    ap.add_argument("--enable-active", action="store_true", help="Enable active tests (SQLi/XSS/LFI)")
    ap.add_argument("--out", default="wer_web_pro_out", help="Output directory")
    args = ap.parse_args()

    if not args.i_am_authorized:
        raise SystemExit("Refusing to run: missing --i-am-authorized flag.")

    guard = ScopeGuard(allowed_cidrs=args.allow_cidr, allowed_domains=args.allow_domain)
    if not guard.is_allowed(args.url):
        raise SystemExit("Target is outside allowed scope (--allow-domain/--allow-cidr).")

    os.makedirs(args.out, exist_ok=True)
    log_path = os.path.join(args.out, "scan.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path, encoding="utf-8")
        ],
    )
    logger = logging.getLogger("wer-web-pro")

    session = make_session()
    limiter = rate_limiter(args.rate_limit)

    # Rate limit wrapper
    _orig_get = session.get
    def _rl_get(*a, **kw):
        limiter()
        return _orig_get(*a, **kw)
    session.get = _rl_get

    base_url = args.url if re.match(r"^https?://", args.url) else "http://" + args.url

    # Scans
    host_info(session, base_url, logger)

    # WHOIS & DNS
    host = urlparse(base_url).hostname
    if host:
        whois_lookup(host, logger)
        dns_records(host, logger)

    # Port scan
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    open_ports = port_scan(host, ports, threads=args.threads, logger=logger)

    sec_headers(session, base_url, logger)
    secrets = secret_files(session, base_url, logger, threads=args.threads)
    js_hits = js_scan(session, base_url, logger)
    cms = cms_detect(session, base_url, logger)
    listings = dir_listing(session, base_url, logger)

    links = crawl(session, base_url, logger, depth=args.depth, max_links=args.max_links)

    if args.enable_active:
        sqli = sqli_scan(session, links, logger)
        xss  = xss_scan(session, links, logger)
        lfi  = lfi_scan(session, links, logger)
    else:
        sqli = xss = lfi = []

    # Save JSON summary
    summary = {
        "target": base_url,
        "open_ports": open_ports,
        "security_headers_checked": SEC_HEADERS,
        "secret_files": secrets,
        "js_sensitive": js_hits,
        "cms": cms,
        "dir_listing": listings,
        "crawled_links": links[:50],
        "whois_enabled": True,
        "dns_enabled": True,
        "active_enabled": args.enable_active,
        "findings": {"sqli": sqli, "xss": xss, "lfi": lfi},
        "log": os.path.abspath(log_path),
    }
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    logger.info(Fore.MAGENTA + f"\n[+] Log file: {log_path}")
    logger.info(Fore.MAGENTA + f"[+] JSON summary: {os.path.join(args.out, 'summary.json')}")
    logger.info(Fore.GREEN +  "Done.")
    
if __name__ == "__main__":
    main()
''')

Path("/mnt/data/wer_web_pro.py").write_text(code, encoding="utf-8")
print("/mnt/data/wer_web_pro.py rebuilt with WHOIS & DNS integrated")