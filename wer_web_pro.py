#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WeR-Web Pro (Safe) — Web scanner for AUTHORIZED pentesting
- Concurrency (thread pools)
- requests.Session with retries + rate limit
- ScopeGuard: --allow-domain / --allow-cidr + required --i-am-authorized
- Discovery: headers, secrets, JS scan, CMS hints, directory listing, crawl
- Recon: WHOIS + DNS (optional if modules installed)
- Active checks (opt-in): SQLi / XSS / LFI (non-destructive heuristics)
- Port scan (common ports) on target host
- Logging to stdout and file + JSON summary
- Interactive mode like your #2: `-scan <url> [options]`

DISCLAIMER: Use ONLY with explicit written permission from the asset owner.
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

BANNER = r"""
***********************************************************************
*  LEGAL & ETHICS WARNING (IMPORTANT):                                *
*  This tool is ONLY for authorized pentesting with written consent.  *
*  DO NOT use it on third-party networks/sites without permission!    *
***********************************************************************
"""

# ------------------ Scope Guard ------------------
class ScopeGuard:
    def __init__(self, allowed_cidrs=None, allowed_domains=None):
        self.allowed_nets = [ipaddress.ip_network(c, strict=False) for c in (allowed_cidrs or [])]
        self.allowed_domains = [d.lower().lstrip(".") for d in (allowed_domains or [])]

    def normalize_host(self, target: str) -> str:
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/", 1)[0]
        if ":" in target:
            target = target.split(":", 1)[0]
        return target

    def is_allowed(self, target: str) -> bool:
        host = self.normalize_host(target)
        # IP target?
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self.allowed_nets) if self.allowed_nets else False
        except ValueError:
            # Hostname target
            host_l = host.lower()
            return any(host_l == d or host_l.endswith("." + d) for d in self.allowed_domains)

# ------------------ Session & helpers ------------------
def make_session(ua="Mozilla/5.0 (compatible; WeR-Web-Pro/1.1)"):
    s = requests.Session()
    s.headers.update({"User-Agent": ua})
    adapter = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=2)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

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

def ensure_url(u: str) -> str:
    return u if re.match(r"^https?://", u, re.I) else "http://" + u

# ------------------ Recon ------------------
def host_info(session, url, logger):
    logger.info(Fore.CYAN + "[HOST INFO]")
    host = urlparse(url).hostname
    if not host:
        logger.error(Fore.RED + "Invalid URL")
        return {}
    info = {"host": host}
    try:
        ip = socket.gethostbyname(host)
        info["ip"] = ip
        logger.info(f"IP: {ip}")
    except Exception as e:
        logger.warning(Fore.YELLOW + f"IP lookup failed: {e}")
    return info

def dns_records(host, logger, timeout=3.0):
    logger.info(Fore.CYAN + "\n[DNS RECORDS]")
    try:
        import dns.resolver  # dnspython
    except Exception:
        logger.info(Fore.YELLOW + "dnspython not installed. Install: pip install dnspython")
        return {}
    recs = {}
    for rtype in ["A","AAAA","MX","TXT","NS","SOA","CAA"]:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=timeout, raise_on_no_answer=False)
            vals = [str(r).strip() for r in answers] if answers else []
            if vals:
                recs[rtype] = vals
                logger.info(f"{rtype}: {', '.join(vals[:10])}" + (" ..." if len(vals) > 10 else ""))
        except Exception:
            pass
    if not recs:
        logger.info(Fore.GREEN + "No DNS records found or resolver blocked")
    return recs

def whois_lookup(host, logger):
    logger.info(Fore.CYAN + "\n[WHOIS]")
    try:
        import whois  # python-whois
    except Exception:
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

# ------------------ Port scan ------------------
def port_scan(host, ports, timeout=0.7, threads=128, logger=None):
    logger and logger.info(Fore.CYAN + "\n[PORT SCAN]")
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

# ------------------ Web checks ------------------
SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
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
    seen = list(dict.fromkeys(candidates))

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

# ------------------ Active checks (opt-in) ------------------
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

# ------------------ Scan orchestrator ------------------
def run_full_scan(url, allow_domains, allow_cidrs, i_am_authorized, enable_active,
                  out_dir="wer_web_pro_out", threads=64, depth=2, max_links=300, rate_limit=300):
    if not i_am_authorized:
        raise SystemExit("Refusing to run: missing --i-am-authorized flag.")
    guard = ScopeGuard(allowed_cidrs=allow_cidrs, allowed_domains=allow_domains)
    if not guard.is_allowed(url):
        raise SystemExit("Target is outside allowed scope (--allow-domain/--allow-cidr).")

    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "scan.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(log_path, encoding="utf-8")]
    )
    logger = logging.getLogger("wer-web-pro")

    session = make_session()
    limiter = rate_limiter(rate_limit)
    _orig_get = session.get
    def _rl_get(*a, **kw):
        limiter()
        return _orig_get(*a, **kw)
    session.get = _rl_get

    base_url = ensure_url(url)
    info = host_info(session, base_url, logger)

    host = urlparse(base_url).hostname
    whois_data = whois_lookup(host, logger) if host else {}
    dns_data = dns_records(host, logger) if host else {}

    # Port scan on hostname
    ports_common = [21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,
                    1433,1521,2049,2082,2083,3306,3389,5432,5900,6379,8080,8081,8443,9200,10000]
    open_ports = port_scan(host, ports_common, threads=threads, logger=logger)

    sec_headers(session, base_url, logger)
    secrets = secret_files(session, base_url, logger, threads=threads)
    js_hits = js_scan(session, base_url, logger)
    cms = cms_detect(session, base_url, logger)
    listings = dir_listing(session, base_url, logger)
    links = crawl(session, base_url, logger, depth=depth, max_links=max_links)

    if enable_active:
        sqli = sqli_scan(session, links, logger)
        xss  = xss_scan(session, links, logger)
        lfi  = lfi_scan(session, links, logger)
    else:
        sqli = xss = lfi = []

    summary = {
        "target": ensure_url(url),
        "host_info": info,
        "open_ports": open_ports,
        "security_headers_checked": SEC_HEADERS,
        "secret_files": secrets,
        "js_sensitive": js_hits,
        "cms": cms,
        "dir_listing": listings,
        "crawled_links_preview": links[:50],
        "whois": whois_data,
        "dns": dns_data,
        "active_enabled": bool(enable_active),
        "findings": {"sqli": sqli, "xss": xss, "lfi": lfi},
        "log": os.path.abspath(log_path),
    }
    out_json = os.path.join(out_dir, "summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    logger.info(Fore.MAGENTA + f"\n[+] Log file: {log_path}")
    logger.info(Fore.MAGENTA + f"[+] JSON summary: {out_json}")
    logger.info(Fore.GREEN +  "Done.")

# ------------------ CLI & Interactive ------------------
def parse_and_run(argv=None):
    ap = argparse.ArgumentParser(description="WeR-Web Pro (Safe) — Discovery & Active Checks (opt-in)")
    ap.add_argument("--url", help="Base URL, e.g. https://target.tld/")
    ap.add_argument("--allow-domain", action="append", default=[], help="Allowed domain suffix(es) (repeatable)")
    ap.add_argument("--allow-cidr", action="append", default=[], help="Allowed CIDR(s) (repeatable)")
    ap.add_argument("--i-am-authorized", action="store_true", help="You assert you are authorized to test this target")
    ap.add_argument("--enable-active", action="store_true", help="Enable active tests (SQLi/XSS/LFI)")
    ap.add_argument("--out", default="wer_web_pro_out", help="Output directory")
    ap.add_argument("--threads", type=int, default=64, help="Thread pool size")
    ap.add_argument("--depth", type=int, default=2, help="Crawl depth")
    ap.add_argument("--max-links", type=int, default=300, help="Max links to crawl")
    ap.add_argument("--rate-limit", type=int, default=300, help="Max HTTP requests per minute (approx)")
    ap.add_argument("--interactive", action="store_true", help="Interactive shell like '-scan <url>'")
    args = ap.parse_args(argv)

    if args.interactive:
        print(BANNER, file=sys.stderr)
        print(Fore.MAGENTA + r"""
░█░█░█▀▀░█▀▄      WeR-Web Pro (Interactive)
░█▄█░█▀▀░█▀▄      Type: -scan <url> [--allow-domain x] [--enable-active]
░▀░▀░▀▀▀░▀░▀      'exit' to quit
""")
        # Require at least one allow-* before scanning for safety
        default_allow_domains = set(args.allow_domain)
        default_allow_cidrs = set(args.allow_cidr)
        while True:
            try:
                cmd = input(Fore.MAGENTA + "WeR-Web> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit","quit","q"):
                break
            parts = cmd.split()
            if len(parts) >= 2 and parts[0].lower() == "-scan":
                # Parse lightweight options from the line
                line_url = parts[1]
                line_enable_active = ("--enable-active" in parts)
                # collect allow-domain/cidr from line
                line_allow_domains = list(default_allow_domains)
                line_allow_cidrs = list(default_allow_cidrs)
                for i,p in enumerate(parts):
                    if p == "--allow-domain" and i+1 < len(parts):
                        line_allow_domains.append(parts[i+1])
                    if p == "--allow-cidr" and i+1 < len(parts):
                        line_allow_cidrs.append(parts[i+1])

                if not line_allow_domains and not line_allow_cidrs:
                    print(Fore.RED + "[!] For safety, set --allow-domain or --allow-cidr first (or pass in the command).")
                    continue

                try:
                    run_full_scan(
                        url=line_url,
                        allow_domains=line_allow_domains,
                        allow_cidrs=line_allow_cidrs,
                        i_am_authorized=True,        # interactive implies your confirmation
                        enable_active=line_enable_active,
                        out_dir=args.out,
                        threads=args.threads,
                        depth=args.depth,
                        max_links=args.max_links,
                        rate_limit=args.rate_limit
                    )
                except SystemExit as e:
                    print(Fore.RED + str(e))
                except Exception as e:
                    print(Fore.RED + f"[ERROR] {e}")
            else:
                print(Fore.YELLOW + "Usage: -scan <url> [--allow-domain example.com] [--allow-cidr 1.2.3.0/24] [--enable-active]")
        return

    # Non-interactive (one-shot)
    if not args.url:
        raise SystemExit("Use --url <target> or --interactive")
    if not args.i_am_authorized:
        raise SystemExit("Refusing to run: missing --i-am-authorized flag.")
    if not (args.allow_domain or args.allow_cidr):
        raise SystemExit("For safety, set at least one --allow-domain or --allow-cidr.")

    run_full_scan(
        url=args.url,
        allow_domains=args.allow_domain,
        allow_cidrs=args.allow_cidr,
        i_am_authorized=args.i_am_authorized,
        enable_active=args.enable_active,
        out_dir=args.out,
        threads=args.threads,
        depth=args.depth,
        max_links=args.max_links,
        rate_limit=args.rate_limit
    )

# ------------------ Entry ------------------
if __name__ == "__main__":
    parse_and_run()
