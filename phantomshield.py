#!/usr/bin/env python3

"""
╔══════════════════════════════════════════════════════════════════╗
║                    P H A N T O M S H I E L D   A I               ║
║         All-in-One Cybersecurity Toolkit  |  Terminal Edition    ║
╚══════════════════════════════════════════════════════════════════╝

A single-file Python CLI tool combining 7 security modules:
  1. Phishing Analyzer       — heuristic email/text phishing detection
  2. URL Scanner             — lexical URL analysis + optional VirusTotal
  3. Security Header Checker — live HTTP header grading (A–F)
  4. CVE Intelligence        — search NVD vulnerability database
  5. Malware Analysis        — file hash reputation + static inspection
  6. Threat Feed Search      — check IP/domain/hash against threat feeds
  7. AI Security Assistant   — ask security questions (rule-based + optional LLM)

Run:
    python3 phantomshield.py

Some modules need internet + free API keys (see README_phantomshield.md).
Everything else works 100% offline.
"""

import os
import sys
import re
import math
import json
import socket
import hashlib
import urllib.parse
import urllib.request
import textwrap
from datetime import datetime

# ── Optional dependency: requests (used for live lookups) ─────────
try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# ── Colours ─────────────────────────────────────────────────────
RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; MAGENTA="\033[95m"; BLUE="\033[94m"; WHITE="\033[97m"

def c(t, col): return f"{col}{t}{RESET}"
def sep(ch="─", w=78, col=DIM): print(f"{col}{ch*w}{RESET}")
def pause(): input(f"\n  {DIM}Press Enter to continue...{RESET}")

# ── API keys (optional — set as environment variables) ──────────
VT_API_KEY     = os.environ.get("VT_API_KEY", "")          # VirusTotal
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")          # NVD CVE (optional, raises rate limit)
ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY", "")        # AbuseIPDB
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY", "")         # For AI assistant (optional)

# ════════════════════════════════════════════════════════════════
#  BANNER / MENU
# ════════════════════════════════════════════════════════════════

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""{CYAN}{BOLD}
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{MAGENTA}        S H I E L D   A I  —  Cybersecurity Toolkit{RESET}
{DIM}        7 modules · CLI · built for security research & learning{RESET}
""")

def main_menu():
    while True:
        banner()
        print(f"  {BOLD}MAIN MENU{RESET}\n")
        print(f"  {CYAN}[1]{RESET} Phishing Analyzer        {DIM}(offline){RESET}")
        print(f"  {CYAN}[2]{RESET} URL Scanner               {DIM}(offline + optional VT){RESET}")
        print(f"  {CYAN}[3]{RESET} Security Header Checker   {DIM}(needs internet){RESET}")
        print(f"  {CYAN}[4]{RESET} CVE Intelligence          {DIM}(needs internet — NVD API){RESET}")
        print(f"  {CYAN}[5]{RESET} Malware Analysis          {DIM}(offline file inspection + optional VT){RESET}")
        print(f"  {CYAN}[6]{RESET} Threat Feed Search        {DIM}(needs internet){RESET}")
        print(f"  {CYAN}[7]{RESET} AI Security Assistant     {DIM}(offline rule-based + optional LLM){RESET}")
        print(f"  {CYAN}[8]{RESET} API Key Status")
        print(f"  {RED}[q]{RESET} Quit\n")
        sep()
        choice = input(f"\n  {YELLOW}phantomshield>{RESET} ").strip().lower()

        if choice == "1": module_phishing()
        elif choice == "2": module_url_scanner()
        elif choice == "3": module_header_checker()
        elif choice == "4": module_cve_intel()
        elif choice == "5": module_malware_analysis()
        elif choice == "6": module_threat_feed()
        elif choice == "7": module_ai_assistant()
        elif choice == "8": show_api_status()
        elif choice == "q":
            print(f"\n  {CYAN}Stay safe out there. 👻{RESET}\n")
            sys.exit(0)
        else:
            print(f"  {RED}Invalid choice.{RESET}")
            pause()


def show_api_status():
    banner()
    print(f"  {BOLD}API KEY STATUS{RESET}\n")
    keys = [
        ("VT_API_KEY", VT_API_KEY, "VirusTotal — URL/file/hash reputation"),
        ("NVD_API_KEY", NVD_API_KEY, "NVD — higher CVE rate limits (optional, works without)"),
        ("ABUSEIPDB_KEY", ABUSEIPDB_KEY, "AbuseIPDB — IP threat feed lookups"),
        ("GROQ_API_KEY", GROQ_API_KEY, "Groq LLM — smarter AI Assistant answers"),
    ]
    for name, val, desc in keys:
        status = c("SET", GREEN) if val else c("NOT SET", YELLOW)
        print(f"  {name:<16} [{status}]  {DIM}{desc}{RESET}")
    print(f"\n  {DIM}Set keys via environment variables before running, e.g.:{RESET}")
    print(f"  {CYAN}export VT_API_KEY=\"your_key_here\"{RESET}   (Linux/Mac)")
    print(f"  {CYAN}set VT_API_KEY=your_key_here{RESET}        (Windows CMD)")
    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 1 — PHISHING ANALYZER
# ════════════════════════════════════════════════════════════════

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "click here", "limited time", "confirm your identity", "unusual activity",
    "your account will be", "final notice", "winner", "congratulations",
    "claim your", "password expires", "security alert", "unauthorized login",
    "update your payment", "verify now", "act fast", "last chance",
]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".loan", ".work"]
BRAND_KEYWORDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix",
                   "bank", "irs", "facebook", "instagram", "whatsapp", "linkedin"]
URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
IP_URL_REGEX = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]


def analyze_phishing_text(raw_text, sender="", subject=""):
    text = f"{subject}\n{raw_text}".lower()
    indicators, score = [], 0

    matched = [w for w in URGENCY_WORDS if w in text]
    if matched:
        pts = min(25, 5 * len(matched)); score += pts
        indicators.append(("Urgency Language", "high" if len(matched) >= 3 else "medium",
                           f"{len(matched)} pressure phrase(s): {', '.join(matched[:5])}", pts))

    mentioned = [b for b in BRAND_KEYWORDS if b in text]
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    if mentioned and sender_domain:
        mismatched = [b for b in mentioned if b not in sender_domain]
        if mismatched:
            score += 25
            indicators.append(("Brand Impersonation", "high",
                               f"Mentions {', '.join(mismatched)} but sender domain '{sender_domain}' differs", 25))

    urls = URL_REGEX.findall(raw_text)
    flagged_urls = []
    for url in urls:
        domain = urllib.parse.urlparse(url).netloc.lower()
        flags = []
        if IP_URL_REGEX.match(url): flags.append("raw IP address")
        if any(domain.endswith(t) for t in SUSPICIOUS_TLDS): flags.append(f"suspicious TLD (.{domain.split('.')[-1]})")
        if any(s in domain for s in SHORTENERS): flags.append("URL shortener")
        if domain.count("-") >= 3: flags.append("excessive hyphens")
        if flags: flagged_urls.append((url, domain, flags))
    if flagged_urls:
        pts = min(30, 10*len(flagged_urls)); score += pts
        indicators.append(("Suspicious URLs", "high", f"{len(flagged_urls)} suspicious link(s)", pts))

    if re.search(r'\b(dear (customer|user|valued|sir|member)|hello user)\b', text):
        score += 10
        indicators.append(("Generic Greeting", "low", "No personalization — mass-phishing pattern", 10))

    if re.search(r'(enable (macros|content)|open the attached|download.{0,15}invoice|\.exe\b|\.scr\b|\.zip\b)', text):
        score += 15
        indicators.append(("Malicious Attachment Bait", "high", "References macro/exe/zip attachment", 15))

    if "reply-to" in text or "reply to" in text:
        score += 5
        indicators.append(("Reply-To Redirection", "medium", "Different reply address than sender", 5))

    score = min(100, score)
    if score >= 70: verdict = "PHISHING — High Confidence"
    elif score >= 40: verdict = "SUSPICIOUS — Review Carefully"
    elif score >= 15: verdict = "LOW RISK — Minor Flags"
    else: verdict = "LIKELY LEGITIMATE"

    return score, verdict, indicators, flagged_urls


def module_phishing():
    banner()
    print(f"  {BOLD}{MAGENTA}[1] PHISHING ANALYZER{RESET}\n")
    print(f"  {DIM}Paste an email/message body. Type END on its own line when done.{RESET}\n")
    sender = input(f"  Sender email (optional): {RESET}").strip()
    subject = input(f"  Subject (optional): {RESET}").strip()
    print(f"\n  {DIM}Paste message body:{RESET}")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    raw_text = "\n".join(lines)

    if not raw_text.strip():
        print(f"\n  {RED}No content provided.{RESET}")
        pause(); return

    score, verdict, indicators, urls = analyze_phishing_text(raw_text, sender, subject)

    print(f"\n")
    sep("═", 78, MAGENTA)
    vcolor = RED if score >= 70 else YELLOW if score >= 40 else GREEN
    print(f"\n  {BOLD}Risk Score: {vcolor}{score}/100{RESET}   {BOLD}Verdict: {vcolor}{verdict}{RESET}\n")
    sep()
    if indicators:
        print(f"\n  {BOLD}Indicators Found:{RESET}\n")
        for itype, sev, detail, pts in indicators:
            scol = RED if sev == "high" else YELLOW if sev == "medium" else DIM
            print(f"  [{scol}{sev.upper():<6}{RESET}] {BOLD}{itype}{RESET} (+{pts}pts)")
            print(f"           {DIM}{detail}{RESET}\n")
    else:
        print(f"\n  {GREEN}No major phishing indicators detected.{RESET}\n")

    if urls:
        print(f"  {BOLD}Suspicious URLs:{RESET}\n")
        for url, domain, flags in urls:
            print(f"  {RED}●{RESET} {url}")
            print(f"      {DIM}{', '.join(flags)}{RESET}\n")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 2 — URL SCANNER
# ════════════════════════════════════════════════════════════════

BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "bankofamerica", "chase", "wellsfargo"]

def shannon_entropy(s):
    if not s: return 0
    probs = [s.count(ch)/len(s) for ch in set(s)]
    return -sum(p*math.log2(p) for p in probs)

def lexical_url_scan(url):
    findings, score = [], 0
    parsed = urllib.parse.urlparse(url if "://" in url else "http://"+url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""
    if not domain:
        return 0, "INVALID URL", [], ""

    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain.split(":")[0]):
        score += 30; findings.append(("IP-based URL", "high", "Domain is a raw IP — rare for legit sites"))
    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 20; findings.append(("Suspicious TLD", "medium", f"'.{domain.split('.')[-1]}' often abused"))
    if any(s in domain for s in SHORTENERS):
        score += 15; findings.append(("URL Shortener", "medium", "Hides real destination"))
    if "@" in url:
        score += 25; findings.append(("@ Symbol Trick", "high", "Text before '@' ignored by browsers"))
    if domain.count(".") >= 4:
        score += 10; findings.append(("Excessive Subdomains", "low", f"{domain.count('.')} dots in domain"))
    if domain.count("-") >= 3:
        score += 10; findings.append(("Excessive Hyphens", "low", "Common in typosquatting"))

    root_parts = domain.split(".")
    root_domain = ".".join(root_parts[-2:]) if len(root_parts) >= 2 else domain
    for brand in BRANDS:
        if brand in domain and brand not in root_domain:
            score += 25; findings.append(("Brand Impersonation", "high",
                         f"'{brand}' in subdomain, real root is '{root_domain}'")); break

    label = root_parts[0] if root_parts else domain
    ent = shannon_entropy(label)
    if ent > 3.6 and len(label) > 10:
        score += 15; findings.append(("High Entropy Domain", "medium", f"entropy={ent:.2f} — looks auto-generated"))
    if parsed.scheme != "https":
        score += 10; findings.append(("No HTTPS", "low", "Unencrypted connection"))
    if re.search(r'(login|verify|account|secure|update|confirm|signin).{0,20}\.(php|html)', path.lower()):
        score += 10; findings.append(("Credential Harvesting Path", "medium", "Path mimics fake login page"))

    score = min(100, score)
    if score >= 70: verdict = "MALICIOUS — High Risk"
    elif score >= 40: verdict = "SUSPICIOUS"
    elif score >= 15: verdict = "LOW RISK"
    else: verdict = "LIKELY SAFE"
    return score, verdict, findings, domain


def virustotal_url_check(url):
    if not VT_API_KEY:
        return None, "No VT_API_KEY set — skipping live VirusTotal check."
    if not HAVE_REQUESTS:
        return None, "Python 'requests' library not installed."
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if resp.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
            return None, "Not previously scanned — submitted to VirusTotal. Check back in a minute."
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
        return stats, None
    except Exception as e:
        return None, str(e)


def module_url_scanner():
    banner()
    print(f"  {BOLD}{MAGENTA}[2] URL SCANNER{RESET}\n")
    url = input(f"  Enter URL to scan: {RESET}").strip()
    if not url:
        print(f"  {RED}No URL provided.{RESET}"); pause(); return

    score, verdict, findings, domain = lexical_url_scan(url)
    print(f"\n")
    sep("═", 78, MAGENTA)
    vcolor = RED if score >= 70 else YELLOW if score >= 40 else GREEN
    print(f"\n  {BOLD}Domain: {WHITE}{domain}{RESET}")
    print(f"  {BOLD}Risk Score: {vcolor}{score}/100{RESET}   {BOLD}Verdict: {vcolor}{verdict}{RESET}\n")
    sep()
    if findings:
        print(f"\n  {BOLD}Lexical Findings:{RESET}\n")
        for ftype, sev, detail in findings:
            scol = RED if sev == "high" else YELLOW if sev == "medium" else DIM
            print(f"  [{scol}{sev.upper():<6}{RESET}] {BOLD}{ftype}{RESET}")
            print(f"           {DIM}{detail}{RESET}\n")
    else:
        print(f"\n  {GREEN}No structural red flags found.{RESET}\n")

    # DNS resolution
    try:
        ip = socket.gethostbyname(domain.split(":")[0])
        print(f"  {BOLD}DNS Resolution:{RESET} {GREEN}{domain} → {ip}{RESET}")
    except Exception:
        print(f"  {BOLD}DNS Resolution:{RESET} {YELLOW}Could not resolve (no internet or invalid domain){RESET}")

    print(f"\n  {BOLD}VirusTotal Check:{RESET}")
    stats, err = virustotal_url_check(url)
    if stats:
        print(f"  {GREEN}Malicious: {stats.get('malicious',0)}  Suspicious: {stats.get('suspicious',0)}  "
              f"Harmless: {stats.get('harmless',0)}  Undetected: {stats.get('undetected',0)}{RESET}")
    else:
        print(f"  {DIM}{err}{RESET}")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 3 — SECURITY HEADER CHECKER
# ════════════════════════════════════════════════════════════════

HEADER_CHECKS = {
    "Strict-Transport-Security": (15, "Forces HTTPS, blocks downgrade attacks", "max-age=63072000; includeSubDomains; preload"),
    "Content-Security-Policy":   (20, "Restricts script/style sources — mitigates XSS", "default-src 'self'"),
    "X-Frame-Options":           (12, "Prevents clickjacking", "DENY"),
    "X-Content-Type-Options":    (10, "Stops MIME-sniffing", "nosniff"),
    "Referrer-Policy":           (8,  "Controls referrer leakage", "strict-origin-when-cross-origin"),
    "Permissions-Policy":        (10, "Restricts camera/mic/geo access", "geolocation=(), camera=(), microphone=()"),
    "X-XSS-Protection":          (5,  "Legacy XSS filter", "1; mode=block"),
    "Cross-Origin-Opener-Policy":(10, "Mitigates Spectre-class attacks", "same-origin"),
    "Cross-Origin-Resource-Policy":(5,"Controls cross-origin resource embedding", "same-origin"),
}
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]


def module_header_checker():
    banner()
    print(f"  {BOLD}{MAGENTA}[3] SECURITY HEADER CHECKER{RESET}\n")
    if not HAVE_REQUESTS:
        print(f"  {RED}'requests' library not installed. Run: pip install requests{RESET}")
        pause(); return

    url = input(f"  Enter URL (e.g. example.com): {RESET}").strip()
    if not url:
        print(f"  {RED}No URL provided.{RESET}"); pause(); return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"\n  {DIM}Fetching headers...{RESET}")
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                           headers={"User-Agent": "PhantomShield-AI/1.0"})
    except Exception as e:
        print(f"\n  {RED}Failed to fetch: {e}{RESET}"); pause(); return

    headers = resp.headers
    total, max_score = 0, sum(v[0] for v in HEADER_CHECKS.values())
    print(f"\n")
    sep("═", 78, MAGENTA)
    print(f"\n  {BOLD}URL:{RESET} {resp.url}   {BOLD}Status:{RESET} {resp.status_code}\n")
    sep()
    print(f"\n  {BOLD}Header Analysis:{RESET}\n")
    for name, (weight, desc, rec) in HEADER_CHECKS.items():
        present = name in headers
        if present: total += weight
        mark = c("✓ PRESENT", GREEN) if present else c("✗ MISSING", RED)
        print(f"  {mark}  {BOLD}{name}{RESET}")
        print(f"           {DIM}{desc}{RESET}")
        if present:
            print(f"           {DIM}Value: {headers.get(name)}{RESET}")
        else:
            print(f"           {YELLOW}Recommended: {name}: {rec}{RESET}")
        print()

    pct = round((total/max_score)*100)
    grade = "A" if pct>=85 else "B" if pct>=70 else "C" if pct>=50 else "D" if pct>=30 else "F"
    gcol = GREEN if grade in "AB" else YELLOW if grade=="C" else RED
    sep()
    print(f"\n  {BOLD}Overall Grade: {gcol}{grade}{RESET}   {BOLD}Score: {gcol}{pct}%{RESET}\n")

    leaks = [(h, headers[h]) for h in INFO_LEAK_HEADERS if h in headers]
    if leaks:
        print(f"  {YELLOW}{BOLD}Information Disclosure:{RESET}")
        for h, v in leaks:
            print(f"    {YELLOW}●{RESET} {h}: {v}")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 4 — CVE INTELLIGENCE
# ════════════════════════════════════════════════════════════════

def module_cve_intel():
    banner()
    print(f"  {BOLD}{MAGENTA}[4] CVE INTELLIGENCE{RESET}\n")
    print(f"  {DIM}Search the NVD (National Vulnerability Database).{RESET}")
    print(f"  {DIM}Examples: 'CVE-2024-3094', 'apache log4j', 'openssl'{RESET}\n")

    if not HAVE_REQUESTS:
        print(f"  {RED}'requests' library not installed. Run: pip install requests{RESET}")
        pause(); return

    query = input(f"  Search query: {RESET}").strip()
    if not query:
        print(f"  {RED}No query provided.{RESET}"); pause(); return

    print(f"\n  {DIM}Querying NVD...{RESET}")
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    if re.match(r'^CVE-\d{4}-\d+$', query.upper()):
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query
        params["resultsPerPage"] = 10

    try:
        resp = requests.get(base, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"\n  {RED}Lookup failed: {e}{RESET}")
        print(f"  {DIM}(NVD may rate-limit without an API key — get a free one at https://nvd.nist.gov/developers/request-an-api-key){RESET}")
        pause(); return

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"\n  {YELLOW}No results found.{RESET}"); pause(); return

    print(f"\n")
    sep("═", 78, MAGENTA)
    print(f"\n  {BOLD}Found {len(vulns)} result(s):{RESET}\n")

    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "?")
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")
        metrics = cve.get("metrics", {})
        severity, score = "N/A", "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", metrics[key][0].get("baseSeverity", "N/A"))
                break
        scol = RED if severity in ("CRITICAL","HIGH") else YELLOW if severity=="MEDIUM" else GREEN if severity=="LOW" else DIM
        print(f"  {BOLD}{CYAN}{cve_id}{RESET}   {scol}{severity} ({score}){RESET}")
        print(f"  {textwrap.fill(desc_en, width=74, initial_indent='  ', subsequent_indent='  ')}")
        published = cve.get("published", "?")
        print(f"  {DIM}Published: {published[:10]}{RESET}\n")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 5 — MALWARE ANALYSIS
# ════════════════════════════════════════════════════════════════

SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"WScript.Shell", b"CreateRemoteThread",
    b"VirtualAlloc", b"URLDownloadToFile", b"RegSetValue", b"keylog",
    b"base64,", b"eval(", b"document.write", b"<script>", b"shell_exec",
    b"WriteProcessMemory", b"SetWindowsHookEx", b"GetAsyncKeyState",
]

def compute_hashes(filepath):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def static_inspect(filepath):
    findings = []
    with open(filepath, "rb") as f:
        data = f.read()

    # Magic byte / file type
    magic_map = {
        b"MZ": "Windows PE Executable (.exe/.dll)",
        b"\x7fELF": "Linux ELF Executable",
        b"PK\x03\x04": "ZIP/Office/JAR Archive",
        b"%PDF": "PDF Document",
        b"\xca\xfe\xba\xbe": "Java Class File",
        b"\xd0\xcf\x11\xe0": "Legacy MS Office Document",
    }
    filetype = "Unknown / Generic Binary"
    for magic, label in magic_map.items():
        if data.startswith(magic):
            filetype = label; break

    found_strings = [s.decode(errors="ignore") for s in SUSPICIOUS_STRINGS if s in data]
    entropy = shannon_entropy_bytes(data)

    return filetype, found_strings, entropy, len(data)

def shannon_entropy_bytes(data):
    if not data: return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    probs = [v/len(data) for v in freq.values()]
    return -sum(p*math.log2(p) for p in probs)

def virustotal_hash_check(sha256):
    if not VT_API_KEY:
        return None, "No VT_API_KEY set — skipping live reputation check."
    if not HAVE_REQUESTS:
        return None, "'requests' not installed."
    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=10)
        if resp.status_code == 404:
            return None, "Hash not found in VirusTotal database (file may be unique/unseen)."
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
        return stats, None
    except Exception as e:
        return None, str(e)


def module_malware_analysis():
    banner()
    print(f"  {BOLD}{MAGENTA}[5] MALWARE ANALYSIS{RESET}\n")
    print(f"  {DIM}Static file inspection — hashing, file type, suspicious strings, entropy.{RESET}")
    print(f"  {YELLOW}Only analyze files you trust the source of. Never execute unknown files.{RESET}\n")

    filepath = input(f"  Path to file: {RESET}").strip().strip('"').strip("'")
    if not filepath or not os.path.isfile(filepath):
        print(f"  {RED}File not found.{RESET}"); pause(); return

    print(f"\n  {DIM}Hashing file...{RESET}")
    md5, sha1, sha256 = compute_hashes(filepath)
    filetype, suspicious, entropy, size = static_inspect(filepath)

    print(f"\n")
    sep("═", 78, MAGENTA)
    print(f"\n  {BOLD}File:{RESET} {filepath}")
    print(f"  {BOLD}Size:{RESET} {size:,} bytes")
    print(f"  {BOLD}Type:{RESET} {filetype}")
    print(f"  {BOLD}Entropy:{RESET} {entropy:.2f}/8.0 {DIM}(>7.5 may indicate packing/encryption){RESET}\n")

    print(f"  {BOLD}Hashes:{RESET}")
    print(f"    MD5:    {DIM}{md5}{RESET}")
    print(f"    SHA1:   {DIM}{sha1}{RESET}")
    print(f"    SHA256: {DIM}{sha256}{RESET}\n")

    if suspicious:
        print(f"  {RED}{BOLD}⚠ Suspicious strings found:{RESET}")
        for s in suspicious:
            print(f"    {RED}●{RESET} {s}")
    else:
        print(f"  {GREEN}No suspicious strings from local signature list.{RESET}")

    if entropy > 7.5:
        print(f"\n  {YELLOW}⚠ High entropy — file may be packed, encrypted, or compressed.{RESET}")

    print(f"\n  {BOLD}VirusTotal Reputation:{RESET}")
    stats, err = virustotal_hash_check(sha256)
    if stats:
        mal = stats.get("malicious", 0)
        col = RED if mal > 0 else GREEN
        print(f"  {col}Malicious: {mal}  Suspicious: {stats.get('suspicious',0)}  "
              f"Harmless: {stats.get('harmless',0)}  Undetected: {stats.get('undetected',0)}{RESET}")
    else:
        print(f"  {DIM}{err}{RESET}")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 6 — THREAT FEED SEARCH
# ════════════════════════════════════════════════════════════════

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None, "No ABUSEIPDB_KEY set — skipping."
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                           params={"ipAddress": ip, "maxAgeInDays": 90},
                           headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", {}), None
    except Exception as e:
        return None, str(e)

def check_otx(indicator, ind_type="domain"):
    """AlienVault OTX — free, no key required for basic indicator lookups."""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{indicator}/general"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            return None, "Not found in OTX."
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        return {"pulse_count": pulses, "reputation": data.get("reputation", 0)}, None
    except Exception as e:
        return None, str(e)


def module_threat_feed():
    banner()
    print(f"  {BOLD}{MAGENTA}[6] THREAT FEED SEARCH{RESET}\n")
    print(f"  {DIM}Check an IP address or domain against threat intelligence feeds:{RESET}")
    print(f"  {DIM} - AbuseIPDB (IPs, needs free API key)")
    print(f"  {DIM} - AlienVault OTX (IPs/domains, no key needed){RESET}\n")

    if not HAVE_REQUESTS:
        print(f"  {RED}'requests' library not installed. Run: pip install requests{RESET}")
        pause(); return

    indicator = input(f"  Enter IP or domain: {RESET}").strip()
    if not indicator:
        print(f"  {RED}No indicator provided.{RESET}"); pause(); return

    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator))

    print(f"\n")
    sep("═", 78, MAGENTA)
    print(f"\n  {BOLD}Indicator:{RESET} {indicator}  {DIM}({'IP' if is_ip else 'Domain'}){RESET}\n")

    if is_ip:
        print(f"  {BOLD}AbuseIPDB:{RESET}")
        data, err = check_abuseipdb(indicator)
        if data:
            score = data.get("abuseConfidenceScore", 0)
            col = RED if score > 50 else YELLOW if score > 10 else GREEN
            print(f"  {col}Abuse Confidence Score: {score}%{RESET}")
            print(f"  {DIM}Total Reports: {data.get('totalReports',0)}  "
                  f"Country: {data.get('countryCode','?')}  "
                  f"ISP: {data.get('isp','?')}{RESET}")
        else:
            print(f"  {DIM}{err}{RESET}")
        print()

    print(f"  {BOLD}AlienVault OTX:{RESET}")
    data, err = check_otx(indicator, "IPv4" if is_ip else "domain")
    if data:
        pulses = data["pulse_count"]
        col = RED if pulses > 5 else YELLOW if pulses > 0 else GREEN
        print(f"  {col}Threat Pulses: {pulses}{RESET}  {DIM}(number of threat reports referencing this indicator){RESET}")
    else:
        print(f"  {DIM}{err}{RESET}")

    pause()

# ════════════════════════════════════════════════════════════════
#  MODULE 7 — AI SECURITY ASSISTANT
# ════════════════════════════════════════════════════════════════

KNOWLEDGE_BASE = {
    "sql injection": "SQL Injection (SQLi) occurs when untrusted input is concatenated into SQL queries. "
                     "Prevent it with parameterized queries/prepared statements, ORM usage, input validation, "
                     "and least-privilege DB accounts. Example vulnerable: f\"SELECT * FROM users WHERE id={user_input}\".",
    "xss": "Cross-Site Scripting (XSS) injects malicious scripts into web pages viewed by others. "
          "Types: Reflected, Stored, DOM-based. Mitigate with output encoding, Content-Security-Policy headers, "
          "and frameworks that auto-escape (React, Vue).",
    "csrf": "Cross-Site Request Forgery tricks a logged-in user's browser into making unwanted requests. "
           "Mitigate with anti-CSRF tokens, SameSite cookies, and checking the Origin/Referer header.",
    "phishing": "Phishing uses deceptive emails/sites to steal credentials or deliver malware. Red flags: urgency, "
               "mismatched sender domains, suspicious links, generic greetings, attachment bait. Use this tool's "
               "Phishing Analyzer (option 1) to scan suspicious messages.",
    "ransomware": "Ransomware encrypts victim files and demands payment. Defense: offline backups (3-2-1 rule), "
                 "patching, email filtering, EDR, and disabling macros by default.",
    "firewall": "A firewall filters network traffic based on rules (IP, port, protocol). Types: packet-filtering, "
               "stateful, next-gen (NGFW with deep packet inspection). Default-deny is best practice.",
    "vpn": "A VPN encrypts traffic between your device and a server, hiding your IP and protecting data on "
          "untrusted networks (public WiFi). It does not make you anonymous from the VPN provider itself.",
    "zero day": "A zero-day is a vulnerability unknown to the vendor with no patch available. Zero-day exploits "
               "are highly valuable on the black market. Defense-in-depth (not relying on a single control) reduces risk.",
    "mfa": "Multi-Factor Authentication requires 2+ factors: something you know (password), have (phone/token), "
          "or are (biometric). Drastically reduces account takeover risk even if password is leaked.",
    "owasp top 10": "OWASP Top 10 (2021): Broken Access Control, Cryptographic Failures, Injection, Insecure Design, "
                   "Security Misconfiguration, Vulnerable Components, Auth Failures, Integrity Failures, "
                   "Logging Failures, SSRF.",
    "buffer overflow": "Occurs when a program writes more data to a buffer than it can hold, corrupting adjacent "
                       "memory. Can lead to crashes or code execution. Mitigations: bounds checking, ASLR, DEP, "
                       "stack canaries, memory-safe languages (Rust).",
    "social engineering": "Manipulating people (not systems) into revealing info or granting access. Common tactics: "
                          "pretexting, baiting, tailgating, phishing, vishing (voice phishing). Best defense: "
                          "security awareness training + verification procedures.",
    "ddos": "Distributed Denial of Service floods a target with traffic from many sources to exhaust resources. "
           "Mitigation: rate limiting, CDN/scrubbing services (Cloudflare), anycast, autoscaling.",
    "encryption": "Encryption transforms data into ciphertext readable only with a key. Symmetric (AES) uses one "
                 "key; Asymmetric (RSA, ECC) uses public/private key pairs. TLS combines both for HTTPS.",
    "hashing": "Hashing produces a fixed-size fingerprint of data (one-way). Used for password storage (bcrypt, "
              "Argon2 — NOT plain MD5/SHA1) and integrity verification.",
}

def ai_assistant_answer(question):
    q = question.lower()
    matches = [(topic, ans) for topic, ans in KNOWLEDGE_BASE.items() if topic in q]
    if matches:
        return "\n\n".join(f"{c(t.upper(), CYAN)}\n{textwrap.fill(a, 74)}" for t, a in matches)

    # Try Groq LLM if configured
    if GROQ_API_KEY and HAVE_REQUESTS:
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are a concise cybersecurity expert assistant. "
                                                       "Answer in under 150 words, practically."},
                        {"role": "user", "content": question}
                    ],
                    "max_tokens": 300,
                },
                timeout=15,
            )
            resp.raise_for_status()
            return textwrap.fill(resp.json()["choices"][0]["message"]["content"], 74)
        except Exception as e:
            return f"{YELLOW}LLM request failed: {e}{RESET}"

    topics = ", ".join(KNOWLEDGE_BASE.keys())
    return (f"No offline match found. Try asking about: {topics}\n\n"
            f"{DIM}Tip: set GROQ_API_KEY environment variable for free-form AI answers "
            f"(get a key at https://console.groq.com).{RESET}")


def module_ai_assistant():
    banner()
    print(f"  {BOLD}{MAGENTA}[7] AI SECURITY ASSISTANT{RESET}\n")
    mode = "LLM-enabled" if GROQ_API_KEY else "offline knowledge-base"
    print(f"  {DIM}Mode: {mode}. Type 'back' to return to menu.{RESET}\n")

    while True:
        q = input(f"  {YELLOW}ask>{RESET} ").strip()
        if not q:
            continue
        if q.lower() in ("back", "exit", "quit"):
            break
        print()
        print(ai_assistant_answer(q))
        print()

# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if not HAVE_REQUESTS:
        print(f"{YELLOW}[!] 'requests' library not found. Some modules need it: pip install requests{RESET}\n")
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {CYAN}Interrupted. Stay safe. 👻{RESET}\n")
        sys.exit(0)

        
# PhantomShield
# Copyright 2026 Suganth B
#
# Licensed under the Apache License, Version 2.0
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.