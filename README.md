<<<<<<< HEAD
# PhantomShield AI — Terminal Edition
**All-in-One Cybersecurity Toolkit | Single Python File**

A menu-driven CLI tool combining 7 security modules — same style as PhantomSniff.

---

## Setup

```bash
pip install requests        # only external dependency
python3 phantomshield.py
```

That's it. No Flask, no browser — pure terminal, just like PhantomSniff.

---

## The 7 Modules

| # | Module | Works Offline? | Needs |
|---|---|---|---|
| 1 | **Phishing Analyzer** | Fully offline | — |
| 2 | **URL Scanner** | Lexical scan offline | `VT_API_KEY` for live VirusTotal verdict |
| 3 | **Security Header Checker** | Needs internet | Just `requests` (no key) |
| 4 | **CVE Intelligence** | Needs internet | NVD API (free, no key required — key just raises rate limit) |
| 5 | **Malware Analysis** | Static inspection offline | `VT_API_KEY` for hash reputation |
| 6 | **Threat Feed Search** | Needs internet | `ABUSEIPDB_KEY` for IPs; OTX domain lookup needs no key |
| 7 | **AI Security Assistant** | Offline knowledge base | `GROQ_API_KEY` for free-form LLM answers |

---

## Module Walkthrough

### 1. Phishing Analyzer
Paste an email/message body (type `END` to finish). Detects:
- Urgency/pressure language ("act now", "account suspended")
- Brand impersonation (mentions PayPal but sender domain isn't paypal.com)
- Suspicious links (IP-based, shorteners, suspicious TLDs)
- Generic greetings, attachment bait, reply-to mismatches

Outputs a 0-100 risk score + verdict.

### 2. URL Scanner
Enter any URL. Checks structure for:
- Raw IP instead of domain
- @ symbol trick, excessive hyphens/subdomains
- Brand typosquatting, high-entropy (auto-generated) domains
- HTTPS presence, credential-harvesting path patterns

Then attempts DNS resolution + optional VirusTotal verdict.

### 3. Security Header Checker
Enter a live site (e.g. example.com). Fetches real HTTP headers and grades A-F based on presence of:
Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more — plus flags info-leaking headers like Server/X-Powered-By.

### 4. CVE Intelligence
Search by CVE ID (CVE-2024-3094) or keyword (log4j, openssl). Pulls live data from the NVD (National Vulnerability Database), showing CVSS severity, score, and description.

### 5. Malware Analysis
Give it a file path. Never executes the file — purely static:
- Computes MD5 / SHA1 / SHA256
- Identifies file type by magic bytes (PE, ELF, ZIP, PDF, etc.)
- Scans for suspicious strings (powershell, CreateRemoteThread, eval(, etc.)
- Calculates Shannon entropy (high entropy = packed/encrypted/possibly malicious)
- Optional VirusTotal hash reputation lookup

### 6. Threat Feed Search
Enter an IP or domain. Checks:
- AbuseIPDB — abuse confidence score for IPs (needs free key)
- AlienVault OTX — threat pulse count for IPs/domains (no key needed)

### 7. AI Security Assistant
Ask security questions. Has a built-in offline knowledge base covering SQLi, XSS, CSRF, phishing, ransomware, firewalls, VPNs, zero-days, MFA, OWASP Top 10, buffer overflows, social engineering, DDoS, encryption, hashing. If GROQ_API_KEY is set, falls back to a free LLM for anything outside the knowledge base.

---

## Getting Free API Keys (Optional)

| Key | Where | Free tier |
|---|---|---|
| VT_API_KEY | https://www.virustotal.com/gui/join-us | 500 requests/day |
| NVD_API_KEY | https://nvd.nist.gov/developers/request-an-api-key | Raises rate limit (works fine without it too) |
| ABUSEIPDB_KEY | https://www.abuseipdb.com/register | 1000 checks/day |
| GROQ_API_KEY | https://console.groq.com | Generous free tier, very fast |

Set them before running:

```bash
# Linux / Mac
export VT_API_KEY="your_key_here"
export GROQ_API_KEY="your_key_here"
python3 phantomshield.py

# Windows CMD
set VT_API_KEY=your_key_here
set GROQ_API_KEY=your_key_here
python phantomshield.py
```

Check what's configured anytime via menu option [8] API Key Status.

---

## Example Session

```
phantomshield> 1

[1] PHISHING ANALYZER
Sender email (optional): security@paypa1-alerts.com
Subject (optional): Urgent: Account Suspended

Paste message body:
Your PayPal account has been suspended due to unusual activity.
Click here immediately to verify: http://paypal-secure-login.tk/verify.php
END

Risk Score: 80/100   Verdict: PHISHING - High Confidence

Indicators Found:
[HIGH] Urgency Language (+25pts)
[HIGH] Brand Impersonation (+25pts)
[HIGH] Suspicious URLs (+30pts)
```

---

## Project Structure

```
phantomshield.py     <- everything in one file, no other files needed
README_phantomshield.md
```

---
## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

---

## Ethics Note

Built for learning and authorized security testing only. Don't scan, probe, or analyze systems/files you don't own or have permission to test.

---

*Phantom brand — suganth_b_cyber*
=======
# PhantomShield
>>>>>>> 81ca5730c305de12e1a993d81081e40b294c4b0a
