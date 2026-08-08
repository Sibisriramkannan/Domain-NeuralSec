# 📡 Category 1 — Passive Scanning

> **No consent required.** All techniques in this category use only publicly available information and do not send any intrusive payloads to the target. Safe for pre-engagement reconnaissance.

---

## 🎯 Purpose

Category 1 performs **non-intrusive, passive reconnaissance** against a target. It gathers intelligence from:
- Public DNS records
- SSL/TLS certificate metadata
- HTTP response headers
- Public email exposure and data breach databases

No active exploits or fuzzing payloads are used. All requests mimic normal browser behavior.

---

## 🕵️ Agents Overview

### 1. `recon_agent.py` — Reconnaissance Agent

**What it does:**
- DNS enumeration (A, MX, NS, TXT, CNAME records)
- WHOIS data collection (registrar, creation date, expiry, registrant info)
- Subdomain discovery via certificate transparency logs (crt.sh)
- IP geolocation and ASN lookup
- Reverse DNS lookup
- Technology stack fingerprinting (Wappalyzer-style detection)
- Robots.txt and sitemap.xml harvesting
- Public GitHub dork searching for exposed credentials/configs

**Key Findings:**
| Finding Type | Risk | CWE |
|---|---|---|
| Subdomain exposure | LOW-MEDIUM | CWE-200 |
| WHOIS data leakage | LOW | CWE-200 |
| Technology disclosure | LOW | CWE-205 |
| Exposed robots.txt paths | LOW-MEDIUM | CWE-538 |

---

### 2. `headers_agent.py` — HTTP Headers Agent

**What it does:**
- Fetches and analyzes all HTTP response headers
- Checks for presence/absence of critical security headers
- Detects server software and version disclosure
- Evaluates cookie security attributes
- Checks for information leakage in custom headers

**Security Headers Checked:**
| Header | Expected Value | Risk if Missing |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HIGH |
| `Content-Security-Policy` | Defined policy | HIGH |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | MEDIUM |
| `X-Content-Type-Options` | `nosniff` | MEDIUM |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | LOW |
| `Permissions-Policy` | Defined policy | LOW |
| `X-XSS-Protection` | `1; mode=block` | LOW |
| `Cache-Control` | `no-store` for sensitive pages | MEDIUM |

**Key Findings:**
| Finding Type | Risk | CWE |
|---|---|---|
| Missing HSTS | HIGH | CWE-319 |
| Missing CSP | HIGH | CWE-1021 |
| Server version disclosure | MEDIUM | CWE-200 |
| Insecure cookie flags | MEDIUM | CWE-614 |

---

### 3. `ssl_agent.py` — SSL/TLS Agent

**What it does:**
- Full SSL/TLS handshake analysis
- Certificate validity, expiry, and chain verification
- Supported TLS protocol versions (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite strength evaluation
- Certificate transparency log verification
- HSTS preload status check
- OCSP stapling verification
- Subject Alternative Name (SAN) analysis
- Self-signed certificate detection
- Wildcard certificate risk assessment

**Key Findings:**
| Finding Type | Risk | CWE |
|---|---|---|
| Expired SSL certificate | CRITICAL | CWE-295 |
| TLS 1.0/1.1 support | HIGH | CWE-326 |
| Weak cipher suites | HIGH | CWE-327 |
| Self-signed certificate | MEDIUM | CWE-295 |
| Missing HSTS preload | LOW | CWE-319 |
| Certificate expiring soon | MEDIUM | CWE-298 |

---

### 4. `email_agent.py` — Email Security Agent

**What it does:**
- SPF record presence and strength analysis
- DMARC policy evaluation (none/quarantine/reject)
- DKIM record lookup and validation
- MX record security analysis
- Email server banner grabbing
- Checks for email addresses exposed in public pages
- Open relay detection (passive)
- BIMI record lookup

**Key Findings:**
| Finding Type | Risk | CWE |
|---|---|---|
| Missing SPF record | HIGH | CWE-290 |
| Weak DMARC policy (p=none) | MEDIUM | CWE-290 |
| Missing DKIM | MEDIUM | CWE-290 |
| Exposed email addresses | LOW | CWE-200 |
| Open relay potential | HIGH | CWE-290 |

---

## 🗂️ Core Components

### `core/orchestrator.py`

```python
class Category1Orchestrator:
    def __init__(self, target_url, session):
        self.target = target_url
        self.session = session          # Injected shared session from SmartConnection
        self.all_findings = []

    def run(self):
        # Runs all 4 agents sequentially
        # Collects findings from each agent
        # Returns combined findings list
Responsibilities:

Initializes all 4 agents with the shared session
Runs each agent's .scan() method sequentially
Aggregates all findings into self.all_findings
Passes findings to ReportGenerator
Handles per-agent exceptions (one agent failure doesn't stop others)
core/report_generator.py
Python

class Category1ReportGenerator:
    def __init__(self, findings, target_url):
        ...

    def generate_markdown(self):
        # Calls Groq API with findings
        # Falls back to _generate_fallback_report() on API failure
        ...

    def generate_pdf(self, markdown_content):
        # Converts Markdown to PDF via ReportLab
        ...
Report Sections Generated:

Executive Summary
Target Information
Passive Reconnaissance Findings
HTTP Header Security Analysis
SSL/TLS Assessment
Email Security Posture
Risk Matrix
Remediation Recommendations
CVSS Score Summary Table
📂 Payloads
⚠️ Category 1 uses NO offensive payloads. All data is collected passively from public sources and HTTP responses.

📊 Sample Output
text

[*] Starting Category 1 - Passive Scan
[*] Target: https://example.com
[*] Risk Level: LOW → Using Direct Connection

[+] ReconAgent       → 12 findings collected
[+] HeadersAgent     → 6 findings collected
[+] SSLAgent         → 3 findings collected
[+] EmailAgent       → 4 findings collected

[*] Total Findings: 25
[*] Generating AI Report via Groq...
[✓] Report saved: output/category1_example_com_2024.md
[✓] PDF saved:    output/category1_example_com_2024.pdf
🔒 Privacy & Ethics
All data sources are publicly accessible (DNS, crt.sh, WHOIS, HTTP headers)
No authentication bypass or credentials are tested
No payloads are injected into any parameter
Requests are throttled and headers are set to mimic browser behavior
This category is safe to run without explicit written consent (though always recommended)
📤 Output Files
text

output/
├── category1_<target>_<timestamp>.md     # Full Markdown report
├── category1_<target>_<timestamp>.json   # Raw findings
└── category1_<target>_<timestamp>.pdf    # PDF report
