# 💀 Category 3 — Advanced Scanning

> **Explicit consent required.** Category 3 tests sophisticated, high-impact vulnerability classes that can result in Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), authentication bypass, and full system compromise. **Only run with written authorization.**

---

## ⚠️ Critical Warning
Category 3 tests include techniques that can:

Execute commands on the server (RCE via Command Injection, SSTI)
Access internal network resources (SSRF)
Corrupt application state (Prototype Pollution, NoSQL Injection)
Upload malicious files (File Upload vulnerabilities)
NEVER run against production systems without a maintenance window.
ALWAYS have explicit, written authorization.

text


---

## 🎯 Purpose

Category 3 represents the **deepest layer** of the assessment. It targets advanced vulnerability classes often missed by automated scanners. Every agent in this category includes a **LiveLogger** that streams real-time progress to the terminal, showing each payload tested, each response analyzed, and each finding confirmed.

---

## 📺 LiveLogger

Category 3 features a unique **LiveLogger** system integrated into the orchestrator:
[LIVE] auth_agent → [STEP 1] Testing default credentials...
[LIVE] auth_agent → [STEP 2] Testing credential stuffing (50 pairs)...
[LIVE] command_injection → [STEP 1] Testing sleep-based blind injection...
[LIVE] command_injection → [PAYLOAD] ; sleep 5 → Response time: 5.2s → ✓ CONFIRMED
[LIVE] ssrf_agent → [STEP 3] Testing internal IP ranges...
[LIVE] file_upload_agent → [STEP 2] Uploading PHP webshell disguised as JPEG...

text


All LiveLogger output is also written to `monitor_logs.txt` for the dashboard.

---

## 🕵️ Agents Overview (14 Agents)

### 1. `auth_agent.py` — Authentication Testing Agent

**What it does:**
- Default/common credential testing (admin:admin, admin:password, etc.)
- Credential stuffing simulation
- Account lockout policy analysis
- Password reset flow vulnerabilities (host header poisoning in reset links)
- Multi-factor authentication bypass techniques
- Session fixation detection
- Brute-force protection assessment

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Default Credentials | 9.8 | CWE-1392 |
| No Account Lockout | 7.5 | CWE-307 |
| Password Reset Poisoning | 8.8 | CWE-640 |
| Session Fixation | 7.3 | CWE-384 |
| MFA Bypass | 9.0 | CWE-308 |

---

### 2. `command_injection_agent.py` — Command Injection Agent

**What it does:**
- OS command injection via `; && || | \`
- Blind command injection via time delays (sleep/ping)
- Out-of-band command injection (DNS/HTTP callbacks)
- Injection in all input vectors (GET, POST, headers, cookies)
- Shell metacharacter fuzzing
- Both Linux and Windows command sets

**Payload File:** `payloads/command_injection_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| OS Command Injection (RCE) | 10.0 | CWE-78 |
| Blind Command Injection | 9.0 | CWE-78 |
| OOB Command Injection | 9.0 | CWE-78 |

---

### 3. `file_upload_agent.py` — File Upload Security Agent

**What it does:**
- File type validation bypass (extension spoofing, double extension)
- MIME type bypass (`image/jpeg` with PHP content)
- Magic bytes manipulation (GIF89a + PHP payload)
- Executable upload to web-accessible directory
- Zip slip attack (path traversal via archive)
- Image polyglot payload crafting
- Upload size limit DoS assessment

**Payload File:** `payloads/file_upload_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Unrestricted File Upload (RCE) | 10.0 | CWE-434 |
| MIME Bypass Upload | 9.0 | CWE-434 |
| Zip Slip | 8.1 | CWE-22 |
| Stored XSS via Upload | 7.3 | CWE-79 |

---

### 4. `ssrf_agent.py` — Server-Side Request Forgery Agent

**What it does:**
- Basic SSRF to internal IP ranges (127.0.0.1, 169.254.x.x, 10.x, 192.168.x)
- Cloud metadata endpoint probing (AWS: 169.254.169.254, GCP, Azure)
- Blind SSRF via DNS/HTTP OOB callbacks
- Protocol smuggling (file://, dict://, gopher://, ftp://)
- URL redirect chain abuse
- SSRF filter bypass (IP encoding, DNS rebinding concepts)

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| SSRF to Internal Network | 9.0 | CWE-918 |
| Cloud Metadata SSRF | 9.8 | CWE-918 |
| Blind SSRF | 7.5 | CWE-918 |
| Protocol Smuggling via SSRF | 8.5 | CWE-918 |

---

### 5. `xxe_agent.py` — XML External Entity Agent

**What it does:**
- Classic XXE file disclosure (`/etc/passwd`)
- Blind XXE via OOB DNS callback
- XXE via file upload (SVG, XLSX, DOCX processing)
- Error-based XXE
- XXE in SOAP endpoints
- XXE to SSRF chaining
- DTD-based billion laughs DoS detection (passive)

**Payload File:** `payloads/xxe_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Classic XXE (File Read) | 9.1 | CWE-611 |
| Blind XXE (OOB) | 8.2 | CWE-611 |
| XXE to SSRF | 9.0 | CWE-611 |
| XXE via File Upload | 8.8 | CWE-611 |

---

### 6. `nosql_agent.py` — NoSQL Injection Agent

**What it does:**
- MongoDB operator injection (`$gt`, `$ne`, `$where`, `$regex`)
- Authentication bypass via NoSQL injection
- JSON body injection
- Array injection techniques
- Blind NoSQL via timing
- Redis/CouchDB injection fingerprinting

**Payload File:** `payloads/nosql_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| NoSQL Auth Bypass | 9.8 | CWE-943 |
| NoSQL Data Extraction | 8.5 | CWE-943 |
| Blind NoSQL Injection | 7.5 | CWE-943 |

---

### 7. `ssti_agent.py` — Server-Side Template Injection Agent

**What it does:**
- Template engine fingerprinting (Jinja2, Twig, Freemarker, Pebble, Smarty, Handlebars)
- Mathematical expression probing (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)
- RCE via SSTI (Jinja2: `{{config.__class__...}}`)
- Blind SSTI via time-based payloads
- Context-specific payload selection

**Payload File:** `payloads/ssti_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| SSTI → RCE | 10.0 | CWE-94 |
| Blind SSTI | 8.5 | CWE-94 |
| Template Info Disclosure | 5.3 | CWE-200 |

---

### 8. `csrf_agent.py` — CSRF Agent

**What it does:**
- CSRF token presence and strength analysis
- Token reuse detection
- Referer header bypass testing
- SameSite cookie attribute assessment
- JSON-based CSRF (Content-Type bypass)
- Multi-step CSRF flow analysis
- State-changing GET request detection

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Missing CSRF Token | 8.8 | CWE-352 |
| CSRF Token Reuse | 7.5 | CWE-352 |
| SameSite Not Set | 6.5 | CWE-352 |
| JSON CSRF | 7.0 | CWE-352 |

---

### 9. `websocket_agent.py` — WebSocket Security Agent

**What it does:**
- WebSocket connection hijacking (CSWSH)
- Origin validation bypass
- Message injection testing (SQLi, XSS in WS messages)
- WebSocket authentication bypass
- Insecure WebSocket (ws:// on HTTPS pages)
- Mass assignment via WebSocket messages
- WebSocket DoS (flood detection)

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| CSWSH | 8.8 | CWE-346 |
| WebSocket Injection | 8.0 | CWE-20 |
| Insecure WS Protocol | 6.5 | CWE-319 |

---

### 10. `http_host_header_agent.py` — HTTP Host Header Agent

**What it does:**
- Host header injection for cache poisoning
- Password reset link poisoning via Host header
- Duplicate Host header injection
- X-Forwarded-Host / X-Host bypass
- Absolute URL injection
- Port-based host confusion attacks

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Host Header Injection | 8.1 | CWE-20 |
| Password Reset Poisoning | 8.8 | CWE-640 |
| Cache Poisoning via Host | 8.0 | CWE-20 |

---

### 11. `web_cache_agent.py` — Web Cache Poisoning Agent

**What it does:**
- Cache key analysis (what headers/params are cached)
- Unkeyed header injection for cache poisoning
- Fat GET request attacks
- Cache deception path manipulation
- Parameter cloaking techniques
- Stored/reflected XSS via cache poisoning

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Web Cache Poisoning | 8.1 | CWE-444 |
| Cache Deception | 7.5 | CWE-444 |
| Stored XSS via Cache | 8.8 | CWE-79 |

---

### 12. `oauth_agent.py` — OAuth 2.0 Security Agent

**What it does:**
- OAuth state parameter CSRF bypass
- Redirect URI manipulation
- Authorization code interception
- Token leakage in Referer header
- Implicit flow token exposure
- Open redirect via OAuth flow
- Account takeover via OAuth misconfiguration

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Missing State Parameter | 8.1 | CWE-352 |
| Redirect URI Bypass | 8.8 | CWE-601 |
| Token Exposure in Referer | 6.5 | CWE-200 |
| OAuth Account Takeover | 9.8 | CWE-287 |

---

### 13. `prototype_pollution_agent.py` — Prototype Pollution Agent

**What it does:**
- Client-side prototype pollution via URL parameters (`?__proto__[x]=1`)
- Server-side prototype pollution in Node.js apps
- JSON body `__proto__` injection
- Constructor pollution (`constructor.prototype`)
- Gadget chain detection for XSS/RCE escalation
- Template library pollution (Lodash, jQuery gadgets)

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Server-side Prototype Pollution | 9.0 | CWE-1321 |
| Client-side Prototype Pollution | 6.5 | CWE-1321 |
| Prototype Pollution → RCE | 10.0 | CWE-1321 |

---

### 14. `access_control_agent.py` — Broken Access Control Agent

**What it does:**
- Horizontal privilege escalation (IDOR via ID manipulation)
- Vertical privilege escalation (user → admin role)
- Forced browsing to admin/restricted paths
- HTTP method override for access bypass (X-HTTP-Method-Override)
- Directory listing detection
- JWT role claim manipulation (works with JWT agent findings)
- RBAC bypass via parameter tampering

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| IDOR | 8.8 | CWE-284 |
| Vertical Privilege Escalation | 9.8 | CWE-269 |
| Forced Browsing | 7.5 | CWE-425 |
| Method Override Bypass | 7.0 | CWE-650 |

---

## 🗂️ Core Components

### `core/orchestrator.py` (with LiveLogger)

```python
class LiveLogger:
    def log(self, agent_name, message):
        # Prints [LIVE] agent_name → message to console
        # Writes to monitor_logs.txt for dashboard

class Category3Orchestrator:
    def __init__(self, target_url, session):
        self.target = target_url
        self.session = session
        self.live_logger = LiveLogger()
        self.all_findings = []

    def run(self):
        # Runs all 14 agents sequentially
        # Each agent receives live_logger for real-time output
        # Aggregates and returns all findings
core/report_generator.py
Report Sections Generated:

Executive Summary (Critical Findings Highlighted)
Scope & Authorization Statement
Methodology & Testing Approach
Authentication & Session Findings
Injection Vulnerability Findings (Command, SSTI, NoSQL, XXE)
File Upload Security Findings
SSRF Findings
Client-Side Security (CSRF, WebSocket, Prototype Pollution)
Infrastructure Findings (Host Header, Cache Poisoning)
OAuth & Access Control Findings
Attack Chain Analysis (Chained Vulnerabilities)
CVSS Score Table (All Findings)
OWASP Top 10 & CWE Mapping
Critical Remediation Roadmap
📂 Payload Files
text

category3/payloads/
├── command_injection_payloads.txt   # OS command injection strings (Linux + Windows)
├── xxe_payloads.txt                 # XXE XML templates (file read, OOB, SSRF chain)
├── nosql_payloads.txt               # MongoDB operators + auth bypass payloads
├── ssti_payloads.txt                # Template engine detection + RCE payloads
└── file_upload_payloads.txt         # File type bypass strategies + polyglots
📊 Sample Output (with LiveLogger)
text

[!] CONSENT REQUIRED
[?] Confirm written authorization to test https://example.com? (yes/no): yes
[✓] Consent confirmed. Starting Category 3 - Advanced Scan.

[*] Risk Level: HIGH → Using Tor + Advanced Anti-Track

[LIVE] auth_agent           → [STEP 1] Testing 50 common credential pairs...
[LIVE] auth_agent           → [STEP 2] Testing account lockout (10 rapid attempts)...
[LIVE] auth_agent           → [!] No lockout detected after 10 failed attempts → FINDING

[LIVE] command_injection    → [STEP 1] Testing ; sleep 5 on /search parameter...
[LIVE] command_injection    → [PAYLOAD] q=test;sleep+5 → Response: 5.3s → ✓ CONFIRMED RCE

[LIVE] file_upload          → [STEP 1] Testing .php extension upload...
[LIVE] file_upload          → [STEP 2] Testing double extension (.php.jpg)...
[LIVE] file_upload          → [STEP 3] Testing MIME bypass with PHP in JPEG...

[LIVE] ssrf_agent           → [STEP 1] Probing AWS metadata (169.254.169.254)...
[LIVE] ssrf_agent           → [!] Cloud metadata accessible → CRITICAL FINDING

[LIVE] ssti_agent           → [PAYLOAD] {{7*7}} → Response contains '49' → Jinja2 DETECTED
[LIVE] ssti_agent           → [!] SSTI → RCE confirmed via __class__ chain

... (14 agents total)

[+] auth_agent              → 2 VULNERABILITIES
[+] command_injection       → 1 CRITICAL (RCE CONFIRMED)
[+] file_upload             → 2 VULNERABILITIES
[+] ssrf_agent              → 1 CRITICAL (Cloud Metadata)
[+] xxe_agent               → 0 findings
[+] nosql_agent             → 1 VULNERABILITY
[+] ssti_agent              → 1 CRITICAL (RCE CONFIRMED)
[+] csrf_agent              → 2 findings
[+] websocket_agent         → 1 finding
[+] http_host_header        → 1 VULNERABILITY
[+] web_cache               → 0 findings
[+] oauth_agent             → 1 VULNERABILITY
[+] prototype_pollution     → 1 VULNERABILITY
[+] access_control          → 3 VULNERABILITIES

[*] Total: 17 findings | 3 CRITICAL (RCE) | 5 HIGH | 6 MEDIUM | 3 LOW
[*] Generating AI Report via Groq...
[✓] Report saved: output/category3_example_com_2024.md
[✓] PDF saved:    output/category3_example_com_2024.pdf
🔒 Safety Mechanisms
Double Consent Gate: Prompted once per session (skipped if Cat2 already confirmed)
Destructive Payload Cap: File upload agents limit to non-destructive probes only
RCE Confirmation: Command injection confirms via time-delay only (no actual command output captured without explicit flag)
Tor Enforcement: HIGH risk targets automatically route through Tor
Request Throttling: Minimum 1s between requests for Cat3 agents
Emergency Stop: Ctrl+C at any point gracefully stops the scan and saves partial findings
📤 Output Files
text

output/
├── category3_<target>_<timestamp>.md
├── category3_<target>_<timestamp>.json
└── category3_<target>_<timestamp>.pdf
🔗 Vulnerability Chaining
Category 3's report generator includes an Attack Chain Analysis section that identifies when multiple findings can be chained for greater impact:

Chain	Components	Impact
SSRF → Cloud Metadata → RCE	SSRF + Metadata Exposure	Full Infrastructure Compromise
SSTI → RCE → File System Read	SSTI + Path Traversal	Full Server Compromise
OAuth Bypass → IDOR → Data Dump	OAuth Misconfig + Access Control	Account Takeover + Data Breach
XXE → SSRF → Internal Scan	XXE + SSRF	Internal Network Mapping
Prototype Pollution → XSS → ATO	PP Gadget + XSS	Account Takeover
