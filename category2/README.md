# ⚔️ Category 2 — Active Scanning

> **Explicit consent required.** This category sends crafted payloads to the target application. Only use against systems you own or have **written authorization** to test.

---

## ⚠️ Consent Warning
Before running Category 2, you will be prompted:

"Do you confirm you have explicit written authorization to actively test [target]? (yes/no)"

Answering 'no' will abort the scan immediately.

text


---

## 🎯 Purpose

Category 2 performs **active vulnerability testing** by injecting crafted payloads into HTTP parameters, headers, and endpoints. It targets the most common web application vulnerability classes as defined by **OWASP Top 10**.

---

## 🕵️ Agents Overview

### 1. `sqli_agent.py` — SQL Injection Agent

**What it does:**
- Error-based SQLi detection (MySQL, MSSQL, PostgreSQL, Oracle)
- Boolean-based blind SQLi
- Time-based blind SQLi (sleep/waitfor/pg_sleep)
- UNION-based injection testing
- Out-of-band SQLi indicators
- Tests GET/POST parameters, cookies, and headers

**Payload File:** `payloads/sqli_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Error-based SQLi | 9.8 | CWE-89 |
| Blind SQLi (Boolean) | 8.8 | CWE-89 |
| Time-based SQLi | 8.8 | CWE-89 |
| Second-order SQLi | 8.0 | CWE-89 |

---

### 2. `xss_agent.py` — Cross-Site Scripting Agent

**What it does:**
- Reflected XSS in GET/POST parameters
- DOM-based XSS via JavaScript sink analysis
- Stored XSS detection (form inputs, comment fields)
- XSS filter bypass techniques (encoding, polyglots)
- CSP bypass assessment
- Context-aware payload selection (HTML, JS, attribute contexts)

**Payload File:** `payloads/xss_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Reflected XSS | 6.1 | CWE-79 |
| Stored XSS | 8.8 | CWE-79 |
| DOM XSS | 6.1 | CWE-79 |
| XSS via HTTP Header | 5.4 | CWE-79 |

---

### 3. `path_traversal_agent.py` — Path Traversal Agent

**What it does:**
- Directory traversal via `../` sequences
- Encoded traversal (`%2e%2e/`, `%252e%252e/`)
- Absolute path injection (`/etc/passwd`, `C:\Windows\win.ini`)
- Null byte injection (`%00`)
- Windows vs Linux path detection
- File disclosure detection in responses

**Payload File:** `payloads/path_traversal_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Local File Inclusion | 8.6 | CWE-22 |
| Path Traversal | 7.5 | CWE-22 |
| Null Byte Injection | 7.5 | CWE-158 |

---

### 4. `cors_agent.py` — CORS Misconfiguration Agent

**What it does:**
- Origin reflection detection (`Access-Control-Allow-Origin: <attacker>`)
- Null origin bypass testing
- Wildcard with credentials check (`* + credentials`)
- Subdomain takeover via CORS
- Pre-flight request analysis
- Trusted origin enumeration weakness

**Payload File:** `payloads/cors_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Reflected Origin CORS | 8.1 | CWE-346 |
| Null Origin Bypass | 7.4 | CWE-346 |
| Wildcard + Credentials | 9.0 | CWE-346 |

---

### 5. `graphql_agent.py` — GraphQL Security Agent

**What it does:**
- Introspection query testing (schema exposure)
- Batch query attack detection
- Query depth limit testing (DoS potential)
- Alias-based rate limit bypass
- Field suggestion enumeration
- Mutation testing for unauthorized actions
- GraphQL injection via arguments

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Introspection Enabled | 5.3 | CWE-200 |
| Batch Query DoS | 7.5 | CWE-400 |
| Injection via Arguments | 9.0 | CWE-89 |
| Unauthorized Mutations | 8.8 | CWE-284 |

---

### 6. `jwt_agent.py` — JWT Security Agent

**What it does:**
- Algorithm confusion attack (`RS256` → `HS256`)
- `alg: none` bypass
- Weak secret brute-force (common secrets list)
- JWT header injection (`kid`, `jku`, `x5u`)
- Expired token acceptance testing
- JWT claim manipulation (role escalation)

**Payload File:** `payloads/jwt_payloads.txt`

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| Algorithm None Bypass | 9.8 | CWE-327 |
| Weak JWT Secret | 8.8 | CWE-521 |
| Algorithm Confusion | 9.0 | CWE-327 |
| Kid Header Injection | 8.0 | CWE-20 |

---

### 7. `api_agent.py` — API Security Agent

**What it does:**
- REST API endpoint enumeration (common paths)
- HTTP method tampering (GET→POST→PUT→DELETE)
- Mass assignment vulnerability detection
- API versioning attack (v1 → v2 bypass)
- Rate limiting assessment
- BOLA/IDOR detection via ID manipulation
- API key exposure in responses/headers
- Unauthenticated endpoint discovery

**Key Findings:**
| Finding Type | CVSS | CWE |
|---|---|---|
| BOLA/IDOR | 8.8 | CWE-284 |
| Mass Assignment | 8.0 | CWE-915 |
| Unauthenticated API | 7.5 | CWE-306 |
| Exposed API Keys | 9.1 | CWE-200 |
| Method Tampering | 6.5 | CWE-650 |

---

## 🗂️ Core Components

### `core/orchestrator.py`

```python
class Category2Orchestrator:
    def __init__(self, target_url, session):
        self.target = target_url
        self.session = session
        self.all_findings = []

    def run(self):
        # Runs all 7 agents sequentially
        # Each agent receives: target_url, session, payload_dir path
        # Aggregates findings
        # Passes to ReportGenerator
Error Handling:

Per-agent try/except blocks
Timeout management (configurable per agent)
WAF detection and automatic throttling
429 rate limit handling with exponential backoff
core/report_generator.py
Report Sections Generated:

Executive Summary
Scope & Authorization Statement
Methodology
SQL Injection Findings
XSS Findings
Path Traversal Findings
CORS Misconfiguration Findings
GraphQL Security Findings
JWT Security Findings
API Security Findings
OWASP Top 10 Mapping Table
CVSS Score Summary
Remediation Priority Matrix
📂 Payload Files
text

category2/payloads/
├── sqli_payloads.txt           # 200+ SQL injection strings
├── xss_payloads.txt            # 150+ XSS vectors including polyglots
├── cors_payloads.txt           # Origin header variations
├── path_traversal_payloads.txt # Traversal sequences (encoded + raw)
└── jwt_payloads.txt            # Weak secrets + manipulation templates
📊 Sample Output
text

[!] CONSENT REQUIRED
[?] Do you confirm you have explicit written authorization to test https://example.com? (yes/no): yes
[✓] Consent confirmed. Starting Category 2 - Active Scan.

[*] Risk Level: MEDIUM → Using Proxy Rotation + Basic Anti-Track

[+] SQLiAgent          → 3 VULNERABILITIES FOUND
[+] XSSAgent           → 2 VULNERABILITIES FOUND
[+] PathTraversalAgent → 0 findings
[+] CORSAgent          → 1 VULNERABILITY FOUND
[+] GraphQLAgent       → 2 findings
[+] JWTAgent           → 1 VULNERABILITY FOUND
[+] APIAgent           → 4 findings

[*] Total Findings: 13 (7 vulnerabilities confirmed)
[*] Generating AI Report via Groq...
[✓] Report saved: output/category2_example_com_2024.md
[✓] PDF saved:    output/category2_example_com_2024.pdf
🔒 Safety Mechanisms
Consent Gate: Hard-coded confirmation prompt before any scan starts
Rate Limiting: Configurable delay between requests (default: 0.5s–2s random jitter)
WAF Detection: Auto-throttles if WAF responses detected (403/429)
Payload Limits: Maximum payload count per parameter is capped to prevent DoS
Timeout: All requests have a hard 10-second timeout
📤 Output Files
text

output/
├── category2_<target>_<timestamp>.md
├── category2_<target>_<timestamp>.json
└── category2_<target>_<timestamp>.pdf
