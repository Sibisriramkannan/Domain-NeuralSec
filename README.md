<div align="center">

# 🛡️ Security Assessment Agent v2.0

### *AI-Powered Modular Penetration Testing Framework*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama--3.3--70B-FF6B35?style=for-the-badge&logo=groq&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
██████╗███████╗ ██████╗ █████╗ ██████╗ ███████╗███╗ ██╗████████╗
██╔════╝██╔════╝██╔════╝ ██╔══██╗██╔════╝ ██╔════╝████╗ ██║╚══██╔══╝
╚█████╗ █████╗ ██║ ███████║██║ ███╗█████╗ ██╔██╗ ██║ ██║
╚═══██╗██╔══╝ ██║ ██╔══██║██║ ██║██╔══╝ ██║╚██╗██║ ██║
██████╔╝███████╗╚██████╗ ██║ ██║╚██████╔╝███████╗██║ ╚████║ ██║
╚═════╝ ╚══════╝ ╚═════╝ ╚═╝ ╚═╝ ╚═════╝ ╚══════╝╚═╝ ╚═══╝ ╚═╝

text


**25 Specialized Agents • 3 Scan Categories • AI Report Generation • Tor/Proxy Routing**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Reports](#-output-reports)

</div>

---

> ⚠️ **LEGAL DISCLAIMER** — This tool is strictly for **authorized security testing and educational purposes only**.
> Unauthorized use against systems you do not own or have **explicit written permission** to test is **illegal** and may
> violate the CFAA, UK Computer Misuse Act, and equivalent laws worldwide.
> **The developers assume zero liability for misuse. Always hack responsibly.**

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Scanning Engine
- **25 Specialized Security Agents** across 3 categories
- **Parallel Execution** — Cat1: 4 | Cat2: 7 | Cat3: 14 agents
- **Per-Agent Timeout** protection (no stuck scans)
- **Fresh session per agent** for Cat3 stability
- **Connection Guard** — WAF/403 auto-detection + rotate

</td>
<td width="50%">

### 🤖 AI & Reporting
- **Groq Llama-3.3-70B** powered analysis
- **Parallel Report Generation** (background threads)
- **PDF + Markdown** auto-export via ReportLab
- **Fallback Report Engine** (works without API)
- **Combined Master Summary** across all categories

</td>
</tr>
<tr>
<td width="50%">

### 🌐 Smart Connection Routing
- **Auto-Select** Direct / Free Proxy / Tor
- **Tor Auto-Start** + IP rotation every 20s
- **Free Proxy Scraper** with auto-rotation
- **Anti-Tracking Engine** — UA randomization + jitter
- **Risk-Based Routing** per target assessment

</td>
<td width="50%">

### 📊 Live Dashboard
- **Rich-powered** real-time terminal dashboard
- **CPU / RAM / Network** live stats
- **Live scan log** stream from `monitor_logs.txt`
- **Cross-platform** terminal launcher
- **QTerminal / xterm / gnome-terminal** auto-detect

</td>
</tr>
</table>

---

## 📁 Project Structure
🛡️ Security Scanner Agent/
│
├── 📄 app.py # Main entry — Menu, routing, scan, reports
├── 📊 monitor.py # Rich live dashboard (CPU/RAM/Net/Logs)
├── 🌐 smart_connection.py # Auto-select Direct/Proxy/Tor connection
├── 🛡️ connection_guard.py # WAF/firewall block detection + auto-rotate
├── 🔌 connection_manager.py # Tor/VPN session management
├── 🔄 proxy_manager.py # Free proxy scraper & rotator
├── 🧅 tor_manager.py # Tor auto-start + IP rotation display
├── ⚖️ risk_checker.py # Target risk assessment (LOW/MEDIUM/HIGH)
├── 🕵️ anti_track.py # Header obfuscation & timing jitter
├── 🖥️ platform_utils.py # Cross-platform terminal launcher
├── 🔧 setup.py # Auto-setup on first run
├── 🩹 patch_groq.py # Groq client patch utility
├── 📝 monitor_logs.txt # Shared log (app writes → monitor reads)
├── 🔑 .env # GROQ_API_KEY (never commit!)
│
├── 🧅 tor_portable/ # Portable Tor installation
│ ├── torrc # Tor configuration
│ └── data/ # Tor runtime data
│
├── 📂 category1/ # ━━━ PASSIVE SCAN ━━━
│ ├── core/
│ │ ├── orchestrator.py # Parallel agent runner (4 agents)
│ │ ├── report_generator.py # Groq AI report → MD + PDF
│ │ └── groq_client.py # Category-scoped Groq client
│ ├── agents/
│ │ ├── 🔎 recon_agent.py # DNS, WHOIS, subdomain enum
│ │ ├── 📋 headers_agent.py # HTTP security headers analysis
│ │ ├── 🔒 ssl_agent.py # SSL/TLS certificate & cipher audit
│ │ └── 📧 email_security_agent.py # SPF, DKIM, DMARC checks
│ ├── main.py
│ └── output/ # Category-specific reports
│
├── 📂 category2/ # ━━━ ACTIVE SCAN ━━━
│ ├── core/
│ │ ├── orchestrator.py # Parallel agent runner (7 agents)
│ │ ├── report_generator.py # Groq AI report → MD + PDF
│ │ └── groq_client.py
│ ├── agents/
│ │ ├── 💉 sqli_agent.py # SQL Injection (Blind/Error/Time-based)
│ │ ├── 🔥 xss_agent.py # XSS (Reflected/Stored/DOM)
│ │ ├── 📁 path_traversal_agent.py # Directory traversal attacks
│ │ ├── 🌐 cors_agent.py # CORS misconfiguration testing
│ │ ├── 🔷 graphql_agent.py # GraphQL introspection & injection
│ │ ├── 🔑 jwt_agent.py # JWT algorithm confusion & bypass
│ │ └── 🔌 api_agent.py # REST API endpoint enumeration
│ ├── payloads/
│ │ ├── sqli_payloads.txt
│ │ ├── xss_payloads.txt
│ │ └── path_traversal_payloads.txt
│ ├── main.py
│ └── output/
│
├── 📂 category3/ # ━━━ ADVANCED SCAN ━━━
│ ├── core/
│ │ ├── orchestrator.py # 2 seq + 12 parallel agents + LiveLogger
│ │ ├── report_generator.py # Groq AI report → MD + PDF
│ │ └── groq_client.py
│ ├── agents/
│ │ ├── 🔐 auth_agent.py # Auth bypass & broken authentication
│ │ ├── 💻 command_injection_agent.py # OS command injection
│ │ ├── 📤 file_upload_agent.py # Malicious file upload vectors
│ │ ├── 🔁 ssrf_agent.py # Server-Side Request Forgery
│ │ ├── 📄 xxe_agent.py # XML External Entity injection
│ │ ├── 🍃 nosql_agent.py # NoSQL injection (MongoDB etc.)
│ │ ├── 🧪 ssti_agent.py # Server-Side Template Injection
│ │ ├── 🛡️ csrf_agent.py # Cross-Site Request Forgery
│ │ ├── 🔌 websocket_agent.py # WebSocket security testing
│ │ ├── 🏠 http_host_header_agent.py # Host header injection
│ │ ├── 💾 web_cache_agent.py # Web cache poisoning
│ │ ├── 🔓 oauth_agent.py # OAuth 2.0 flow vulnerabilities
│ │ ├── ☣️ prototype_pollution_agent.py # JS prototype pollution
│ │ └── 🚪 access_control_agent.py # Broken access control / IDOR
│ ├── payloads/
│ │ ├── command_injection_payloads.txt
│ │ ├── xxe_payloads.txt
│ │ ├── nosql_payloads.txt
│ │ ├── ssti_payloads.txt
│ │ └── file_upload_extensions.txt
│ ├── main.py
│ └── output/
│
└── 📂 output/ # ━━━ MASTER OUTPUT ━━━
├── category1/ # Copied Cat1 reports
├── category2/ # Copied Cat2 reports
├── category3/ # Copied Cat3 reports
├── *_SUMMARY.md # Combined master report
└── *_SUMMARY.pdf # Combined master PDF

text


---

## 🔬 Scan Categories

<table>
<thead>
<tr>
<th>Category</th>
<th>Type</th>
<th>Agents</th>
<th>Execution</th>
<th>Checks</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>🟢 Cat 1</b></td>
<td>Passive</td>
<td>4</td>
<td>4 Parallel</td>
<td>DNS, WHOIS, Headers, SSL/TLS, SPF/DKIM/DMARC</td>
</tr>
<tr>
<td><b>🟡 Cat 2</b></td>
<td>Active</td>
<td>7</td>
<td>7 Parallel</td>
<td>SQLi, XSS, Path Traversal, CORS, GraphQL, JWT, API</td>
</tr>
<tr>
<td><b>🔴 Cat 3</b></td>
<td>Advanced</td>
<td>14</td>
<td>2 Seq + 12 Parallel</td>
<td>Auth, CMDi, FileUpload, SSRF, XXE, NoSQL, SSTI, CSRF, WebSocket, HostHeader, Cache, OAuth, Proto, IDOR</td>
</tr>
</tbody>
</table>

---

## ⚙️ Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Required |
| Groq API Key | — | [Get free key](https://console.groq.com) |
| Tor | Optional | Auto-started for HIGH risk targets |

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/security-assessment-agent-v2.git
cd security-assessment-agent-v2

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
echo "GROQ_API_KEY=your_key_here" > .env

# 5. Launch (auto-setup runs on first start)
python app.py
💡 First run auto-setup: installs packages, creates directories, checks Tor availability — no manual config needed!

.env Configuration
env

GROQ_API_KEY=your_groq_api_key_here
📦 Dependencies
txt

groq>=0.4.0
reportlab>=4.0.0
colorama>=0.4.6
requests>=2.31.0
beautifulsoup4>=4.12.0
dnspython>=2.4.0
rich>=13.0.0
python-dotenv>=1.0.0
stem>=1.8.0
fake-useragent>=1.4.0
psutil>=5.9.0
websocket-client>=1.6.0
🖥️ Usage
Launch
Bash

python app.py
Main Menu
text

╔══════════════════════════════════════════════════════╗
║          🛡️  Security Assessment Agent v2.0          ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║   [1]  Category 1 — Passive Scan                     ║
║   [2]  Category 2 — Active Scan                      ║
║   [3]  Category 3 — Advanced Scan                    ║
║   [4]  Full Scan   — All Categories (1 + 2 + 3)      ║
║   [5]  Cat 1 + 2   — Passive + Active                ║
║   [6]  Cat 1 + 3   — Passive + Advanced              ║
║   [7]  Cat 2 + 3   — Active + Advanced               ║
║   [8]  Custom      — Select Categories               ║
║                                                      ║
║   [0]  Exit                                          ║
╚══════════════════════════════════════════════════════╝

  Connection: [D] Direct  [P] Proxy  [T] Tor  [A] Auto
Scan Workflow
text

  Enter Target URL
        │
        ▼
  ⚖️  Risk Assessment (LOW / MEDIUM / HIGH)
        │
        ▼
  🌐 Smart Connection Setup (Direct / Proxy / Tor)
        │
        ▼
  🕵️  Anti-Track Engine Activated
        │
        ▼
  🔄 Connection Guard Started (WAF/403 monitoring)
        │
        ▼
  🚀 Parallel Agent Execution
        │
        ├── 📊 Live Dashboard Updates (separate terminal)
        │
        ▼
  🤖 AI Report Generation (Groq — background thread)
        │
        ▼
  📄 PDF + Markdown Export → output/
        │
        ▼
  📋 Combined Master Summary Report
🌐 Smart Connection Routing
Risk Level	Detection Criteria	Connection	Anti-Track
🟢 LOW	Normal domains	Direct	None
🟡 MEDIUM	WAF/CDN detected	Free Proxy rotation	Basic header obfuscation
🔴 HIGH	.gov .mil .bank / Bug Bounty	Tor + IP rotate/20s	Full jitter + UA randomization
Risk factors evaluated:

Target TLD (.gov, .mil, .bank, .edu)
WAF/CDN presence (Cloudflare, Akamai, Imperva, etc.)
Bug bounty program detection
Sensitive keyword analysis in domain
📊 Live Monitor Dashboard
Launches automatically in a new terminal window (QTerminal → xterm → gnome-terminal → fallback):

text

┌─────────────────────────────────────────────────────────┐
│  🛡️  Security Scanner — Live Monitor                     │
├──────────────────┬──────────────────┬───────────────────┤
│  CPU: ████░░ 42% │  RAM: ██████ 61% │  NET: ↑2.1 ↓8.4MB │
├─────────────────────────────────────────────────────────┤
│  [12:34:56]  🔍 ReconAgent         → Completed          │
│  [12:34:58]  📋 HeadersAgent       → 3 findings         │
│  [12:35:01]  🔒 SSLAgent           → Weak cipher found  │
│  [12:35:03]  💉 SQLiAgent          → Testing payloads…  │
└─────────────────────────────────────────────────────────┘
📁 Output Reports
All reports saved to output/ (master) and categoryX/output/ (per-category):

Format	Content
.md	Full Markdown — findings, CVSS scores, CWE IDs, remediation
.json	Raw structured findings — pipeline/integration ready
.pdf	Professional PDF via ReportLab — ready to share
*_SUMMARY.md	Master report merging all category findings
Finding Structure
JSON

{
  "type": "SQL Injection",
  "risk": "HIGH",
  "description": "Blind SQLi detected on /login via 'username' parameter",
  "cvss_score": 9.8,
  "cwe": "CWE-89",
  "evidence": "Response delay of 5.2s on payload: ' OR SLEEP(5)--",
  "fix": "Use parameterized queries / prepared statements"
}
🏗️ Architecture
Pre-Scan Setup Flow
Python

run_pre_scan_setup(target_url)
    ├── RiskChecker.assess(target_url)           → risk_level
    ├── AntiTrackManager.activate(risk_level)    → session headers modified  
    ├── SmartConnection.get_session(risk_level)  → shared_session
    └── ConnectionGuard.start(session)           → WAF block monitor
Agent Execution Flow
Python

Orchestrator.run(target_url, session)
    ├── ThreadPoolExecutor(max_workers=N)
    │   ├── Agent1.scan() → findings[]          ─┐
    │   ├── Agent2.scan() → findings[]           ├─ Parallel
    │   └── AgentN.scan() → findings[]          ─┘
    │
    └── all_findings[]
         │
         ▼ (background thread — starts immediately)
    ReportGenerator.generate(all_findings)
         ├── Groq API → AI-formatted Markdown
         ├── Fallback  → hardcoded template (if API fails)
         └── ReportLab → PDF export
Path Isolation (Import Safety)
Python

# app.py — prevents module collision between identical
# core/ and agents/ folder names across categories

_switch_to(category_path)   # Prepends category to sys.path
    import orchestrator
    import report_generator
_restore_all()              # Restores original sys.path
Connection Guard Flow
Python

ConnectionGuard.monitor()
    ├── Detect 403 / 429 / WAF signatures
    ├── Auto-rotate → next proxy or new Tor circuit
    ├── Log event → monitor_logs.txt
    └── Resume scan transparently
🤝 Contributing
Bash

# 1. Fork the repository
# 2. Create your feature branch
git checkout -b feature/new-agent-name

# 3. Follow agent structure
findings = [{
    "type": "Vulnerability Name",
    "risk": "HIGH | MEDIUM | LOW | INFO",
    "description": "...",
    "cvss_score": 0.0,
    "cwe": "CWE-XXX",
    "evidence": "...",
    "fix": "..."
}]

# 4. Submit pull request with clear description
Agent categories to contribute to:

Add new agents to existing categories following the same scan(target, session) interface
New payload files go in categoryX/payloads/
Update the orchestrator's agent list
📜 License
This project is licensed under the MIT License — see LICENSE for details.

<div align="center">
👨‍💻 Author
Built with ❤️ for the ethical hacking and bug bounty community.

text

  Always get written permission before testing any target.
              H a c k   R e s p o n s i b l y 🛡️
Visitors

</div> ```
