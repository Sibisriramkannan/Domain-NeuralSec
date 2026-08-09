<div align="center">

# 🛡️ Security Assessment Agent v2.0

### *AI-Powered Modular Penetration Testing Framework*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama--3.3--70B-FF6B35?style=for-the-badge\&logo=groq\&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

                                
                                 ██████╗███████╗ ██████╗    █████╗  ██████╗ ███████╗███╗   ██╗████████╗
                                ██╔════╝██╔════╝██╔════╝   ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
                                ╚█████╗ █████╗  ██║        ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
                                 ╚═══██╗██╔══╝  ██║        ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
                                ██████╔╝███████╗╚██████╗   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
                                ╚═════╝ ╚══════╝ ╚═════╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝

**25 Specialized Agents • 3 Scan Categories • AI Report Generation • Tor/Proxy Routing**

[Features](#-features) • [Installation](#️-installation) • [Usage](#️-usage) • [Architecture](#️-architecture-deep-dive) • [Reports](#-output-reports)

</div>

---

> ⚠️ **LEGAL DISCLAIMER** — This tool is strictly for **authorized security testing and educational purposes only**.
>
> Unauthorized use against systems you do not own or have **explicit written permission** to test is **illegal** and may violate applicable computer misuse and cybersecurity laws.
>
> **The developers assume zero liability for misuse. Always hack responsibly.**

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Scanning Engine

* **25 Specialized Security Agents** across 3 categories
* **Parallel Execution** — Cat 1: 4 | Cat 2: 7 | Cat 3: 14 agents
* **Per-Agent Timeout** protection
* **Fresh session per agent** for Category 3 stability
* **Connection Guard** — WAF/403 detection and connection rotation

</td>
<td width="50%">

### 🤖 AI & Reporting

* **Groq Llama-3.3-70B** powered analysis
* **Parallel Report Generation**
* **PDF + Markdown** auto-export via ReportLab
* **Fallback Report Engine** when API generation is unavailable
* **Combined Master Summary** across all scan categories

</td>
</tr>

<tr>
<td width="50%">

### 🌐 Smart Connection Routing

* **Auto-Select** Direct / Free Proxy / Tor
* **Tor Auto-Start**
* **IP Rotation**
* **Free Proxy Scraper** with automatic rotation
* **Anti-Tracking Engine** — User-Agent randomization and timing jitter
* **Risk-Based Routing** based on target assessment

</td>
<td width="50%">

### 📊 Live Dashboard

* **Rich-powered** real-time terminal dashboard
* **CPU / RAM / Network** live statistics
* Live scan log stream from `monitor_logs.txt`
* **Cross-platform** terminal launcher
* QTerminal / xterm / gnome-terminal auto-detection

</td>
</tr>
</table>

---

## 📁 Project Structure

```text
security-scanner-agent/
│
├── app.py                          # Main entry — menu, routing, scans, reports
├── monitor.py                      # Rich live dashboard
├── smart_connection.py            # Direct / Proxy / Tor selection
├── connection_guard.py            # WAF/firewall detection
├── connection_manager.py          # Connection session management
├── proxy_manager.py               # Proxy management
├── tor_manager.py                 # Tor management
├── risk_checker.py                # Target risk assessment
├── anti_track.py                  # Header randomization & timing jitter
├── platform_utils.py              # Cross-platform utilities
├── setup.py                       # First-run setup
├── patch_groq.py                  # Groq client utility
├── .env                           # GROQ_API_KEY — never commit
├── monitor_logs.txt               # Shared application/monitor log
│
├── tor_portable/
│   ├── torrc
│   └── data/
│
├── category1/                     # ━━━ PASSIVE SCAN ━━━
│   │
│   ├── core/
│   │   ├── orchestrator.py
│   │   ├── report_generator.py
│   │   └── groq_client.py
│   │
│   ├── agents/
│   │   ├── recon_agent.py
│   │   ├── headers_agent.py
│   │   ├── ssl_agent.py
│   │   └── email_security_agent.py
│   │
│   ├── main.py
│   └── output/
│
├── category2/                     # ━━━ ACTIVE SCAN ━━━
│   │
│   ├── core/
│   │   ├── orchestrator.py
│   │   ├── report_generator.py
│   │   └── groq_client.py
│   │
│   ├── agents/
│   │   ├── sqli_agent.py
│   │   ├── xss_agent.py
│   │   ├── path_traversal_agent.py
│   │   ├── cors_agent.py
│   │   ├── graphql_agent.py
│   │   ├── jwt_agent.py
│   │   └── api_agent.py
│   │
│   ├── payloads/
│   │   ├── sqli_payloads.txt
│   │   ├── xss_payloads.txt
│   │   └── path_traversal_payloads.txt
│   │
│   ├── main.py
│   └── output/
│
├── category3/                     # ━━━ ADVANCED SCAN ━━━
│   │
│   ├── core/
│   │   ├── orchestrator.py
│   │   ├── report_generator.py
│   │   └── groq_client.py
│   │
│   ├── agents/
│   │   ├── auth_agent.py
│   │   ├── command_injection_agent.py
│   │   ├── file_upload_agent.py
│   │   ├── ssrf_agent.py
│   │   ├── xxe_agent.py
│   │   ├── nosql_agent.py
│   │   ├── ssti_agent.py
│   │   ├── csrf_agent.py
│   │   ├── websocket_agent.py
│   │   ├── http_host_header_agent.py
│   │   ├── web_cache_agent.py
│   │   ├── oauth_agent.py
│   │   ├── prototype_pollution_agent.py
│   │   └── access_control_agent.py
│   │
│   ├── payloads/
│   │   ├── command_injection_payloads.txt
│   │   ├── xxe_payloads.txt
│   │   ├── nosql_payloads.txt
│   │   ├── ssti_payloads.txt
│   │   └── file_upload_extensions.txt
│   │
│   ├── main.py
│   └── output/
│
└── output/                         # ━━━ MASTER OUTPUT ━━━
    ├── category1/
    ├── category2/
    ├── category3/
    ├── *_SUMMARY.md
    └── *_SUMMARY.pdf
```

---

## 🔬 Scan Categories

| Category     | Type     | Agents | Execution                  | Checks                                                                                                                 |
| ------------ | -------- | -----: | -------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 🟢 **Cat 1** | Passive  |      4 | 4 Parallel                 | DNS, WHOIS, Headers, SSL/TLS, SPF/DKIM/DMARC                                                                           |
| 🟡 **Cat 2** | Active   |      7 | 7 Parallel                 | SQLi, XSS, Path Traversal, CORS, GraphQL, JWT, API                                                                     |
| 🔴 **Cat 3** | Advanced |     14 | 2 Sequential + 12 Parallel | Auth, CMDi, File Upload, SSRF, XXE, NoSQL, SSTI, CSRF, WebSocket, Host Header, Cache, OAuth, Prototype Pollution, IDOR |

**Total: 25 specialized security agents**

---

## ⚙️ Installation

### Prerequisites

| Requirement  | Version  | Notes                             |
| ------------ | -------- | --------------------------------- |
| Python       | 3.10+    | Required                          |
| Groq API Key | —        | Required for AI report generation |
| Tor          | Optional | Used when Tor routing is selected |

### Quick Setup

Clone the repository:

```bash
git clone https://github.com/yourusername/security-assessment-agent-v2.git
cd security-assessment-agent-v2
```

Create a virtual environment:

```bash
python -m venv venv
```

### Linux / macOS

```bash
source venv/bin/activate
```

### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

### Windows CMD

```cmd
venv\Scripts\activate.bat
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create the `.env` file:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Start the application:

```bash
python app.py
```

> 💡 **First Run:** The setup module can initialize required directories, dependencies, and connection-related components depending on the platform.

---

## 🔐 Environment Configuration

Store sensitive configuration in `.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
```

### Important

Never commit `.env` to GitHub.

Add it to `.gitignore`:

```gitignore
.env
venv/
__pycache__/
*.pyc
monitor_logs.txt
```

---

## 📦 Dependencies

Core Python packages:

```text
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
```

Install them using:

```bash
pip install -r requirements.txt
```

---

## 🖥️ Usage

### Launch

```bash
python app.py
```

### Main Menu

```text
╔══════════════════════════════════════════════════════╗
║          🛡️ Security Assessment Agent v2.0           ║
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

Connection:
[D] Direct
[P] Proxy
[T] Tor
[A] Auto
```

---

## 🔄 Scan Workflow

```text
┌───────────────────────────────┐
│       Enter Target URL        │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Risk Assessment         │
│    LOW / MEDIUM / HIGH        │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│   Smart Connection Setup      │
│   Direct / Proxy / Tor        │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│      Anti-Track Engine        │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│      Connection Guard         │
│     WAF / 403 Monitoring      │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│   Parallel Agent Execution    │
│   + Live Dashboard Updates    │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│     AI Report Generation      │
│           Groq API            │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│    Markdown + PDF Export      │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│    Combined Master Summary    │
└───────────────────────────────┘
```

---

## 🌐 Smart Connection Routing

The framework supports multiple connection modes:

| Mode       | Description                                                           |
| ---------- | --------------------------------------------------------------------- |
| **Direct** | Uses the normal system internet connection                            |
| **Proxy**  | Routes supported HTTP traffic through configured proxy infrastructure |
| **Tor**    | Routes supported traffic through a Tor session                        |
| **Auto**   | Selects a connection strategy based on configured risk logic          |

### Risk Assessment

The risk checker can evaluate factors such as:

* Target/domain characteristics
* WAF/CDN presence
* Configured domain patterns
* Security-testing context
* Target-specific routing rules

> Connection routing is not a substitute for authorization. Only scan systems for which you have explicit permission.

---

## 📊 Live Monitor Dashboard

The monitoring component displays runtime statistics and scan activity.

```text
┌─────────────────────────────────────────────────────────┐
│  🛡️ Security Scanner — Live Monitor                     │
├──────────────────┬──────────────────┬───────────────────┤
│ CPU: ████░░ 42%  │ RAM: ██████ 61% │ NET: ↑2.1 ↓8.4MB │
├─────────────────────────────────────────────────────────┤
│ [12:34:56] 🔍 ReconAgent       → Completed              │
│ [12:34:58] 📋 HeadersAgent     → 3 findings             │
│ [12:35:01] 🔒 SSLAgent         → Weak cipher found      │
│ [12:35:03] 💉 SQLiAgent        → Testing...             │
└─────────────────────────────────────────────────────────┘
```

The application and monitor can exchange runtime events through:

```text
monitor_logs.txt
```

---

## 📁 Output Reports

Reports are stored in category-specific directories and the master `output/` directory.

| Format          | Description                                   |
| --------------- | --------------------------------------------- |
| `.md`           | Markdown vulnerability assessment report      |
| `.json`         | Structured findings for further processing    |
| `.pdf`          | Shareable PDF report generated with ReportLab |
| `*_SUMMARY.md`  | Combined summary across selected categories   |
| `*_SUMMARY.pdf` | Combined PDF summary                          |

Example:

```text
output/
├── category1/
├── category2/
├── category3/
├── target_2026_SUMMARY.md
└── target_2026_SUMMARY.pdf
```

---

## 🔎 Finding Structure

Individual findings follow a structured format:

```json
{
  "type": "SQL Injection",
  "risk": "HIGH",
  "description": "Potential SQL injection behavior identified during authorized testing.",
  "cvss_score": 9.8,
  "cwe": "CWE-89",
  "evidence": "Relevant request/response behavior recorded by the scanner.",
  "fix": "Use parameterized queries and prepared statements."
}
```

Typical information includes:

* Vulnerability name
* Severity
* Description
* CVSS score
* CWE identifier
* Evidence
* Recommended remediation

---

## 🏗️ Architecture Deep Dive

### Pre-Scan Setup Flow

```text
run_pre_scan_setup(target_url)
    │
    ├── RiskChecker.assess(target_url)
    │       └── risk_level
    │
    ├── AntiTrackManager.activate(risk_level)
    │       └── session configuration
    │
    ├── SmartConnection.get_session(risk_level)
    │       └── shared_session
    │
    └── ConnectionGuard.start(session)
            └── connection monitoring
```

---

### Agent Execution Flow

```text
Orchestrator.run(target_url, session)
    │
    ├── ThreadPoolExecutor(max_workers=N)
    │       │
    │       ├── Agent1.scan() ──┐
    │       ├── Agent2.scan() ──┼── Parallel Execution
    │       └── AgentN.scan() ──┘
    │
    └── all_findings[]
            │
            ▼
      ReportGenerator
            │
            ├── AI-assisted formatting
            ├── Fallback report generation
            └── PDF generation
```

---

### Path Isolation

The application can isolate category imports to prevent collisions between similarly named `core/` and `agents/` modules.

```python
_switch_to(category_path)

import orchestrator
import report_generator

_restore_all()
```

---

### Connection Guard Flow

```text
ConnectionGuard.monitor()
    │
    ├── Detect connection errors / configured block conditions
    │
    ├── Trigger supported connection recovery
    │
    ├── Log event
    │       └── monitor_logs.txt
    │
    └── Continue scan when possible
```

---

## 🤝 Contributing

Contributions are welcome for authorized security-testing and defensive research functionality.

### 1. Fork the Repository

Create a feature branch:

```bash
git checkout -b feature/new-agent-name
```

### 2. Follow the Agent Finding Structure

```python
findings = [
    {
        "type": "Vulnerability Name",
        "risk": "HIGH | MEDIUM | LOW | INFO",
        "description": "...",
        "cvss_score": 0.0,
        "cwe": "CWE-XXX",
        "evidence": "...",
        "fix": "..."
    }
]
```

### 3. Add the Agent

Place the module inside the appropriate category:

```text
categoryX/agents/
```

Update:

```text
categoryX/core/orchestrator.py
```

Add required supporting files under:

```text
categoryX/payloads/
```

### 4. Submit a Pull Request

Include:

* Purpose of the new agent
* Security check performed
* Expected output
* Testing performed
* Dependencies added
* Example findings when appropriate

---

## 🛡️ Responsible Use

This framework is intended for:

* Authorized penetration testing
* Security labs
* CTF environments
* Bug bounty programs where testing is explicitly permitted
* Internal security assessments
* Security education and research

Do **not** use this project against systems without authorization.

Always review the applicable scope and rules of engagement before running active or advanced scans.

---

## 📜 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

---

<div align="center">

## 👨‍💻 Author

Built with ❤️ for the **ethical hacking**, **cybersecurity**, and **bug bounty** community.

```text
Always get written permission before testing any target.

        H A C K   R E S P O N S I B L Y   🛡️
```

![Ethical](https://img.shields.io/badge/Ethical-Hackers%20Only-red?style=for-the-badge)

### ⭐ If you find this project useful, consider starring the repository.

</div>
