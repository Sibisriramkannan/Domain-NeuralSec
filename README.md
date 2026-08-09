<div align="center">

# 🛡️ Security Assessment Agent v2.0

### AI-Powered Modular Penetration Testing Framework

<p>
  <strong>Automated Reconnaissance • Vulnerability Assessment • AI Reporting • Smart Connection Routing</strong>
</p>

<p>
  <img src="assets/sec-agent-banner.png" alt="Security Assessment Agent v2.0" width="100%">
</p>

<p>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AI-Groq-FF6B35?style=flat-square" alt="Groq">
  <img src="https://img.shields.io/badge/Agents-25+-00A8E8?style=flat-square" alt="Agents">
  <img src="https://img.shields.io/badge/Categories-3-F5B700?style=flat-square" alt="Categories">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-success?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" alt="Status">
</p>

<p>
  <strong>25 Specialized Security Agents • 3 Scan Categories • AI-Powered Reports • Direct / Proxy / Tor Routing</strong>
</p>

<p>
  <a href="#-overview">Overview</a> •
  <a href="#-features">Features</a> •
  <a href="#-scan-categories">Scan Categories</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#️-architecture">Architecture</a> •
  <a href="#-output-reports">Reports</a>
</p>

</div>

---

> [!WARNING]
> ### Legal Disclaimer
>
> Security Assessment Agent v2.0 is designed strictly for **authorized security testing, defensive security research, security laboratories, CTF environments, and educational purposes**.
>
> Do not use this framework against systems, applications, networks, APIs, or infrastructure that you do not own or do not have **explicit authorization** to test.
>
> Users are responsible for ensuring that all testing activities comply with applicable laws, contractual requirements, bug bounty rules, and defined rules of engagement.
>
> **The developers assume no liability for unauthorized or unlawful use of this software.**

---

# 📖 Overview

**Security Assessment Agent v2.0** is a modular Python-based security assessment framework designed to coordinate multiple specialized security agents through a unified command-line interface.

Instead of manually launching separate tools for reconnaissance, web security checks, advanced application testing, connection management, monitoring, and report generation, the framework organizes these activities into a structured workflow.

The framework currently contains **25 specialized agents** divided into three major assessment categories:

- 🟢 **Category 1 — Passive Assessment**
- 🟡 **Category 2 — Active Assessment**
- 🔴 **Category 3 — Advanced Assessment**

The framework also integrates:

- 🤖 AI-assisted security report generation
- 🌐 Smart connection routing
- 🧅 Tor connectivity
- 🔄 Proxy management
- 🛡️ Connection monitoring
- 🕵️ Request/session customization
- 📊 Live system and scan monitoring
- 📄 Markdown and PDF reporting
- 📦 Structured JSON findings
- ⚡ Parallel agent execution
- 🧩 Modular agent architecture

The goal of the project is to provide a single extensible framework capable of coordinating security assessment workflows while producing structured, readable reports.

---

# ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Security Scanning Engine

- **25 specialized security agents**
- Three assessment categories
- Modular agent architecture
- Parallel execution
- Per-agent timeout protection
- Category-specific orchestration
- Fresh sessions where required
- Structured findings
- Centralized scan workflow

</td>

<td width="50%" valign="top">

### 🤖 AI & Reporting

- Groq-powered AI analysis
- Llama-based report generation
- Markdown report generation
- PDF report generation
- JSON structured findings
- AI-assisted remediation summaries
- Fallback reporting capability
- Combined master reports

</td>
</tr>

<tr>
<td width="50%" valign="top">

### 🌐 Connection Management

- Direct connection support
- Proxy connection support
- Tor connection support
- Automatic connection selection
- Proxy rotation
- Tor session management
- Risk-based routing
- Connection recovery logic

</td>

<td width="50%" valign="top">

### 📊 Live Monitoring

- Real-time terminal dashboard
- CPU monitoring
- Memory monitoring
- Network statistics
- Live agent activity
- Shared scan logs
- Rich-powered terminal UI
- Cross-platform terminal support

</td>
</tr>
</table>

---

# 🧠 How the Framework Works

At a high level, Security Assessment Agent follows the workflow below:

```text
                     ┌─────────────────────┐
                     │     Target URL      │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Risk Assessment   │
                     │ LOW / MEDIUM / HIGH │
                     └──────────┬──────────┘
                                │
                                ▼
                  ┌────────────────────────────┐
                  │ Smart Connection Selection │
                  └─────────────┬──────────────┘
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
                 ▼              ▼              ▼
             DIRECT          PROXY            TOR
                 │              │              │
                 └──────────────┼──────────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Session Preparation │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Connection Guard    │
                     └──────────┬──────────┘
                                │
                                ▼
                  ┌─────────────────────────┐
                  │ Security Agent Execution│
                  └─────────────┬───────────┘
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
          Category 1       Category 2       Category 3
            Passive          Active          Advanced
               │                │                │
               └────────────────┼────────────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Structured Findings │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ AI Report Generator │
                     └──────────┬──────────┘
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
                 ▼              ▼              ▼
             Markdown          JSON            PDF
                 │              │              │
                 └──────────────┼──────────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Master Summary    │
                     └─────────────────────┘
```

---

# 🔬 Scan Categories

## 🟢 Category 1 — Passive Assessment

Category 1 focuses primarily on reconnaissance and externally observable security configuration.

It contains **4 specialized agents** that can execute in parallel.

| Agent | Purpose |
|---|---|
| 🔎 Recon Agent | DNS, WHOIS and reconnaissance-related information |
| 📋 Headers Agent | HTTP response and security-header analysis |
| 🔒 SSL Agent | SSL/TLS certificate and configuration assessment |
| 📧 Email Security Agent | SPF, DKIM and DMARC-related checks |

### Category 1 Summary

```text
Agents      : 4
Execution   : Parallel
Type        : Passive Assessment

Checks:
├── DNS
├── WHOIS
├── Reconnaissance
├── HTTP Headers
├── Security Headers
├── SSL/TLS
├── Certificates
├── SPF
├── DKIM
└── DMARC
```

---

## 🟡 Category 2 — Active Assessment

Category 2 performs active web-application security checks against targets that the user is authorized to assess.

It contains **7 specialized agents**.

| Agent | Assessment Area |
|---|---|
| 💉 SQLi Agent | SQL injection testing |
| 🧪 XSS Agent | Cross-Site Scripting checks |
| 📂 Path Traversal Agent | Path and directory traversal checks |
| 🌍 CORS Agent | CORS configuration assessment |
| 🔷 GraphQL Agent | GraphQL security checks |
| 🔑 JWT Agent | JSON Web Token security assessment |
| 🔌 API Agent | REST/API endpoint assessment |

### Category 2 Summary

```text
Agents      : 7
Execution   : Parallel
Type        : Active Assessment

Checks:
├── SQL Injection
├── Cross-Site Scripting
├── Path Traversal
├── CORS
├── GraphQL
├── JWT
└── REST/API Security
```

---

## 🔴 Category 3 — Advanced Assessment

Category 3 contains the framework's advanced web security assessment modules.

It contains **14 specialized agents**, using a combination of sequential and parallel execution depending on the module.

| Agent | Assessment Area |
|---|---|
| 🔐 Auth Agent | Authentication security |
| 💻 Command Injection Agent | OS command injection |
| 📤 File Upload Agent | File upload security |
| 🌐 SSRF Agent | Server-Side Request Forgery |
| 📄 XXE Agent | XML External Entity issues |
| 🗄️ NoSQL Agent | NoSQL injection |
| 🧩 SSTI Agent | Server-Side Template Injection |
| 🔁 CSRF Agent | Cross-Site Request Forgery |
| 🔌 WebSocket Agent | WebSocket security |
| 🏷️ Host Header Agent | HTTP Host header issues |
| 🗃️ Web Cache Agent | Web cache security |
| 🔑 OAuth Agent | OAuth flow security |
| 🧬 Prototype Pollution Agent | JavaScript prototype pollution |
| 🚪 Access Control Agent | Broken access control / IDOR |

### Category 3 Summary

```text
Agents      : 14
Execution   : Sequential + Parallel
Type        : Advanced Assessment

Checks:
├── Authentication
├── Command Injection
├── File Upload
├── SSRF
├── XXE
├── NoSQL Injection
├── SSTI
├── CSRF
├── WebSocket Security
├── HTTP Host Header
├── Web Cache
├── OAuth
├── Prototype Pollution
└── Broken Access Control / IDOR
```

---

# 📊 Agent Overview

| Category | Type | Agents | Execution |
|---|---|---:|---|
| 🟢 Category 1 | Passive | 4 | Parallel |
| 🟡 Category 2 | Active | 7 | Parallel |
| 🔴 Category 3 | Advanced | 14 | Sequential + Parallel |
| **Total** | — | **25** | Multi-Agent |

---

# 🌐 Smart Connection Routing

Security Assessment Agent includes a connection-management layer that allows scans to operate using different connection strategies.

Supported connection modes include:

```text
[D] Direct
[P] Proxy
[T] Tor
[A] Auto
```

### Direct Mode

Uses the host system's standard network connection.

```text
Scanner
   │
   ▼
Internet
   │
   ▼
Authorized Target
```

### Proxy Mode

Uses the configured proxy-management layer for supported requests.

```text
Scanner
   │
   ▼
Proxy Manager
   │
   ▼
Proxy
   │
   ▼
Authorized Target
```

### Tor Mode

Uses the framework's Tor-management component for supported traffic.

```text
Scanner
   │
   ▼
Tor Manager
   │
   ▼
Tor Network
   │
   ▼
Authorized Target
```

### Auto Mode

Auto mode allows the framework's routing logic to choose an available connection strategy based on its configured assessment logic.

> [!IMPORTANT]
> Connection routing and privacy features do not provide authorization to test a target. Authorization must exist independently before any assessment begins.

---

# ⚖️ Risk Assessment

Before the main assessment begins, the framework can evaluate target-related factors and assign a risk classification.

```text
┌──────────────────────┐
│      Target URL      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│     Risk Checker     │
└──────────┬───────────┘
           │
     ┌─────┼─────┐
     │     │     │
     ▼     ▼     ▼
    LOW  MEDIUM HIGH
```

Risk information can then be used by other framework components when preparing the scan environment.

---

# 🛡️ Connection Guard

The Connection Guard monitors supported connection conditions while agents execute.

Its responsibilities include:

- Detecting connection-related failures
- Identifying configured HTTP blocking conditions
- Recording connection events
- Requesting connection recovery where supported
- Coordinating with proxy/Tor components
- Writing status information to the live monitor

Simplified flow:

```text
Request
   │
   ▼
Connection Guard
   │
   ├── Normal Response ──────────────► Continue
   │
   └── Connection / Block Condition
                 │
                 ▼
          Recovery Handler
                 │
         ┌───────┴────────┐
         │                │
         ▼                ▼
       Proxy             Tor
       Rotate          Recovery
         │                │
         └───────┬────────┘
                 │
                 ▼
              Continue
```

---

# 📊 Live Monitoring Dashboard

The project includes a terminal-based monitoring component powered by Python's Rich ecosystem.

The dashboard can display information such as:

- CPU utilization
- RAM utilization
- Network activity
- Current scan status
- Agent activity
- Completed agents
- Scan messages
- Runtime logs

Example:

```text
┌──────────────────────────────────────────────────────────────┐
│           🛡️ Security Assessment Agent Monitor              │
├────────────────────┬───────────────────┬─────────────────────┤
│ CPU                │ RAM               │ NETWORK             │
│ 42%                │ 61%               │ Active              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│ [12:34:56] ReconAgent                 → Completed            │
│ [12:34:58] HeadersAgent               → Completed            │
│ [12:35:01] SSLAgent                   → Completed            │
│ [12:35:03] SQLiAgent                  → Running              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

Runtime events can be shared through:

```text
monitor_logs.txt
```

The application writes scan events while the monitoring component reads and displays them.

---

# 🤖 AI-Powered Reporting

Security Assessment Agent integrates Groq-powered AI reporting.

After scan results have been collected, the reporting layer can process structured findings and generate a more readable security assessment report.

```text
Security Agents
      │
      ▼
Raw Findings
      │
      ▼
Structured Findings
      │
      ▼
Report Generator
      │
      ├───────────────┐
      │               │
      ▼               ▼
   Groq AI         Fallback
   Reporting       Reporting
      │               │
      └───────┬───────┘
              │
              ▼
       Final Assessment
              │
       ┌──────┼──────┐
       │      │      │
       ▼      ▼      ▼
      MD     JSON    PDF
```

Reports may include:

- Finding name
- Risk/severity
- Vulnerability description
- CVSS score
- CWE identifier
- Supporting evidence
- Recommended remediation
- Category summary
- Consolidated assessment information

---

# 🔎 Finding Structure

The framework uses structured findings so information can be processed consistently by the reporting layer.

Example:

```json
{
  "type": "SQL Injection",
  "risk": "HIGH",
  "description": "Potential SQL injection behavior identified during authorized security testing.",
  "cvss_score": 9.8,
  "cwe": "CWE-89",
  "evidence": "Relevant request and response behavior recorded during assessment.",
  "fix": "Use parameterized queries and prepared statements."
}
```

### Standard Fields

| Field | Description |
|---|---|
| `type` | Vulnerability or finding name |
| `risk` | Severity classification |
| `description` | Explanation of the finding |
| `cvss_score` | CVSS severity score |
| `cwe` | CWE identifier |
| `evidence` | Supporting assessment evidence |
| `fix` | Recommended remediation |

---

# 📁 Output Reports

Reports are stored in category-specific directories and the master `output/` directory.

```text
output/
│
├── category1/
├── category2/
├── category3/
│
├── target_SUMMARY.md
└── target_SUMMARY.pdf
```

### Supported Formats

| Format | Purpose |
|---|---|
| `.md` | Human-readable Markdown assessment |
| `.json` | Structured machine-readable findings |
| `.pdf` | Shareable security assessment report |
| `*_SUMMARY.md` | Consolidated Markdown summary |
| `*_SUMMARY.pdf` | Consolidated PDF summary |

---

# 🏗️ Project Structure

```text
security-scanner-agent/
│
├── app.py
│   └── Main application, menu, routing and scan coordination
│
├── monitor.py
│   └── Rich-based live monitoring dashboard
│
├── smart_connection.py
│   └── Connection strategy selection
│
├── connection_guard.py
│   └── Connection monitoring and recovery coordination
│
├── connection_manager.py
│   └── Connection/session management
│
├── proxy_manager.py
│   └── Proxy management
│
├── tor_manager.py
│   └── Tor management
│
├── risk_checker.py
│   └── Target risk assessment
│
├── anti_track.py
│   └── Session/request customization
│
├── platform_utils.py
│   └── Cross-platform terminal utilities
│
├── setup.py
│   └── First-run environment setup
│
├── patch_groq.py
│   └── Groq client utility
│
├── .env
│   └── Local environment configuration
│
├── monitor_logs.txt
│   └── Shared runtime log
│
├── assets/
│   └── sec-agent-banner.png
│
├── tor_portable/
│   ├── torrc
│   └── data/
│
├── category1/
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
├── category2/
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
├── category3/
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
└── output/
    ├── category1/
    ├── category2/
    ├── category3/
    ├── *_SUMMARY.md
    └── *_SUMMARY.pdf
```

---

# ⚙️ Installation

## Requirements

Before installing the framework, ensure the following requirements are available.

| Requirement | Version | Required |
|---|---|---|
| Python | 3.10+ | ✅ Yes |
| pip | Latest recommended | ✅ Yes |
| Groq API Key | — | For AI reporting |
| Tor | — | Optional |
| Git | — | Recommended |

---

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/security-assessment-agent-v2.git
```

Enter the project directory:

```bash
cd security-assessment-agent-v2
```

> Replace the repository URL above with the actual GitHub repository URL if required.

---

## 2️⃣ Create a Virtual Environment

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

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

Core dependencies include:

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

---

## 4️⃣ Configure Environment Variables

Create a `.env` file in the project root:

```text
security-scanner-agent/
└── .env
```

Add:

```env
GROQ_API_KEY=your_groq_api_key_here
```

> [!CAUTION]
> Never commit your real API key to GitHub.

Recommended `.gitignore` entries:

```gitignore
.env
venv/
.venv/
__pycache__/
*.pyc
*.pyo
*.log
monitor_logs.txt
```

---

## 5️⃣ Start the Framework

```bash
python app.py
```

---

# 🖥️ Usage

Launch the framework:

```bash
python app.py
```

The main application provides category and connection selections.

Example:

```text
╔══════════════════════════════════════════════════════╗
║          🛡️ Security Assessment Agent v2.0           ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║   [1] Category 1 — Passive Scan                      ║
║   [2] Category 2 — Active Scan                       ║
║   [3] Category 3 — Advanced Scan                     ║
║                                                      ║
║   [4] Full Scan — Category 1 + 2 + 3                 ║
║                                                      ║
║   [5] Category 1 + 2                                 ║
║   [6] Category 1 + 3                                 ║
║   [7] Category 2 + 3                                 ║
║                                                      ║
║   [8] Custom Category Selection                      ║
║                                                      ║
║   [0] Exit                                           ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

Connection Mode

[D] Direct
[P] Proxy
[T] Tor
[A] Auto
```

---

# 🚀 Assessment Modes

## Passive Assessment

```text
Target
  │
  ▼
Category 1
  │
  ├── Recon
  ├── Headers
  ├── SSL/TLS
  └── Email Security
```

Suitable for reconnaissance and externally observable configuration analysis.

---

## Active Assessment

```text
Target
  │
  ▼
Category 2
  │
  ├── SQLi
  ├── XSS
  ├── Path Traversal
  ├── CORS
  ├── GraphQL
  ├── JWT
  └── API
```

Requires explicit authorization from the system owner.

---

## Advanced Assessment

```text
Target
  │
  ▼
Category 3
  │
  ├── Authentication
  ├── Command Injection
  ├── File Upload
  ├── SSRF
  ├── XXE
  ├── NoSQL
  ├── SSTI
  ├── CSRF
  ├── WebSocket
  ├── Host Header
  ├── Web Cache
  ├── OAuth
  ├── Prototype Pollution
  └── Access Control
```

Advanced assessments should only be performed within a clearly defined authorized testing scope.

---

# ⚡ Parallel Execution

The framework uses parallel execution to reduce overall assessment time.

Conceptually:

```python
ThreadPoolExecutor(max_workers=N)
    │
    ├── Agent1.scan()
    ├── Agent2.scan()
    ├── Agent3.scan()
    └── AgentN.scan()
```

Each agent returns findings that are collected by the orchestrator.

```text
Agent 1 ──────┐
Agent 2 ──────┤
Agent 3 ──────┼────► all_findings[]
Agent 4 ──────┤
...           │
Agent N ──────┘
```

---

# 🏗️ Architecture

The project follows a modular architecture where the main application coordinates independent scanning, connection, monitoring, and reporting components.

```text
                           ┌───────────────────┐
                           │      app.py       │
                           │ Main Controller   │
                           └─────────┬─────────┘
                                     │
             ┌───────────────────────┼───────────────────────┐
             │                       │                       │
             ▼                       ▼                       ▼
    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
    │ Risk / Routing  │    │ Scan Categories │    │    Monitoring   │
    └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
             │                      │                      │
     ┌───────┼───────┐       ┌─────┼─────┐                ▼
     │       │       │       │     │     │          monitor.py
     ▼       ▼       ▼       ▼     ▼     ▼
   Direct  Proxy    Tor     Cat1  Cat2  Cat3
                             │     │     │
                             └─────┼─────┘
                                   │
                                   ▼
                          Structured Findings
                                   │
                                   ▼
                          ┌─────────────────┐
                          │ Report Generator│
                          └────────┬────────┘
                                   │
                          ┌────────┼────────┐
                          │        │        │
                          ▼        ▼        ▼
                         MD       JSON      PDF
```

---

# 🧩 Category Architecture

Each category follows a similar modular design.

```text
categoryX/
│
├── core/
│   ├── orchestrator.py
│   ├── report_generator.py
│   └── groq_client.py
│
├── agents/
│   ├── agent1.py
│   ├── agent2.py
│   └── ...
│
├── payloads/
│   └── supporting assessment data
│
├── main.py
│
└── output/
```

This structure allows additional security agents to be integrated without redesigning the entire application.

---

# 🔀 Import / Category Isolation

Because multiple categories contain modules with similar names, the main application can switch category paths before loading category-specific modules.

Conceptually:

```python
_switch_to(category_path)

import orchestrator
import report_generator

_restore_all()
```

This prevents similarly named modules from different categories from interfering with each other.

---

# 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core framework |
| Requests | HTTP communication |
| BeautifulSoup | HTML parsing |
| dnspython | DNS operations |
| Rich | Terminal dashboard |
| psutil | System monitoring |
| ReportLab | PDF generation |
| Groq | AI-assisted reporting |
| python-dotenv | Environment configuration |
| Stem | Tor integration |
| fake-useragent | User-Agent generation |
| websocket-client | WebSocket support |

---

# 🔐 Security Considerations

Because this framework performs security assessment activities:

### Never commit secrets

Do not commit:

```text
.env
API Keys
Passwords
Tokens
Private Keys
Session Cookies
Client Credentials
```

### Use isolated environments

Run assessments from controlled environments whenever possible.

### Define scope before testing

Before performing an assessment, document:

```text
Target
Authorized domains/IPs
Allowed techniques
Excluded systems
Testing window
Rate limitations
Emergency contact
Data-handling requirements
```

### Protect assessment reports

Generated reports may contain sensitive security information.

Treat the following as confidential:

- Vulnerability evidence
- Internal endpoints
- Server information
- Authentication details
- Application behavior
- Security weaknesses
- Infrastructure information

---

# 🧪 Recommended Testing Environment

For development and validation, use environments specifically intended for security testing, such as:

```text
Local applications
Development environments
Security labs
CTF environments
Intentionally vulnerable applications
Authorized bug bounty targets
Internal testing environments
```

Do not use third-party production systems without explicit permission.

---

# 🤝 Contributing

Contributions are welcome for defensive and authorized security-testing functionality.

## Create a Feature Branch

```bash
git checkout -b feature/new-agent
```

## Agent Finding Format

New agents should return structured findings following the framework's format.

```python
findings = [
    {
        "type": "Vulnerability Name",
        "risk": "HIGH | MEDIUM | LOW | INFO",
        "description": "Description of the finding",
        "cvss_score": 0.0,
        "cwe": "CWE-XXX",
        "evidence": "Assessment evidence",
        "fix": "Recommended remediation"
    }
]
```

## Add the Agent

Place new agents under:

```text
categoryX/agents/
```

Update the relevant:

```text
categoryX/core/orchestrator.py
```

If supporting assessment data is required, place it under:

```text
categoryX/payloads/
```

## Pull Request

A pull request should clearly describe:

- What the agent checks
- Why the check is useful
- Which category it belongs to
- Dependencies introduced
- Testing performed
- Expected finding structure
- Limitations
- Relevant defensive remediation

---

# 🗺️ Future Development

Potential areas for future development include:

- Additional security assessment agents
- Improved plugin architecture
- Better structured report templates
- Enhanced scan configuration
- Additional report export formats
- Improved dashboard visualization
- Scan profiles
- CI/CD integration
- Improved agent isolation
- Centralized configuration management
- Expanded test coverage

---

# 🛡️ Responsible Use

Security Assessment Agent v2.0 is intended for:

- ✅ Authorized penetration testing
- ✅ Internal security assessments
- ✅ Security laboratories
- ✅ CTF environments
- ✅ Authorized bug bounty programs
- ✅ Cybersecurity education
- ✅ Defensive security research

It is **not intended for unauthorized access, disruption, exploitation, or testing of third-party systems without permission**.

Always obtain appropriate authorization before starting an assessment.

---

# 📜 License

This project is licensed under the **MIT License**.

See the `LICENSE` file included with the repository for full license terms.

---

# ⭐ Support the Project

If you find Security Assessment Agent useful:

- ⭐ Star the repository
- 🍴 Fork the project
- 🐛 Report bugs
- 💡 Suggest improvements
- 🧩 Contribute new security agents
- 📖 Improve documentation

---

<div align="center">

## 🛡️ Security Assessment Agent v2.0

### AI-Powered Modular Penetration Testing Framework

**25+ Specialized Agents • 3 Scan Categories • AI Reporting • Smart Connection Routing**

<br>

<img src="https://img.shields.io/badge/Build-Active-brightgreen?style=flat-square" alt="Build">
<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT">
<img src="https://img.shields.io/badge/Security-Authorized%20Testing%20Only-red?style=flat-square" alt="Authorized Testing">

<br><br>

**Always obtain explicit authorization before testing any system.**

### H A C K &nbsp; R E S P O N S I B L Y 🛡️

</div>
