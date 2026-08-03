# 🛡️ Security Assessment Agent v2.0

> An advanced, modular, AI-powered CLI security assessment tool for ethical penetration testers and bug bounty hunters. Built with Python, powered by Groq (Llama-3.3-70b-versatile), and designed with smart connection routing, anti-tracking, and automated PDF/Markdown reporting.

---

## ⚠️ Legal Disclaimer

> **This tool is strictly for authorized security testing and educational purposes only.**
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and may violate laws including but not limited to the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide.
> **The developers assume zero liability for misuse.**

---

## 📁 Project Structure

```text
security_passive_agent/
├── app.py                        # Main entry point (Menu, Routing, Reporting)
├── monitor.py                    # Rich-based live terminal dashboard
├── risk_checker.py               # Target risk assessment (LOW/MEDIUM/HIGH)
├── smart_connection.py           # Smart routing (Direct/Proxy/Tor)
├── anti_track.py                 # Header obfuscation & timing jitter
├── connection_manager.py         # Tor/VPN session management
├── proxy_manager.py              # Free proxy scraper & tester
├── .env                          # API keys (never commit this)
├── requirements.txt              # All Python dependencies
│
├── category1/                    # Passive Scanning (No Consent Required)
│   ├── README.md
│   ├── core/
│   │   ├── orchestrator.py
│   │   └── report_generator.py
│   └── agents/
│       ├── recon_agent.py
│       ├── headers_agent.py
│       ├── ssl_agent.py
│       └── email_agent.py
│
├── category2/                    # Active Scanning (Consent Required)
│   ├── README.md
│   ├── payloads/
│   │   ├── sqli_payloads.txt
│   │   ├── xss_payloads.txt
│   │   ├── cors_payloads.txt
│   │   ├── path_traversal_payloads.txt
│   │   └── jwt_payloads.txt
│   ├── core/
│   │   ├── orchestrator.py
│   │   └── report_generator.py
│   └── agents/
│       ├── sqli_agent.py
│       ├── xss_agent.py
│       ├── path_traversal_agent.py
│       ├── cors_agent.py
│       ├── graphql_agent.py
│       ├── jwt_agent.py
│       └── api_agent.py
│
├── category3/                    # Advanced Scanning (Consent Required)
│   ├── README.md
│   ├── payloads/
│   │   ├── command_injection_payloads.txt
│   │   ├── xxe_payloads.txt
│   │   ├── nosql_payloads.txt
│   │   ├── ssti_payloads.txt
│   │   └── file_upload_payloads.txt
│   ├── core/
│   │   ├── orchestrator.py       # Includes LiveLogger
│   │   └── report_generator.py
│   └── agents/
│       ├── auth_agent.py
│       ├── command_injection_agent.py
│       ├── file_upload_agent.py
│       ├── ssrf_agent.py
│       ├── xxe_agent.py
│       ├── nosql_agent.py
│       ├── ssti_agent.py
│       ├── csrf_agent.py
│       ├── websocket_agent.py
│       ├── http_host_header_agent.py
│       ├── web_cache_agent.py
│       ├── oauth_agent.py
│       ├── prototype_pollution_agent.py
│       └── access_control_agent.py
│
└── output/                       # All generated reports
    ├── *.md                      # Markdown reports
    ├── *.json                    # Raw findings (JSON)
    └── *.pdf                     # Final PDF reports
🚀 Features
Feature	Description
🔍 25 Security Agents	Covering Passive, Active, and Advanced vulnerability classes
🤖 AI-Powered Reports	Groq API (Llama-3.3-70b-versatile) formats findings into professional Markdown
📄 PDF Generation	ReportLab converts Markdown reports to styled PDFs automatically
🌐 Smart Connection Routing	Auto-selects Direct / Free Proxy / Tor based on target risk
🕵️ Anti-Tracking Engine	Randomizes headers, User-Agents, and adds timing jitter for high-risk targets
📊 Live Dashboard	Rich-powered real-time monitor showing CPU, RAM, Network, and scan logs
⚖️ Risk Assessment	Pre-scan risk engine evaluates TLD, WAF, CDN, and bug bounty status
📂 Combined Reports	Master summary report merges all category findings into one document
🔄 Fallback Reporting	If Groq API fails, hardcoded fallback generates complete Markdown reports
🗂️ Modular Architecture	Each category is fully independent with its own orchestrator and agents
⚙️ Installation
Prerequisites
Python 3.10+
Tor (optional, for HIGH risk targets) → Download Tor
A valid Groq API Key
Step-by-Step Setup
Bash

# 1. Clone the repository
git clone https://github.com/yourusername/security-assessment-agent-v2.git
cd security-assessment-agent-v2

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your API key
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
.env Configuration
env

GROQ_API_KEY=your_groq_api_key_here
📦 Dependencies
text

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
Install all at once:

Bash

pip install -r requirements.txt
🖥️ Usage
Launch the Tool
Bash

python app.py
Main Menu
text

╔══════════════════════════════════════════╗
║     Security Assessment Agent v2.0      ║
╠══════════════════════════════════════════╣
║  [1] Category 1 - Passive Scan          ║
║  [2] Category 2 - Active Scan           ║
║  [3] Category 3 - Advanced Scan         ║
║  [4] Full Scan  - All Categories (1+2+3)║
║  [5] Custom     - Select Categories     ║
║  [0] Exit                               ║
╚══════════════════════════════════════════╝
Scan Workflow
text

Enter Target URL → Risk Assessment → Connection Routing → Anti-Track Setup
       ↓
Run Selected Category Agents → Live Dashboard Updates
       ↓
AI Report Generation (Groq) → PDF Export → Combined Summary
🔐 Smart Connection Routing
Risk Level	Connection Method	Anti-Track
🟢 LOW	Direct connection	None
🟡 MEDIUM	Free Proxy rotation	Basic header obfuscation
🔴 HIGH	Tor circuit routing	Advanced jitter + full header randomization
The RiskChecker evaluates:

Target TLD (.gov, .mil, .bank → HIGH)
WAF/CDN presence (Cloudflare, Akamai, etc.)
Bug bounty program status
Sensitive keyword detection in domain
📊 Live Monitor Dashboard
The monitor launches automatically in a new terminal window showing:

🖥️ Real-time CPU & RAM usage
🌐 Network I/O statistics
📋 Live scan action log (from monitor_logs.txt)
⏱️ Elapsed scan time
📁 Output Reports
All reports are saved to the output/ directory:

Format	Content
.md	Full Markdown report with findings, CVSS scores, CWE IDs, and fixes
.json	Raw structured findings for integration with other tools
.pdf	Professional PDF report generated via ReportLab
combined_*.md	Master summary merging all category reports
Report Structure (per finding)
JSON

{
  "type": "SQL Injection",
  "risk": "HIGH",
  "description": "Blind SQLi detected on /login endpoint via 'username' parameter",
  "cvss_score": 9.8,
  "cwe": "CWE-89",
  "fix": "Use parameterized queries / prepared statements"
}
🏗️ Architecture Deep Dive
Pre-Scan Setup Flow
Python

run_pre_scan_setup(target_url)
    ├── RiskChecker.assess(target_url)          → risk_level
    ├── AntiTrackManager.activate(risk_level)   → session headers modified
    └── SmartConnection.get_session(risk_level) → shared_session
Agent Execution Flow
Python

Orchestrator.run(target_url, session)
    ├── Agent1.scan() → findings[]
    ├── Agent2.scan() → findings[]
    └── ...AgentN.scan() → findings[]
         ↓
    ReportGenerator.generate(all_findings)
         ↓
    Groq API → Markdown → PDF
Path Isolation (Import Safety)
Since all 3 categories have identically named core/ and agents/ folders, app.py uses _switch_to() and _restore_all() helpers to safely manipulate sys.path before importing each category, preventing module collision.

🤝 Contributing
Fork the repository
Create your feature branch (git checkout -b feature/new-agent)
Follow the existing agent structure (findings dict with type, risk, description, cvss_score, cwe, fix)
Submit a pull request with a clear description
📜 License
This project is licensed under the MIT License — see LICENSE for details.

👨‍💻 Author
Built with ❤️ for the ethical hacking and bug bounty community.

Remember: Always get written permission before testing any target. Hack responsibly.
