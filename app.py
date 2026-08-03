"""
Security Assessment Agent v2.0
Category 1 + Category 2 + Category 3 Combined
AI Engine: Groq (Llama 3.3 70B) - FREE
Smart Connection + Anti-Track Auto Integration
"""

import os
import sys
import json
import time
import importlib
import subprocess
import threading
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init

load_dotenv()
init(autoreset=True)

# ── Path setup ──────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAT1_DIR = os.path.join(BASE_DIR, 'category1')
CAT2_DIR = os.path.join(BASE_DIR, 'category2')
CAT3_DIR = os.path.join(BASE_DIR, 'category3')
ALL_CAT_DIRS = [CAT1_DIR, CAT2_DIR, CAT3_DIR]

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, CAT1_DIR)
sys.path.insert(0, CAT2_DIR)
sys.path.insert(0, CAT3_DIR)

# ── Global state ────────────────────────────────────
monitor_process = None
LOG_FILE = os.path.join(BASE_DIR, 'monitor_logs.txt')
smart_conn = None        # SmartConnection instance
anti_track = None        # AntiTrackManager instance
risk_level = 'LOW'       # Global risk level
scan_session = None      # Shared requests session


# ════════════════════════════════════════════════════
#  LOG WRITER
# ════════════════════════════════════════════════════
def write_log(message, level='INFO'):
    """Write log entry for monitor.py to read."""
    timestamp = datetime.now().strftime(
        '%H:%M:%S'
    )
    prefix = {
        'INFO': '[INFO]',
        'WARN': '[WARN]',
        'ERROR': '[ERROR]',
        'SUCCESS': '[OK]',
        'CRITICAL': '[CRITICAL]',
        'SCAN': '[SCAN]',
        'AGENT': '[AGENT]',
        'CONNECT': '[CONN]',
        'SECURITY': '[SEC]',
    }.get(level, '[INFO]')

    log_line = f"{timestamp} {prefix} {message}\n"

    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_line)
    except Exception:
        pass


def clear_log_file():
    """Clear log file at scan start."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(
                f"# Scan started: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
    except Exception:
        pass


# ════════════════════════════════════════════════════
#  MONITOR LAUNCHER
# ════════════════════════════════════════════════════
def start_monitor():
    """Launch monitor.py in separate terminal."""
    global monitor_process
    monitor_path = os.path.join(
        BASE_DIR, 'monitor.py'
    )

    if not os.path.exists(monitor_path):
        write_log(
            'monitor.py not found - skipping',
            'WARN'
        )
        return

    try:
        if sys.platform == 'win32':
            # Try Windows Terminal first
            for cmd in [
                ['wt', 'python', monitor_path],
                [
                    'cmd', '/c', 'start',
                    'python', monitor_path
                ],
            ]:
                try:
                    monitor_process = subprocess.Popen(
                        cmd,
                        creationflags=(
                            subprocess.CREATE_NEW_CONSOLE
                        )
                    )
                    break
                except FileNotFoundError:
                    continue

        elif sys.platform == 'darwin':
            monitor_process = subprocess.Popen([
                'osascript', '-e',
                f'tell app "Terminal" to do script '
                f'"python3 {monitor_path}"'
            ])

        else:
            # Linux
            for term in [
                'gnome-terminal', 'xterm',
                'konsole', 'xfce4-terminal'
            ]:
                try:
                    if term == 'gnome-terminal':
                        monitor_process = (
                            subprocess.Popen([
                                term, '--',
                                'python3', monitor_path
                            ])
                        )
                    else:
                        monitor_process = (
                            subprocess.Popen([
                                term, '-e',
                                f'python3 {monitor_path}'
                            ])
                        )
                    break
                except FileNotFoundError:
                    continue

        write_log(
            'Monitor dashboard launched', 'SUCCESS'
        )

    except Exception as e:
        write_log(
            f'Monitor launch failed: {e}', 'WARN'
        )


def stop_monitor():
    """Stop monitor process."""
    global monitor_process
    if monitor_process:
        try:
            monitor_process.terminate()
        except Exception:
            pass


# ════════════════════════════════════════════════════
#  HELPERS - path switching
# ════════════════════════════════════════════════════
def _switch_to(cat_dir):
    """
    Remove all cat dirs, insert target at front,
    clear cached core/agents modules.
    """
    for d in ALL_CAT_DIRS:
        while d in sys.path:
            sys.path.remove(d)
    sys.path.insert(0, cat_dir)

    for key in list(sys.modules.keys()):
        if (
            key.startswith('core')
            or key.startswith('agents')
        ):
            del sys.modules[key]


def _restore_all():
    """Restore all cat dirs to sys.path."""
    for d in ALL_CAT_DIRS:
        if d not in sys.path:
            sys.path.append(d)


# ════════════════════════════════════════════════════
#  BANNER
# ════════════════════════════════════════════════════
def print_main_banner():
    print(f"\n{Fore.CYAN}" + "═" * 62)
    print("  ███████╗███████╗ ██████╗")
    print("  ██╔════╝██╔════╝██╔════╝")
    print("  ███████╗█████╗  ██║")
    print("  ╚════██║██╔══╝  ██║")
    print("  ███████║███████╗╚██████╗")
    print("  ╚══════╝╚══════╝ ╚═════╝")
    print("")
    print("  Security Assessment Agent v2.0")
    print("  Category 1 + Category 2 + Category 3")
    print(
        "  AI Engine: Groq (Llama 3.3 70B) - FREE"
    )
    print(
        "  Smart Connection + Anti-Track: AUTO"
    )
    print("═" * 62 + Style.RESET_ALL)


# ════════════════════════════════════════════════════
#  MENU
# ════════════════════════════════════════════════════
def print_menu():
    print(
        f"\n{Fore.YELLOW}"
        "┌─────────────────────────────────────────"
        "────────┐"
    )
    print(
        "│           SELECT SCAN MODE               "
        "       │"
    )
    print(
        "├─────────────────────────────────────────"
        "────────┤"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.GREEN}[1]{Fore.YELLOW}"
        " Category 1  - Passive Only               "
        "   │"
    )
    print(
        "│       Recon | Headers | SSL | Email      "
        "       │"
    )
    print(
        "│       Safe - No consent needed           "
        "       │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.RED}[2]{Fore.YELLOW}"
        " Category 2  - Active Scan                "
        "   │"
    )
    print(
        "│       SQLi | XSS | PathTraversal | CORS  "
        "       │"
    )
    print(
        "│       GraphQL | JWT | API                "
        "       │"
    )
    print(
        "│       Requires written consent           "
        "       │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.MAGENTA}[3]{Fore.YELLOW}"
        " Category 3  - Advanced Scan              "
        "   │"
    )
    print(
        "│       Auth | CmdInject | FileUpload ...  "
        "       │"
    )
    print(
        "│       Requires written consent           "
        "       │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.CYAN}[4]{Fore.YELLOW}"
        " Cat 1 + 2   - Passive + Active           "
        "   │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.CYAN}[5]{Fore.YELLOW}"
        " Cat 1 + 3   - Passive + Advanced         "
        "   │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.CYAN}[6]{Fore.YELLOW}"
        " Cat 2 + 3   - Active + Advanced          "
        "   │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.WHITE}[7]{Fore.YELLOW}"
        " Full Scan   - All 3 Categories           "
        "   │"
    )
    print(
        "│       Cat1 + Cat2 + Cat3 assessment      "
        "       │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        f"│  {Fore.WHITE}[8]{Fore.YELLOW}"
        " Exit                                     "
        "   │"
    )
    print(
        "│                                          "
        "       │"
    )
    print(
        "└─────────────────────────────────────────"
        "────────┘"
        + Style.RESET_ALL
    )


# ════════════════════════════════════════════════════
#  TARGET INPUT
# ════════════════════════════════════════════════════
def get_target():
    print(
        f"\n{Fore.YELLOW}Enter target domain or URL:"
    )
    print(
        f"{Fore.WHITE}Examples: example.com  |  "
        "https://www.example.com"
    )
    target = input(
        f"{Fore.CYAN}Target ➜ {Style.RESET_ALL}"
    ).strip()

    if not target:
        print(
            f"{Fore.RED}[!] No target. Exiting."
            + Style.RESET_ALL
        )
        sys.exit(1)

    return target


# ════════════════════════════════════════════════════
#  API KEY CHECK
# ════════════════════════════════════════════════════
def get_api_key():
    groq_key = os.getenv(
        'GROQ_API_KEY', ''
    ).strip()

    if groq_key:
        masked = (
            groq_key[:8] + '....' + groq_key[-4:]
        )
        print(
            f"\n{Fore.GREEN}[✓] Groq API Key : "
            f"{masked}"
        )
        print(
            f"{Fore.GREEN}[✓] AI Engine    : "
            "Groq AI (Llama 3.3 70B) - FREE"
            + Style.RESET_ALL
        )
    else:
        print(
            f"\n{Fore.YELLOW}[!] No GROQ_API_KEY "
            "in .env"
        )
        print(
            f"{Fore.YELLOW}[!] Raw JSON will be "
            "saved. No AI report."
            + Style.RESET_ALL
        )

    return groq_key


# ════════════════════════════════════════════════════
#  SECTION DIVIDER
# ════════════════════════════════════════════════════
def print_section(title, color=Fore.CYAN):
    print(f"\n{color}" + "═" * 62)
    print(f"  {title}")
    print("═" * 62 + Style.RESET_ALL)
    write_log(f"Section: {title}", 'SCAN')


# ════════════════════════════════════════════════════
#  SAVE RAW JSON
# ════════════════════════════════════════════════════
def save_raw_json(results, out_dir, target, label):
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime(
        '%Y%m%d_%H%M%S'
    )
    target_clean = (
        target.replace('https://', '')
        .replace('http://', '')
        .replace('/', '_')
        .replace('.', '_')
    )
    json_path = os.path.join(
        out_dir,
        f"{target_clean}_{timestamp}"
        f"_{label}_raw.json"
    )
    with open(
        json_path, 'w', encoding='utf-8'
    ) as f:
        json.dump(
            results, f,
            indent=2, default=str
        )
    print(
        f"{Fore.YELLOW}[!] Raw JSON: {json_path}"
        + Style.RESET_ALL
    )
    write_log(f"Raw JSON saved: {json_path}", 'INFO')
    return json_path


# ════════════════════════════════════════════════════
#  RISK ASSESSMENT + ANTI-TRACK INIT
# ════════════════════════════════════════════════════
def run_pre_scan_setup(target, groq_key):
    """
    Run before any scan:
    1. Assess target risk
    2. Init anti-track if needed
    3. Setup smart connection
    Returns: (risk_level, session)
    """
    global smart_conn, anti_track, risk_level
    global scan_session

    print_section(
        "PRE-SCAN SETUP", Fore.CYAN
    )
    write_log(
        f"Pre-scan setup for: {target}", 'SCAN'
    )

    # ── Step 1: Risk Assessment ──────────────────────
    print(
        f"\n{Fore.CYAN}[STEP 1/3] "
        "Target Risk Assessment"
        + Style.RESET_ALL
    )
    write_log('Running risk assessment...', 'SECURITY')

    try:
        from risk_checker import RiskChecker
        checker = RiskChecker(target)
        detected_risk, risk_factors = checker.assess()
        risk_level = detected_risk
        write_log(
            f"Risk level: {risk_level} "
            f"({len(risk_factors)} factors)",
            'SECURITY'
        )
    except ImportError:
        print(
            f"  {Fore.YELLOW}[!] risk_checker.py "
            "not found. Using LOW risk default."
            + Style.RESET_ALL
        )
        risk_level = 'LOW'
        write_log(
            'risk_checker not found, using LOW',
            'WARN'
        )
    except Exception as e:
        print(
            f"  {Fore.YELLOW}[!] Risk check error: "
            f"{e}. Using LOW."
            + Style.RESET_ALL
        )
        risk_level = 'LOW'
        write_log(
            f'Risk check error: {e}', 'WARN'
        )

    # ── Step 2: Anti-Track (if needed) ──────────────
    print(
        f"\n{Fore.CYAN}[STEP 2/3] "
        "Anti-Track Configuration"
        + Style.RESET_ALL
    )

    if risk_level in ['MEDIUM', 'HIGH']:
        write_log(
            f'Activating anti-track '
            f'(risk={risk_level})',
            'SECURITY'
        )
        try:
            from anti_track import AntiTrackManager
            anti_track = AntiTrackManager()

            if risk_level == 'HIGH':
                print(
                    f"  {Fore.RED}[*] HIGH RISK - "
                    "Running ADVANCED anti-track..."
                    + Style.RESET_ALL
                )
                write_log(
                    'Advanced anti-track active',
                    'SECURITY'
                )
                anti_track.enable_all()
                anti_track.randomize_fingerprint()
                anti_track.obfuscate_timing()
                anti_track.minimize_logs()
                anti_track.print_security_precautions()

            elif risk_level == 'MEDIUM':
                print(
                    f"  {Fore.YELLOW}[*] MEDIUM RISK - "
                    "Running BASIC anti-track..."
                    + Style.RESET_ALL
                )
                write_log(
                    'Basic anti-track active',
                    'SECURITY'
                )
                anti_track.enable_dns_protection()
                anti_track.sanitize_headers()

            print(
                f"  {Fore.GREEN}[✓] Anti-track "
                "configured"
                + Style.RESET_ALL
            )

        except ImportError:
            print(
                f"  {Fore.YELLOW}[!] anti_track.py "
                "not found. Skipping."
                + Style.RESET_ALL
            )
            write_log(
                'anti_track.py not found', 'WARN'
            )
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] Anti-track "
                f"error: {e}"
                + Style.RESET_ALL
            )
            write_log(
                f'Anti-track error: {e}', 'WARN'
            )
    else:
        print(
            f"  {Fore.GREEN}[✓] LOW RISK - "
            "Anti-track: OFF (not needed)"
            + Style.RESET_ALL
        )
        write_log(
            'Anti-track: OFF (low risk)', 'INFO'
        )

    # ── Step 3: Smart Connection ─────────────────────
    print(
        f"\n{Fore.CYAN}[STEP 3/3] "
        "Smart Connection Setup"
        + Style.RESET_ALL
    )
    write_log(
        f'Setting up smart connection '
        f'(risk={risk_level})',
        'CONNECT'
    )

    try:
        from smart_connection import SmartConnection
        smart_conn = SmartConnection(
            target, risk_level
        )
        scan_session = smart_conn.get_session()

        if scan_session is None:
            print(
                f"  {Fore.RED}[!] Could not "
                "establish connection. Exiting."
                + Style.RESET_ALL
            )
            write_log(
                'Connection setup failed', 'ERROR'
            )
            sys.exit(1)

        method = smart_conn.selected_method
        write_log(
            f'Connection: {method.upper()}',
            'CONNECT'
        )
        print(
            f"  {Fore.GREEN}[✓] Connection ready: "
            f"{method.upper()}"
            + Style.RESET_ALL
        )

    except ImportError:
        print(
            f"  {Fore.YELLOW}[!] smart_connection.py "
            "not found. Using direct."
            + Style.RESET_ALL
        )
        import requests
        scan_session = requests.Session()
        scan_session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 '
                '(Windows NT 10.0; Win64; x64)'
            )
        })
        write_log(
            'smart_connection not found, '
            'using direct session',
            'WARN'
        )
    except Exception as e:
        print(
            f"  {Fore.YELLOW}[!] Smart connection "
            f"error: {e}. Using direct."
            + Style.RESET_ALL
        )
        import requests
        scan_session = requests.Session()
        write_log(
            f'Smart connection error: {e}', 'WARN'
        )

    # ── Summary ──────────────────────────────────────
    print(
        f"\n{Fore.CYAN}" + "─" * 40
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Risk Level  : "
        + {
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }.get(risk_level, Fore.WHITE)
        + risk_level
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Anti-Track  : "
        + (
            f"{Fore.RED}ADVANCED"
            if risk_level == 'HIGH'
            else f"{Fore.YELLOW}BASIC"
            if risk_level == 'MEDIUM'
            else f"{Fore.GREEN}OFF"
        )
        + Style.RESET_ALL
    )
    conn_method = getattr(
        smart_conn, 'selected_method', 'direct'
    ) if smart_conn else 'direct'
    print(
        f"  {Fore.WHITE}Connection  : "
        f"{Fore.CYAN}{conn_method.upper()}"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.CYAN}" + "─" * 40
        + Style.RESET_ALL
    )
    write_log(
        f'Pre-scan complete. '
        f'Risk={risk_level} '
        f'Connection={conn_method}',
        'SUCCESS'
    )

    return risk_level, scan_session


# ════════════════════════════════════════════════════
#  GENERATE PDF HELPER
# ════════════════════════════════════════════════════
def generate_pdf_from_content(
    content, pdf_path, groq_key
):
    """
    Try cat2 → cat3 → cat1 for PDF generation.
    """
    generators = [
        (CAT2_DIR, 'ActiveReportGenerator'),
        (CAT3_DIR, 'AdvancedReportGenerator'),
        (CAT1_DIR, 'ReportGenerator'),
    ]

    old_dir = os.getcwd()

    for cat_dir, class_name in generators:
        try:
            _switch_to(cat_dir)
            os.chdir(cat_dir)

            mod = importlib.import_module(
                'core.report_generator'
            )
            GenClass = getattr(
                mod, class_name, None
            )

            if GenClass is None:
                continue

            gen = GenClass(groq_key or 'no-key')
            gen.generate_pdf(content, pdf_path)
            print(
                f"{Fore.GREEN}[✓] PDF: {pdf_path}"
                + Style.RESET_ALL
            )
            write_log(
                f'PDF generated: {pdf_path}',
                'SUCCESS'
            )
            return True

        except Exception as e:
            print(
                f"{Fore.YELLOW}[!] PDF via "
                f"{class_name} failed: {e}"
                + Style.RESET_ALL
            )
            continue

        finally:
            os.chdir(old_dir)
            _restore_all()

    write_log('All PDF generators failed', 'ERROR')
    return False


# ════════════════════════════════════════════════════
#  BUILD COMBINED STATS
# ════════════════════════════════════════════════════
def build_combined_stats(
    cat1_report, cat2_results, cat3_results
):
    cat1_stats = (
        cat1_report.get('stats', {})
        if cat1_report else {}
    )

    def count_from_results(results):
        counts = {
            'CRITICAL': 0, 'HIGH': 0,
            'MEDIUM': 0, 'LOW': 0
        }
        if not results:
            return counts
        for findings in results.values():
            if not isinstance(findings, list):
                continue
            for f in findings:
                risk = f.get('risk', '').upper()
                if risk in counts:
                    counts[risk] += 1
        return counts

    cat2_stats = count_from_results(cat2_results)
    cat3_stats = count_from_results(cat3_results)

    return {
        'critical': (
            cat1_stats.get('critical', 0)
            + cat2_stats.get('CRITICAL', 0)
            + cat3_stats.get('CRITICAL', 0)
        ),
        'high': (
            cat1_stats.get('high', 0)
            + cat2_stats.get('HIGH', 0)
            + cat3_stats.get('HIGH', 0)
        ),
        'medium': (
            cat1_stats.get('medium', 0)
            + cat2_stats.get('MEDIUM', 0)
            + cat3_stats.get('MEDIUM', 0)
        ),
        'low': (
            cat1_stats.get('low', 0)
            + cat2_stats.get('LOW', 0)
            + cat3_stats.get('LOW', 0)
        ),
    }


# ════════════════════════════════════════════════════
#  SAVE COMBINED SUMMARY
# ════════════════════════════════════════════════════
def save_combined_summary(
    target,
    cat1_results, cat2_results, cat3_results,
    cat1_report, cat2_report, cat3_report,
    total_duration, groq_key,
    scan_label='FULL'
):
    timestamp = datetime.now().strftime(
        '%Y%m%d_%H%M%S'
    )
    target_clean = (
        target.replace('https://', '')
        .replace('http://', '')
        .replace('/', '_')
        .replace('.', '_')
    )

    out_dir = os.path.join(BASE_DIR, 'output')
    os.makedirs(out_dir, exist_ok=True)

    summary_path = os.path.join(
        out_dir,
        f"{target_clean}_{timestamp}"
        f"_{scan_label}_SUMMARY.md"
    )

    stats = build_combined_stats(
        cat1_report, cat2_results, cat3_results
    )
    total = (
        stats['critical'] + stats['high']
        + stats['medium'] + stats['low']
    )
    now = datetime.now().strftime(
        '%Y-%m-%d %H:%M:%S'
    )

    cats_run = []
    if cat1_results:
        cats_run.append('Category 1 (Passive)')
    if cat2_results:
        cats_run.append('Category 2 (Active)')
    if cat3_results:
        cats_run.append('Category 3 (Advanced)')
    cats_str = ' + '.join(cats_run) or 'N/A'

    conn_method = getattr(
        smart_conn, 'selected_method', 'direct'
    ) if smart_conn else 'direct'

    lines = []
    lines.append("# Security Assessment Summary")
    lines.append("")
    lines.append("| Field | Details |")
    lines.append("| --- | --- |")
    lines.append(f"| Target | {target} |")
    lines.append(f"| Date | {now} |")
    lines.append(f"| Duration | {total_duration}s |")
    lines.append(f"| Scan Type | {cats_str} |")
    lines.append(
        f"| Risk Level | {risk_level} |"
    )
    lines.append(
        f"| Connection | {conn_method.upper()} |"
    )
    lines.append(
        "| Classification | CONFIDENTIAL |"
    )
    lines.append("")
    lines.append("## Combined Risk Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    lines.append(
        f"| Critical | {stats['critical']} |"
    )
    lines.append(f"| High | {stats['high']} |")
    lines.append(f"| Medium | {stats['medium']} |")
    lines.append(f"| Low | {stats['low']} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if cat1_report and cat1_report.get('markdown'):
        lines.append("---")
        lines.append("")
        lines.append(
            "# Category 1: Passive Scan Report"
        )
        lines.append("")
        lines.append(cat1_report['markdown'])
        lines.append("")

    if cat2_report and cat2_report.get('markdown'):
        lines.append("---")
        lines.append("")
        lines.append(
            "# Category 2: Active Scan Report"
        )
        lines.append("")
        lines.append(cat2_report['markdown'])
        lines.append("")

    if cat3_report and cat3_report.get('markdown'):
        lines.append("---")
        lines.append("")
        lines.append(
            "# Category 3: Advanced Scan Report"
        )
        lines.append("")
        lines.append(cat3_report['markdown'])
        lines.append("")

    content = '\n'.join(lines)

    with open(
        summary_path, 'w', encoding='utf-8'
    ) as f:
        f.write(content)

    print(
        f"\n{Fore.GREEN}[✓] Summary: "
        f"{summary_path}" + Style.RESET_ALL
    )
    write_log(
        f'Summary saved: {summary_path}', 'SUCCESS'
    )

    pdf_path = summary_path.replace('.md', '.pdf')
    generate_pdf_from_content(
        content, pdf_path, groq_key
    )

    return summary_path


# ════════════════════════════════════════════════════
#  RUN CATEGORY 1
# ════════════════════════════════════════════════════
def run_category1(target, groq_key):
    print_section(
        "CATEGORY 1 - PASSIVE SECURITY SCAN",
        Fore.GREEN
    )
    print(
        f"{Fore.GREEN}Agents: Recon | Headers | "
        "SSL | Email Security" + Style.RESET_ALL
    )
    write_log(
        'Starting Category 1 - Passive scan',
        'AGENT'
    )

    cat1_out = os.path.join(
        BASE_DIR, 'output', 'category1'
    )
    os.makedirs(cat1_out, exist_ok=True)
    old_dir = os.getcwd()

    cat1_results = None
    cat1_report = None

    try:
        _switch_to(CAT1_DIR)
        os.chdir(CAT1_DIR)

        from core.orchestrator import (
            PassiveSecurityOrchestrator
        )

        orchestrator = PassiveSecurityOrchestrator(
            target, groq_key
        )

        # Inject shared session if available
        if scan_session:
            orchestrator.session = scan_session

        start = time.time()
        write_log('Cat1: Running 4 agents...', 'AGENT')

        cat1_results = orchestrator.run_assessment()
        duration = round(time.time() - start)

        write_log(
            f'Cat1 complete in {duration}s',
            'SUCCESS'
        )

        print_section(
            "CATEGORY 1 - GENERATING REPORT",
            Fore.GREEN
        )

        if groq_key:
            cat1_report = (
                orchestrator.generate_report()
            )
        else:
            save_raw_json(
                cat1_results, cat1_out,
                target, 'cat1'
            )
            cat1_report = None

        print(
            f"\n{Fore.GREEN}[✓] Category 1 Complete!"
            f" Duration: {duration}s"
            + Style.RESET_ALL
        )

    except Exception as e:
        print(
            f"{Fore.RED}[!] Category 1 Error: {e}"
            + Style.RESET_ALL
        )
        write_log(
            f'Cat1 error: {e}', 'ERROR'
        )
        import traceback
        traceback.print_exc()

    finally:
        os.chdir(old_dir)
        _restore_all()

    return cat1_results, cat1_report


# ════════════════════════════════════════════════════
#  RUN CATEGORY 2
# ════════════════════════════════════════════════════
def run_category2(target, groq_key):
    print_section(
        "CATEGORY 2 - ACTIVE SECURITY SCAN",
        Fore.RED
    )
    print(
        f"{Fore.RED}Agents: SQLi | XSS | "
        "PathTraversal | CORS | "
        "GraphQL | JWT | API" + Style.RESET_ALL
    )
    write_log(
        'Starting Category 2 - Active scan',
        'AGENT'
    )

    cat2_out = os.path.join(
        BASE_DIR, 'output', 'category2'
    )
    os.makedirs(cat2_out, exist_ok=True)
    old_dir = os.getcwd()

    cat2_results = None
    cat2_report = None

    try:
        _switch_to(CAT2_DIR)
        os.chdir(CAT2_DIR)

        from core.orchestrator import (
            ActiveScanOrchestrator
        )

        orchestrator = ActiveScanOrchestrator(
            target, groq_key
        )

        # Inject shared session
        if scan_session:
            orchestrator.shared_session = scan_session

        start = time.time()
        cat2_results = orchestrator.run_assessment(
            skip_consent=False
        )
        duration = round(time.time() - start)

        if cat2_results is None:
            print(
                f"{Fore.YELLOW}[!] Category 2 "
                "cancelled - no consent."
                + Style.RESET_ALL
            )
            write_log(
                'Cat2 cancelled - no consent',
                'WARN'
            )
            return None, None

        write_log(
            f'Cat2 complete in {duration}s',
            'SUCCESS'
        )

        print_section(
            "CATEGORY 2 - GENERATING REPORT",
            Fore.RED
        )

        if groq_key:
            cat2_report = (
                orchestrator.generate_report()
            )
        else:
            save_raw_json(
                cat2_results, cat2_out,
                target, 'cat2'
            )
            cat2_report = None

        print(
            f"\n{Fore.GREEN}[✓] Category 2 Complete!"
            f" Duration: {duration}s"
            + Style.RESET_ALL
        )

    except Exception as e:
        print(
            f"{Fore.RED}[!] Category 2 Error: {e}"
            + Style.RESET_ALL
        )
        write_log(f'Cat2 error: {e}', 'ERROR')
        import traceback
        traceback.print_exc()

    finally:
        os.chdir(old_dir)
        _restore_all()

    return cat2_results, cat2_report


# ════════════════════════════════════════════════════
#  RUN CATEGORY 3
# ════════════════════════════════════════════════════
def run_category3(
    target, groq_key, skip_consent=False
):
    print_section(
        "CATEGORY 3 - ADVANCED SECURITY SCAN",
        Fore.MAGENTA
    )
    print(
        f"{Fore.MAGENTA}Agents: Auth | CmdInject | "
        "FileUpload | SSRF | XXE | NoSQL"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.MAGENTA}         SSTI | CSRF | "
        "WebSocket | HostHeader | WebCache"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.MAGENTA}         OAuth | ProtoPollution"
        " | AccessControl" + Style.RESET_ALL
    )
    write_log(
        'Starting Category 3 - Advanced scan',
        'AGENT'
    )

    cat3_out = os.path.join(
        BASE_DIR, 'output', 'category3'
    )
    os.makedirs(cat3_out, exist_ok=True)
    old_dir = os.getcwd()

    cat3_results = None
    cat3_report = None

    try:
        _switch_to(CAT3_DIR)
        os.chdir(CAT3_DIR)

        from core.orchestrator import (
            AdvancedScanOrchestrator
        )

        orchestrator = AdvancedScanOrchestrator(
            target, groq_key
        )

        # Inject shared session
        if scan_session:
            orchestrator.shared_session = scan_session

        start = time.time()
        cat3_results = orchestrator.run_assessment(
            skip_consent=skip_consent
        )
        duration = round(time.time() - start)

        if cat3_results is None:
            print(
                f"{Fore.YELLOW}[!] Category 3 "
                "cancelled - no consent."
                + Style.RESET_ALL
            )
            write_log(
                'Cat3 cancelled - no consent',
                'WARN'
            )
            return None, None

        write_log(
            f'Cat3 complete in {duration}s',
            'SUCCESS'
        )

        print_section(
            "CATEGORY 3 - GENERATING REPORT",
            Fore.MAGENTA
        )

        if groq_key:
            cat3_report = (
                orchestrator.generate_report()
            )
        else:
            save_raw_json(
                cat3_results, cat3_out,
                target, 'cat3'
            )
            cat3_report = None

        print(
            f"\n{Fore.GREEN}[✓] Category 3 Complete!"
            f" Duration: {duration}s"
            + Style.RESET_ALL
        )

    except Exception as e:
        print(
            f"{Fore.RED}[!] Category 3 Error: {e}"
            + Style.RESET_ALL
        )
        write_log(f'Cat3 error: {e}', 'ERROR')
        import traceback
        traceback.print_exc()

    finally:
        os.chdir(old_dir)
        _restore_all()

    return cat3_results, cat3_report


# ════════════════════════════════════════════════════
#  AGENT SUMMARY PRINTER
# ════════════════════════════════════════════════════
def _print_agent_summary(results, agent_list):
    for key, label in agent_list:
        findings = results.get(key, [])
        count = (
            len(findings)
            if isinstance(findings, list)
            else 0
        )
        color = (
            Fore.RED if count > 0 else Fore.GREEN
        )
        icon = '⚠' if count > 0 else '✓'
        print(
            f"  {color}{icon}{Fore.WHITE} {label}: "
            f"{color}{count} findings"
            + Style.RESET_ALL
        )
        if count > 0:
            write_log(
                f'{label}: {count} findings',
                'WARN'
            )


# ════════════════════════════════════════════════════
#  FINAL SUMMARY PRINT
# ════════════════════════════════════════════════════
def print_final_summary(
    target,
    cat1_results, cat2_results, cat3_results,
    cat1_report, cat2_report, cat3_report,
    total_duration
):
    print(f"\n{Fore.CYAN}" + "═" * 62)
    print("  ASSESSMENT COMPLETE")
    print("═" * 62 + Style.RESET_ALL)

    print(
        f"\n{Fore.WHITE}Target   : "
        f"{Fore.CYAN}{target}" + Style.RESET_ALL
    )
    print(
        f"{Fore.WHITE}Duration : "
        f"{Fore.CYAN}{total_duration}s"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.WHITE}Risk     : "
        + {
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }.get(risk_level, Fore.WHITE)
        + risk_level + Style.RESET_ALL
    )
    conn_method = getattr(
        smart_conn, 'selected_method', 'direct'
    ) if smart_conn else 'direct'
    print(
        f"{Fore.WHITE}Via      : "
        f"{Fore.CYAN}{conn_method.upper()}"
        + Style.RESET_ALL
    )

    if cat1_results:
        print(
            f"\n{Fore.GREEN}"
            "Category 1 - Passive Scan:"
            + Style.RESET_ALL
        )
        c1_checks = [
            ('reconnaissance', 'Reconnaissance'),
            ('security_headers', 'Security Headers'),
            ('ssl_tls', 'SSL/TLS'),
            ('email_security', 'Email Security'),
        ]
        for key, label in c1_checks:
            data = cat1_results.get(key, {})
            ok = data and 'error' not in data
            status = (
                f"{Fore.GREEN}✓ Done"
                if ok
                else f"{Fore.RED}✗ Error"
            )
            print(
                f"  {status}{Fore.WHITE} {label}"
                + Style.RESET_ALL
            )

    if cat2_results:
        print(
            f"\n{Fore.RED}"
            "Category 2 - Active Scan:"
            + Style.RESET_ALL
        )
        c2_agents = [
            ('sql_injection', 'SQL Injection'),
            ('xss', 'XSS'),
            ('path_traversal', 'Path Traversal'),
            ('cors', 'CORS'),
            ('graphql', 'GraphQL'),
            ('jwt', 'JWT'),
            ('api', 'API Security'),
        ]
        _print_agent_summary(
            cat2_results, c2_agents
        )

    if cat3_results:
        print(
            f"\n{Fore.MAGENTA}"
            "Category 3 - Advanced Scan:"
            + Style.RESET_ALL
        )
        c3_agents = [
            ('authentication', 'Authentication'),
            (
                'command_injection',
                'Command Injection'
            ),
            ('file_upload', 'File Upload'),
            ('ssrf', 'SSRF'),
            ('xxe', 'XXE Injection'),
            ('nosql_injection', 'NoSQL Injection'),
            ('ssti', 'SSTI'),
            ('csrf', 'CSRF'),
            ('websocket', 'WebSocket'),
            (
                'http_host_header',
                'HTTP Host Header'
            ),
            ('web_cache', 'Web Cache'),
            ('oauth', 'OAuth'),
            (
                'prototype_pollution',
                'Prototype Pollution'
            ),
            ('access_control', 'Access Control'),
        ]
        _print_agent_summary(
            cat3_results, c3_agents
        )

    stats = build_combined_stats(
        cat1_report, cat2_results, cat3_results
    )
    total = (
        stats['critical'] + stats['high']
        + stats['medium'] + stats['low']
    )

    print(
        f"\n{Fore.CYAN}" + "─" * 40
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Total Findings : "
        f"{Fore.CYAN}{total}" + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Critical       : "
        f"{Fore.RED}{stats['critical']}"
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}High           : "
        f"{Fore.YELLOW}{stats['high']}"
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Medium         : "
        f"{Fore.YELLOW}{stats['medium']}"
        + Style.RESET_ALL
    )
    print(
        f"  {Fore.WHITE}Low            : "
        f"{Fore.GREEN}{stats['low']}"
        + Style.RESET_ALL
    )
    print(
        f"\n{Fore.GREEN}Output: output/"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.CYAN}" + "═" * 62 + Style.RESET_ALL
    )

    write_log(
        f'SCAN COMPLETE. Total: {total} findings. '
        f'Critical: {stats["critical"]} '
        f'High: {stats["high"]}',
        'SUCCESS'
    )


# ════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════
def main():
    print_main_banner()

    groq_key = get_api_key()
    print_menu()

    choice = input(
        f"\n{Fore.CYAN}Select option [1-8]: "
        + Style.RESET_ALL
    ).strip()

    if choice == '8':
        print(
            f"{Fore.YELLOW}Goodbye!"
            + Style.RESET_ALL
        )
        sys.exit(0)

    valid = ['1', '2', '3', '4', '5', '6', '7']
    if choice not in valid:
        print(
            f"{Fore.RED}[!] Invalid option. "
            "Please select 1-8." + Style.RESET_ALL
        )
        sys.exit(1)

    target = get_target()

    # ── Pre-scan setup ───────────────────────────────
    clear_log_file()
    start_monitor()
    write_log(
        f'Target: {target} | Choice: {choice}',
        'SCAN'
    )

    # ✅ Risk assessment + anti-track + connection
    run_pre_scan_setup(target, groq_key)

    app_start = time.time()

    cat1_results = None
    cat1_report = None
    cat2_results = None
    cat2_report = None
    cat3_results = None
    cat3_report = None

    # ════════════════════════════════════════════════
    #  CHOICE ROUTING
    # ════════════════════════════════════════════════

    if choice == '1':
        cat1_results, cat1_report = run_category1(
            target, groq_key
        )

    elif choice == '2':
        cat2_results, cat2_report = run_category2(
            target, groq_key
        )

    elif choice == '3':
        cat3_results, cat3_report = run_category3(
            target, groq_key,
            skip_consent=False
        )

    elif choice == '4':
        print(
            f"\n{Fore.CYAN}[*] Cat 1 + Cat 2"
            + Style.RESET_ALL
        )
        cat1_results, cat1_report = run_category1(
            target, groq_key
        )
        cat2_results, cat2_report = run_category2(
            target, groq_key
        )
        if cat1_results or cat2_results:
            save_combined_summary(
                target,
                cat1_results, cat2_results, None,
                cat1_report, cat2_report, None,
                round(time.time() - app_start),
                groq_key, 'CAT1_CAT2'
            )

    elif choice == '5':
        print(
            f"\n{Fore.CYAN}[*] Cat 1 + Cat 3"
            + Style.RESET_ALL
        )
        cat1_results, cat1_report = run_category1(
            target, groq_key
        )
        cat3_results, cat3_report = run_category3(
            target, groq_key,
            skip_consent=False
        )
        if cat1_results or cat3_results:
            save_combined_summary(
                target,
                cat1_results, None, cat3_results,
                cat1_report, None, cat3_report,
                round(time.time() - app_start),
                groq_key, 'CAT1_CAT3'
            )

    elif choice == '6':
        print(
            f"\n{Fore.CYAN}[*] Cat 2 + Cat 3"
            + Style.RESET_ALL
        )
        cat2_results, cat2_report = run_category2(
            target, groq_key
        )
        if cat2_results is None:
            print(
                f"{Fore.YELLOW}[!] Cat2 cancelled."
                + Style.RESET_ALL
            )
        else:
            # Cat2 gave consent → Cat3 skips it
            cat3_results, cat3_report = (
                run_category3(
                    target, groq_key,
                    skip_consent=True
                )
            )
            if cat2_results or cat3_results:
                save_combined_summary(
                    target,
                    None, cat2_results, cat3_results,
                    None, cat2_report, cat3_report,
                    round(time.time() - app_start),
                    groq_key, 'CAT2_CAT3'
                )

    elif choice == '7':
        print(
            f"\n{Fore.CYAN}[*] FULL SCAN - "
            "All 3 Categories" + Style.RESET_ALL
        )

        print(
            f"\n{Fore.GREEN}[*] Phase 1: Cat1 "
            "(Passive)" + Style.RESET_ALL
        )
        write_log('Phase 1: Category 1', 'SCAN')
        cat1_results, cat1_report = run_category1(
            target, groq_key
        )

        print(
            f"\n{Fore.YELLOW}[*] Phase 2: Cat2 "
            "(Active)" + Style.RESET_ALL
        )
        write_log('Phase 2: Category 2', 'SCAN')
        cat2_results, cat2_report = run_category2(
            target, groq_key
        )

        print(
            f"\n{Fore.MAGENTA}[*] Phase 3: Cat3 "
            "(Advanced)" + Style.RESET_ALL
        )
        write_log('Phase 3: Category 3', 'SCAN')

        # If Cat2 succeeded → skip Cat3 consent
        skip = cat2_results is not None
        cat3_results, cat3_report = run_category3(
            target, groq_key,
            skip_consent=skip
        )

        if (
            cat1_results
            or cat2_results
            or cat3_results
        ):
            save_combined_summary(
                target,
                cat1_results,
                cat2_results,
                cat3_results,
                cat1_report,
                cat2_report,
                cat3_report,
                round(time.time() - app_start),
                groq_key, 'FULL'
            )

    # ── Final summary ────────────────────────────────
    total_duration = round(time.time() - app_start)

    print_final_summary(
        target,
        cat1_results, cat2_results, cat3_results,
        cat1_report, cat2_report, cat3_report,
        total_duration
    )

    stop_monitor()


if __name__ == "__main__":
    main()
