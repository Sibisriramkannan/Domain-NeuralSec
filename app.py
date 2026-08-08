"""
Security Assessment Agent v2.0
Category 1 + 2 + 3 Combined
Smart Connection + Anti-Track + Guard
Tor: Auto-launch with live display terminal
Consent: DISABLED
Auto-Setup: Runs on first launch
Cross-Platform: Windows + Linux + macOS + QTerminal
Connection: User choice D/P/T/A
"""

import os
import sys
import subprocess
import platform
import shutil
from datetime import datetime

# ── BASE DIR ─────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Suppress Qt/KDE warnings
os.environ['QT_LOGGING_RULES'] = '*.debug=false'
os.environ['KF_LOGGING_RULES']  = '*.debug=false'


# ════════════════════════════════════════════════════
#  AUTO SETUP
# ════════════════════════════════════════════════════
def auto_setup():
    PLATFORM   = platform.system()
    IS_WINDOWS = PLATFORM == 'Windows'
    IS_LINUX   = PLATFORM == 'Linux'
    IS_MAC     = PLATFORM == 'Darwin'

    setup_flag = os.path.join(BASE_DIR, '.setup_done')

    if os.path.exists(setup_flag):
        try:
            age = (
                datetime.now().timestamp()
                - os.path.getmtime(setup_flag)
            )
            if age < 86400:
                return
        except:
            pass

    print("\n" + "═" * 55)
    print("  AUTO SETUP - First Run Check")
    print(f"  Platform : {PLATFORM}")
    print(f"  Python   : {sys.version.split()[0]}")
    print("═" * 55)

    # ── Step 1: Python Packages ──────────────────────
    print("\n[1/5] Checking Python packages...")
    required_pkgs = [
        ('requests',  'requests'),
        ('colorama',  'colorama'),
        ('dotenv',    'python-dotenv'),
        ('bs4',       'beautifulsoup4'),
        ('rich',      'rich'),
        ('psutil',    'psutil'),
        ('groq',      'groq'),
        ('reportlab', 'reportlab'),
        ('socks',     'pysocks'),
        ('whois',     'python-whois'),
        ('dns',       'dnspython'),
        ('stem',      'stem'),
    ]

    missing = []
    for import_name, pip_name in required_pkgs:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print(f"  [*] Installing {len(missing)} missing packages...")
        pip_base = [
            sys.executable, '-m', 'pip', 'install',
            '--quiet', '--disable-pip-version-check'
        ]
        if IS_LINUX:
            test = subprocess.run(
                pip_base + ['--dry-run', 'requests'],
                capture_output=True
            )
            stderr = test.stderr.decode('utf-8', errors='ignore')
            if 'externally-managed' in stderr or 'break-system' in stderr:
                pip_base.append('--break-system-packages')

        for pkg in missing:
            try:
                result = subprocess.run(
                    pip_base + [pkg],
                    capture_output=True,
                    timeout=120
                )
                if result.returncode == 0:
                    print(f"  [✓] {pkg}")
                else:
                    print(f"  [!] {pkg} failed")
            except subprocess.TimeoutExpired:
                print(f"  [!] {pkg} timeout")
            except Exception as e:
                print(f"  [!] {pkg}: {e}")
        try:
            subprocess.run(
                pip_base + ['requests[socks]'],
                capture_output=True, timeout=60
            )
        except:
            pass
    else:
        print("  [✓] All packages OK")

    # ── Step 2: Directories ──────────────────────────
    print("\n[2/5] Creating directories...")
    for d in [
        'output',
        os.path.join('output', 'category1'),
        os.path.join('output', 'category2'),
        os.path.join('output', 'category3'),
        'tor_portable',
        'tor_portable/data',
    ]:
        os.makedirs(os.path.join(BASE_DIR, d), exist_ok=True)
    print("  [✓] Directories ready")

    # ── Step 3: .env ─────────────────────────────────
    print("\n[3/5] Checking .env file...")
    env_path = os.path.join(BASE_DIR, '.env')
    if not os.path.exists(env_path):
        with open(env_path, 'w') as f:
            f.write(
                "# Security Scanner Config\n"
                "GROQ_API_KEY=your_groq_key_here\n"
            )
        print("  [✓] .env created")
        print("  [!] Add your GROQ_API_KEY to .env!")
        print("  [→] Get free key: console.groq.com")
    else:
        with open(env_path) as f:
            content = f.read()
        if 'GROQ_API_KEY' in content and 'your_groq_key' not in content:
            print("  [✓] .env with API key found")
        else:
            print("  [!] GROQ_API_KEY not set in .env")

    # ── Step 4: Tor ──────────────────────────────────
    print("\n[4/5] Checking Tor...")
    tor_found = bool(shutil.which('tor'))
    if not tor_found:
        if IS_WINDOWS:
            user = os.getenv('USERNAME', '')
            check_paths = [
                rf'C:\Users\{user}\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                r'C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                r'C:\Tor\tor.exe',
            ]
        elif IS_MAC:
            check_paths = [
                '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor',
                '/usr/local/bin/tor',
                '/opt/homebrew/bin/tor',
            ]
        else:
            check_paths = ['/usr/bin/tor', '/usr/local/bin/tor']
        check_paths.append(
            os.path.join(BASE_DIR, 'tor_portable', 'tor',
                         'tor.exe' if IS_WINDOWS else 'tor')
        )
        for p in check_paths:
            if os.path.exists(p):
                tor_found = True
                break

    if tor_found:
        print("  [✓] Tor found")
    else:
        print("  [~] Tor not installed (optional)")
        if IS_LINUX:
            print("  [*] Auto-installing Tor...")
            try:
                result = subprocess.run(
                    ['sudo', 'apt-get', 'install', '-y', 'tor'],
                    capture_output=True, timeout=120, text=True
                )
                if result.returncode == 0:
                    subprocess.run(['sudo', 'systemctl', 'enable', 'tor'], capture_output=True)
                    subprocess.run(['sudo', 'systemctl', 'start', 'tor'], capture_output=True)
                    print("  [✓] Tor installed + started")
                else:
                    print("  [→] Manual: sudo apt install tor")
            except Exception as e:
                print(f"  [!] Tor install error: {e}")
                print("  [→] Manual: sudo apt install tor")
        elif IS_MAC:
            print("  [→] Install: brew install tor")
        else:
            print("  [→] choco install tor  OR  Open Tor Browser")

    # ── Step 5: Terminal ─────────────────────────────
    if IS_LINUX:
        print("\n[5/5] Checking terminal emulator...")
        all_terms = [
            'qterminal', 'gnome-terminal', 'konsole',
            'xfce4-terminal', 'xterm', 'lxterminal',
            'kitty', 'alacritty', 'mate-terminal',
            'tilix', 'terminator',
        ]
        found_term = next(
            (t for t in all_terms if shutil.which(t)), None
        )
        if found_term:
            print(f"  [✓] Terminal: {found_term}")
        else:
            print("  [!] No terminal emulator found")
            print("  [*] Auto-installing xterm...")
            try:
                result = subprocess.run(
                    ['sudo', 'apt-get', 'install', '-y', 'xterm'],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0:
                    print("  [✓] xterm installed")
                else:
                    print("  [→] sudo apt install xterm")
            except Exception as e:
                print(f"  [!] Error: {e}")
    else:
        print("\n[5/5] Terminal: N/A")
        print(f"  [✓] {PLATFORM} uses system terminal")

    try:
        with open(setup_flag, 'w') as f:
            f.write(
                f"setup_time={datetime.now().isoformat()}\n"
                f"platform={PLATFORM}\n"
                f"python={sys.version}\n"
            )
    except:
        pass

    print("\n" + "═" * 55)
    print("  [✓] Setup Complete!")
    print(f"  Platform : {PLATFORM}")
    print("═" * 55 + "\n")

    import time as _t
    _t.sleep(1)


# ════════════════════════════════════════════════════
#  RUN SETUP FIRST
# ════════════════════════════════════════════════════
auto_setup()


# ════════════════════════════════════════════════════
#  IMPORTS
# ════════════════════════════════════════════════════
import json
import time
import re
import importlib
import threading
from dotenv import load_dotenv
from colorama import Fore, Style, init

load_dotenv()
init(autoreset=True)

CAT1_DIR = os.path.join(BASE_DIR, 'category1')
CAT2_DIR = os.path.join(BASE_DIR, 'category2')
CAT3_DIR = os.path.join(BASE_DIR, 'category3')
ALL_CAT_DIRS = [CAT1_DIR, CAT2_DIR, CAT3_DIR]

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, CAT1_DIR)
sys.path.insert(0, CAT2_DIR)
sys.path.insert(0, CAT3_DIR)

monitor_process  = None
LOG_FILE         = os.path.join(BASE_DIR, 'monitor_logs.txt')
smart_conn       = None
anti_track       = None
connection_guard = None
risk_level       = 'LOW'
scan_session     = None
_log_lock        = threading.Lock()


# ════════════════════════════════════════════════════
#  LOG WRITER
# ════════════════════════════════════════════════════
def write_log(message, level='INFO'):
    timestamp = datetime.now().strftime('%H:%M:%S')
    prefix = {
        'INFO':     '[INFO]',
        'WARN':     '[WARN]',
        'ERROR':    '[ERROR]',
        'SUCCESS':  '[OK]',
        'CRITICAL': '[CRITICAL]',
        'SCAN':     '[SCAN]',
        'AGENT':    '[AGENT]',
        'CONNECT':  '[CONN]',
        'SECURITY': '[SEC]',
        'GUARD':    '[GUARD]',
        'BLOCK':    '[BLOCK]',
        'ROTATE':   '[ROTATE]',
    }.get(level, '[INFO]')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', str(message))
    log_line = f"{timestamp} {prefix} {clean}\n"
    try:
        with _log_lock:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_line)
    except:
        pass


def clear_log_file():
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(
                f"# Scan started: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
    except:
        pass


# ════════════════════════════════════════════════════
#  MONITOR LAUNCHER
# ════════════════════════════════════════════════════
def start_monitor():
    """
    Launch monitor.py in new terminal.
    Tries platform_utils first, then manual fallback.
    Retries 3 times on failure.
    """
    global monitor_process
    monitor_path = os.path.join(BASE_DIR, 'monitor.py')

    if not os.path.exists(monitor_path):
        write_log('monitor.py not found', 'WARN')
        return

    # ── Try platform_utils ────────────────────────
    try:
        from platform_utils import launch_in_terminal
        for attempt in range(3):
            try:
                monitor_process = launch_in_terminal(
                    script_path=monitor_path,
                    title='SEC MONITOR',
                    args=[],
                    cwd=BASE_DIR,
                    log_writer=write_log
                )
                if monitor_process:
                    write_log(
                        f'Monitor launched via platform_utils'
                        f' (attempt {attempt+1})',
                        'SUCCESS'
                    )
                    time.sleep(1)
                    return
            except Exception as e:
                write_log(
                    f'Monitor attempt {attempt+1}: {e}',
                    'WARN'
                )
            time.sleep(1)
    except ImportError:
        write_log('platform_utils not found, using fallback', 'WARN')
    except Exception as e:
        write_log(f'platform_utils error: {e}', 'WARN')

    # ── Manual fallback ───────────────────────────
    py      = sys.executable
    cmd_str = f'{py} {monitor_path}'

    if sys.platform == 'win32':
        # Windows
        for attempt in range(3):
            try:
                monitor_process = subprocess.Popen(
                    [py, monitor_path],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=BASE_DIR
                )
                write_log('Monitor: Windows console', 'SUCCESS')
                time.sleep(1)
                return
            except Exception as e:
                write_log(f'Win console attempt {attempt+1}: {e}', 'WARN')
                time.sleep(1)
        try:
            os.system(f'start "SEC MONITOR" "{py}" "{monitor_path}"')
            write_log('Monitor: cmd start', 'SUCCESS')
            return
        except:
            pass

    elif sys.platform == 'darwin':
        # macOS
        try:
            subprocess.Popen([
                'osascript', '-e',
                f'tell app "Terminal" to do script'
                f' "cd {BASE_DIR} && {py} {monitor_path}"'
            ])
            write_log('Monitor: macOS Terminal', 'SUCCESS')
            return
        except Exception as e:
            write_log(f'macOS Terminal failed: {e}', 'WARN')

    else:
        # Linux - try all terminals
        terminals = [
            ('qterminal',
             ['qterminal', '-T', 'SEC MONITOR', '-e', py, monitor_path]),
            ('gnome-terminal',
             ['gnome-terminal', '--title', 'SEC MONITOR', '--', py, monitor_path]),
            ('konsole',
             ['konsole', '-p', 'tabtitle=SEC MONITOR', '-e', py, monitor_path]),
            ('xfce4-terminal',
             ['xfce4-terminal', '--title', 'SEC MONITOR', '-e', cmd_str]),
            ('xterm',
             ['xterm', '-T', 'SEC MONITOR', '-e', cmd_str]),
            ('lxterminal',
             ['lxterminal', '-t', 'SEC MONITOR', '-e', cmd_str]),
            ('kitty',
             ['kitty', '--title', 'SEC MONITOR', py, monitor_path]),
            ('alacritty',
             ['alacritty', '--title', 'SEC MONITOR', '-e', py, monitor_path]),
            ('mate-terminal',
             ['mate-terminal', '--title', 'SEC MONITOR', '-e', cmd_str]),
            ('tilix',
             ['tilix', '-t', 'SEC MONITOR', '-e', cmd_str]),
            ('terminator',
             ['terminator', '-T', 'SEC MONITOR', '-e', cmd_str]),
        ]

        launched = False
        for term_name, term_cmd in terminals:
            if not shutil.which(term_name):
                continue
            try:
                monitor_process = subprocess.Popen(
                    term_cmd, cwd=BASE_DIR,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                write_log(f'Monitor: {term_name}', 'SUCCESS')
                time.sleep(1)
                launched = True
                break
            except Exception as e:
                write_log(f'{term_name}: {e}', 'WARN')
                continue

        if not launched and shutil.which('tmux'):
            try:
                subprocess.Popen(
                    ['tmux', 'new-window', '-n', 'SEC-MONITOR', cmd_str],
                    cwd=BASE_DIR
                )
                write_log('Monitor: tmux', 'SUCCESS')
                launched = True
            except:
                pass

        if not launched:
            # Background fallback
            write_log(
                'No terminal found - monitor running in background',
                'WARN'
            )
            print(
                f"  {Fore.YELLOW}[!] No terminal found -"
                f" monitor in background mode"
                + Style.RESET_ALL
            )

            def _bg():
                try:
                    subprocess.run(
                        [py, monitor_path],
                        cwd=BASE_DIR,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                except:
                    pass

            t = threading.Thread(target=_bg, daemon=True)
            t.start()


def stop_monitor():
    global monitor_process
    if monitor_process:
        try:
            monitor_process.terminate()
        except:
            pass


# ════════════════════════════════════════════════════
#  PATH HELPERS
# ════════════════════════════════════════════════════
def _switch_to(cat_dir):
    for d in ALL_CAT_DIRS:
        while d in sys.path:
            sys.path.remove(d)
    sys.path.insert(0, cat_dir)
    for key in list(sys.modules.keys()):
        if key.startswith('core') or key.startswith('agents'):
            del sys.modules[key]


def _restore_all():
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
    print("  AI Engine: Groq (Llama 3.3 70B) - FREE")
    print("  Smart Connection + Anti-Track + Guard")
    print("  Tor: Auto-launch | Consent: DISABLED")
    print("═" * 62 + Style.RESET_ALL)


# ════════════════════════════════════════════════════
#  MENU
# ════════════════════════════════════════════════════
def print_menu():
    print(
        f"\n{Fore.YELLOW}"
        "┌──────────────────────────────────────────────────┐"
    )
    print("│            SELECT SCAN MODE                      │")
    print("├──────────────────────────────────────────────────┤")
    print("│                                                  │")
    print(f"│  {Fore.GREEN}[1]{Fore.YELLOW} Category 1  - Passive Only                   │")
    print("│       Recon | Headers | SSL | Email              │")
    print("│                                                  │")
    print(f"│  {Fore.RED}[2]{Fore.YELLOW} Category 2  - Active Scan                    │")
    print("│       SQLi | XSS | PathTraversal | CORS          │")
    print("│       GraphQL | JWT | API                        │")
    print("│                                                  │")
    print(f"│  {Fore.MAGENTA}[3]{Fore.YELLOW} Category 3  - Advanced Scan                  │")
    print("│       Auth | CmdInject | FileUpload | SSRF       │")
    print("│       XXE | NoSQL | SSTI | CSRF | WS             │")
    print("│       HostHeader | Cache | OAuth | AccessCtrl    │")
    print("│                                                  │")
    print(f"│  {Fore.CYAN}[4]{Fore.YELLOW} Cat 1 + 2   - Passive + Active               │")
    print(f"│  {Fore.CYAN}[5]{Fore.YELLOW} Cat 1 + 3   - Passive + Advanced             │")
    print(f"│  {Fore.CYAN}[6]{Fore.YELLOW} Cat 2 + 3   - Active + Advanced              │")
    print(f"│  {Fore.WHITE}[7]{Fore.YELLOW} Full Scan   - All 3 Categories               │")
    print("│                                                  │")
    print(f"│  {Fore.WHITE}[8]{Fore.YELLOW} Exit                                         │")
    print("│                                                  │")
    print("└──────────────────────────────────────────────────┘")
    print()
    print("┌──────────────────────────────────────────────────┐")
    print("│         CONNECTION MODE (Optional)               │")
    print("├──────────────────────────────────────────────────┤")
    print(f"│  {Fore.GREEN}[D]{Fore.YELLOW} Direct  - No proxy/VPN  (fastest)            │")
    print(f"│  {Fore.CYAN}[P]{Fore.YELLOW} Proxy   - Free proxy rotation                │")
    print(f"│  {Fore.MAGENTA}[T]{Fore.YELLOW} Tor     - Anonymous via Tor network          │")
    print(f"│  {Fore.WHITE}[A]{Fore.YELLOW} Auto    - Smart detect  (default)            │")
    print("└──────────────────────────────────────────────────┘"
          + Style.RESET_ALL)


# ════════════════════════════════════════════════════
#  CONNECTION CHOICE
# ════════════════════════════════════════════════════
def get_connection_choice():
    """Ask user connection mode. Enter = Auto."""
    print(
        f"\n{Fore.CYAN}Connection mode"
        f" [D/P/T/A] (Enter = Auto): "
        + Style.RESET_ALL,
        end='', flush=True
    )
    try:
        conn = input().strip().upper()
    except (KeyboardInterrupt, EOFError):
        conn = 'A'

    mapping = {
        'D': 'direct',
        'P': 'proxy',
        'T': 'tor',
        'A': 'auto',
        '':  'auto',
    }
    chosen = mapping.get(conn, 'auto')

    colors = {
        'direct': Fore.GREEN,
        'proxy':  Fore.CYAN,
        'tor':    Fore.MAGENTA,
        'auto':   Fore.WHITE,
    }
    labels = {
        'direct': 'DIRECT (no proxy)',
        'proxy':  'PROXY rotation',
        'tor':    'TOR network',
        'auto':   'AUTO detect',
    }
    print(
        f"  {colors[chosen]}[✓] Connection:"
        f" {labels[chosen]}"
        + Style.RESET_ALL
    )
    return chosen


def get_target():
    print(f"\n{Fore.YELLOW}Enter target domain or URL:")
    print(f"{Fore.WHITE}Examples: example.com  |  https://www.example.com")
    target = input(f"{Fore.CYAN}Target ➜ {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}[!] No target. Exiting." + Style.RESET_ALL)
        sys.exit(1)
    return target


def get_api_key():
    groq_key = os.getenv('GROQ_API_KEY', '').strip()
    if groq_key:
        masked = groq_key[:8] + '....' + groq_key[-4:]
        print(f"\n{Fore.GREEN}[✓] Groq API Key : {masked}")
        print(f"{Fore.GREEN}[✓] AI Engine    : Groq AI (Llama 3.3 70B) - FREE" + Style.RESET_ALL)
    else:
        print(f"\n{Fore.YELLOW}[!] No GROQ_API_KEY" + Style.RESET_ALL)
    return groq_key


def print_section(title, color=Fore.CYAN):
    print(f"\n{color}" + "═" * 62)
    print(f"  {title}")
    print("═" * 62 + Style.RESET_ALL)
    write_log(f"Section: {title}", 'SCAN')


def save_raw_json(results, out_dir, target, label):
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    tc = (
        target.replace('https://','').replace('http://','')
        .replace('/','_').replace('.','_')
    )
    json_path = os.path.join(out_dir, f"{tc}_{ts}_{label}_raw.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"{Fore.YELLOW}[!] Raw JSON: {json_path}" + Style.RESET_ALL)
    write_log(f"Raw JSON: {json_path}", 'INFO')
    return json_path


# ════════════════════════════════════════════════════
#  PRE-SCAN SETUP
# ════════════════════════════════════════════════════
def run_pre_scan_setup(
    target, groq_key,
    forced_connection='auto'
):
    global smart_conn, anti_track
    global risk_level, scan_session, connection_guard

    print_section("PRE-SCAN SETUP", Fore.CYAN)
    write_log(f"Pre-scan: {target}", 'SCAN')
    write_log(
        f"Connection mode: {forced_connection}",
        'CONNECT'
    )

    # ── STEP 1: Risk ─────────────────────────────
    print(f"\n{Fore.CYAN}[STEP 1/4] Risk Assessment" + Style.RESET_ALL)
    write_log('Running risk assessment...', 'SECURITY')
    try:
        from risk_checker import RiskChecker
        checker = RiskChecker(target)
        detected_risk, factors = checker.assess()
        risk_level = detected_risk
        write_log(
            f"Risk: {risk_level} ({len(factors)} factors)",
            'SECURITY'
        )
        print(f"  {Fore.GREEN}[✓] Risk: {risk_level}" + Style.RESET_ALL)
    except ImportError:
        risk_level = 'LOW'
        print(f"  {Fore.YELLOW}[!] risk_checker not found → LOW" + Style.RESET_ALL)
        write_log('risk_checker → LOW', 'WARN')
    except Exception as e:
        risk_level = 'LOW'
        write_log(f'Risk error: {e}', 'WARN')

    # ── STEP 2: Anti-Track ───────────────────────
    print(f"\n{Fore.CYAN}[STEP 2/4] Anti-Track" + Style.RESET_ALL)
    if risk_level in ['MEDIUM', 'HIGH']:
        write_log(f'Anti-track: risk={risk_level}', 'SECURITY')
        try:
            from anti_track import AntiTrackManager
            anti_track = AntiTrackManager()
            if risk_level == 'HIGH':
                anti_track.enable_all()
                anti_track.randomize_fingerprint()
                anti_track.obfuscate_timing()
                anti_track.minimize_logs()
            elif risk_level == 'MEDIUM':
                anti_track.enable_dns_protection()
                anti_track.sanitize_headers()
            print(f"  {Fore.GREEN}[✓] Anti-track ON" + Style.RESET_ALL)
        except ImportError:
            write_log('anti_track.py not found', 'WARN')
        except Exception as e:
            write_log(f'Anti-track error: {e}', 'WARN')
    else:
        print(f"  {Fore.GREEN}[✓] LOW - Anti-track OFF" + Style.RESET_ALL)
        write_log('Anti-track: OFF', 'INFO')

    # ── STEP 3: Smart Connection ─────────────────
    print(f"\n{Fore.CYAN}[STEP 3/4] Smart Connection" + Style.RESET_ALL)

    if forced_connection != 'auto':
        write_log(
            f'User forced: {forced_connection.upper()}',
            'CONNECT'
        )
        print(
            f"  {Fore.CYAN}[*] User selected:"
            f" {forced_connection.upper()}"
            + Style.RESET_ALL
        )

    write_log(
        f'Connection setup (risk={risk_level}'
        f' mode={forced_connection})',
        'CONNECT'
    )

    raw_session = None
    try:
        from smart_connection import SmartConnection
        smart_conn = SmartConnection(
            target, risk_level,
            log_writer=write_log
        )

        if forced_connection == 'direct':
            # ── Force Direct ──────────────────────
            raw_session = smart_conn._direct_session()
            smart_conn.selected_method = 'direct'
            smart_conn._session = raw_session
            write_log('Forced: DIRECT', 'CONNECT')
            print(
                f"  {Fore.GREEN}[✓] DIRECT"
                + Style.RESET_ALL
            )

        elif forced_connection == 'proxy':
            # ── Force Proxy ───────────────────────
            raw_session = smart_conn._proxy_session()
            if raw_session:
                smart_conn.selected_method = 'proxy'
                smart_conn._session = raw_session
                write_log('Forced: PROXY', 'CONNECT')
                print(
                    f"  {Fore.GREEN}[✓] PROXY"
                    + Style.RESET_ALL
                )
            else:
                write_log(
                    'Proxy failed → DIRECT fallback',
                    'WARN'
                )
                raw_session = smart_conn._direct_session()
                smart_conn.selected_method = 'direct'
                print(
                    f"  {Fore.YELLOW}[!] Proxy failed"
                    f" → DIRECT fallback"
                    + Style.RESET_ALL
                )

        elif forced_connection == 'tor':
            # ── Force Tor ─────────────────────────
            raw_session = smart_conn._tor_session()
            if raw_session:
                smart_conn.selected_method = 'tor'
                smart_conn._session = raw_session
                write_log('Forced: TOR', 'CONNECT')
                tor_ip = getattr(
                    smart_conn.tor_mgr,
                    'current_ip', '?'
                )
                print(
                    f"  {Fore.MAGENTA}[✓] TOR"
                    f" | IP: {tor_ip}"
                    + Style.RESET_ALL
                )
            else:
                write_log(
                    'Tor failed → DIRECT fallback',
                    'WARN'
                )
                raw_session = smart_conn._direct_session()
                smart_conn.selected_method = 'direct'
                print(
                    f"  {Fore.YELLOW}[!] Tor failed"
                    f" → DIRECT fallback"
                    + Style.RESET_ALL
                )

        else:
            # ── Auto mode ─────────────────────────
            raw_session = smart_conn.get_session()
            if raw_session is None:
                print(
                    f"  {Fore.RED}[!] Connection failed!"
                    + Style.RESET_ALL
                )
                sys.exit(1)
            method = smart_conn.selected_method
            write_log(
                f'AUTO Connection: {method.upper()}',
                'CONNECT'
            )
            print(
                f"  {Fore.GREEN}[✓] AUTO → "
                f"{method.upper()}"
                + Style.RESET_ALL
            )
            if method == 'tor':
                tor_ip = getattr(
                    smart_conn.tor_mgr,
                    'current_ip', '?'
                )
                write_log(f'Tor IP: {tor_ip}', 'CONNECT')
                print(
                    f"  {Fore.GREEN}[✓] Tor IP:"
                    f" {tor_ip}" + Style.RESET_ALL
                )

        if raw_session is None:
            raw_session = smart_conn._direct_session()
            smart_conn.selected_method = 'direct'

    except ImportError:
        import requests as _req
        raw_session = _req.Session()
        raw_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        write_log('smart_connection not found → direct', 'WARN')
    except Exception as e:
        import requests as _req
        raw_session = _req.Session()
        write_log(f'Connection error: {e}', 'WARN')

    # ── STEP 4: Guard ────────────────────────────
    print(f"\n{Fore.CYAN}[STEP 4/4] Connection Guard" + Style.RESET_ALL)
    write_log('Initializing guard...', 'GUARD')
    try:
        from connection_guard import ConnectionGuard
        connection_guard = ConnectionGuard(
            smart_connection=smart_conn,
            log_writer=write_log
        )
        connection_guard.risk_level = risk_level
        connection_guard.init_session(raw_session)
        if risk_level == 'HIGH':
            connection_guard.block_threshold = 2
            connection_guard.timeout_threshold = 3
        elif risk_level == 'MEDIUM':
            connection_guard.block_threshold = 3
            connection_guard.timeout_threshold = 4
        else:
            connection_guard.block_threshold = 5
            connection_guard.timeout_threshold = 7
        connection_guard.start()
        scan_session = connection_guard.get_session()
        print(f"  {Fore.GREEN}[✓] Guard ACTIVE" + Style.RESET_ALL)
        print(f"  {Fore.WHITE}  Block  : {connection_guard.block_threshold}" + Style.RESET_ALL)
        print(f"  {Fore.WHITE}  Timeout: {connection_guard.timeout_threshold}" + Style.RESET_ALL)
        write_log(
            f'Guard: block={connection_guard.block_threshold}'
            f' timeout={connection_guard.timeout_threshold}',
            'GUARD'
        )
    except ImportError:
        scan_session = raw_session
        write_log('connection_guard not found', 'WARN')
    except Exception as e:
        scan_session = raw_session
        write_log(f'Guard error: {e}', 'WARN')

    conn_method = getattr(
        smart_conn, 'selected_method', 'direct'
    ) if smart_conn else 'direct'
    guard_active = connection_guard is not None

    print(f"\n{Fore.CYAN}" + "─" * 45)
    print(f"  Risk Level  : {risk_level}")
    print(f"  Connection  : {conn_method.upper()}")
    print(f"  Mode        : {forced_connection.upper()}")
    print(f"  Guard       : {'ACTIVE' if guard_active else 'OFF'}")
    if conn_method == 'tor':
        tor_ip = getattr(
            smart_conn.tor_mgr, 'current_ip', '?'
        ) if smart_conn else '?'
        print(f"  Tor IP      : {tor_ip}")
        print(f"  Auto-Rotate : every 20s")
    print("─" * 45 + Style.RESET_ALL)

    write_log(
        f'Setup done: Risk={risk_level}'
        f' Conn={conn_method}'
        f' Mode={forced_connection}'
        f' Guard={guard_active}',
        'SUCCESS'
    )
    return risk_level, scan_session


# ════════════════════════════════════════════════════
#  PDF HELPER
# ════════════════════════════════════════════════════
def generate_pdf_from_content(content, pdf_path, groq_key):
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
            mod = importlib.import_module('core.report_generator')
            GenClass = getattr(mod, class_name, None)
            if GenClass is None:
                continue
            gen = GenClass(groq_key or 'no-key')
            gen.generate_pdf(content, pdf_path)
            print(f"{Fore.GREEN}[✓] PDF: {pdf_path}" + Style.RESET_ALL)
            write_log(f'PDF: {pdf_path}', 'SUCCESS')
            return True
        except:
            continue
        finally:
            os.chdir(old_dir)
            _restore_all()
    write_log('PDF generation failed', 'ERROR')
    return False


# ════════════════════════════════════════════════════
#  STATS
# ════════════════════════════════════════════════════
def build_combined_stats(cat1_report, cat2_results, cat3_results):
    cat1_stats = cat1_report.get('stats', {}) if cat1_report else {}

    def count_from(results):
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
        if not results:
            return counts
        for findings in results.values():
            if not isinstance(findings, list):
                continue
            for f in findings:
                r = f.get('risk','').upper()
                if r in counts:
                    counts[r] += 1
        return counts

    c2 = count_from(cat2_results)
    c3 = count_from(cat3_results)
    return {
        'critical': cat1_stats.get('critical',0)+c2['CRITICAL']+c3['CRITICAL'],
        'high':     cat1_stats.get('high',0)+c2['HIGH']+c3['HIGH'],
        'medium':   cat1_stats.get('medium',0)+c2['MEDIUM']+c3['MEDIUM'],
        'low':      cat1_stats.get('low',0)+c2['LOW']+c3['LOW'],
    }


# ════════════════════════════════════════════════════
#  COMBINED SUMMARY
# ════════════════════════════════════════════════════
def save_combined_summary(
    target,
    cat1_results, cat2_results, cat3_results,
    cat1_report, cat2_report, cat3_report,
    total_duration, groq_key, scan_label='FULL'
):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    tc = (
        target.replace('https://','').replace('http://','')
        .replace('/','_').replace('.','_')
    )
    out_dir = os.path.join(BASE_DIR, 'output')
    os.makedirs(out_dir, exist_ok=True)
    summary_path = os.path.join(out_dir, f"{tc}_{ts}_{scan_label}_SUMMARY.md")

    stats = build_combined_stats(cat1_report, cat2_results, cat3_results)
    total = sum(stats.values())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cats_run = []
    if cat1_results: cats_run.append('Category 1 (Passive)')
    if cat2_results: cats_run.append('Category 2 (Active)')
    if cat3_results: cats_run.append('Category 3 (Advanced)')
    cats_str = ' + '.join(cats_run) or 'N/A'

    conn_method = getattr(smart_conn, 'selected_method', 'direct') if smart_conn else 'direct'
    guard_stats = connection_guard.get_stats() if connection_guard else {}

    lines = ["# Security Assessment Summary\n"]
    lines += [
        "| Field | Details |", "| --- | --- |",
        f"| Target | {target} |", f"| Date | {now} |",
        f"| Duration | {total_duration}s |",
        f"| Scan Type | {cats_str} |",
        f"| Risk Level | {risk_level} |",
        f"| Connection | {conn_method.upper()} |",
    ]
    if conn_method == 'tor' and smart_conn:
        tor_ip = getattr(smart_conn.tor_mgr, 'current_ip', '?')
        lines.append(f"| Tor IP | {tor_ip} |")
    if guard_stats:
        lines += [
            f"| Requests | {guard_stats.get('total_requests',0)} |",
            f"| Blocked | {guard_stats.get('blocked',0)} |",
            f"| Rotations | {guard_stats.get('rotations',0)} |",
        ]
    lines += [
        "| Classification | CONFIDENTIAL |\n",
        "## Risk Summary\n",
        "| Severity | Count |", "| --- | --- |",
        f"| Critical | {stats['critical']} |",
        f"| High | {stats['high']} |",
        f"| Medium | {stats['medium']} |",
        f"| Low | {stats['low']} |",
        f"| **Total** | **{total}** |\n",
    ]
    if cat1_report and cat1_report.get('markdown'):
        lines.append("---\n\n# Category 1\n\n" + cat1_report['markdown'] + "\n")
    if cat2_report and cat2_report.get('markdown'):
        lines.append("---\n\n# Category 2\n\n" + cat2_report['markdown'] + "\n")
    if cat3_report and cat3_report.get('markdown'):
        lines.append("---\n\n# Category 3\n\n" + cat3_report['markdown'] + "\n")

    content = '\n'.join(lines)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n{Fore.GREEN}[✓] Summary: {summary_path}" + Style.RESET_ALL)
    write_log(f'Summary: {summary_path}', 'SUCCESS')
    pdf_path = summary_path.replace('.md', '.pdf')
    generate_pdf_from_content(content, pdf_path, groq_key)
    return summary_path


# ════════════════════════════════════════════════════
#  RUN CATEGORIES
# ════════════════════════════════════════════════════
def run_category1(target, groq_key):
    print_section("CATEGORY 1 - PASSIVE SECURITY SCAN", Fore.GREEN)
    write_log('Starting Category 1', 'AGENT')
    cat1_out = os.path.join(BASE_DIR, 'output', 'category1')
    os.makedirs(cat1_out, exist_ok=True)
    old_dir = os.getcwd()
    cat1_results = cat1_report = None
    try:
        _switch_to(CAT1_DIR)
        os.chdir(CAT1_DIR)
        from core.orchestrator import PassiveSecurityOrchestrator
        orchestrator = PassiveSecurityOrchestrator(target, groq_key)
        orchestrator._write_log = write_log
        if scan_session:
            orchestrator.shared_session = scan_session
            orchestrator.session = scan_session
            write_log('GuardedSession → Cat1', 'GUARD')
        start = time.time()
        write_log('Cat1: 4 agents parallel...', 'AGENT')
        cat1_results = orchestrator.run_assessment()
        duration = round(time.time() - start)
        write_log(f'Cat1 done in {duration}s', 'SUCCESS')
        print_section("CATEGORY 1 - GENERATING REPORT", Fore.GREEN)
        write_log('Cat1: Generating report...', 'AGENT')
        if groq_key:
            cat1_report = orchestrator.generate_report()
            write_log('Cat1: Report done', 'SUCCESS')
        else:
            save_raw_json(cat1_results, cat1_out, target, 'cat1')
        print(f"\n{Fore.GREEN}[✓] Category 1 Done! {duration}s" + Style.RESET_ALL)
    except Exception as e:
        print(f"{Fore.RED}[!] Cat1 Error: {e}" + Style.RESET_ALL)
        write_log(f'Cat1 error: {e}', 'ERROR')
        import traceback; traceback.print_exc()
    finally:
        os.chdir(old_dir)
        _restore_all()
    return cat1_results, cat1_report


def run_category2(target, groq_key):
    print_section("CATEGORY 2 - ACTIVE SECURITY SCAN", Fore.RED)
    write_log('Starting Category 2', 'AGENT')
    write_log('Cat2: SQLi|XSS|Path|CORS|GraphQL|JWT|API', 'AGENT')
    cat2_out = os.path.join(BASE_DIR, 'output', 'category2')
    os.makedirs(cat2_out, exist_ok=True)
    old_dir = os.getcwd()
    cat2_results = cat2_report = None
    try:
        _switch_to(CAT2_DIR)
        os.chdir(CAT2_DIR)
        from core.orchestrator import ActiveScanOrchestrator
        orchestrator = ActiveScanOrchestrator(target, groq_key)
        orchestrator._write_log = write_log
        if scan_session:
            orchestrator.shared_session = scan_session
            orchestrator.session = scan_session
            write_log('GuardedSession → Cat2', 'GUARD')
        write_log('Cat2: 7 agents parallel...', 'AGENT')
        start = time.time()
        cat2_results = orchestrator.run_assessment(skip_consent=True)
        duration = round(time.time() - start)
        if cat2_results is None:
            write_log('Cat2 returned None', 'WARN')
            return None, None
        for agent in ['sql_injection','xss','path_traversal','cors','graphql','jwt','api']:
            findings = cat2_results.get(agent, [])
            count = len(findings) if isinstance(findings, list) else 0
            write_log(f'Cat2 [{agent}]: {count} findings', 'WARN' if count>0 else 'SUCCESS')
        write_log(f'Cat2 done in {duration}s', 'SUCCESS')
        print_section("CATEGORY 2 - GENERATING REPORT", Fore.RED)
        write_log('Cat2: Generating report...', 'AGENT')
        if groq_key:
            cat2_report = orchestrator.generate_report()
            write_log('Cat2: Report done', 'SUCCESS')
        else:
            save_raw_json(cat2_results, cat2_out, target, 'cat2')
        print(f"\n{Fore.GREEN}[✓] Category 2 Done! {duration}s" + Style.RESET_ALL)
    except Exception as e:
        print(f"{Fore.RED}[!] Cat2 Error: {e}" + Style.RESET_ALL)
        write_log(f'Cat2 error: {e}', 'ERROR')
        import traceback; traceback.print_exc()
    finally:
        os.chdir(old_dir)
        _restore_all()
    return cat2_results, cat2_report


def run_category3(target, groq_key, skip_consent=True):
    print_section("CATEGORY 3 - ADVANCED SECURITY SCAN", Fore.MAGENTA)
    write_log('Starting Category 3', 'AGENT')
    write_log('Cat3: Auth|Cmd|Upload|SSRF|XXE|NoSQL|SSTI|CSRF|WS|Host|Cache|OAuth|Proto|Access', 'AGENT')
    cat3_out = os.path.join(BASE_DIR, 'output', 'category3')
    os.makedirs(cat3_out, exist_ok=True)
    old_dir = os.getcwd()
    cat3_results = cat3_report = None
    try:
        _switch_to(CAT3_DIR)
        os.chdir(CAT3_DIR)
        from core.orchestrator import AdvancedScanOrchestrator
        orchestrator = AdvancedScanOrchestrator(target, groq_key)
        orchestrator._write_log = write_log
        if scan_session:
            orchestrator.shared_session = scan_session
            orchestrator.session = scan_session
            write_log('GuardedSession → Cat3', 'GUARD')
        write_log('Cat3: 14 agents (2seq+12parallel)...', 'AGENT')
        start = time.time()
        cat3_results = orchestrator.run_assessment(skip_consent=True)
        duration = round(time.time() - start)
        if cat3_results is None:
            write_log('Cat3 returned None', 'WARN')
            return None, None
        for agent in ['authentication','command_injection','file_upload','ssrf','xxe','nosql_injection','ssti','csrf','websocket','http_host_header','web_cache','oauth','prototype_pollution','access_control']:
            findings = cat3_results.get(agent, [])
            count = len(findings) if isinstance(findings, list) else 0
            write_log(f'Cat3 [{agent}]: {count} findings', 'WARN' if count>0 else 'SUCCESS')
        write_log(f'Cat3 done in {duration}s', 'SUCCESS')
        print_section("CATEGORY 3 - GENERATING REPORT", Fore.MAGENTA)
        write_log('Cat3: Generating report...', 'AGENT')
        if groq_key:
            cat3_report = orchestrator.generate_report()
            write_log('Cat3: Report done', 'SUCCESS')
        else:
            save_raw_json(cat3_results, cat3_out, target, 'cat3')
        print(f"\n{Fore.GREEN}[✓] Category 3 Done! {duration}s" + Style.RESET_ALL)
    except Exception as e:
        print(f"{Fore.RED}[!] Cat3 Error: {e}" + Style.RESET_ALL)
        write_log(f'Cat3 error: {e}', 'ERROR')
        import traceback; traceback.print_exc()
    finally:
        os.chdir(old_dir)
        _restore_all()
    return cat3_results, cat3_report


def _print_agent_summary(results, agent_list):
    for key, label in agent_list:
        findings = results.get(key, [])
        count = len(findings) if isinstance(findings, list) else 0
        color = Fore.RED if count > 0 else Fore.GREEN
        icon = '⚠' if count > 0 else '✓'
        print(f"  {color}{icon}{Fore.WHITE} {label}: {color}{count} findings" + Style.RESET_ALL)
        if count > 0:
            write_log(f'{label}: {count} findings', 'WARN')


def print_final_summary(
    target,
    cat1_results, cat2_results, cat3_results,
    cat1_report, cat2_report, cat3_report,
    total_duration
):
    print(f"\n{Fore.CYAN}" + "═" * 62)
    print("  ASSESSMENT COMPLETE")
    print("═" * 62 + Style.RESET_ALL)
    print(f"\n{Fore.WHITE}Target   : {Fore.CYAN}{target}" + Style.RESET_ALL)
    print(f"{Fore.WHITE}Duration : {Fore.CYAN}{total_duration}s" + Style.RESET_ALL)
    risk_color = {'HIGH':Fore.RED,'MEDIUM':Fore.YELLOW,'LOW':Fore.GREEN}.get(risk_level, Fore.WHITE)
    print(f"{Fore.WHITE}Risk     : {risk_color}{risk_level}" + Style.RESET_ALL)
    conn_method = getattr(smart_conn, 'selected_method', 'direct') if smart_conn else 'direct'
    print(f"{Fore.WHITE}Via      : {Fore.CYAN}{conn_method.upper()}" + Style.RESET_ALL)
    if conn_method == 'tor' and smart_conn:
        tor_ip = getattr(smart_conn.tor_mgr, 'current_ip', '?')
        print(f"{Fore.WHITE}Tor IP   : {Fore.GREEN}{tor_ip}" + Style.RESET_ALL)
    if connection_guard:
        gs = connection_guard.get_stats()
        print(f"{Fore.WHITE}Guard    : {Fore.GREEN}Reqs={gs['total_requests']} Blocked={gs['blocked']} Rotated={gs['rotations']}" + Style.RESET_ALL)
    if cat1_results:
        print(f"\n{Fore.GREEN}Category 1:" + Style.RESET_ALL)
        for key, label in [
            ('reconnaissance','Reconnaissance'),
            ('security_headers','Security Headers'),
            ('ssl_tls','SSL/TLS'),
            ('email_security','Email Security'),
        ]:
            data = cat1_results.get(key, {})
            ok = data and 'error' not in data
            status = f"{Fore.GREEN}✓ Done" if ok else f"{Fore.RED}✗ Error"
            print(f"  {status}{Fore.WHITE} {label}" + Style.RESET_ALL)
    if cat2_results:
        print(f"\n{Fore.RED}Category 2:" + Style.RESET_ALL)
        _print_agent_summary(cat2_results, [
            ('sql_injection','SQL Injection'),
            ('xss','XSS'),
            ('path_traversal','Path Traversal'),
            ('cors','CORS'),
            ('graphql','GraphQL'),
            ('jwt','JWT'),
            ('api','API Security'),
        ])
    if cat3_results:
        print(f"\n{Fore.MAGENTA}Category 3:" + Style.RESET_ALL)
        _print_agent_summary(cat3_results, [
            ('authentication','Authentication'),
            ('command_injection','Command Injection'),
            ('file_upload','File Upload'),
            ('ssrf','SSRF'),
            ('xxe','XXE Injection'),
            ('nosql_injection','NoSQL Injection'),
            ('ssti','SSTI'),
            ('csrf','CSRF'),
            ('websocket','WebSocket'),
            ('http_host_header','HTTP Host Header'),
            ('web_cache','Web Cache'),
            ('oauth','OAuth'),
            ('prototype_pollution','Prototype Pollution'),
            ('access_control','Access Control'),
        ])
    stats = build_combined_stats(cat1_report, cat2_results, cat3_results)
    total = sum(stats.values())
    print(f"\n{Fore.CYAN}" + "─" * 40 + Style.RESET_ALL)
    print(f"  {Fore.WHITE}Total    : {Fore.CYAN}{total}" + Style.RESET_ALL)
    print(f"  {Fore.WHITE}Critical : {Fore.RED}{stats['critical']}" + Style.RESET_ALL)
    print(f"  {Fore.WHITE}High     : {Fore.YELLOW}{stats['high']}" + Style.RESET_ALL)
    print(f"  {Fore.WHITE}Medium   : {Fore.YELLOW}{stats['medium']}" + Style.RESET_ALL)
    print(f"  {Fore.WHITE}Low      : {Fore.GREEN}{stats['low']}" + Style.RESET_ALL)
    print(f"\n{Fore.GREEN}Output: output/" + Style.RESET_ALL)
    print(f"{Fore.CYAN}" + "═" * 62 + Style.RESET_ALL)
    write_log(
        f'SCAN COMPLETE: Total={total}'
        f' C={stats["critical"]} H={stats["high"]}',
        'SUCCESS'
    )


def cleanup():
    global connection_guard, monitor_process
    if smart_conn:
        if hasattr(smart_conn, 'tor_mgr') and smart_conn.tor_mgr:
            write_log(
                f'Tor final IP: {smart_conn.tor_mgr.current_ip}',
                'CONNECT'
            )
            smart_conn.tor_mgr.stop()
    if connection_guard:
        gs = connection_guard.get_stats()
        write_log(
            f'Guard: Reqs={gs["total_requests"]}'
            f' OK={gs["successful"]}'
            f' Blocked={gs["blocked"]}'
            f' Timeouts={gs["timeouts"]}'
            f' Rotations={gs["rotations"]}',
            'GUARD'
        )
        print(f"\n{Fore.CYAN}Guard Stats:" + Style.RESET_ALL)
        print(f"  Requests  : {gs['total_requests']}")
        print(f"  Successful: {gs['successful']}")
        print(f"  Blocked   : {gs['blocked']}")
        print(f"  Timeouts  : {gs['timeouts']}")
        print(f"  Rotations : {gs['rotations']}")
        connection_guard.stop()
    stop_monitor()
    write_log('Cleanup complete', 'SUCCESS')


# ════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════
def main():
    print_main_banner()
    groq_key = get_api_key()
    print_menu()

    # ── Scan mode choice ─────────────────────────
    choice = input(
        f"\n{Fore.CYAN}Select option [1-8]: "
        + Style.RESET_ALL
    ).strip()

    if choice == '8':
        print(f"{Fore.YELLOW}Goodbye!" + Style.RESET_ALL)
        sys.exit(0)

    if choice not in ['1','2','3','4','5','6','7']:
        print(f"{Fore.RED}[!] Invalid option." + Style.RESET_ALL)
        sys.exit(1)

    # ── Connection mode choice ───────────────────
    conn_choice = get_connection_choice()

    # ── Target ───────────────────────────────────
    target = get_target()

    # ── Launch monitor (with delay) ──────────────
    clear_log_file()
    print(
        f"\n{Fore.CYAN}[*] Launching monitor..."
        + Style.RESET_ALL
    )
    start_monitor()
    time.sleep(2)   # Give terminal time to open

    write_log(
        f'Target: {target} | Mode: {choice}'
        f' | Conn: {conn_choice}',
        'SCAN'
    )

    # ── Pre-scan setup ───────────────────────────
    run_pre_scan_setup(target, groq_key, conn_choice)

    app_start = time.time()
    cat1_results = cat1_report = None
    cat2_results = cat2_report = None
    cat3_results = cat3_report = None

    try:
        if choice == '1':
            cat1_results, cat1_report = run_category1(target, groq_key)

        elif choice == '2':
            cat2_results, cat2_report = run_category2(target, groq_key)

        elif choice == '3':
            cat3_results, cat3_report = run_category3(target, groq_key)

        elif choice == '4':
            write_log('Mode: Cat1+Cat2', 'SCAN')
            cat1_results, cat1_report = run_category1(target, groq_key)
            cat2_results, cat2_report = run_category2(target, groq_key)
            if cat1_results or cat2_results:
                save_combined_summary(
                    target,
                    cat1_results, cat2_results, None,
                    cat1_report, cat2_report, None,
                    round(time.time()-app_start),
                    groq_key, 'CAT1_CAT2'
                )

        elif choice == '5':
            write_log('Mode: Cat1+Cat3', 'SCAN')
            cat1_results, cat1_report = run_category1(target, groq_key)
            cat3_results, cat3_report = run_category3(target, groq_key)
            if cat1_results or cat3_results:
                save_combined_summary(
                    target,
                    cat1_results, None, cat3_results,
                    cat1_report, None, cat3_report,
                    round(time.time()-app_start),
                    groq_key, 'CAT1_CAT3'
                )

        elif choice == '6':
            write_log('Mode: Cat2+Cat3', 'SCAN')
            cat2_results, cat2_report = run_category2(target, groq_key)
            cat3_results, cat3_report = run_category3(target, groq_key)
            if cat2_results or cat3_results:
                save_combined_summary(
                    target,
                    None, cat2_results, cat3_results,
                    None, cat2_report, cat3_report,
                    round(time.time()-app_start),
                    groq_key, 'CAT2_CAT3'
                )

        elif choice == '7':
            write_log('Mode: FULL SCAN', 'SCAN')
            print(f"\n{Fore.GREEN}[*] Phase 1: Cat1" + Style.RESET_ALL)
            write_log('Phase 1: Cat1', 'SCAN')
            cat1_results, cat1_report = run_category1(target, groq_key)
            print(f"\n{Fore.YELLOW}[*] Phase 2: Cat2" + Style.RESET_ALL)
            write_log('Phase 2: Cat2', 'SCAN')
            cat2_results, cat2_report = run_category2(target, groq_key)
            print(f"\n{Fore.MAGENTA}[*] Phase 3: Cat3" + Style.RESET_ALL)
            write_log('Phase 3: Cat3', 'SCAN')
            cat3_results, cat3_report = run_category3(target, groq_key)
            if cat1_results or cat2_results or cat3_results:
                save_combined_summary(
                    target,
                    cat1_results, cat2_results, cat3_results,
                    cat1_report, cat2_report, cat3_report,
                    round(time.time()-app_start),
                    groq_key, 'FULL'
                )

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted." + Style.RESET_ALL)
        write_log('Interrupted by user', 'WARN')

    total_duration = round(time.time() - app_start)
    print_final_summary(
        target,
        cat1_results, cat2_results, cat3_results,
        cat1_report, cat2_report, cat3_report,
        total_duration
    )
    cleanup()


if __name__ == "__main__":
    main()
