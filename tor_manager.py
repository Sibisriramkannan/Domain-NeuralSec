"""
Tor Manager - Auto Start + Live IP Rotation Display
Opens in separate terminal with bold TOR banner
Auto-scrolling live IP rotation log
"""

import os
import sys
import time
import socket
import shutil
import platform
import subprocess
import threading
import requests
import random
from platform_utils import clear_screen, IS_WINDOWS
from datetime import datetime
from collections import deque

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=WHITE=''
    class Style:
        RESET_ALL=BRIGHT=''

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOR_DIR = os.path.join(BASE_DIR, 'tor_portable')
TOR_LOG = os.path.join(BASE_DIR, 'tor_rotation.log')

TOR_SOCKS_PORTS = [9150, 9050]
TOR_CONTROL_PORTS = [9151, 9051]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def is_port_open(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(('127.0.0.1', port))
        s.close()
        return r == 0
    except:
        return False


def find_socks_port():
    for p in TOR_SOCKS_PORTS:
        if is_port_open(p):
            return p
    return None


def find_control_port():
    for p in TOR_CONTROL_PORTS:
        if is_port_open(p):
            return p
    return None


def find_tor_executable():
    os_name = platform.system()
    paths = []

    if os_name == 'Windows':
        paths.append(os.path.join(TOR_DIR, 'tor', 'tor.exe'))
        paths.append(os.path.join(TOR_DIR, 'Tor', 'tor.exe'))
        username = os.getenv('USERNAME', '')
        paths.extend([
            rf'C:\Users\{username}\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
            r'C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
            r'C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
        ])
    elif os_name == 'Darwin':
        paths.extend([
            '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor',
            '/usr/local/bin/tor',
            '/opt/homebrew/bin/tor',
        ])
    else:
        paths.extend(['/usr/bin/tor', '/usr/local/bin/tor'])

    paths.append(os.path.join(TOR_DIR, 'tor', 'tor'))
    tor_which = shutil.which('tor')
    if tor_which:
        paths.insert(0, tor_which)

    for p in paths:
        if os.path.exists(p):
            return p
    return None


def generate_torrc():
    os.makedirs(TOR_DIR, exist_ok=True)
    data_dir = os.path.join(TOR_DIR, 'data')
    os.makedirs(data_dir, exist_ok=True)
    torrc_path = os.path.join(TOR_DIR, 'torrc')
    # Use forward slashes even on Windows for Tor
    dd = data_dir.replace('\\', '/')
    config = (
        f"SocksPort 9050\n"
        f"ControlPort 9051\n"
        f"DataDirectory {dd}\n"
        f"CookieAuthentication 0\n"
        f"MaxCircuitDirtiness 20\n"
        f"NewCircuitPeriod 15\n"
        f"CircuitBuildTimeout 10\n"
    )
    with open(torrc_path, 'w') as f:
        f.write(config)
    return torrc_path


def get_tor_session(port):
    s = requests.Session()
    proxy = f"socks5h://127.0.0.1:{port}"
    s.proxies = {'http': proxy, 'https': proxy}
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    return s


def get_ip(session):
    for url in ['https://api.ipify.org', 'https://icanhazip.com', 'https://ifconfig.me/ip']:
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                return r.text.strip()
        except:
            continue
    return 'Unknown'


def get_ip_info(session, ip):
    try:
        r = session.get(f'http://ip-api.com/json/{ip}?fields=countryCode,country,org,isp', timeout=5)
        if r.status_code == 200:
            d = r.json()
            return d.get('countryCode', '??'), d.get('country', '??'), d.get('org', '??')[:25]
    except:
        pass
    return '??', '??', '??'


def rotate_circuit(control_port):
    # Method 1: stem
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=control_port) as c:
            c.authenticate()
            c.signal(Signal.NEWNYM)
            return True
    except:
        pass
    # Method 2: raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('127.0.0.1', control_port))
        s.send(b'AUTHENTICATE\r\n')
        r = s.recv(256)
        if b'250' in r:
            s.send(b'SIGNAL NEWNYM\r\n')
            r = s.recv(256)
            s.close()
            return b'250' in r
        s.close()
    except:
        pass
    return False


def write_tor_log(msg):
    """Write to shared log file for app.py to read."""
    try:
        ts = datetime.now().strftime('%H:%M:%S')
        with open(TOR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"{ts} {msg}\n")
    except:
        pass


def print_banner():
    clear_screen()
    print()
    print(f"{Fore.GREEN}{'═'*60}")
    print(f"{Fore.GREEN}║{' '*58}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}  ████████╗ ██████╗ ██████╗                              {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}  ╚══██╔══╝██╔═══██╗██╔══██╗                             {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}     ██║   ██║   ██║██████╔╝                              {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}     ██║   ██║   ██║██╔══██╗                              {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}     ██║   ╚██████╔╝██║  ██║                              {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.CYAN}     ╚═╝    ╚═════╝ ╚═╝  ╚═╝                             {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{' '*58}║")
    print(f"{Fore.GREEN}║{Fore.WHITE}   TOR NETWORK - AUTO IP ROTATOR                         {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{Fore.WHITE}   Security Scanner Integration Module                   {Fore.GREEN}║")
    print(f"{Fore.GREEN}║{' '*58}║")
    print(f"{Fore.GREEN}{'═'*60}{Style.RESET_ALL}")
    print()


def print_status_header():
    print(f"  {Fore.CYAN}{'─'*56}{Style.RESET_ALL}")
    print(
        f"  {Fore.WHITE}{'#':<4} "
        f"{'Time':<10} "
        f"{'IP Address':<18} "
        f"{'Country':<8} "
        f"{'Org':<16} "
        f"{'Status'}"
        + Style.RESET_ALL
    )
    print(f"  {Fore.CYAN}{'─'*56}{Style.RESET_ALL}")


class TorRotatorDisplay:
    """
    Live display for Tor IP rotations.
    Auto-scrolling like tail -f.
    """

    def __init__(self):
        self.tor_process = None
        self.socks_port = None
        self.control_port = None
        self.session = None
        self.running = False
        self.rotation_count = 0
        self.used_ips = set()
        self.current_ip = None
        self.real_ip = None
        self.interval = 20
        self.history = deque(maxlen=100)
        self.start_time = None

    def start_tor(self):
        """Full Tor startup sequence."""
        print(f"  {Fore.CYAN}[1/4] Checking Tor status...{Style.RESET_ALL}")
        write_tor_log("[TOR] Checking Tor status...")

        # Check if already running
        port = find_socks_port()
        if port:
            self.socks_port = port
            self.control_port = find_control_port()
            print(f"  {Fore.GREEN}[✓] Tor already running on port {port}{Style.RESET_ALL}")
            write_tor_log(f"[TOR] Already running on port {port}")
            return True

        print(f"  {Fore.YELLOW}[!] Tor not running{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[2/4] Finding Tor binary...{Style.RESET_ALL}")
        write_tor_log("[TOR] Searching for Tor binary...")

        tor_exe = find_tor_executable()
        if not tor_exe:
            print(f"  {Fore.RED}[!] Tor binary not found!{Style.RESET_ALL}")
            print()
            print(f"  {Fore.YELLOW}Install Tor:{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  Windows : choco install tor{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  Linux   : sudo apt install tor{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  Mac     : brew install tor{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  Or open Tor Browser manually{Style.RESET_ALL}")
            write_tor_log("[TOR] ERROR: Tor binary not found")
            return False

        print(f"  {Fore.GREEN}[✓] Found: {tor_exe}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[3/4] Generating config...{Style.RESET_ALL}")

        torrc = generate_torrc()
        print(f"  {Fore.GREEN}[✓] Config: {torrc}{Style.RESET_ALL}")

        print(f"  {Fore.CYAN}[4/4] Starting Tor process...{Style.RESET_ALL}")
        write_tor_log("[TOR] Starting Tor process...")

        try:
            self.tor_process = subprocess.Popen(
                [tor_exe, '-f', torrc],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=TOR_DIR
            )

            for i in range(60):
                time.sleep(1)
                if is_port_open(9050):
                    self.socks_port = 9050
                    self.control_port = find_control_port()
                    print(f"  {Fore.GREEN}[✓] Tor started! SOCKS:9050{Style.RESET_ALL}")
                    write_tor_log("[TOR] Tor started successfully on port 9050")
                    return True

                if (i + 1) % 5 == 0:
                    dots = '.' * ((i // 5) % 4 + 1)
                    print(f"  {Fore.YELLOW}[*] Connecting{dots} ({i+1}/60s){Style.RESET_ALL}")

                if self.tor_process.poll() is not None:
                    err = self.tor_process.stderr.read().decode()[:200]
                    print(f"  {Fore.RED}[!] Tor died: {err}{Style.RESET_ALL}")
                    write_tor_log(f"[TOR] ERROR: Tor process died: {err}")
                    return False

            print(f"  {Fore.RED}[!] Timeout (60s){Style.RESET_ALL}")
            write_tor_log("[TOR] ERROR: Startup timeout")
            return False

        except Exception as e:
            print(f"  {Fore.RED}[!] Start failed: {e}{Style.RESET_ALL}")
            write_tor_log(f"[TOR] ERROR: {e}")
            return False

    def init_session(self):
        """Create Tor session and get initial IP."""
        self.session = get_tor_session(self.socks_port)

        # Real IP
        print(f"\n  {Fore.CYAN}[*] Detecting IPs...{Style.RESET_ALL}")
        try:
            r = requests.get('https://api.ipify.org', timeout=5)
            self.real_ip = r.text.strip()
        except:
            self.real_ip = 'Unknown'

        self.current_ip = get_ip(self.session)
        self.used_ips.add(self.current_ip)

        print(f"  {Fore.RED}  Real IP : {self.real_ip}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}  Tor IP  : {self.current_ip}{Style.RESET_ALL}")

        if self.real_ip == self.current_ip and self.real_ip != 'Unknown':
            print(f"  {Fore.RED}  ⚠ WARNING: Same IP! Tor may not be working{Style.RESET_ALL}")
            write_tor_log("[TOR] WARNING: Tor IP = Real IP!")
        else:
            print(f"  {Fore.GREEN}  ✓ IP is different - Tor working!{Style.RESET_ALL}")
            write_tor_log(f"[TOR] Tor working. IP: {self.current_ip}")

    def run_live_display(self):
        """Main live display loop - auto scrolling."""
        self.running = True
        self.start_time = datetime.now()

        print()
        print(f"  {Fore.GREEN}[✓] Auto-rotation: Every {self.interval}s{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
        print()

        # Status line
        print(f"  {Fore.GREEN}┌──────────────────────────────────────────────────┐{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}│  {Fore.WHITE}TOR ACTIVE{Fore.GREEN} │ {Fore.WHITE}Auto-Rotate: {self.interval}s{Fore.GREEN} │ {Fore.WHITE}Ctrl+C: Stop{Fore.GREEN} │{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}└──────────────────────────────────────────────────┘{Style.RESET_ALL}")
        print()

        print_status_header()

        # Initial entry
        country, cname, org = get_ip_info(self.session, self.current_ip)
        self._print_row(1, self.current_ip, country, org, 'INITIAL')
        write_tor_log(f"[TOR] #{1} IP:{self.current_ip} [{country}] {org} (INITIAL)")

        try:
            while self.running:
                # Wait for interval
                for sec in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                # Rotate
                self.rotation_count += 1
                old_ip = self.current_ip

                # Try circuit rotation
                rotated = False
                if self.control_port:
                    rotated = rotate_circuit(self.control_port)

                if not rotated:
                    self.session.close()
                    time.sleep(2)
                    self.session = get_tor_session(self.socks_port)

                time.sleep(3)

                # Get new IP
                new_ip = get_ip(self.session)
                self.current_ip = new_ip
                self.used_ips.add(new_ip)

                is_new = new_ip != old_ip
                country, cname, org = get_ip_info(self.session, new_ip)

                status = 'NEW' if is_new else 'SAME'
                self._print_row(
                    self.rotation_count + 1,
                    new_ip, country, org, status
                )

                write_tor_log(
                    f"[TOR] #{self.rotation_count+1} "
                    f"IP:{new_ip} [{country}] {org} "
                    f"({status})"
                )

                # Save to history
                self.history.append({
                    'num': self.rotation_count + 1,
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'ip': new_ip,
                    'country': country,
                    'org': org,
                    'status': status,
                })

        except KeyboardInterrupt:
            self.running = False

        self._print_final_stats()

    def _print_row(self, num, ip, country, org, status):
        """Print single rotation row."""
        now = datetime.now().strftime('%H:%M:%S')

        if status == 'NEW' or status == 'INITIAL':
            ip_color = Fore.GREEN
            status_display = f"{Fore.GREEN}✓ {status}"
        elif status == 'SAME':
            ip_color = Fore.YELLOW
            status_display = f"{Fore.YELLOW}~ {status}"
        else:
            ip_color = Fore.RED
            status_display = f"{Fore.RED}✗ {status}"

        print(
            f"  {Fore.WHITE}{num:<4} "
            f"{now:<10} "
            f"{ip_color}{ip:<18} "
            f"{Fore.CYAN}{country:<8} "
            f"{Fore.WHITE}{org:<16} "
            f"{status_display}"
            + Style.RESET_ALL
        )

    def _print_final_stats(self):
        """Print stats on exit."""
        duration = 0
        if self.start_time:
            duration = (datetime.now() - self.start_time).seconds

        print()
        print(f"  {Fore.GREEN}{'═'*56}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║{' '*54}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}TOR SESSION SUMMARY{Fore.GREEN}{' '*35}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║{' '*54}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}Duration       : {Fore.CYAN}{duration}s{Fore.GREEN}{' '*(35-len(str(duration)))}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}Total Rotations: {Fore.CYAN}{self.rotation_count}{Fore.GREEN}{' '*(35-len(str(self.rotation_count)))}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}Unique IPs     : {Fore.CYAN}{len(self.used_ips)}{Fore.GREEN}{' '*(35-len(str(len(self.used_ips))))}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}Real IP        : {Fore.RED}{self.real_ip}{Fore.GREEN}{' '*(35-len(str(self.real_ip)))}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║{' '*54}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}║  {Fore.WHITE}All IPs Used:{Fore.GREEN}{' '*41}║{Style.RESET_ALL}")

        for ip in sorted(self.used_ips):
            if ip != 'Unknown':
                pad = 54 - len(ip) - 6
                print(f"  {Fore.GREEN}║    {Fore.CYAN}→ {ip}{' '*max(0,pad)}{Fore.GREEN}║{Style.RESET_ALL}")

        print(f"  {Fore.GREEN}║{' '*54}║{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}{'═'*56}{Style.RESET_ALL}")

        write_tor_log(
            f"[TOR] SESSION END: Duration={duration}s "
            f"Rotations={self.rotation_count} "
            f"UniqueIPs={len(self.used_ips)}"
        )

    def stop(self):
        """Full cleanup."""
        self.running = False
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except:
                try:
                    self.tor_process.kill()
                except:
                    pass
        write_tor_log("[TOR] Tor manager stopped")


def run_tor_display(interval=20):
    """
    Main entry point.
    Called when tor_manager.py runs in separate terminal.
    """
    print_banner()

    display = TorRotatorDisplay()
    display.interval = interval

    # Start Tor
    if not display.start_tor():
        print(f"\n  {Fore.RED}[!] Cannot start Tor.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[*] Open Tor Browser manually and retry.{Style.RESET_ALL}")
        write_tor_log("[TOR] FAILED: Cannot start Tor")
        input(f"\n  Press Enter to exit...")
        return

    # Init session
    display.init_session()

    # Run live display
    display.run_live_display()

    # Cleanup
    display.stop()


# ════════════════════════════════════════════════════
#  LAUNCHER CLASS (used by app.py)
# ════════════════════════════════════════════════════
class TorLauncher:
    """
    Launches tor_manager.py in separate terminal.
    Provides session to scanner.
    """

    def __init__(self, log_writer=None):
        self.log = log_writer
        self.tor_process = None
        self.display_process = None
        self.socks_port = None
        self.control_port = None
        self.session = None
        self.current_ip = None

    def _w(self, msg, lvl='INFO'):
        if self.log:
            try:
                self.log(msg, lvl)
            except:
                pass

    def launch(self, interval=20):
        """
        1. Start Tor if not running
        2. Open separate terminal with live display
        3. Return session for scanner
        """
        self._w('TorLauncher: Starting...', 'CONNECT')

        # ── Check if Tor already running ─────────────
        port = find_socks_port()
        if port:
            self.socks_port = port
            self.control_port = find_control_port()
            self._w(f'Tor already running on {port}', 'SUCCESS')
        else:
            # ── Start Tor ourselves ──────────────────
            self._w('Tor not running. Starting...', 'CONNECT')
            tor_exe = find_tor_executable()
            if not tor_exe:
                self._w('Tor binary not found!', 'ERROR')
                return None

            torrc = generate_torrc()
            try:
                self.tor_process = subprocess.Popen(
                    [tor_exe, '-f', torrc],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=TOR_DIR
                )
                # Wait for port
                for i in range(60):
                    time.sleep(1)
                    if is_port_open(9050):
                        self.socks_port = 9050
                        self.control_port = find_control_port()
                        self._w('Tor started on 9050', 'SUCCESS')
                        break
                    if self.tor_process.poll() is not None:
                        self._w('Tor process died', 'ERROR')
                        return None
                else:
                    self._w('Tor startup timeout', 'ERROR')
                    return None
            except Exception as e:
                self._w(f'Tor start failed: {e}', 'ERROR')
                return None

        # ── Open display terminal ────────────────────
        self._w('Opening Tor display terminal...', 'CONNECT')
        tor_display_script = os.path.join(BASE_DIR, 'tor_manager.py')
        python_exe = sys.executable

        try:
            if sys.platform == 'win32':
                # Windows - new CMD window
                try:
                    self.display_process = subprocess.Popen(
                        [python_exe, tor_display_script, f'--interval={interval}', '--display-only'],
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                        cwd=BASE_DIR
                    )
                    self._w('Tor display opened in new CMD', 'SUCCESS')
                except:
                    os.system(f'start "TOR ROTATOR" "{python_exe}" "{tor_display_script}" --interval={interval} --display-only')
                    self._w('Tor display opened via start', 'SUCCESS')

            elif sys.platform == 'darwin':
                subprocess.Popen([
                    'osascript', '-e',
                    f'tell app "Terminal" to do script "cd {BASE_DIR} && {python_exe} {tor_display_script} --interval={interval} --display-only"'
                ])
                self._w('Tor display opened in macOS Terminal', 'SUCCESS')

            else:
                for term in ['gnome-terminal', 'xterm', 'konsole', 'xfce4-terminal']:
                    try:
                        if term == 'gnome-terminal':
                            self.display_process = subprocess.Popen([
                                term, '--', python_exe, tor_display_script, f'--interval={interval}', '--display-only'
                            ], cwd=BASE_DIR)
                        else:
                            self.display_process = subprocess.Popen([
                                term, '-e', f'{python_exe} {tor_display_script} --interval={interval} --display-only'
                            ], cwd=BASE_DIR)
                        self._w(f'Tor display opened in {term}', 'SUCCESS')
                        break
                    except FileNotFoundError:
                        continue

        except Exception as e:
            self._w(f'Display terminal failed: {e}', 'WARN')

        # ── Create session ───────────────────────────
        self.session = get_tor_session(self.socks_port)
        self.current_ip = get_ip(self.session)
        self._w(f'Tor session ready. IP: {self.current_ip}', 'SUCCESS')

        # ── Start background rotation ────────────────
        self._start_bg_rotation(interval)

        return self.session

    def _start_bg_rotation(self, interval):
        """Background rotation for scanner session."""
        def _rotate():
            while True:
                time.sleep(interval)
                try:
                    cp = self.control_port
                    if cp:
                        rotate_circuit(cp)
                    else:
                        self.session.close()
                        time.sleep(2)
                        self.session = get_tor_session(self.socks_port)
                    time.sleep(3)
                    self.current_ip = get_ip(self.session)
                    self._w(f'Tor rotated → {self.current_ip}', 'ROTATE')
                except:
                    pass

        t = threading.Thread(target=_rotate, daemon=True)
        t.start()
        self._w(f'Background rotation started ({interval}s)', 'ROTATE')

    def get_session(self):
        return self.session

    def stop(self):
        if self.tor_process:
            try:
                self.tor_process.terminate()
            except:
                pass
        if self.display_process:
            try:
                self.display_process.terminate()
            except:
                pass
        self._w('TorLauncher stopped', 'CONNECT')


# ════════════════════════════════════════════════════
#  MAIN - Standalone or Display Mode
# ════════════════════════════════════════════════════
if __name__ == "__main__":
    interval = 20

    # Parse args
    for arg in sys.argv[1:]:
        if arg.startswith('--interval='):
            try:
                interval = int(arg.split('=')[1])
                interval = max(10, interval)
            except:
                pass

    # Display-only mode (launched by app.py)
    if '--display-only' in sys.argv:
        # Tor already started by app.py
        # Just show the live rotation display
        print_banner()

        port = find_socks_port()
        if not port:
            print(f"  {Fore.RED}[!] Tor not running. Waiting...{Style.RESET_ALL}")
            for i in range(30):
                time.sleep(1)
                port = find_socks_port()
                if port:
                    break
            if not port:
                print(f"  {Fore.RED}[!] Tor never started.{Style.RESET_ALL}")
                input("Press Enter...")
                sys.exit(1)

        display = TorRotatorDisplay()
        display.socks_port = port
        display.control_port = find_control_port()
        display.interval = interval
        display.session = get_tor_session(port)
        display.init_session()
        display.run_live_display()
        display.stop()

    else:
        # Standalone mode
        run_tor_display(interval)
