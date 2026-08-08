"""
Connection Manager
Auto-handles VPN, Tor, Proxy rotation
Bypasses firewalls and IP blocks automatically
"""

import os
import sys
import time
import random
import socket
import subprocess
import requests
import platform
from colorama import Fore, Style, init

init(autoreset=True)


# ════════════════════════════════════════════════════
#  BROWSER USER AGENTS
# ════════════════════════════════════════════════════
BROWSER_USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/119.0.0.0 Safari/537.36 "
        "Edg/119.0.0.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X "
        "10_15_7) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; "
        "rv:121.0) Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
]


# ════════════════════════════════════════════════════
#  OPTION 1: TOR AUTO CONNECT
# ════════════════════════════════════════════════════
class TorManager:
    """
    Auto-connect to Tor network
    Rotate Tor circuits automatically
    """

    def __init__(self):
        self.tor_port = 9050
        self.control_port = 9051
        self.tor_process = None
        self.connected = False

    def is_tor_running(self):
        """Check if Tor is already running"""
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            result = sock.connect_ex(
                ('127.0.0.1', self.tor_port)
            )
            sock.close()
            return result == 0
        except Exception:
            return False

    def start_tor(self):
        """Auto-start Tor if not running"""
        if self.is_tor_running():
            print(
                f"  {Fore.GREEN}[✓] Tor already "
                f"running on port {self.tor_port}"
                + Style.RESET_ALL
            )
            self.connected = True
            return True

        print(
            f"  {Fore.CYAN}[*] Starting Tor..."
            + Style.RESET_ALL
        )

        # Try to find Tor executable
        tor_paths = self._find_tor_executable()

        for tor_path in tor_paths:
            try:
                self.tor_process = subprocess.Popen(
                    [tor_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                # Wait for Tor to start
                for i in range(30):
                    time.sleep(1)
                    if self.is_tor_running():
                        print(
                            f"  {Fore.GREEN}[✓] Tor "
                            f"started successfully!"
                            + Style.RESET_ALL
                        )
                        self.connected = True
                        return True
                    print(
                        f"  {Fore.CYAN}[*] Waiting "
                        f"for Tor... {i+1}/30"
                        + Style.RESET_ALL,
                        end='\r'
                    )

            except FileNotFoundError:
                continue
            except Exception as e:
                print(
                    f"  {Fore.YELLOW}[!] Tor start "
                    f"error: {e}"
                    + Style.RESET_ALL
                )

        print(
            f"  {Fore.RED}[!] Could not start Tor"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.YELLOW}[!] Please open "
            f"Tor Browser manually"
            + Style.RESET_ALL
        )
        return False

    def _find_tor_executable(self):
        """Find Tor executable on system"""
        os_name = platform.system()
        paths = []

        if os_name == 'Windows':
            paths = [
                r'C:\Users\{}\Desktop\Tor Browser'
                r'\Browser\TorBrowser\Tor\tor.exe'
                .format(os.getenv('USERNAME', '')),
                r'C:\Program Files\Tor Browser'
                r'\Browser\TorBrowser\Tor\tor.exe',
                r'C:\Tor\tor.exe',
                'tor.exe',
                'tor',
            ]
        elif os_name == 'Darwin':  # macOS
            paths = [
                '/Applications/Tor Browser.app'
                '/Contents/MacOS/Tor/tor',
                '/usr/local/bin/tor',
                '/opt/homebrew/bin/tor',
                'tor',
            ]
        else:  # Linux
            paths = [
                '/usr/bin/tor',
                '/usr/local/bin/tor',
                'tor',
            ]

        return paths

    def get_session(self):
        """Get requests session through Tor"""
        session = requests.Session()
        session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        }
        ua = random.choice(BROWSER_USER_AGENTS)
        session.headers.update({'User-Agent': ua})
        return session

    def get_current_ip(self):
        """Get current IP through Tor"""
        try:
            session = self.get_session()
            resp = session.get(
                'https://api.ipify.org',
                timeout=15
            )
            return resp.text.strip()
        except Exception:
            return 'Unknown'

    def rotate_circuit(self):
        """
        Get new Tor circuit (new IP)
        Uses stem library if available
        """
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(
                port=self.control_port
            ) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                time.sleep(3)
                print(
                    f"  {Fore.GREEN}[✓] Tor circuit "
                    f"rotated - new IP assigned"
                    + Style.RESET_ALL
                )
                return True

        except ImportError:
            # stem not installed
            # Just wait for automatic rotation
            print(
                f"  {Fore.CYAN}[*] Waiting for "
                f"Tor rotation (10s)..."
                + Style.RESET_ALL
            )
            time.sleep(10)
            return True

        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] Circuit "
                f"rotation failed: {e}"
                + Style.RESET_ALL
            )
            return False

    def stop_tor(self):
        """Stop Tor if we started it"""
        if self.tor_process:
            self.tor_process.terminate()
            print(
                f"  {Fore.CYAN}[*] Tor stopped"
                + Style.RESET_ALL
            )


# ════════════════════════════════════════════════════
#  OPTION 2: PROTONVPN AUTO CONNECT
# ════════════════════════════════════════════════════
class ProtonVPNManager:
    """
    Auto-connect ProtonVPN
    Requires ProtonVPN CLI installed
    """

    def __init__(self):
        self.connected = False
        self.server = None

    def is_installed(self):
        """Check if ProtonVPN CLI is installed"""
        try:
            result = subprocess.run(
                ['protonvpn-cli', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def is_connected(self):
        """Check if ProtonVPN is connected"""
        try:
            result = subprocess.run(
                ['protonvpn-cli', 'status'],
                capture_output=True,
                text=True
            )
            return 'Connected' in result.stdout
        except Exception:
            return False

    def connect(self, server='fastest'):
        """
        Auto-connect to ProtonVPN
        server: 'fastest', 'random', 'US', 'NL', etc
        """
        if not self.is_installed():
            print(
                f"  {Fore.YELLOW}[!] ProtonVPN CLI "
                f"not installed"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.CYAN}[→] Install: "
                f"pip install protonvpn-cli"
                + Style.RESET_ALL
            )
            return False

        if self.is_connected():
            print(
                f"  {Fore.GREEN}[✓] ProtonVPN "
                f"already connected"
                + Style.RESET_ALL
            )
            self.connected = True
            return True

        print(
            f"  {Fore.CYAN}[*] Connecting "
            f"ProtonVPN ({server})..."
            + Style.RESET_ALL
        )

        try:
            if server == 'fastest':
                cmd = [
                    'protonvpn-cli', 'connect',
                    '--fastest'
                ]
            elif server == 'random':
                cmd = [
                    'protonvpn-cli', 'connect',
                    '--random'
                ]
            else:
                cmd = [
                    'protonvpn-cli', 'connect',
                    '--cc', server
                ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                print(
                    f"  {Fore.GREEN}[✓] ProtonVPN "
                    f"connected!"
                    + Style.RESET_ALL
                )
                self.connected = True
                return True
            else:
                print(
                    f"  {Fore.RED}[!] ProtonVPN "
                    f"connection failed: "
                    f"{result.stderr[:100]}"
                    + Style.RESET_ALL
                )
                return False

        except subprocess.TimeoutExpired:
            print(
                f"  {Fore.RED}[!] ProtonVPN "
                f"connection timeout"
                + Style.RESET_ALL
            )
            return False
        except Exception as e:
            print(
                f"  {Fore.RED}[!] ProtonVPN "
                f"error: {e}"
                + Style.RESET_ALL
            )
            return False

    def switch_server(self):
        """Switch to different VPN server"""
        print(
            f"  {Fore.CYAN}[*] Switching VPN "
            f"server..."
            + Style.RESET_ALL
        )
        self.disconnect()
        time.sleep(2)
        return self.connect('random')

    def disconnect(self):
        """Disconnect ProtonVPN"""
        try:
            subprocess.run(
                ['protonvpn-cli', 'disconnect'],
                capture_output=True
            )
            self.connected = False
            print(
                f"  {Fore.CYAN}[*] ProtonVPN "
                f"disconnected"
                + Style.RESET_ALL
            )
        except Exception:
            pass


# ════════════════════════════════════════════════════
#  OPTION 3: FREE PROXY ROTATION
# ════════════════════════════════════════════════════
class FreeProxyManager:
    """
    Auto-fetch and rotate free proxies
    Multiple sources for reliability
    """

    def __init__(self):
        self.proxies = []
        self.working = []
        self.current = 0
        self.failed = set()

    def fetch_all(self):
        """Fetch proxies from all sources"""
        print(
            f"  {Fore.CYAN}[*] Fetching free "
            f"proxies from all sources..."
            + Style.RESET_ALL
        )
        all_proxies = []

        sources = [
            self._fetch_proxyscrape,
            self._fetch_geonode,
            self._fetch_github_list,
            self._fetch_free_proxy_list,
        ]

        for source in sources:
            try:
                proxies = source()
                all_proxies.extend(proxies)
            except Exception:
                continue

        self.proxies = list(set(all_proxies))
        print(
            f"  {Fore.GREEN}[✓] Fetched "
            f"{len(self.proxies)} proxies total"
            + Style.RESET_ALL
        )
        return self.proxies

    def _fetch_proxyscrape(self):
        """ProxyScrape API - free"""
        resp = requests.get(
            'https://api.proxyscrape.com/v2/'
            '?request=getproxies'
            '&protocol=https'
            '&timeout=5000'
            '&country=all'
            '&ssl=all'
            '&anonymity=elite',
            timeout=10
        )
        proxies = []
        for line in resp.text.strip().split('\n'):
            line = line.strip()
            if ':' in line:
                proxies.append(f"http://{line}")
        print(
            f"  {Fore.GREEN}[✓] ProxyScrape: "
            f"{len(proxies)} proxies"
            + Style.RESET_ALL
        )
        return proxies

    def _fetch_geonode(self):
        """GeoNode free proxy API"""
        resp = requests.get(
            'https://proxylist.geonode.com/api/'
            'proxy-list?limit=100&page=1'
            '&sort_by=lastChecked&sort_type=desc'
            '&protocols=https&anonymityLevel=elite',
            timeout=10
        )
        data = resp.json()
        proxies = []
        for p in data.get('data', []):
            ip = p.get('ip', '')
            port = p.get('port', '')
            if ip and port:
                proxies.append(
                    f"http://{ip}:{port}"
                )
        print(
            f"  {Fore.GREEN}[✓] GeoNode: "
            f"{len(proxies)} proxies"
            + Style.RESET_ALL
        )
        return proxies

    def _fetch_github_list(self):
        """GitHub proxy lists"""
        urls = [
            'https://raw.githubusercontent.com/'
            'TheSpeedX/PROXY-List/master/https.txt',
            'https://raw.githubusercontent.com/'
            'clarketm/proxy-list/master/proxy-list-raw.txt',
            'https://raw.githubusercontent.com/'
            'ShiftyTR/Proxy-List/master/https.txt',
        ]
        proxies = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=8)
                for line in resp.text.strip().split('\n'):
                    line = line.strip()
                    if ':' in line:
                        proxies.append(
                            f"http://{line}"
                        )
            except Exception:
                continue
        print(
            f"  {Fore.GREEN}[✓] GitHub lists: "
            f"{len(proxies)} proxies"
            + Style.RESET_ALL
        )
        return proxies

    def _fetch_free_proxy_list(self):
        """free-proxy-list.net scraper"""
        try:
            from bs4 import BeautifulSoup
            resp = requests.get(
                'https://free-proxy-list.net/',
                timeout=10
            )
            soup = BeautifulSoup(
                resp.text, 'html.parser'
            )
            proxies = []
            table = soup.find('table')
            if table:
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 7:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        https = cols[6].text.strip()
                        if https == 'yes':
                            proxies.append(
                                f"http://{ip}:{port}"
                            )
            print(
                f"  {Fore.GREEN}[✓] free-proxy-list:"
                f" {len(proxies)} proxies"
                + Style.RESET_ALL
            )
            return proxies
        except Exception:
            return []

    def test_proxy(self, proxy, timeout=5):
        """Test if proxy works"""
        try:
            resp = requests.get(
                'https://httpbin.org/ip',
                proxies={
                    'http': proxy,
                    'https': proxy
                },
                timeout=timeout
            )
            if resp.status_code == 200:
                ip = resp.json().get('origin', '')
                return True, ip
        except Exception:
            pass
        return False, None

    def find_working(self, need=10, max_test=50):
        """Test proxies and collect working ones"""
        print(
            f"  {Fore.CYAN}[*] Testing proxies "
            f"(need {need} working)..."
            + Style.RESET_ALL
        )
        random.shuffle(self.proxies)
        tested = 0

        for proxy in self.proxies:
            if len(self.working) >= need:
                break
            if tested >= max_test:
                break

            tested += 1
            working, ip = self.test_proxy(proxy)

            if working:
                self.working.append(proxy)
                num = len(self.working)
                print(
                    f"  {Fore.GREEN}[✓] #{num} "
                    f"Working: {proxy[:35]} "
                    f"→ {ip}"
                    + Style.RESET_ALL
                )

        print(
            f"  {Fore.GREEN}[✓] "
            f"{len(self.working)} working proxies"
            + Style.RESET_ALL
        )
        return self.working

    def get_next(self):
        """Get next proxy in rotation"""
        if not self.working:
            return None
        proxy = self.working[
            self.current % len(self.working)
        ]
        self.current += 1
        return proxy

    def mark_failed(self, proxy):
        """Remove failed proxy"""
        if proxy in self.working:
            self.working.remove(proxy)
            self.failed.add(proxy)

    def setup(self, need=5):
        """Full setup"""
        self.fetch_all()
        self.find_working(need=need)
        return len(self.working) > 0


# ════════════════════════════════════════════════════
#  OPTION 4: I2P NETWORK (Alternative to Tor)
# ════════════════════════════════════════════════════
class I2PManager:
    """
    I2P Network - alternative anonymous network
    More decentralized than Tor
    """

    def __init__(self):
        self.http_proxy = 'http://127.0.0.1:4444'
        self.https_proxy = 'http://127.0.0.1:4445'
        self.connected = False

    def is_running(self):
        """Check if I2P is running"""
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            result = sock.connect_ex(
                ('127.0.0.1', 4444)
            )
            sock.close()
            return result == 0
        except Exception:
            return False

    def get_session(self):
        """Get session through I2P"""
        session = requests.Session()
        session.proxies = {
            'http': self.http_proxy,
            'https': self.https_proxy
        }
        ua = random.choice(BROWSER_USER_AGENTS)
        session.headers.update({'User-Agent': ua})
        return session

    def setup_info(self):
        """Print I2P setup instructions"""
        print(
            f"\n{Fore.CYAN}I2P Setup Instructions:"
            + Style.RESET_ALL
        )
        print("1. Download I2P from geti2p.net")
        print("2. Install and run I2P router")
        print("3. Wait 5-10 min for network integration")
        print("4. I2P HTTP proxy: 127.0.0.1:4444")
        print("5. I2P HTTPS proxy: 127.0.0.1:4445")


# ════════════════════════════════════════════════════
#  OPTION 5: CLOUDFLARE WARP (FREE VPN)
# ════════════════════════════════════════════════════
class CloudflareWarpManager:
    """
    Cloudflare WARP - Free VPN by Cloudflare
    Very fast and reliable
    """

    def __init__(self):
        self.connected = False

    def is_installed(self):
        """Check if WARP is installed"""
        os_name = platform.system()
        if os_name == 'Windows':
            cmd = ['warp-cli', '--version']
        else:
            cmd = ['warp-cli', '--version']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def connect(self):
        """Connect to Cloudflare WARP"""
        if not self.is_installed():
            print(
                f"  {Fore.YELLOW}[!] Cloudflare WARP "
                f"not installed"
                + Style.RESET_ALL
            )
            self._print_install_instructions()
            return False

        try:
            # Register if needed
            subprocess.run(
                ['warp-cli', 'register'],
                capture_output=True,
                timeout=30
            )

            # Connect
            result = subprocess.run(
                ['warp-cli', 'connect'],
                capture_output=True,
                text=True,
                timeout=30
            )

            time.sleep(3)

            # Check status
            status = subprocess.run(
                ['warp-cli', 'status'],
                capture_output=True,
                text=True
            )

            if 'Connected' in status.stdout:
                print(
                    f"  {Fore.GREEN}[✓] Cloudflare "
                    f"WARP connected!"
                    + Style.RESET_ALL
                )
                self.connected = True
                return True
            else:
                print(
                    f"  {Fore.RED}[!] WARP connection"
                    f" failed"
                    + Style.RESET_ALL
                )
                return False

        except Exception as e:
            print(
                f"  {Fore.RED}[!] WARP error: {e}"
                + Style.RESET_ALL
            )
            return False

    def disconnect(self):
        """Disconnect WARP"""
        try:
            subprocess.run(
                ['warp-cli', 'disconnect'],
                capture_output=True
            )
            self.connected = False
        except Exception:
            pass

    def _print_install_instructions(self):
        print(
            f"\n{Fore.CYAN}Install Cloudflare WARP:"
            + Style.RESET_ALL
        )
        os_name = platform.system()
        if os_name == 'Windows':
            print(
                "Download: "
                "1.1.1.1/en-US/download/windows"
            )
        elif os_name == 'Darwin':
            print(
                "Download: "
                "1.1.1.1/en-US/download/mac"
            )
        else:
            print(
                "sudo apt install cloudflare-warp"
            )


# ════════════════════════════════════════════════════
#  MASTER CONNECTION MANAGER
# ════════════════════════════════════════════════════
class ConnectionManager:
    """
    Master manager - automatically selects
    and switches between all bypass methods
    """

    def __init__(self):
        self.tor = TorManager()
        self.protonvpn = ProtonVPNManager()
        self.proxy = FreeProxyManager()
        self.warp = CloudflareWarpManager()
        self.i2p = I2PManager()

        self.active_method = None
        self.session = None
        self.current_ip = None
        self.block_count = 0

        # Priority order for auto-selection
        self.priority = [
            'tor',
            'protonvpn',
            'warp',
            'proxy',
            'direct'
        ]

    def get_real_ip(self):
        """Get current public IP"""
        try:
            resp = requests.get(
                'https://api.ipify.org',
                timeout=5
            )
            return resp.text.strip()
        except Exception:
            return 'Unknown'

    def auto_setup(self, preferred=None):
        """
        Automatically connect using best
        available method
        """
        print(
            f"\n{Fore.CYAN}[*] Auto-detecting "
            f"best connection method..."
            + Style.RESET_ALL
        )

        real_ip = self.get_real_ip()
        print(
            f"  {Fore.WHITE}[→] Current IP: "
            f"{real_ip}"
            + Style.RESET_ALL
        )

        # Use preferred method first
        if preferred:
            success = self._try_method(preferred)
            if success:
                return True

        # Auto-try all methods in priority order
        for method in self.priority:
            print(
                f"\n  {Fore.CYAN}[*] Trying: "
                f"{method.upper()}..."
                + Style.RESET_ALL
            )
            success = self._try_method(method)
            if success:
                new_ip = self.get_masked_ip()
                print(
                    f"  {Fore.GREEN}[✓] Connected via "
                    f"{method.upper()} | "
                    f"IP: {new_ip}"
                    + Style.RESET_ALL
                )
                self.active_method = method
                return True

        print(
            f"  {Fore.YELLOW}[!] Using direct "
            f"connection (no bypass available)"
            + Style.RESET_ALL
        )
        self.active_method = 'direct'
        self.session = self._build_direct_session()
        return False

    def _try_method(self, method):
        """Try a specific connection method"""
        try:
            if method == 'tor':
                return self._setup_tor()
            elif method == 'protonvpn':
                return self._setup_protonvpn()
            elif method == 'warp':
                return self._setup_warp()
            elif method == 'proxy':
                return self._setup_proxy()
            elif method == 'direct':
                self.session = (
                    self._build_direct_session()
                )
                return True
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] {method} "
                f"failed: {e}"
                + Style.RESET_ALL
            )
            return False
        return False

    def _setup_tor(self):
        """Setup Tor connection"""
        if self.tor.start_tor():
            self.session = self.tor.get_session()
            self.active_method = 'tor'
            return True
        return False

    def _setup_protonvpn(self):
        """Setup ProtonVPN connection"""
        if self.protonvpn.connect('fastest'):
            self.session = self._build_direct_session()
            self.active_method = 'protonvpn'
            return True
        return False

    def _setup_warp(self):
        """Setup Cloudflare WARP"""
        if self.warp.connect():
            self.session = self._build_direct_session()
            self.active_method = 'warp'
            return True
        return False

    def _setup_proxy(self):
        """Setup free proxy rotation"""
        self.proxy.fetch_all()
        self.proxy.find_working(need=5)
        if self.proxy.working:
            proxy = self.proxy.get_next()
            self.session = self._build_proxy_session(
                proxy
            )
            self.active_method = 'proxy'
            return True
        return False

    def _build_direct_session(self):
        """Build direct browser-like session"""
        session = requests.Session()
        ua = random.choice(BROWSER_USER_AGENTS)
        session.headers.update({'User-Agent': ua})
        return session

    def _build_proxy_session(self, proxy):
        """Build session with proxy"""
        session = requests.Session()
        session.proxies = {
            'http': proxy,
            'https': proxy
        }
        ua = random.choice(BROWSER_USER_AGENTS)
        session.headers.update({'User-Agent': ua})
        return session

    def get_masked_ip(self):
        """Get IP through current connection"""
        try:
            if self.session:
                resp = self.session.get(
                    'https://api.ipify.org',
                    timeout=10
                )
                return resp.text.strip()
        except Exception:
            pass
        return 'Unknown'

    def handle_block(self):
        """
        Auto-handle IP block
        Rotates to next available method
        """
        self.block_count += 1
        print(
            f"\n  {Fore.RED}[!] IP BLOCKED! "
            f"(Block #{self.block_count})"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.CYAN}[*] Auto-switching "
            f"connection method..."
            + Style.RESET_ALL
        )

        old_method = self.active_method

        # Handle based on current method
        if self.active_method == 'tor':
            print(
                f"  {Fore.CYAN}[*] Rotating "
                f"Tor circuit..."
                + Style.RESET_ALL
            )
            self.tor.rotate_circuit()
            self.session = self.tor.get_session()

        elif self.active_method == 'protonvpn':
            print(
                f"  {Fore.CYAN}[*] Switching "
                f"ProtonVPN server..."
                + Style.RESET_ALL
            )
            self.protonvpn.switch_server()

        elif self.active_method == 'proxy':
            print(
                f"  {Fore.CYAN}[*] Rotating "
                f"to next proxy..."
                + Style.RESET_ALL
            )
            next_proxy = self.proxy.get_next()
            if next_proxy:
                self.session = (
                    self._build_proxy_session(
                        next_proxy
                    )
                )
            else:
                # No proxies left, try Tor
                print(
                    f"  {Fore.YELLOW}[!] No proxies "
                    f"left, trying Tor..."
                    + Style.RESET_ALL
                )
                self._setup_tor()

        elif self.active_method == 'warp':
            # WARP blocked, try Tor
            print(
                f"  {Fore.CYAN}[*] WARP blocked, "
                f"switching to Tor..."
                + Style.RESET_ALL
            )
            if not self._setup_tor():
                self._setup_proxy()

        elif self.active_method == 'direct':
            # Direct blocked, try everything
            print(
                f"  {Fore.CYAN}[*] Direct blocked, "
                f"trying all methods..."
                + Style.RESET_ALL
            )
            self.auto_setup()

        # Show new IP
        time.sleep(2)
        new_ip = self.get_masked_ip()
        print(
            f"  {Fore.GREEN}[✓] New IP: {new_ip} "
            f"via {self.active_method.upper()}"
            + Style.RESET_ALL
        )

    def get_session(self):
        """Get current session"""
        if not self.session:
            self.session = self._build_direct_session()
        return self.session

    def cleanup(self):
        """Cleanup all connections"""
        if self.active_method == 'tor':
            self.tor.stop_tor()
        elif self.active_method == 'protonvpn':
            self.protonvpn.disconnect()
        elif self.active_method == 'warp':
            self.warp.disconnect()


# ════════════════════════════════════════════════════
#  INTERACTIVE SETUP MENU
# ════════════════════════════════════════════════════
def show_connection_menu():
    """Show connection method selection menu"""
    print(
        f"\n{Fore.YELLOW}"
        "┌──────────────────────────────────────────┐"
    )
    print(
        "│        CONNECTION METHOD                 │"
    )
    print(
        "├──────────────────────────────────────────┤"
    )
    print(
        f"│  {Fore.GREEN}[1]{Fore.YELLOW}"
        " Auto-Select (Recommended)            │"
    )
    print(
        "│       Tries all methods automatically    │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.CYAN}[2]{Fore.YELLOW}"
        " Tor Network (Free + Anonymous)       │"
    )
    print(
        "│       Routes through Tor automatically   │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.CYAN}[3]{Fore.YELLOW}"
        " ProtonVPN (Free + Fast)              │"
    )
    print(
        "│       Auto-connects ProtonVPN CLI        │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.CYAN}[4]{Fore.YELLOW}"
        " Cloudflare WARP (Free + Very Fast)   │"
    )
    print(
        "│       1.1.1.1 WARP VPN by Cloudflare    │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.CYAN}[5]{Fore.YELLOW}"
        " Free Proxy Rotation                  │"
    )
    print(
        "│       Auto-fetches and rotates proxies   │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.CYAN}[6]{Fore.YELLOW}"
        " I2P Network (Anonymous + P2P)        │"
    )
    print(
        "│       Alternative to Tor network         │"
    )
    print(
        "│                                          │"
    )
    print(
        f"│  {Fore.WHITE}[7]{Fore.YELLOW}"
        " Direct (No bypass)                   │"
    )
    print(
        "│       Standard connection no VPN         │"
    )
    print(
        "└──────────────────────────────────────────┘"
        + Style.RESET_ALL
    )

    choice = input(
        f"{Fore.CYAN}Select [1-7]: "
        + Style.RESET_ALL
    ).strip()

    method_map = {
        '1': None,          # auto
        '2': 'tor',
        '3': 'protonvpn',
        '4': 'warp',
        '5': 'proxy',
        '6': 'i2p',
        '7': 'direct',
    }

    return method_map.get(choice, None)
