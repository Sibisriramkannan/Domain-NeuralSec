"""
Smart Connection Manager - Cross Platform
QTerminal + Windows + Linux + macOS
Direct → Proxy → Tor (auto-detect + launch)
"""

import os
import sys
import time
import random
import socket
import threading
import requests
from colorama import Fore, Style

try:
    from proxy_manager import FreeProxyManager
    HAS_PROXY_MGR = True
except:
    HAS_PROXY_MGR = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

TOR_SOCKS_PORTS = [9150, 9050]
TOR_CONTROL_PORTS = [9151, 9051]


def is_port_open(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(('127.0.0.1', port))
        s.close()
        return r == 0
    except:
        return False


def random_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'DNT': '1',
    }


def find_tor_socks_port():
    for p in TOR_SOCKS_PORTS:
        if is_port_open(p):
            return p
    return None


def find_tor_control_port():
    for p in TOR_CONTROL_PORTS:
        if is_port_open(p):
            return p
    return None


class TorManager:
    def __init__(self, log_writer=None):
        self.log = log_writer
        self.active_port = None
        self.control_port = None
        self.tor_process = None
        self.display_process = None
        self.session = None
        self.current_ip = None
        self._rotating = False
        self._rotate_thread = None

    def _w(self, msg, lvl='INFO'):
        if self.log:
            try:
                self.log(msg, lvl)
            except:
                pass

    def _find_tor_binary(self):
        import shutil
        import platform as plat

        paths = []
        os_name = plat.system()
        tor_dir = os.path.join(BASE_DIR, 'tor_portable')

        if os_name == 'Windows':
            paths += [
                os.path.join(tor_dir, 'tor', 'tor.exe'),
                os.path.join(tor_dir, 'Tor', 'tor.exe'),
            ]
            user = os.getenv('USERNAME', '')
            paths += [
                rf'C:\Users\{user}\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                r'C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
            ]
        elif os_name == 'Darwin':
            paths += [
                '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor',
                '/usr/local/bin/tor',
                '/opt/homebrew/bin/tor',
            ]
        else:
            paths += [
                '/usr/bin/tor',
                '/usr/local/bin/tor',
                os.path.join(tor_dir, 'tor', 'tor'),
            ]

        w = shutil.which('tor')
        if w:
            paths.insert(0, w)

        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def _generate_torrc(self):
        tor_dir = os.path.join(BASE_DIR, 'tor_portable')
        os.makedirs(tor_dir, exist_ok=True)
        data_dir = os.path.join(tor_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        torrc = os.path.join(tor_dir, 'torrc')
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
        with open(torrc, 'w') as f:
            f.write(config)
        return torrc

    def check_running(self):
        port = find_tor_socks_port()
        if port:
            self.active_port = port
            self.control_port = find_tor_control_port()
            return True
        return False

    def start_tor(self):
        import subprocess as sp

        self._w('Checking Tor status...', 'CONNECT')

        if self.check_running():
            self._w(f'Tor running on {self.active_port}', 'SUCCESS')
            return True

        # Linux: try systemctl
        import platform as plat
        if plat.system() == 'Linux':
            self._w('Trying systemctl start tor...', 'CONNECT')
            try:
                sp.run(['sudo', 'systemctl', 'start', 'tor'], capture_output=True, timeout=10)
                time.sleep(3)
                if self.check_running():
                    self._w('Tor service started!', 'SUCCESS')
                    return True
            except:
                pass

        tor_exe = self._find_tor_binary()
        if not tor_exe:
            self._w('Tor binary not found!', 'ERROR')
            return False

        self._w(f'Starting Tor: {tor_exe}', 'CONNECT')
        torrc = self._generate_torrc()
        tor_dir = os.path.join(BASE_DIR, 'tor_portable')

        try:
            self.tor_process = sp.Popen(
                [tor_exe, '-f', torrc],
                stdout=sp.PIPE, stderr=sp.PIPE,
                cwd=tor_dir
            )
            for i in range(60):
                time.sleep(1)
                if is_port_open(9050):
                    self.active_port = 9050
                    self.control_port = find_tor_control_port()
                    self._w('Tor started on 9050!', 'SUCCESS')
                    return True
                if (i + 1) % 10 == 0:
                    self._w(f'Connecting... {i+1}/60s', 'CONNECT')
                if self.tor_process.poll() is not None:
                    err = self.tor_process.stderr.read().decode()[:150]
                    self._w(f'Tor died: {err}', 'ERROR')
                    return False
            self._w('Tor timeout (60s)', 'ERROR')
            return False
        except Exception as e:
            self._w(f'Tor start error: {e}', 'ERROR')
            return False

    def launch_display(self, interval=20):
        tor_mgr_path = os.path.join(BASE_DIR, 'tor_manager.py')
        if not os.path.exists(tor_mgr_path):
            self._w('tor_manager.py not found', 'WARN')
            return
        self._w('Opening Tor display terminal...', 'CONNECT')
        try:
            from platform_utils import launch_in_terminal
            self.display_process = launch_in_terminal(
                script_path=tor_mgr_path,
                title='TOR ROTATOR',
                args=[f'--interval={interval}', '--display-only'],
                cwd=BASE_DIR,
                log_writer=self.log
            )
        except Exception as e:
            self._w(f'Tor display error: {e}', 'WARN')

    def _make_session(self):
        sess = requests.Session()
        proxy = f"socks5h://127.0.0.1:{self.active_port}"
        sess.proxies = {'http': proxy, 'https': proxy}
        sess.headers.update(random_headers())
        return sess

    def _rotate_circuit(self):
        cp = self.control_port
        if not cp:
            return False
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=cp) as c:
                c.authenticate()
                c.signal(Signal.NEWNYM)
                return True
        except:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(('127.0.0.1', cp))
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

    def _get_ip(self, sess=None):
        s = sess or self.session
        if not s:
            return 'Unknown'
        for url in ['https://api.ipify.org', 'https://icanhazip.com']:
            try:
                r = s.get(url, timeout=10)
                if r.status_code == 200:
                    return r.text.strip()
            except:
                continue
        return 'Unknown'

    def start_bg_rotation(self, interval=20):
        self._rotating = True

        def _loop():
            self._w(f'Tor rotation: every {interval}s', 'ROTATE')
            while self._rotating:
                time.sleep(interval)
                if not self._rotating:
                    break
                try:
                    if not self._rotate_circuit():
                        if self.session:
                            self.session.close()
                        time.sleep(2)
                        self.session = self._make_session()
                    time.sleep(3)
                    old = self.current_ip
                    new = self._get_ip()
                    self.current_ip = new
                    st = 'NEW' if new != old else 'SAME'
                    self._w(f'Tor IP → {new} ({st})', 'ROTATE')
                except Exception as e:
                    self._w(f'Rotation error: {e}', 'ERROR')

        self._rotate_thread = threading.Thread(target=_loop, daemon=True)
        self._rotate_thread.start()

    def get_session(self, interval=20):
        if not self.start_tor():
            return None
        self.launch_display(interval)
        time.sleep(1)
        self.session = self._make_session()
        try:
            ip = self._get_ip()
            self.current_ip = ip
            self._w(f'Tor IP: {ip}', 'SUCCESS')
        except Exception as e:
            self._w(f'Tor verify failed: {e}', 'WARN')
            return None
        self.start_bg_rotation(interval)
        return self.session

    def stop(self):
        self._rotating = False
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except:
                try:
                    self.tor_process.kill()
                except:
                    pass
        if self.display_process:
            try:
                self.display_process.terminate()
            except:
                pass


class SmartConnection:
    def __init__(self, target, risk_level='LOW', log_writer=None):
        self.target = target
        self.risk = risk_level
        self.log_writer = log_writer
        self.selected_method = 'direct'
        self.proxy_mgr = None
        self.tor_mgr = TorManager(log_writer=log_writer)
        self._session = None

    def _w(self, msg, lvl='INFO'):
        if self.log_writer:
            try:
                self.log_writer(msg, lvl)
            except:
                pass

    def _direct_session(self):
        sess = requests.Session()
        sess.headers.update(random_headers())
        return sess

    def _proxy_session(self):
        self._w('Fetching proxies...', 'CONNECT')
        try:
            if HAS_PROXY_MGR:
                mgr = FreeProxyManager(log_writer=self.log_writer)
                mgr.fetch_proxies()
                working = mgr.find_working_proxies(need=3, max_test=20)
                if working:
                    proxy = mgr.get_next_proxy()
                    sess = requests.Session()
                    sess.proxies = {'http': proxy, 'https': proxy}
                    sess.headers.update(random_headers())
                    self.proxy_mgr = mgr
                    self._w(f'Proxy: {proxy[:40]}', 'SUCCESS')
                    return sess
            else:
                resp = requests.get(
                    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all',
                    timeout=10
                )
                proxies = [f"http://{l.strip()}" for l in resp.text.split('\n') if ':' in l and len(l) < 25]
                random.shuffle(proxies)
                for proxy in proxies[:10]:
                    try:
                        sess = requests.Session()
                        sess.proxies = {'http': proxy, 'https': proxy}
                        sess.headers.update(random_headers())
                        r = sess.get('https://api.ipify.org', timeout=5)
                        if r.status_code == 200:
                            self._w(f'Proxy: {proxy}', 'SUCCESS')
                            return sess
                    except:
                        continue
        except Exception as e:
            self._w(f'Proxy failed: {e}', 'WARN')
        return None

    def _tor_session(self):
        self._w('Setting up Tor...', 'CONNECT')
        sess = self.tor_mgr.get_session(interval=20)
        if sess:
            self._w('Tor ready!', 'SUCCESS')
        else:
            self._w('Tor failed', 'WARN')
        return sess

    def _test_session(self, sess):
        try:
            r = sess.get('https://api.ipify.org', timeout=8)
            return r.status_code == 200
        except:
            return False

    def get_session(self):
        if self.risk == 'HIGH':
            order = ['tor', 'proxy', 'direct']
        elif self.risk == 'MEDIUM':
            order = ['direct', 'proxy', 'tor']
        else:
            order = ['direct', 'proxy']

        for method in order:
            self._w(f'Trying: {method.upper()}', 'CONNECT')
            if method == 'direct':
                sess = self._direct_session()
                if self._test_session(sess):
                    self.selected_method = 'direct'
                    self._session = sess
                    self._w('DIRECT OK', 'SUCCESS')
                    return sess
            elif method == 'proxy':
                sess = self._proxy_session()
                if sess:
                    self.selected_method = 'proxy'
                    self._session = sess
                    return sess
            elif method == 'tor':
                sess = self._tor_session()
                if sess:
                    self.selected_method = 'tor'
                    self._session = sess
                    return sess

        self._w('All failed → direct fallback', 'WARN')
        sess = self._direct_session()
        self.selected_method = 'direct'
        self._session = sess
        return sess

    def rotate(self):
        self._w(f'Rotating from {self.selected_method}', 'ROTATE')
        if self.selected_method == 'direct':
            sess = self._proxy_session() or self._tor_session()
        elif self.selected_method == 'proxy':
            sess = self._tor_session() or self._direct_session()
        else:
            if self.tor_mgr._rotate_circuit():
                time.sleep(3)
                self.tor_mgr.session = self.tor_mgr._make_session()
                sess = self.tor_mgr.session
                self._w('Tor circuit rotated', 'ROTATE')
            else:
                sess = self._proxy_session() or self._direct_session()
        if sess:
            self._session = sess
            return sess
        self._session = self._direct_session()
        self.selected_method = 'direct'
        return self._session

    def stop(self):
        if self.tor_mgr:
            self.tor_mgr.stop()
