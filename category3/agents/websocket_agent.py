import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


class WebSocketAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 '
                '(Authorized Assessment)'
            )
        })
        self.findings = []

    def detect_websocket_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Detecting WebSocket "
            f"endpoints...{Style.RESET_ALL}"
        )
        ws_paths = [
            '/ws', '/websocket', '/socket',
            '/socket.io', '/ws/chat',
            '/api/ws', '/api/websocket',
            '/realtime', '/live', '/stream',
            '/notifications', '/events',
        ]

        found = []

        # Check page source for WS connections
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            body = r.text
            import re
            ws_patterns = re.findall(
                r'ws[s]?://[^\'">\s]+',
                body
            )
            for pattern in ws_patterns:
                found.append({
                    'url': pattern,
                    'type': 'extracted_from_source',
                    'risk': 'INFO'
                })
                print(
                    f"  {Fore.GREEN}[+] WS found: "
                    f"{pattern}{Style.RESET_ALL}"
                )

            # Check JS files for WebSocket
            soup = BeautifulSoup(body, 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts[:5]:
                script_url = urljoin(
                    self.target, script['src']
                )
                try:
                    sr = self.session.get(
                        script_url, timeout=8
                    )
                    ws_in_js = re.findall(
                        r'ws[s]?://[^\'">\s]+',
                        sr.text
                    )
                    for ws in ws_in_js:
                        if ws not in [
                            f['url'] for f in found
                        ]:
                            found.append({
                                'url': ws,
                                'type': 'from_js_file',
                                'source': script_url
                            })
                except Exception:
                    pass

        except Exception:
            pass

        # Common path check
        parsed = urlparse(self.target)
        for path in ws_paths:
            http_url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    http_url, timeout=5
                )
                if r.status_code in [
                    200, 400, 426
                ]:
                    ws_url = (
                        http_url.replace(
                            'https://', 'wss://'
                        ).replace(
                            'http://', 'ws://'
                        )
                    )
                    if ws_url not in [
                        f['url'] for f in found
                    ]:
                        found.append({
                            'url': ws_url,
                            'http_status': r.status_code,
                            'type': 'path_probe'
                        })
            except Exception:
                pass

        return found

    def analyze_websocket_security(self, ws_endpoints):
        print(
            f"  {Fore.CYAN}[*] Analyzing WebSocket "
            f"security...{Style.RESET_ALL}"
        )

        for ws in ws_endpoints:
            url = ws.get('url', '')

            # Check if WSS (encrypted)
            if url.startswith('ws://'):
                self.findings.append({
                    'type': 'Unencrypted WebSocket (ws://)',
                    'category': 'websocket',
                    'risk': 'HIGH',
                    'url': url,
                    'description': (
                        'WebSocket uses ws:// not wss://. '
                        'Traffic is unencrypted.'
                    ),
                    'business_impact': (
                        'All WebSocket messages interceptable '
                        'by network attacker. '
                        'Session data exposed.'
                    ),
                    'fix': (
                        '1. Use wss:// exclusively\n'
                        '2. Enable HTTPS on server\n'
                        '3. Reject ws:// connections'
                    ),
                    'cvss_score': 7.4,
                    'cwe': 'CWE-319'
                })
                print(
                    f"  {Fore.YELLOW}[!] Unencrypted WS: "
                    f"{url}{Style.RESET_ALL}"
                )

            # Log found WS endpoints as info
            if ws.get('type') != 'INFO':
                self.findings.append({
                    'type': 'WebSocket Endpoint Found',
                    'category': 'websocket',
                    'risk': 'INFO',
                    'url': url,
                    'source': ws.get('type', 'unknown'),
                    'description': (
                        f'WebSocket endpoint discovered: {url}'
                    ),
                    'note': (
                        'Manual testing recommended: '
                        'auth bypass, injection, '
                        'message manipulation'
                    )
                })

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[WEBSOCKET AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        ws_endpoints = self.detect_websocket_endpoints()
        print(
            f"  {Fore.CYAN}[*] Found "
            f"{len(ws_endpoints)} WebSocket endpoints"
            f"{Style.RESET_ALL}"
        )
        self.analyze_websocket_security(ws_endpoints)
        print(
            f"{Fore.GREEN}[WEBSOCKET AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
