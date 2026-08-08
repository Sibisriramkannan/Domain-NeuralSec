import os
import time
import requests
from urllib.parse import quote, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class SSTIAgent:
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
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        path = os.path.join(
            'payloads', 'ssti_payloads.txt'
        )
        try:
            with open(path, 'r') as f:
                return [
                    l.strip() for l in f
                    if l.strip()
                    and not l.startswith('#')
                ]
        except FileNotFoundError:
            return [
                '{{7*7}}', '${7*7}',
                '<%= 7*7 %>', '#{7*7}',
                '*{7*7}', '{{7*"7"}}'
            ]

    def _build_url(self, parsed, params):
        q = '&'.join(
            f'{k}={quote(str(v), safe="")}'
            for k, v in params.items()
        )
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{parsed.path}?{q}"
        )

    def detect_ssti(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing SSTI..."
            f"{Style.RESET_ALL}"
        )

        math_payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('#{7*7}', '49'),
            ('*{7*7}', '49'),
        ]

        parsed = urlparse(url)
        if not parsed.query:
            return self.findings

        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v

        for param in list(params.keys())[:3]:
            for payload, expected in math_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = self._build_url(
                    parsed, test_params
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    if expected in r.text:
                        engine = self._detect_engine(
                            payload
                        )
                        self.findings.append({
                            'type': (
                                'Server-Side Template '
                                'Injection (SSTI)'
                            ),
                            'category': 'ssti',
                            'risk': 'CRITICAL',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'expected_output': expected,
                            'template_engine': engine,
                            'description': (
                                f'SSTI in "{param}". '
                                f'Expression evaluated: '
                                f'{payload} = {expected}'
                            ),
                            'business_impact': (
                                'Remote Code Execution via '
                                'template engine. Complete '
                                'server compromise possible.'
                            ),
                            'fix': (
                                '1. Never pass user input '
                                'to template engine\n'
                                '2. Use sandboxed templates\n'
                                '3. Sanitize template context\n'
                                '4. Upgrade template library'
                            ),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-1336'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] SSTI FOUND in: {param} "
                            f"({engine})"
                            f"{Style.RESET_ALL}"
                        )
                        break
                    time.sleep(0.3)
                except Exception:
                    pass

        return self.findings

    def _detect_engine(self, payload):
        engine_map = {
            '{{': 'Jinja2/Twig/Pebble',
            '${': 'Freemarker/Thymeleaf',
            '<%=': 'ERB/EJS',
            '#{': 'Ruby/Slim',
            '*{': 'Thymeleaf',
        }
        for marker, engine in engine_map.items():
            if marker in payload:
                return engine
        return 'Unknown'

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[SSTI AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.detect_ssti(url)
        print(
            f"{Fore.GREEN}[SSTI AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
