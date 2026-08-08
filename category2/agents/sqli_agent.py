import os
import re
import time
import requests
from urllib.parse import quote, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class SQLiAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 (Authorized Assessment)'
            )
        })
        self.findings = []
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        payload_file = os.path.join(
            'payloads', 'sqli_payloads.txt'
        )
        try:
            with open(payload_file, 'r') as f:
                return [
                    line.strip()
                    for line in f.readlines()
                    if line.strip()
                    and not line.startswith('#')
                ]
        except FileNotFoundError:
            return [
                "'", '"', "1 OR 1=1",
                "' OR '1'='1",
                "1 AND SLEEP(5)--",
                "' AND SLEEP(5)--"
            ]

    def _get_baseline(self, url):
        try:
            r = self.session.get(url, timeout=10)
            return {
                'status': r.status_code,
                'length': len(r.content),
                'time': r.elapsed.total_seconds()
            }
        except Exception:
            return None

    def _build_test_url(self, parsed, params):
        query = '&'.join(
            f'{k}={quote(str(v), safe="")}'
            for k, v in params.items()
        )
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{parsed.path}?{query}"
        )

    def detect_error_based(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing error-based "
            f"SQLi...{Style.RESET_ALL}"
        )

        error_signatures = [
            "you have an error in your sql syntax",
            "warning: mysql", "mysql_fetch_array()",
            "mysql_num_rows()", "supplied argument is not "
            "a valid mysql", "pg_query()", "pg_exec()",
            "unterminated quoted string", "postgresql",
            "microsoft sql server", "mssql_query()",
            "[microsoft][odbc sql server driver]",
            "unclosed quotation mark", "ora-01756",
            "ora-00907", "ora-", "sqlite3.operationalerror",
            "sqlite_error", "sql syntax", "sql error",
            "database error", "syntax error",
            "unexpected end of sql command",
        ]

        parsed = urlparse(url)
        if not parsed.query:
            return self.findings

        params = {}
        for param in parsed.query.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                params[k] = v

        for param_name, original_value in params.items():
            for payload in self.payloads[:10]:
                test_params = params.copy()
                test_params[param_name] = (
                    original_value + payload
                )
                test_url = self._build_test_url(
                    parsed, test_params
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    response_lower = r.text.lower()
                    for error in error_signatures:
                        if error in response_lower:
                            self.findings.append({
                                'type': (
                                    'SQL Injection - Error Based'
                                ),
                                'category': 'sqli',
                                'risk': 'CRITICAL',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': error,
                                'description': (
                                    f'SQL error in parameter '
                                    f'"{param_name}" - '
                                    f'database error exposed'
                                ),
                                'business_impact': (
                                    'Attacker can read/modify '
                                    'entire database'
                                ),
                                'fix': (
                                    '1. Use parameterized queries\n'
                                    '2. Use prepared statements\n'
                                    '3. Implement input validation\n'
                                    '4. Disable detailed errors'
                                ),
                                'cvss_score': 9.8,
                                'cwe': 'CWE-89'
                            })
                            print(
                                f"  {Fore.RED}[!!!] SQLi FOUND "
                                f"in: {param_name}"
                                f"{Style.RESET_ALL}"
                            )
                            break
                    time.sleep(0.3)
                except Exception:
                    pass

        return self.findings

    def detect_time_based(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing time-based "
            f"SQLi...{Style.RESET_ALL}"
        )

        time_payloads = [
            ("MySQL", "1 AND SLEEP(5)--"),
            ("MSSQL", "1; WAITFOR DELAY '0:0:5'--"),
        ]

        parsed = urlparse(url)
        if not parsed.query:
            return self.findings

        params = {}
        for param in parsed.query.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                params[k] = v

        for param_name in list(params.keys())[:3]:
            baseline = self._get_baseline(url)
            if not baseline:
                continue
            baseline_time = baseline['time']

            for db_type, payload in time_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                test_url = self._build_test_url(
                    parsed, test_params
                )
                try:
                    start = time.time()
                    self.session.get(
                        test_url, timeout=15
                    )
                    elapsed = time.time() - start

                    if elapsed > (baseline_time + 4):
                        self.findings.append({
                            'type': (
                                'SQL Injection - '
                                'Time Based Blind'
                            ),
                            'category': 'sqli',
                            'risk': 'CRITICAL',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'db_type': db_type,
                            'baseline_time': round(
                                baseline_time, 2
                            ),
                            'actual_time': round(
                                elapsed, 2
                            ),
                            'description': (
                                f'Time-based SQLi in '
                                f'"{param_name}". '
                                f'Delayed by '
                                f'{round(elapsed - baseline_time, 1)}s'
                            ),
                            'business_impact': (
                                'Blind SQLi allows complete '
                                'database extraction'
                            ),
                            'fix': (
                                'Use parameterized queries. '
                                'Never concatenate user input.'
                            ),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-89'
                        })
                        print(
                            f"  {Fore.RED}[!!!] Time-based SQLi "
                            f"in: {param_name}{Style.RESET_ALL}"
                        )
                except Exception:
                    pass
                time.sleep(0.5)

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[SQLI AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            print(
                f"  {Fore.CYAN}Testing: "
                f"{url[:60]}{Style.RESET_ALL}"
            )
            self.detect_error_based(url)
            self.detect_time_based(url)
        print(
            f"{Fore.GREEN}[SQLI AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
