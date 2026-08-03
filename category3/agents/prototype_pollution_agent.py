import json
import requests
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)


class PrototypePollutionAgent:
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

    def detect_client_side_indicators(self):
        print(
            f"  {Fore.CYAN}[*] Detecting prototype "
            f"pollution indicators...{Style.RESET_ALL}"
        )
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            body = r.text

            dangerous_patterns = [
                '__proto__', 'constructor.prototype',
                'Object.prototype', 'prototype.pollution',
                'merge(', 'extend(', 'clone(',
                'assign(', 'defaults(',
                'deepmerge', 'deep-extend',
                'lodash.merge', '_.merge',
                'jquery.extend', '$.extend',
            ]

            found_patterns = [
                p for p in dangerous_patterns
                if p in body
            ]

            if found_patterns:
                self.findings.append({
                    'type': (
                        'Prototype Pollution '
                        'Code Patterns Detected'
                    ),
                    'category': 'prototype_pollution',
                    'risk': 'MEDIUM',
                    'url': self.target,
                    'patterns_found': found_patterns,
                    'description': (
                        'JavaScript patterns that may '
                        'be vulnerable to prototype '
                        'pollution detected in source'
                    ),
                    'business_impact': (
                        'Client-side prototype pollution '
                        'can lead to XSS and bypass '
                        'security controls'
                    ),
                    'fix': (
                        '1. Use Object.create(null)\n'
                        '2. Validate input keys\n'
                        '3. Reject __proto__ keys\n'
                        '4. Update lodash to 4.17.21+\n'
                        '5. Use safe merge libraries'
                    ),
                    'note': (
                        'Manual verification required - '
                        'these are indicators only'
                    ),
                    'cvss_score': 6.5,
                    'cwe': 'CWE-1321'
                })
                print(
                    f"  {Fore.YELLOW}"
                    f"[!] Prototype pollution indicators: "
                    f"{found_patterns[:3]}"
                    f"{Style.RESET_ALL}"
                )
        except Exception:
            pass

        return self.findings

    def test_server_side_pollution(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing server-side "
            f"prototype pollution...{Style.RESET_ALL}"
        )
        pp_payloads = [
            {'__proto__': {'polluted': 'yes'}},
            {'constructor': {'prototype': {'polluted': 'yes'}}},
            {'__proto__[polluted]': 'yes'},
        ]

        headers = {'Content-Type': 'application/json'}

        for payload in pp_payloads:
            try:
                r = self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10
                )
                if (
                    r.status_code not in [400, 422]
                    and 'polluted' in r.text
                ):
                    self.findings.append({
                        'type': (
                            'Server-Side Prototype '
                            'Pollution'
                        ),
                        'category': 'prototype_pollution',
                        'risk': 'HIGH',
                        'url': url,
                        'payload': str(payload),
                        'description': (
                            'Server reflects prototype '
                            'pollution payload. '
                            'JSON merge vulnerability.'
                        ),
                        'business_impact': (
                            'RCE possible via gadget chains. '
                            'Security bypass. '
                            'Privilege escalation.'
                        ),
                        'fix': (
                            '1. Use JSON schema validation\n'
                            '2. Block __proto__ keys\n'
                            '3. Use Object.freeze\n'
                            '4. Update vulnerable packages'
                        ),
                        'cvss_score': 8.1,
                        'cwe': 'CWE-1321'
                    })
                    print(
                        f"  {Fore.RED}"
                        f"[!!!] SERVER PROTOTYPE POLLUTION!"
                        f"{Style.RESET_ALL}"
                    )
                    break
            except Exception:
                pass

        return self.findings

    def run_full_scan(self, api_urls=None):
        print(
            f"\n{Fore.YELLOW}[PROTOTYPE POLLUTION AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.detect_client_side_indicators()
        test_urls = api_urls or [self.target]
        for url in test_urls:
            self.test_server_side_pollution(url)
        print(
            f"{Fore.GREEN}[PROTOTYPE POLLUTION AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
