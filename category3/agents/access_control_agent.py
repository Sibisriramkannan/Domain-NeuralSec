import requests
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)


class AccessControlAgent:
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

    def test_admin_access(self):
        print(
            f"  {Fore.CYAN}[*] Testing admin "
            f"endpoint access...{Style.RESET_ALL}"
        )
        admin_paths = [
            '/admin', '/admin/dashboard',
            '/admin/users', '/admin/settings',
            '/administrator', '/panel',
            '/superadmin', '/manage',
            '/api/admin', '/api/admin/users',
            '/api/admin/settings',
            '/api/v1/admin', '/api/v2/admin',
            '/internal', '/staff',
            '/moderator', '/cp',
        ]

        for path in admin_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                if r.status_code == 200:
                    content_lower = r.text.lower()
                    is_admin = any(
                        k in content_lower for k in [
                            'admin', 'dashboard',
                            'users list', 'manage',
                            'settings', 'control panel'
                        ]
                    )
                    if is_admin:
                        self.findings.append({
                            'type': (
                                'Admin Panel Accessible '
                                'Without Auth'
                            ),
                            'category': 'access_control',
                            'risk': 'CRITICAL',
                            'url': url,
                            'description': (
                                f'Admin endpoint "{path}" '
                                f'accessible without '
                                f'authentication'
                            ),
                            'business_impact': (
                                'Full admin access without '
                                'credentials. Complete '
                                'system compromise.'
                            ),
                            'fix': (
                                '1. Require authentication\n'
                                '2. Require admin role\n'
                                '3. IP whitelist for admin\n'
                                '4. Enable MFA for admin'
                            ),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-862'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] ADMIN ACCESS: {path}"
                            f"{Style.RESET_ALL}"
                        )

                elif r.status_code == 403:
                    self.findings.append({
                        'type': 'Admin Path Exists (403)',
                        'category': 'access_control',
                        'risk': 'LOW',
                        'url': url,
                        'description': (
                            f'Admin path exists but '
                            f'returns 403. '
                            f'Check for bypass techniques.'
                        ),
                        'note': (
                            'Manual testing: '
                            'try header bypasses'
                        )
                    })
            except Exception:
                pass

        return self.findings

    def test_method_based_bypass(self):
        print(
            f"  {Fore.CYAN}[*] Testing method-based "
            f"access control bypass..."
            f"{Style.RESET_ALL}"
        )
        sensitive_paths = [
            '/admin', '/api/admin/users',
            '/api/admin', '/panel',
        ]
        bypass_methods = [
            'POST', 'PUT', 'PATCH',
            'OPTIONS', 'HEAD'
        ]

        for path in sensitive_paths[:3]:
            url = urljoin(self.target, path)

            try:
                get_r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                if get_r.status_code not in [
                    401, 403
                ]:
                    continue
            except Exception:
                continue

            for method in bypass_methods:
                try:
                    r = self.session.request(
                        method, url,
                        timeout=8,
                        allow_redirects=False
                    )
                    if r.status_code == 200:
                        self.findings.append({
                            'type': (
                                'Access Control Bypass '
                                'via HTTP Method'
                            ),
                            'category': 'access_control',
                            'risk': 'HIGH',
                            'url': url,
                            'bypass_method': method,
                            'description': (
                                f'GET returns 403 but '
                                f'{method} returns 200. '
                                f'Method-based bypass.'
                            ),
                            'business_impact': (
                                'Protected resources '
                                'accessible via alternate '
                                'HTTP method'
                            ),
                            'fix': (
                                '1. Enforce auth on all methods\n'
                                '2. Whitelist allowed methods\n'
                                '3. Method-level access control'
                            ),
                            'cvss_score': 8.1,
                            'cwe': 'CWE-863'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] METHOD BYPASS: "
                            f"{method} on {path}"
                            f"{Style.RESET_ALL}"
                        )
                        break
                except Exception:
                    pass

        return self.findings

    def test_header_based_bypass(self):
        print(
            f"  {Fore.CYAN}[*] Testing header-based "
            f"bypass...{Style.RESET_ALL}"
        )
        bypass_headers = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
        ]

        protected_url = urljoin(self.target, '/admin')

        try:
            base_r = self.session.get(
                protected_url, timeout=8,
                allow_redirects=False
            )
            if base_r.status_code not in [401, 403]:
                return self.findings
        except Exception:
            return self.findings

        for bypass_header in bypass_headers:
            try:
                headers = {
                    'User-Agent': (
                        'SecurityAudit/1.0 '
                        '(Authorized Assessment)'
                    )
                }
                headers.update(bypass_header)
                r = self.session.get(
                    protected_url,
                    headers=headers,
                    timeout=8,
                    allow_redirects=False
                )
                if r.status_code == 200:
                    self.findings.append({
                        'type': (
                            'Access Control Bypass '
                            'via Header'
                        ),
                        'category': 'access_control',
                        'risk': 'CRITICAL',
                        'url': protected_url,
                        'bypass_header': str(
                            bypass_header
                        ),
                        'description': (
                            f'Admin access bypassed '
                            f'using header: '
                            f'{list(bypass_header.keys())[0]}'
                        ),
                        'business_impact': (
                            'Any attacker bypasses '
                            'access control using '
                            'simple HTTP header'
                        ),
                        'fix': (
                            '1. Remove trust in proxy headers\n'
                            '2. Never use headers for auth\n'
                            '3. Server-side access control\n'
                            '4. Validate at application layer'
                        ),
                        'cvss_score': 9.8,
                        'cwe': 'CWE-863'
                    })
                    print(
                        f"  {Fore.RED}"
                        f"[!!!] HEADER BYPASS WORKS: "
                        f"{list(bypass_header.keys())[0]}"
                        f"{Style.RESET_ALL}"
                    )
            except Exception:
                pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[ACCESS CONTROL AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.test_admin_access()
        self.test_method_based_bypass()
        self.test_header_based_bypass()
        print(
            f"{Fore.GREEN}[ACCESS CONTROL AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
