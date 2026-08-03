import requests
from colorama import Fore, Style, init

init(autoreset=True)


class HTTPHostHeaderAgent:
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

    def test_host_header_injection(self):
        print(
            f"  {Fore.CYAN}[*] Testing Host header "
            f"injection...{Style.RESET_ALL}"
        )
        evil_hosts = [
            'evil-attacker.com',
            'attacker.com',
            'evil.com:8080',
        ]

        for evil_host in evil_hosts:
            try:
                r = self.session.get(
                    self.target,
                    headers={
                        'Host': evil_host,
                        'User-Agent': (
                            'SecurityAudit/1.0 '
                            '(Authorized Assessment)'
                        )
                    },
                    timeout=10
                )
                if (
                    evil_host in r.text
                    or evil_host in str(r.headers)
                ):
                    self.findings.append({
                        'type': 'HTTP Host Header Injection',
                        'category': 'http_host_header',
                        'risk': 'HIGH',
                        'url': self.target,
                        'injected_host': evil_host,
                        'description': (
                            f'Server reflects injected '
                            f'Host header "{evil_host}" '
                            f'in response'
                        ),
                        'business_impact': (
                            'Password reset link poisoning. '
                            'Cache poisoning. '
                            'SSRF via host. '
                            'Web cache deception.'
                        ),
                        'fix': (
                            '1. Whitelist allowed Host values\n'
                            '2. Use absolute URLs in email links\n'
                            '3. Validate Host against config\n'
                            '4. Set SERVER_NAME explicitly'
                        ),
                        'cvss_score': 8.1,
                        'cwe': 'CWE-644'
                    })
                    print(
                        f"  {Fore.RED}"
                        f"[!!!] HOST HEADER INJECTION!"
                        f"{Style.RESET_ALL}"
                    )
                    break
            except Exception:
                pass

        return self.findings

    def test_password_reset_poisoning_indicator(self):
        print(
            f"  {Fore.CYAN}[*] Checking password reset "
            f"poison indicators...{Style.RESET_ALL}"
        )
        from urllib.parse import urljoin

        reset_paths = [
            '/forgot-password',
            '/reset-password',
            '/password/reset',
            '/auth/forgot',
            '/account/forgot-password',
        ]

        for path in reset_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url,
                    headers={
                        'Host': 'evil-attacker.com',
                        'User-Agent': (
                            'SecurityAudit/1.0 '
                            '(Authorized Assessment)'
                        )
                    },
                    timeout=8
                )
                if r.status_code == 200:
                    if 'evil-attacker.com' in r.text:
                        self.findings.append({
                            'type': (
                                'Password Reset '
                                'Poisoning Risk'
                            ),
                            'category': 'http_host_header',
                            'risk': 'HIGH',
                            'url': url,
                            'description': (
                                'Password reset page reflects '
                                'injected Host header. '
                                'Reset link poisoning possible.'
                            ),
                            'business_impact': (
                                'Attacker captures password '
                                'reset tokens of victims. '
                                'Account takeover at scale.'
                            ),
                            'fix': (
                                '1. Use hardcoded base URL\n'
                                '2. Whitelist Host header\n'
                                '3. Never use Host in emails'
                            ),
                            'cvss_score': 8.8,
                            'cwe': 'CWE-644'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] RESET POISONING RISK!"
                            f"{Style.RESET_ALL}"
                        )
            except Exception:
                pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[HTTP HOST HEADER AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.test_host_header_injection()
        self.test_password_reset_poisoning_indicator()
        print(
            f"{Fore.GREEN}[HTTP HOST HEADER AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
