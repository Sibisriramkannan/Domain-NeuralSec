import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class CORSAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 (Authorized Assessment)'
            )
        })
        self.findings = []

    def test_cors_misconfig(self):
        print(
            f"  {Fore.CYAN}[*] Testing CORS "
            f"misconfigurations...{Style.RESET_ALL}"
        )

        parsed = urlparse(self.target)
        domain = parsed.netloc

        origins_to_test = [
            'https://evil-attacker.com',
            'https://attacker.example.com',
            'null',
            f'https://evil-{domain}',
            f'https://{domain}.evil.com',
        ]

        seen_types = set()

        for origin in origins_to_test:
            try:
                r = self.session.get(
                    self.target,
                    headers={
                        'Origin': origin,
                        'User-Agent': (
                            'SecurityAudit/1.0 '
                            '(Authorized Assessment)'
                        )
                    },
                    timeout=10
                )

                acao = r.headers.get(
                    'Access-Control-Allow-Origin', ''
                )
                acac = r.headers.get(
                    'Access-Control-Allow-Credentials',
                    ''
                )

                if acao == '*' and 'wildcard' not in seen_types:
                    seen_types.add('wildcard')
                    self.findings.append({
                        'type': 'CORS Wildcard Origin',
                        'category': 'cors',
                        'risk': 'HIGH',
                        'url': self.target,
                        'origin_tested': origin,
                        'reflected_origin': acao,
                        'credentials_allowed': (
                            acac.lower() == 'true'
                        ),
                        'description': (
                            'CORS allows all origins (*). '
                            'Any website can make '
                            'cross-origin requests'
                        ),
                        'business_impact': (
                            'API data accessible by any '
                            'malicious website'
                        ),
                        'fix': (
                            '1. Replace * with specific origins\n'
                            '2. Never use * with credentials\n'
                            '3. Maintain origin whitelist'
                        ),
                        'cvss_score': 7.5,
                        'cwe': 'CWE-942'
                    })
                    print(
                        f"  {Fore.RED}[!!!] CORS wildcard "
                        f"detected{Style.RESET_ALL}"
                    )

                elif (
                    origin.lower() in acao.lower()
                    and 'reflection' not in seen_types
                ):
                    seen_types.add('reflection')
                    severity = (
                        'CRITICAL'
                        if acac.lower() == 'true'
                        else 'HIGH'
                    )
                    self.findings.append({
                        'type': 'CORS Origin Reflection',
                        'category': 'cors',
                        'risk': severity,
                        'url': self.target,
                        'origin_tested': origin,
                        'reflected_origin': acao,
                        'credentials_allowed': (
                            acac.lower() == 'true'
                        ),
                        'description': (
                            f'Server reflects malicious '
                            f'origin "{origin}"'
                        ),
                        'business_impact': (
                            'Authenticated API requests '
                            'on behalf of victim users'
                        ),
                        'fix': (
                            '1. Strict origin whitelist\n'
                            '2. Validate against approved list\n'
                            '3. Never trust Origin header blindly'
                        ),
                        'cvss_score': (
                            9.6
                            if acac.lower() == 'true'
                            else 7.5
                        ),
                        'cwe': 'CWE-942'
                    })
                    print(
                        f"  {Fore.RED}[!!!] CORS reflection: "
                        f"{origin}{Style.RESET_ALL}"
                    )

                elif (
                    acao == 'null'
                    and 'null' not in seen_types
                ):
                    seen_types.add('null')
                    self.findings.append({
                        'type': 'CORS Null Origin Allowed',
                        'category': 'cors',
                        'risk': 'HIGH',
                        'url': self.target,
                        'description': (
                            'null origin is allowed. '
                            'Sandboxed iframes can exploit.'
                        ),
                        'fix': (
                            'Never whitelist null origin'
                        ),
                        'cvss_score': 6.5,
                        'cwe': 'CWE-942'
                    })

            except Exception:
                pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[CORS AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.test_cors_misconfig()
        print(
            f"{Fore.GREEN}[CORS AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
