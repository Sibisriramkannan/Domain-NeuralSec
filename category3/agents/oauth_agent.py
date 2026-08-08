import requests
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style, init

init(autoreset=True)


class OAuthAgent:
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

    def discover_oauth_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Discovering OAuth "
            f"endpoints...{Style.RESET_ALL}"
        )
        oauth_paths = [
            '/oauth', '/oauth2', '/oauth/authorize',
            '/oauth2/authorize', '/auth/oauth',
            '/connect/authorize', '/.well-known/openid-configuration',
            '/oauth/token', '/oauth2/token',
            '/api/oauth', '/auth/google',
            '/auth/facebook', '/auth/github',
            '/auth/twitter', '/login/oauth',
            '/authorize', '/oauth/callback',
        ]

        found = []
        for path in oauth_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                if r.status_code in [
                    200, 302, 400, 401
                ]:
                    found.append({
                        'url': url,
                        'status': r.status_code,
                        'path': path
                    })
                    print(
                        f"  {Fore.GREEN}[+] OAuth: "
                        f"{url} [{r.status_code}]"
                        f"{Style.RESET_ALL}"
                    )
            except Exception:
                pass

        return found

    def test_state_parameter(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Checking OAuth state "
            f"parameter...{Style.RESET_ALL}"
        )
        for ep in endpoints:
            url = ep['url']
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                location = r.headers.get(
                    'Location', ''
                )
                if location:
                    parsed = urlparse(location)
                    params = parse_qs(parsed.query)
                    if 'state' not in params:
                        self.findings.append({
                            'type': (
                                'OAuth Missing State Parameter'
                            ),
                            'category': 'oauth',
                            'risk': 'HIGH',
                            'url': url,
                            'redirect_to': location[:100],
                            'description': (
                                'OAuth flow missing state '
                                'parameter. CSRF attack '
                                'on OAuth possible.'
                            ),
                            'business_impact': (
                                'Attacker links their account '
                                'to victim account. '
                                'Account takeover via '
                                'OAuth CSRF.'
                            ),
                            'fix': (
                                '1. Always use state parameter\n'
                                '2. Validate state on callback\n'
                                '3. Use crypto random state\n'
                                '4. Bind state to session'
                            ),
                            'cvss_score': 8.8,
                            'cwe': 'CWE-352'
                        })
                        print(
                            f"  {Fore.YELLOW}"
                            f"[!] No OAuth state param"
                            f"{Style.RESET_ALL}"
                        )
            except Exception:
                pass

        return self.findings

    def test_redirect_uri_validation(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing redirect_uri "
            f"validation...{Style.RESET_ALL}"
        )
        evil_redirects = [
            'https://evil-attacker.com',
            'https://evil.com/callback',
            'https://evil-attacker.com/callback',
        ]

        for ep in endpoints:
            for evil_uri in evil_redirects[:2]:
                url = ep['url']
                if '?' in url:
                    test_url = (
                        url
                        + f"&redirect_uri={evil_uri}"
                    )
                else:
                    test_url = (
                        url
                        + f"?redirect_uri={evil_uri}"
                        + "&response_type=code"
                        + "&client_id=test"
                    )

                try:
                    r = self.session.get(
                        test_url, timeout=8,
                        allow_redirects=False
                    )
                    location = r.headers.get(
                        'Location', ''
                    )
                    if evil_uri in location:
                        self.findings.append({
                            'type': (
                                'OAuth redirect_uri '
                                'Not Validated'
                            ),
                            'category': 'oauth',
                            'risk': 'CRITICAL',
                            'url': test_url,
                            'evil_redirect': evil_uri,
                            'description': (
                                'OAuth accepts arbitrary '
                                'redirect_uri. '
                                'Auth codes sent to attacker.'
                            ),
                            'business_impact': (
                                'Authorization code stolen. '
                                'Account takeover. '
                                'All OAuth users affected.'
                            ),
                            'fix': (
                                '1. Whitelist redirect URIs\n'
                                '2. Exact match only\n'
                                '3. No wildcard redirects\n'
                                '4. Validate per client_id'
                            ),
                            'cvss_score': 9.3,
                            'cwe': 'CWE-601'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] OAUTH REDIRECT BYPASS!"
                            f"{Style.RESET_ALL}"
                        )
                        break
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[OAUTH AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        endpoints = self.discover_oauth_endpoints()
        if endpoints:
            self.test_state_parameter(endpoints)
            self.test_redirect_uri_validation(endpoints)
        else:
            print(
                f"  {Fore.YELLOW}[*] No OAuth endpoints "
                f"found{Style.RESET_ALL}"
            )
        print(
            f"{Fore.GREEN}[OAUTH AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
