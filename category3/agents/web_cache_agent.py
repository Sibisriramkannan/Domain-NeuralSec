import requests
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class WebCacheAgent:
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

    def analyze_cache_headers(self):
        print(
            f"  {Fore.CYAN}[*] Analyzing cache "
            f"headers...{Style.RESET_ALL}"
        )
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            headers = r.headers

            cache_control = headers.get(
                'Cache-Control', ''
            ).lower()
            pragma = headers.get('Pragma', '').lower()
            x_cache = headers.get('X-Cache', '')
            cf_cache = headers.get(
                'CF-Cache-Status', ''
            )
            age = headers.get('Age', '')
            vary = headers.get('Vary', '')

            # Check for sensitive data caching
            sensitive_paths = [
                '/account', '/profile',
                '/dashboard', '/admin',
                '/settings', '/api/user',
                '/api/me', '/user/profile',
            ]

            for path in sensitive_paths[:5]:
                url = urljoin(self.target, path)
                try:
                    sr = self.session.get(
                        url, timeout=8
                    )
                    sh = sr.headers
                    sc = sh.get(
                        'Cache-Control', ''
                    ).lower()

                    if (
                        sr.status_code == 200
                        and (
                            'no-store' not in sc
                            and 'private' not in sc
                        )
                    ):
                        self.findings.append({
                            'type': (
                                'Sensitive Page Not '
                                'Protected from Caching'
                            ),
                            'category': 'web_cache',
                            'risk': 'MEDIUM',
                            'url': url,
                            'cache_control': sc or 'MISSING',
                            'description': (
                                f'Sensitive page "{path}" '
                                f'missing cache protection. '
                                f'May be cached by CDN/proxy.'
                            ),
                            'business_impact': (
                                'User data cached and served '
                                'to other users. '
                                'Privacy violation.'
                            ),
                            'fix': (
                                '1. Add Cache-Control: '
                                'no-store, private\n'
                                '2. Add Pragma: no-cache\n'
                                '3. Set Vary: Cookie header'
                            ),
                            'cvss_score': 6.5,
                            'cwe': 'CWE-524'
                        })
                        print(
                            f"  {Fore.YELLOW}[!] Cacheable "
                            f"sensitive page: {path}"
                            f"{Style.RESET_ALL}"
                        )
                except Exception:
                    pass

            # Check Vary header
            if 'cookie' not in vary.lower():
                self.findings.append({
                    'type': 'Missing Vary: Cookie Header',
                    'category': 'web_cache',
                    'risk': 'LOW',
                    'url': self.target,
                    'description': (
                        'Vary header does not include Cookie. '
                        'Cache may serve wrong user data.'
                    ),
                    'fix': (
                        'Add Vary: Cookie to responses '
                        'with user-specific content'
                    ),
                    'cvss_score': 4.0,
                    'cwe': 'CWE-524'
                })

        except Exception:
            pass

        return self.findings

    def test_cache_deception(self):
        print(
            f"  {Fore.CYAN}[*] Testing web cache "
            f"deception...{Style.RESET_ALL}"
        )
        deception_suffixes = [
            '/nonexistent.css',
            '/nonexistent.jpg',
            '/nonexistent.js',
            '/nonexistent.png',
        ]

        sensitive_paths = [
            '/account', '/profile',
            '/api/user', '/dashboard',
        ]

        for s_path in sensitive_paths[:3]:
            for suffix in deception_suffixes[:2]:
                test_url = urljoin(
                    self.target,
                    s_path + suffix
                )
                try:
                    r = self.session.get(
                        test_url, timeout=8
                    )
                    if r.status_code == 200:
                        cache_headers = [
                            'X-Cache', 'CF-Cache-Status',
                            'Age', 'X-Drupal-Cache',
                            'Fastly-Cache-Status',
                            'X-Varnish'
                        ]
                        is_cached = any(
                            h in r.headers
                            for h in cache_headers
                        )
                        if is_cached:
                            self.findings.append({
                                'type': (
                                    'Web Cache Deception Risk'
                                ),
                                'category': 'web_cache',
                                'risk': 'HIGH',
                                'url': test_url,
                                'description': (
                                    f'Sensitive path served '
                                    f'with static suffix '
                                    f'and cached. '
                                    f'Cache deception possible.'
                                ),
                                'business_impact': (
                                    'Attacker tricks victim '
                                    'to visit crafted URL. '
                                    'Victim data cached '
                                    'publicly.'
                                ),
                                'fix': (
                                    '1. Validate URL path '
                                    'strictly\n'
                                    '2. Never cache '
                                    'authenticated responses\n'
                                    '3. Use Cache-Control: '
                                    'private, no-store'
                                ),
                                'cvss_score': 7.5,
                                'cwe': 'CWE-524'
                            })
                            print(
                                f"  {Fore.RED}"
                                f"[!!!] CACHE DECEPTION RISK!"
                                f"{Style.RESET_ALL}"
                            )
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[WEB CACHE AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.analyze_cache_headers()
        self.test_cache_deception()
        print(
            f"{Fore.GREEN}[WEB CACHE AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
