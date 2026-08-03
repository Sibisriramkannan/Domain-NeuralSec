"""
Security Headers Agent
Analyzes HTTP security headers
Safe passive check
"""

import requests
import json
from colorama import Fore, Style, init

init(autoreset=True)


class SecurityHeadersAgent:
    def __init__(self, target_domain):
        self.target = target_domain.replace(
            'https://', ''
        ).replace('http://', '').strip('/')
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36'
            )
        })

    def analyze_headers(self):
        """Comprehensive security headers analysis"""
        print(
            f"\n{Fore.YELLOW}[HEADERS AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        print(
            f"  {Fore.CYAN}[*] Fetching and analyzing "
            f"headers...{Style.RESET_ALL}"
        )

        try:
            response = self.session.get(
                f"https://{self.target}",
                timeout=15
            )
            headers = response.headers
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }

        # Security headers definitions
        security_header_checks = {
            'Strict-Transport-Security': {
                'present': (
                    'Strict-Transport-Security' in headers
                ),
                'value': headers.get(
                    'Strict-Transport-Security', 'MISSING'
                ),
                'risk_if_missing': 'HIGH',
                'description': (
                    'HTTP Strict Transport Security (HSTS) '
                    'forces browsers to use HTTPS'
                ),
                'attack': (
                    'Man-in-the-Middle attack, '
                    'SSL stripping'
                ),
                'fix': (
                    'Strict-Transport-Security: '
                    'max-age=31536000; '
                    'includeSubDomains; preload'
                ),
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/Strict-Transport-Security'
                )
            },
            'Content-Security-Policy': {
                'present': (
                    'Content-Security-Policy' in headers
                ),
                'value': headers.get(
                    'Content-Security-Policy', 'MISSING'
                ),
                'risk_if_missing': 'HIGH',
                'description': (
                    'CSP prevents XSS by controlling '
                    'which resources can be loaded'
                ),
                'attack': (
                    'Cross-Site Scripting (XSS), '
                    'data injection'
                ),
                'fix': (
                    "Content-Security-Policy: "
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self'"
                ),
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/CSP'
                )
            },
            'X-Content-Type-Options': {
                'present': (
                    'X-Content-Type-Options' in headers
                ),
                'value': headers.get(
                    'X-Content-Type-Options', 'MISSING'
                ),
                'risk_if_missing': 'MEDIUM',
                'description': (
                    'Prevents browsers from MIME-sniffing '
                    'response content type'
                ),
                'attack': (
                    'MIME type confusion attack'
                ),
                'fix': 'X-Content-Type-Options: nosniff',
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/X-Content-Type-Options'
                )
            },
            'X-Frame-Options': {
                'present': (
                    'X-Frame-Options' in headers
                ),
                'value': headers.get(
                    'X-Frame-Options', 'MISSING'
                ),
                'risk_if_missing': 'MEDIUM',
                'description': (
                    'Prevents page from being loaded '
                    'in iframes'
                ),
                'attack': 'Clickjacking attack',
                'fix': 'X-Frame-Options: DENY',
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/X-Frame-Options'
                )
            },
            'X-XSS-Protection': {
                'present': (
                    'X-XSS-Protection' in headers
                ),
                'value': headers.get(
                    'X-XSS-Protection', 'MISSING'
                ),
                'risk_if_missing': 'LOW',
                'description': (
                    'Enables browser built-in XSS filter '
                    '(legacy browsers)'
                ),
                'attack': 'Cross-Site Scripting (XSS)',
                'fix': 'X-XSS-Protection: 1; mode=block',
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/X-XSS-Protection'
                )
            },
            'Referrer-Policy': {
                'present': (
                    'Referrer-Policy' in headers
                ),
                'value': headers.get(
                    'Referrer-Policy', 'MISSING'
                ),
                'risk_if_missing': 'MEDIUM',
                'description': (
                    'Controls referrer information sent '
                    'with requests'
                ),
                'attack': (
                    'Information leakage via '
                    'Referer header'
                ),
                'fix': (
                    'Referrer-Policy: '
                    'strict-origin-when-cross-origin'
                ),
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/Referrer-Policy'
                )
            },
            'Permissions-Policy': {
                'present': (
                    'Permissions-Policy' in headers
                ),
                'value': headers.get(
                    'Permissions-Policy', 'MISSING'
                ),
                'risk_if_missing': 'MEDIUM',
                'description': (
                    'Controls browser features and APIs '
                    'access'
                ),
                'attack': (
                    'Unauthorized access to camera, '
                    'microphone, geolocation'
                ),
                'fix': (
                    'Permissions-Policy: '
                    'camera=(), microphone=(), '
                    'geolocation=(), '
                    'payment=()'
                ),
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/Permissions-Policy'
                )
            },
            'Cache-Control': {
                'present': 'Cache-Control' in headers,
                'value': headers.get(
                    'Cache-Control', 'MISSING'
                ),
                'risk_if_missing': 'LOW',
                'description': (
                    'Controls how responses are cached'
                ),
                'attack': (
                    'Sensitive data cached in browser '
                    'or proxy'
                ),
                'fix': (
                    'Cache-Control: '
                    'no-store, no-cache, '
                    'must-revalidate '
                    '(for sensitive pages)'
                ),
                'reference': (
                    'https://developer.mozilla.org/docs/Web/'
                    'HTTP/Headers/Cache-Control'
                )
            },
        }

        # Calculate scores
        present_count = sum(
            1 for h in security_header_checks.values()
            if h['present']
        )
        total_count = len(security_header_checks)
        score = round((present_count / total_count) * 100)

        # Information disclosure check
        info_disclosure = {}
        risky_headers = [
            'Server', 'X-Powered-By',
            'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Debug-Token',
            'X-Debug-Token-Link', 'X-Cf-Powered-By',
            'X-Backend-Server', 'X-Runtime',
            'X-Version'
        ]

        for h in risky_headers:
            if h in headers:
                info_disclosure[h] = {
                    'value': headers[h],
                    'risk': 'MEDIUM',
                    'description': (
                        f'{h} header reveals server '
                        f'technology details'
                    ),
                    'fix': (
                        f'Remove {h} header from '
                        f'server configuration'
                    )
                }

        # Cookie security check
        cookie_issues = []
        set_cookie = response.headers.get(
            'Set-Cookie', ''
        )

        if set_cookie:
            cookies = response.headers.getlist(
                'Set-Cookie'
            ) if hasattr(
                response.headers, 'getlist'
            ) else [set_cookie]

            for cookie in cookies:
                cookie_lower = cookie.lower()
                issues = []

                if 'httponly' not in cookie_lower:
                    issues.append({
                        'flag': 'HttpOnly',
                        'missing': True,
                        'risk': 'HIGH',
                        'description': (
                            'Cookie accessible via '
                            'JavaScript - XSS can steal '
                            'session'
                        ),
                        'fix': 'Add HttpOnly flag to cookie'
                    })
                if 'secure' not in cookie_lower:
                    issues.append({
                        'flag': 'Secure',
                        'missing': True,
                        'risk': 'HIGH',
                        'description': (
                            'Cookie transmitted over '
                            'HTTP - interception possible'
                        ),
                        'fix': 'Add Secure flag to cookie'
                    })
                if 'samesite' not in cookie_lower:
                    issues.append({
                        'flag': 'SameSite',
                        'missing': True,
                        'risk': 'MEDIUM',
                        'description': (
                            'CSRF attack possible - '
                            'no SameSite restriction'
                        ),
                        'fix': (
                            'Add SameSite=Strict '
                            'or SameSite=Lax'
                        )
                    })

                if issues:
                    cookie_issues.append({
                        'cookie': cookie[:100] + '...',
                        'issues': issues
                    })

        # CORS check
        cors_result = self._check_cors()

        # Compile results
        self.results = {
            'status': 'success',
            'target': self.target,
            'scan_time': str(
                __import__('datetime').datetime.now()
            ),
            'score': {
                'value': score,
                'grade': self._get_grade(score),
                'headers_present': present_count,
                'headers_total': total_count,
                'interpretation': (
                    'Excellent'
                    if score >= 80
                    else 'Good'
                    if score >= 60
                    else 'Poor'
                    if score >= 40
                    else 'Very Poor'
                )
            },
            'security_headers': security_header_checks,
            'information_disclosure': info_disclosure,
            'cookie_security': cookie_issues,
            'cors': cors_result,
            'missing_critical': [
                name
                for name, data
                in security_header_checks.items()
                if not data['present']
                and data['risk_if_missing'] == 'HIGH'
            ],
            'missing_high': [
                name
                for name, data
                in security_header_checks.items()
                if not data['present']
                and data['risk_if_missing'] == 'HIGH'
            ],
        }

        print(
            f"  {Fore.GREEN}[✓] Headers analysis "
            f"complete - Score: {score}/100 "
            f"({self._get_grade(score)})"
            f"{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}[HEADERS AGENT] "
            f"Complete!{Style.RESET_ALL}"
        )
        return self.results

    def _check_cors(self):
        """Check CORS configuration"""
        try:
            cors_response = self.session.get(
                f"https://{self.target}",
                headers={
                    'Origin': 'https://evil-attacker.com'
                },
                timeout=10
            )
            acao = cors_response.headers.get(
                'Access-Control-Allow-Origin', ''
            )
            acac = cors_response.headers.get(
                'Access-Control-Allow-Credentials', ''
            )

            if acao == '*':
                return {
                    'misconfigured': True,
                    'risk': 'HIGH',
                    'value': acao,
                    'description': (
                        'CORS allows all origins (*) - '
                        'API data exposed to any website'
                    ),
                    'fix': (
                        'Replace * with specific '
                        'trusted origins'
                    )
                }
            elif 'evil-attacker.com' in acao:
                return {
                    'misconfigured': True,
                    'risk': 'CRITICAL',
                    'value': acao,
                    'credentials': acac,
                    'description': (
                        'CORS reflects arbitrary origin '
                        '- critical misconfiguration'
                    ),
                    'fix': (
                        'Implement strict origin whitelist'
                    )
                }
            else:
                return {
                    'misconfigured': False,
                    'risk': 'NONE',
                    'value': acao or 'Not set',
                    'description': (
                        'CORS appears correctly '
                        'configured'
                    )
                }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'could not test'
            }

    def _get_grade(self, score):
        """Convert score to letter grade"""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
