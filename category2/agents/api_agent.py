import json
import requests
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)


class APIAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 (Authorized Assessment)'
            )
        })
        self.findings = []

    def discover_api_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Discovering API "
            f"endpoints...{Style.RESET_ALL}"
        )
        common_api_paths = [
            '/api', '/api/v1', '/api/v2',
            '/v1', '/v2', '/v3',
            '/api/users', '/api/user',
            '/api/admin', '/api/auth',
            '/api/login', '/api/logout',
            '/api/register', '/api/profile',
            '/api/products', '/api/orders',
            '/rest', '/rest/v1',
            '/api/docs', '/api/swagger',
            '/api/health', '/api/status',
            '/api/config', '/api/settings'
        ]

        discovered = []
        for path in common_api_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                if r.status_code in [
                    200, 401, 403, 405
                ]:
                    discovered.append({
                        'url': url,
                        'status': r.status_code,
                        'content_type': r.headers.get(
                            'Content-Type', ''
                        ),
                        'is_json': (
                            'application/json'
                            in r.headers.get(
                                'Content-Type', ''
                            )
                        ),
                        'requires_auth': (
                            r.status_code == 401
                        ),
                        'forbidden': (
                            r.status_code == 403
                        ),
                    })
            except Exception:
                pass
        return discovered

    def test_http_methods(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing HTTP "
            f"methods...{Style.RESET_ALL}"
        )
        methods = [
            'GET', 'POST', 'PUT', 'DELETE',
            'PATCH', 'OPTIONS', 'HEAD', 'TRACE'
        ]

        for endpoint in endpoints[:5]:
            url = endpoint['url']
            allowed_methods = []

            for method in methods:
                try:
                    r = self.session.request(
                        method, url,
                        timeout=8,
                        allow_redirects=False
                    )
                    if r.status_code not in [405, 501]:
                        allowed_methods.append({
                            'method': method,
                            'status': r.status_code
                        })
                except Exception:
                    pass

            dangerous = ['TRACE', 'DELETE', 'PUT']
            found_dangerous = [
                m for m in allowed_methods
                if m['method'] in dangerous
                and m['status'] not in [401, 403]
            ]

            if found_dangerous:
                self.findings.append({
                    'type': (
                        'Dangerous HTTP Methods Allowed'
                    ),
                    'category': 'api',
                    'risk': 'MEDIUM',
                    'url': url,
                    'dangerous_methods': found_dangerous,
                    'description': (
                        f'Dangerous methods allowed: '
                        f'{[m["method"] for m in found_dangerous]}'
                    ),
                    'fix': (
                        '1. Disable TRACE method\n'
                        '2. Restrict DELETE/PUT/PATCH\n'
                        '3. Require auth for mutations'
                    ),
                    'cvss_score': 5.3,
                    'cwe': 'CWE-749'
                })

    def test_broken_object_auth(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing BOLA/IDOR "
            f"indicators...{Style.RESET_ALL}"
        )
        for endpoint in endpoints:
            if not endpoint.get('is_json'):
                continue
            url = endpoint['url']
            for test_id in ['1', '2', '0']:
                test_url = f"{url}/{test_id}"
                try:
                    r = self.session.get(
                        test_url, timeout=8
                    )
                    if (
                        r.status_code == 200
                        and len(r.content) > 50
                    ):
                        try:
                            data = r.json()
                            if data:
                                self.findings.append({
                                    'type': (
                                        'Potential BOLA/IDOR'
                                    ),
                                    'category': 'api',
                                    'risk': 'HIGH',
                                    'url': test_url,
                                    'description': (
                                        f'Endpoint returns data '
                                        f'for ID {test_id} - '
                                        f'auth check unclear'
                                    ),
                                    'business_impact': (
                                        'Users may access other '
                                        "users' data by changing IDs"
                                    ),
                                    'fix': (
                                        '1. Object-level auth checks\n'
                                        '2. Use UUIDs not sequential IDs\n'
                                        '3. Verify ownership every request'
                                    ),
                                    'note': (
                                        'Manual verification required'
                                    ),
                                    'cvss_score': 8.1,
                                    'cwe': 'CWE-639'
                                })
                                break
                        except Exception:
                            pass
                except Exception:
                    pass

    def test_rate_limiting(self):
        print(
            f"  {Fore.CYAN}[*] Testing rate "
            f"limiting...{Style.RESET_ALL}"
        )
        login_endpoints = [
            '/api/login', '/api/auth',
            '/api/signin', '/login', '/auth'
        ]
        for path in login_endpoints:
            url = urljoin(self.target, path)
            responses = []
            for i in range(10):
                try:
                    r = self.session.post(
                        url,
                        json={
                            'username': 'test',
                            'password': f'wrong_{i}'
                        },
                        timeout=5
                    )
                    responses.append(r.status_code)
                except Exception:
                    break

            if len(responses) >= 10:
                if 429 not in responses:
                    self.findings.append({
                        'type': 'Missing Rate Limiting',
                        'category': 'api',
                        'risk': 'HIGH',
                        'url': url,
                        'description': (
                            'No rate limiting on login. '
                            '10 requests with no 429.'
                        ),
                        'business_impact': (
                            'Brute force login attacks possible'
                        ),
                        'fix': (
                            '1. Implement rate limiting\n'
                            '2. Add CAPTCHA after failures\n'
                            '3. Account lockout after N attempts'
                        ),
                        'cvss_score': 7.5,
                        'cwe': 'CWE-307'
                    })
                    print(
                        f"  {Fore.RED}[!!!] No rate limiting "
                        f"on {path}{Style.RESET_ALL}"
                    )
                break

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[API AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        endpoints = self.discover_api_endpoints()
        print(
            f"  {Fore.CYAN}[*] Found "
            f"{len(endpoints)} endpoints{Style.RESET_ALL}"
        )
        self.test_http_methods(endpoints)
        self.test_broken_object_auth(endpoints)
        self.test_rate_limiting()
        print(
            f"{Fore.GREEN}[API AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
