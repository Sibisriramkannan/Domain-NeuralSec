import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


class AuthAgent:
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

    def detect_login_pages(self):
        print(
            f"  {Fore.CYAN}[*] Detecting login "
            f"pages...{Style.RESET_ALL}"
        )
        login_paths = [
            '/login', '/signin', '/auth',
            '/admin', '/admin/login',
            '/user/login', '/account/login',
            '/wp-login.php', '/wp-admin',
            '/administrator', '/panel',
            '/dashboard', '/portal',
            '/api/login', '/api/auth',
            '/api/v1/login', '/api/v2/login',
            '/member/login', '/user/signin',
            '/auth/login', '/auth/signin',
        ]

        found_pages = []
        for path in login_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=True
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(
                        r.text, 'html.parser'
                    )
                    forms = soup.find_all('form')
                    has_password = any(
                        inp.get('type') == 'password'
                        for form in forms
                        for inp in form.find_all('input')
                    )
                    if has_password or 'login' in r.text.lower():
                        found_pages.append({
                            'url': url,
                            'has_form': bool(forms),
                            'has_password_field': has_password
                        })
            except Exception:
                pass

        return found_pages

    def test_default_credentials(self, login_pages):
        print(
            f"  {Fore.CYAN}[*] Testing default "
            f"credentials...{Style.RESET_ALL}"
        )
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('administrator', 'administrator'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('admin', 'letmein'),
        ]

        success_indicators = [
            'dashboard', 'logout', 'welcome',
            'profile', 'settings', 'account',
            'signed in', 'logged in',
        ]
        failure_indicators = [
            'invalid', 'incorrect', 'wrong',
            'failed', 'error', 'denied',
            'unauthorized', 'bad credentials',
        ]

        for page in login_pages[:3]:
            url = page['url']
            try:
                r = self.session.get(
                    url, timeout=8
                )
                soup = BeautifulSoup(
                    r.text, 'html.parser'
                )
                form = soup.find('form')
                if not form:
                    continue

                inputs = form.find_all('input')
                user_field = None
                pass_field = None
                for inp in inputs:
                    itype = inp.get('type', '').lower()
                    iname = inp.get('name', '').lower()
                    if itype in ['text', 'email'] or any(
                        k in iname for k in [
                            'user', 'email', 'login',
                            'name', 'id'
                        ]
                    ):
                        user_field = inp.get('name')
                    elif itype == 'password':
                        pass_field = inp.get('name')

                if not user_field or not pass_field:
                    continue

                action = form.get('action', url)
                if not action.startswith('http'):
                    action = urljoin(url, action)

                for username, password in default_creds[:6]:
                    data = {
                        user_field: username,
                        pass_field: password
                    }
                    try:
                        resp = self.session.post(
                            action, data=data,
                            timeout=10,
                            allow_redirects=True
                        )
                        resp_lower = resp.text.lower()

                        success = any(
                            s in resp_lower
                            for s in success_indicators
                        )
                        failure = any(
                            f in resp_lower
                            for f in failure_indicators
                        )

                        if success and not failure:
                            self.findings.append({
                                'type': (
                                    'Default Credentials Accepted'
                                ),
                                'category': 'authentication',
                                'risk': 'CRITICAL',
                                'url': action,
                                'username': username,
                                'password': password,
                                'description': (
                                    f'Default credentials '
                                    f'"{username}:{password}" '
                                    f'accepted by application'
                                ),
                                'business_impact': (
                                    'Full account takeover. '
                                    'Attacker gains immediate access '
                                    'to admin/user panel'
                                ),
                                'fix': (
                                    '1. Change all default passwords\n'
                                    '2. Enforce strong password policy\n'
                                    '3. Implement account lockout\n'
                                    '4. Enable MFA immediately'
                                ),
                                'cvss_score': 9.8,
                                'cwe': 'CWE-798'
                            })
                            print(
                                f"  {Fore.RED}[!!!] DEFAULT CREDS: "
                                f"{username}:{password}"
                                f"{Style.RESET_ALL}"
                            )
                    except Exception:
                        pass
            except Exception:
                pass

        return self.findings

    def test_account_lockout(self, login_pages):
        print(
            f"  {Fore.CYAN}[*] Testing account "
            f"lockout...{Style.RESET_ALL}"
        )
        for page in login_pages[:2]:
            url = page['url']
            try:
                r = self.session.get(
                    url, timeout=8
                )
                soup = BeautifulSoup(
                    r.text, 'html.parser'
                )
                form = soup.find('form')
                if not form:
                    continue

                inputs = form.find_all('input')
                user_field = None
                pass_field = None
                for inp in inputs:
                    itype = inp.get('type', '').lower()
                    iname = inp.get('name', '').lower()
                    if itype in ['text', 'email'] or any(
                        k in iname for k in [
                            'user', 'email', 'login'
                        ]
                    ):
                        user_field = inp.get('name')
                    elif itype == 'password':
                        pass_field = inp.get('name')

                if not user_field or not pass_field:
                    continue

                action = form.get('action', url)
                if not action.startswith('http'):
                    action = urljoin(url, action)

                lockout_detected = False
                for i in range(10):
                    data = {
                        user_field: 'test_lockout_user',
                        pass_field: f'wrong_password_{i}'
                    }
                    try:
                        resp = self.session.post(
                            action, data=data,
                            timeout=8
                        )
                        resp_lower = resp.text.lower()
                        if any(
                            k in resp_lower for k in [
                                'locked', 'too many',
                                'blocked', 'suspended',
                                'temporarily', 'limit'
                            ]
                        ):
                            lockout_detected = True
                            break
                        if resp.status_code == 429:
                            lockout_detected = True
                            break
                    except Exception:
                        pass

                if not lockout_detected:
                    self.findings.append({
                        'type': 'Missing Account Lockout',
                        'category': 'authentication',
                        'risk': 'HIGH',
                        'url': url,
                        'description': (
                            'No account lockout after '
                            '10 failed login attempts'
                        ),
                        'business_impact': (
                            'Brute force attacks possible. '
                            'Attacker can guess passwords '
                            'without restriction'
                        ),
                        'fix': (
                            '1. Lock after 5 failed attempts\n'
                            '2. Implement progressive delay\n'
                            '3. Add CAPTCHA after failures\n'
                            '4. Alert on multiple failures'
                        ),
                        'cvss_score': 7.5,
                        'cwe': 'CWE-307'
                    })
                    print(
                        f"  {Fore.YELLOW}[!] No lockout on: "
                        f"{url}{Style.RESET_ALL}"
                    )
            except Exception:
                pass

        return self.findings

    def test_mfa_detection(self, login_pages):
        print(
            f"  {Fore.CYAN}[*] Checking MFA "
            f"indicators...{Style.RESET_ALL}"
        )
        mfa_indicators = [
            'two-factor', '2fa', 'totp',
            'authenticator', 'otp', 'verification code',
            'one-time', 'sms code', 'email code'
        ]
        for page in login_pages[:3]:
            try:
                r = self.session.get(
                    page['url'], timeout=8
                )
                resp_lower = r.text.lower()
                has_mfa = any(
                    m in resp_lower
                    for m in mfa_indicators
                )
                if not has_mfa:
                    self.findings.append({
                        'type': 'No MFA Detected on Login',
                        'category': 'authentication',
                        'risk': 'MEDIUM',
                        'url': page['url'],
                        'description': (
                            'No multi-factor authentication '
                            'indicators found on login page'
                        ),
                        'business_impact': (
                            'Compromised password = '
                            'full account access. '
                            'No second layer of protection'
                        ),
                        'fix': (
                            '1. Implement TOTP (Google Auth)\n'
                            '2. Add SMS/Email OTP\n'
                            '3. Use hardware keys (FIDO2)\n'
                            '4. Enforce MFA for admin accounts'
                        ),
                        'cvss_score': 6.5,
                        'cwe': 'CWE-308'
                    })
            except Exception:
                pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[AUTH AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        login_pages = self.detect_login_pages()
        print(
            f"  {Fore.CYAN}[*] Found "
            f"{len(login_pages)} login pages"
            f"{Style.RESET_ALL}"
        )
        if login_pages:
            self.test_default_credentials(login_pages)
            self.test_account_lockout(login_pages)
            self.test_mfa_detection(login_pages)
        else:
            self.findings.append({
                'type': 'No Login Page Found',
                'category': 'authentication',
                'risk': 'INFO',
                'description': (
                    'No standard login pages detected'
                ),
                'note': (
                    'Custom auth paths may exist'
                )
            })
        print(
            f"{Fore.GREEN}[AUTH AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
