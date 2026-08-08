import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


class CSRFAgent:
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

    def analyze_forms(self):
        print(
            f"  {Fore.CYAN}[*] Analyzing forms for "
            f"CSRF tokens...{Style.RESET_ALL}"
        )
        pages_to_check = [
            self.target,
            urljoin(self.target, '/login'),
            urljoin(self.target, '/register'),
            urljoin(self.target, '/profile'),
            urljoin(self.target, '/settings'),
            urljoin(self.target, '/account'),
        ]

        csrf_token_names = [
            'csrf', 'csrf_token', '_token',
            'csrfmiddlewaretoken', '_csrf',
            'authenticity_token', 'nonce',
            'x-csrf-token', 'csrfkey',
            'form_token', '__requestverificationtoken'
        ]

        for page_url in pages_to_check:
            try:
                r = self.session.get(
                    page_url, timeout=8
                )
                if r.status_code != 200:
                    continue

                soup = BeautifulSoup(
                    r.text, 'html.parser'
                )
                forms = soup.find_all('form')

                for form in forms:
                    method = form.get(
                        'method', 'get'
                    ).lower()
                    if method != 'post':
                        continue

                    inputs = form.find_all('input')
                    has_csrf = False
                    for inp in inputs:
                        name = inp.get(
                            'name', ''
                        ).lower()
                        if any(
                            t in name
                            for t in csrf_token_names
                        ):
                            has_csrf = True
                            break

                    # Check meta tags for CSRF
                    metas = soup.find_all('meta')
                    for meta in metas:
                        meta_name = meta.get(
                            'name', ''
                        ).lower()
                        if 'csrf' in meta_name:
                            has_csrf = True
                            break

                    if not has_csrf:
                        action = form.get(
                            'action', page_url
                        )
                        if not action.startswith('http'):
                            action = urljoin(
                                page_url, action
                            )

                        self.findings.append({
                            'type': (
                                'CSRF Token Missing on Form'
                            ),
                            'category': 'csrf',
                            'risk': 'HIGH',
                            'url': page_url,
                            'form_action': action,
                            'description': (
                                f'POST form at {page_url} '
                                f'has no CSRF token. '
                                f'Cross-site attacks possible.'
                            ),
                            'business_impact': (
                                'Attacker tricks logged-in '
                                'users to submit unwanted '
                                'actions (transfer money, '
                                'change email/password)'
                            ),
                            'fix': (
                                '1. Add CSRF token to all forms\n'
                                '2. Use SameSite=Strict cookies\n'
                                '3. Validate Origin/Referer header\n'
                                '4. Use double-submit pattern'
                            ),
                            'cvss_score': 8.8,
                            'cwe': 'CWE-352'
                        })
                        print(
                            f"  {Fore.YELLOW}[!] CSRF token "
                            f"missing: {page_url}"
                            f"{Style.RESET_ALL}"
                        )
            except Exception:
                pass

        return self.findings

    def test_samesite_cookie(self):
        print(
            f"  {Fore.CYAN}[*] Checking SameSite "
            f"cookie attribute...{Style.RESET_ALL}"
        )
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            set_cookie = r.headers.get(
                'Set-Cookie', ''
            )
            if set_cookie:
                if 'samesite' not in set_cookie.lower():
                    self.findings.append({
                        'type': 'SameSite Cookie Missing',
                        'category': 'csrf',
                        'risk': 'MEDIUM',
                        'url': self.target,
                        'description': (
                            'Cookies lack SameSite attribute. '
                            'CSRF attacks easier.'
                        ),
                        'fix': (
                            '1. Set SameSite=Strict or Lax\n'
                            '2. Review all cookie settings'
                        ),
                        'cvss_score': 6.5,
                        'cwe': 'CWE-352'
                    })
        except Exception:
            pass
        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[CSRF AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.analyze_forms()
        self.test_samesite_cookie()
        print(
            f"{Fore.GREEN}[CSRF AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
