import os
import requests
from urllib.parse import quote, urlparse
from colorama import Fore, Style, init

init(autoreset=True)


class XSSAgent:
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
            'payloads', 'xss_payloads.txt'
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
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
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

    def _determine_context(self, html, payload):
        pos = html.find(payload)
        if pos == -1:
            return 'unknown'
        before = html[max(0, pos - 100):pos]
        if '<script' in before:
            return 'javascript'
        elif 'value="' in html[max(0, pos - 20):pos]:
            return 'attribute_value'
        else:
            return 'html_body'

    def detect_reflected_xss(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing reflected "
            f"XSS...{Style.RESET_ALL}"
        )
        parsed = urlparse(url)

        if not parsed.query:
            test_params_list = [
                'q', 'search', 'id', 'name',
                'input', 's', 'term', 'keyword'
            ]
            test_urls = [
                f"{url}?{p}=test"
                for p in test_params_list[:4]
            ]
        else:
            test_urls = [url]

        for test_url in test_urls:
            parsed = urlparse(test_url)
            params = {}
            for param in parsed.query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v

            for param_name in list(params.keys())[:3]:
                for payload in self.payloads[:8]:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_target = self._build_test_url(
                        parsed, test_params
                    )
                    try:
                        r = self.session.get(
                            test_target,
                            timeout=10,
                            allow_redirects=True
                        )
                        if payload in r.text:
                            context = (
                                self._determine_context(
                                    r.text, payload
                                )
                            )
                            self.findings.append({
                                'type': 'Reflected XSS',
                                'category': 'xss',
                                'risk': 'HIGH',
                                'url': test_target,
                                'parameter': param_name,
                                'payload': payload,
                                'context': context,
                                'description': (
                                    f'XSS payload reflected in '
                                    f'"{param_name}" without '
                                    f'sanitization'
                                ),
                                'business_impact': (
                                    'Attacker can steal sessions, '
                                    'redirect users, capture creds'
                                ),
                                'fix': (
                                    '1. Encode all output\n'
                                    '2. Implement CSP header\n'
                                    '3. Use DOMPurify\n'
                                    '4. Validate inputs'
                                ),
                                'cvss_score': 7.2,
                                'cwe': 'CWE-79'
                            })
                            print(
                                f"  {Fore.RED}[!!!] XSS FOUND "
                                f"in: {param_name}"
                                f"{Style.RESET_ALL}"
                            )
                            break
                    except Exception:
                        pass

        return self.findings

    def detect_dom_xss_indicators(self, url):
        print(
            f"  {Fore.CYAN}[*] Checking DOM XSS "
            f"indicators...{Style.RESET_ALL}"
        )
        try:
            r = self.session.get(url, timeout=10)
            body = r.text

            dangerous_sinks = [
                'innerHTML', 'outerHTML',
                'document.write', 'document.writeln',
                'eval(', 'setTimeout(',
                'setInterval(', 'Function(',
                'execScript('
            ]
            dangerous_sources = [
                'location.hash', 'location.search',
                'location.href', 'document.URL',
                'document.referrer', 'window.name'
            ]

            found_sinks = [
                s for s in dangerous_sinks if s in body
            ]
            found_sources = [
                s for s in dangerous_sources if s in body
            ]

            if found_sinks or found_sources:
                self.findings.append({
                    'type': 'DOM XSS Indicators Found',
                    'category': 'xss',
                    'risk': 'MEDIUM',
                    'url': url,
                    'dangerous_sinks': found_sinks,
                    'dangerous_sources': found_sources,
                    'description': (
                        'Dangerous JavaScript patterns '
                        'detected - may lead to DOM XSS'
                    ),
                    'business_impact': (
                        'Client-side code execution '
                        'without server interaction'
                    ),
                    'fix': (
                        '1. Use textContent not innerHTML\n'
                        '2. Implement DOMPurify\n'
                        '3. Add strict CSP header'
                    ),
                    'note': (
                        'Manual verification required'
                    ),
                    'cvss_score': 6.1,
                    'cwe': 'CWE-79'
                })
        except Exception:
            pass

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[XSS AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.detect_reflected_xss(url)
            self.detect_dom_xss_indicators(url)
        print(
            f"{Fore.GREEN}[XSS AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
