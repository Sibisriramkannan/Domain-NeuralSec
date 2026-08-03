import json
import requests
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)


class GraphQLAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': (
                'SecurityAudit/1.0 (Authorized Assessment)'
            )
        })
        self.findings = []
        self.graphql_endpoints = []

    def discover_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Discovering GraphQL "
            f"endpoints...{Style.RESET_ALL}"
        )
        common_paths = [
            '/graphql', '/graphiql',
            '/api/graphql', '/v1/graphql',
            '/v2/graphql', '/gql',
            '/graph', '/graphql/console',
            '/playground', '/api/v1/graphql'
        ]

        for path in common_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.post(
                    url,
                    json={'query': '{__typename}'},
                    timeout=10
                )
                if r.status_code in [200, 400]:
                    ct = r.headers.get(
                        'Content-Type', ''
                    )
                    if 'application/json' in ct:
                        try:
                            data = r.json()
                            if (
                                'data' in data
                                or 'errors' in data
                            ):
                                self.graphql_endpoints.append(
                                    url
                                )
                                print(
                                    f"  {Fore.GREEN}[+] Found: "
                                    f"{url}{Style.RESET_ALL}"
                                )
                        except Exception:
                            pass
            except Exception:
                pass

        return self.graphql_endpoints

    def test_introspection(self, endpoint):
        print(
            f"  {Fore.CYAN}[*] Testing introspection "
            f"at {endpoint}...{Style.RESET_ALL}"
        )
        introspection_query = {
            'query': (
                '{ __schema { types '
                '{ name fields { name '
                'type { name } } } } }'
            )
        }
        try:
            r = self.session.post(
                endpoint,
                json=introspection_query,
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                if '__schema' in str(data):
                    types_data = (
                        data.get('data', {})
                        .get('__schema', {})
                        .get('types', [])
                    )
                    self.findings.append({
                        'type': (
                            'GraphQL Introspection Enabled'
                        ),
                        'category': 'graphql',
                        'risk': 'MEDIUM',
                        'url': endpoint,
                        'description': (
                            'Introspection enabled - '
                            'full API schema accessible'
                        ),
                        'schema_types_count': len(types_data),
                        'exposed_types': [
                            t.get('name')
                            for t in types_data[:10]
                            if t.get('name')
                            and not t['name'].startswith('__')
                        ],
                        'business_impact': (
                            'Attacker gets complete map '
                            'of all API endpoints'
                        ),
                        'fix': (
                            '1. Disable introspection in prod\n'
                            '2. Use query depth limiting\n'
                            '3. Implement field-level auth'
                        ),
                        'cvss_score': 5.3,
                        'cwe': 'CWE-200'
                    })
                    print(
                        f"  {Fore.YELLOW}[!] Introspection "
                        f"enabled{Style.RESET_ALL}"
                    )
        except Exception:
            pass
        return self.findings

    def test_batch_queries(self, endpoint):
        print(
            f"  {Fore.CYAN}[*] Testing batch "
            f"queries...{Style.RESET_ALL}"
        )
        batch_query = [
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
        ]
        try:
            r = self.session.post(
                endpoint,
                json=batch_query,
                timeout=10
            )
            if (
                r.status_code == 200
                and isinstance(r.json(), list)
            ):
                self.findings.append({
                    'type': 'GraphQL Batching Enabled',
                    'category': 'graphql',
                    'risk': 'MEDIUM',
                    'url': endpoint,
                    'description': (
                        'Batching enabled - DoS and '
                        'rate-limit bypass possible'
                    ),
                    'business_impact': (
                        'Thousands of queries in one '
                        'request, bypassing rate limits'
                    ),
                    'fix': (
                        '1. Disable batching\n'
                        '2. Limit batch size if needed\n'
                        '3. Rate limit per operation'
                    ),
                    'cvss_score': 5.0,
                    'cwe': 'CWE-770'
                })
        except Exception:
            pass
        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[GRAPHQL AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        endpoints = self.discover_endpoints()
        for endpoint in endpoints:
            self.test_introspection(endpoint)
            self.test_batch_queries(endpoint)
        print(
            f"{Fore.GREEN}[GRAPHQL AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
