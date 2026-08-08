"""
Reconnaissance Agent
Passive public information gathering
NO active scanning - safe to use
"""

import socket
import json
import requests
import whois
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class ReconAgent:
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

    def tech_stack_detection(self):
        """Detect technology stack from public signals"""
        print(
            f"  {Fore.CYAN}[*] Detecting tech stack...{Style.RESET_ALL}"
        )
        try:
            response = self.session.get(
                f"https://{self.target}", timeout=15
            )
            headers = response.headers
            body = response.text.lower()

            # Header-based detection
            header_indicators = {
                'X-Powered-By': headers.get(
                    'X-Powered-By', None
                ),
                'Server': headers.get('Server', None),
                'X-AspNet-Version': headers.get(
                    'X-AspNet-Version', None
                ),
                'X-Generator': headers.get(
                    'X-Generator', None
                ),
                'X-Drupal-Cache': headers.get(
                    'X-Drupal-Cache', None
                ),
                'X-Shopify-Stage': headers.get(
                    'X-Shopify-Stage', None
                ),
            }
            # Remove None values
            header_indicators = {
                k: v for k, v in header_indicators.items()
                if v is not None
            }

            # Body-based framework detection
            framework_patterns = {
                'WordPress': [
                    'wp-content', 'wp-includes',
                    'wp-json', 'wordpress'
                ],
                'Drupal': [
                    'drupal', 'sites/default',
                    'drupal.js'
                ],
                'Joomla': [
                    'joomla', '/components/com_',
                    'option=com_'
                ],
                'Magento': [
                    'magento', 'mage/', 'varien'
                ],
                'Shopify': [
                    'shopify', 'cdn.shopify.com',
                    'myshopify.com'
                ],
                'Wix': ['wix.com', 'wixstatic.com'],
                'Squarespace': [
                    'squarespace', 'sqsp.net'
                ],
                'Next.js': [
                    '__next', '_next/static',
                    'next.js'
                ],
                'React': [
                    'react-dom', '__react',
                    'data-reactroot'
                ],
                'Angular': [
                    'ng-version', 'angular.min.js',
                    'ng-app'
                ],
                'Vue.js': [
                    'vue.js', 'vue.min.js',
                    '__vue__'
                ],
                'Laravel': [
                    'laravel', 'laravel_session',
                    'illuminate'
                ],
                'Django': [
                    'django', 'csrfmiddlewaretoken',
                    '__admin'
                ],
                'Ruby on Rails': [
                    'rails', 'ruby-on-rails',
                    '_rails_'
                ],
                'Bootstrap': [
                    'bootstrap.min.css',
                    'bootstrap.min.js'
                ],
                'jQuery': [
                    'jquery.min.js', 'jquery-'
                ],
            }

            detected_frameworks = []
            for framework, patterns in (
                framework_patterns.items()
            ):
                if any(p in body for p in patterns):
                    detected_frameworks.append(framework)

            # Meta tag analysis
            soup = BeautifulSoup(
                response.text, 'html.parser'
            )
            meta_generator = soup.find(
                'meta', {'name': 'generator'}
            )
            generator = (
                meta_generator.get('content', '')
                if meta_generator else ''
            )

            result = {
                'status': 'success',
                'header_indicators': header_indicators,
                'detected_frameworks': detected_frameworks,
                'meta_generator': generator,
                'page_title': (
                    soup.title.string.strip()
                    if soup.title else 'N/A'
                ),
                'response_code': response.status_code,
                'content_type': headers.get(
                    'Content-Type', 'Unknown'
                ),
            }

            # Risk assessment
            risks = []
            if header_indicators.get('X-Powered-By'):
                risks.append({
                    'issue': 'X-Powered-By header exposes '
                             'technology',
                    'value': header_indicators[
                        'X-Powered-By'
                    ],
                    'risk': 'MEDIUM',
                    'fix': 'Remove X-Powered-By header '
                           'from server config'
                })
            if header_indicators.get('Server'):
                server_val = header_indicators['Server']
                if any(
                    v in server_val
                    for v in [
                        'Apache/2', 'nginx/1',
                        'IIS/7', 'IIS/8'
                    ]
                ):
                    risks.append({
                        'issue': 'Server version number '
                                 'exposed',
                        'value': server_val,
                        'risk': 'MEDIUM',
                        'fix': 'Hide version number in '
                               'server configuration'
                    })
            if 'WordPress' in detected_frameworks:
                risks.append({
                    'issue': 'WordPress detected - '
                             'ensure plugins are updated',
                    'risk': 'INFO',
                    'fix': 'Keep WordPress core and '
                           'plugins updated'
                })

            result['risks'] = risks
            self.results['tech_stack'] = result
            print(
                f"  {Fore.GREEN}[✓] Tech stack "
                f"detection complete{Style.RESET_ALL}"
            )
            return result

        except requests.exceptions.SSLError:
            result = {
                'status': 'ssl_error',
                'error': 'SSL certificate issue',
                'risk': 'HIGH'
            }
            self.results['tech_stack'] = result
            return result
        except Exception as e:
            result = {
                'status': 'error',
                'error': str(e)
            }
            self.results['tech_stack'] = result
            return result

    def subdomain_enumeration(self):
        """Passive subdomain discovery"""
        print(
            f"  {Fore.CYAN}[*] Enumerating "
            f"subdomains...{Style.RESET_ALL}"
        )
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api',
            'dev', 'staging', 'test', 'portal',
            'blog', 'shop', 'app', 'dashboard',
            'cdn', 'media', 'static', 'docs',
            'support', 'help', 'status', 'monitor',
            'remote', 'vpn', 'git', 'gitlab',
            'jenkins', 'jira', 'confluence',
            'smtp', 'pop', 'imap', 'webmail',
            'ns1', 'ns2', 'm', 'mobile', 'beta',
            'demo', 'old', 'new', 'secure',
            'login', 'auth', 'sso', 'id',
        ]

        found = []
        not_found = []

        for sub in common_subdomains:
            try:
                host = f"{sub}.{self.target}"
                ip = socket.gethostbyname(host)
                found.append({
                    'subdomain': host,
                    'ip': ip,
                    'risk': self._assess_subdomain_risk(sub)
                })
            except socket.gaierror:
                not_found.append(f"{sub}.{self.target}")

        result = {
            'found_count': len(found),
            'found': found,
            'high_risk_found': [
                s for s in found
                if s['risk'] == 'HIGH'
            ]
        }

        self.results['subdomains'] = result
        print(
            f"  {Fore.GREEN}[✓] Found {len(found)} "
            f"subdomains{Style.RESET_ALL}"
        )
        return result

    def _assess_subdomain_risk(self, subdomain):
        """Assess risk level of found subdomain"""
        high_risk = [
            'admin', 'dev', 'staging', 'test',
            'jenkins', 'gitlab', 'git', 'jira',
            'confluence', 'vpn', 'remote', 'beta',
            'old', 'backup'
        ]
        medium_risk = [
            'api', 'portal', 'dashboard', 'secure',
            'login', 'auth', 'sso', 'id', 'demo'
        ]

        if subdomain in high_risk:
            return 'HIGH'
        elif subdomain in medium_risk:
            return 'MEDIUM'
        return 'LOW'

    def robots_sitemap_check(self):
        """Check robots.txt and sitemap for
           exposed information"""
        print(
            f"  {Fore.CYAN}[*] Checking robots.txt "
            f"and sitemap...{Style.RESET_ALL}"
        )
        findings = {}

        # robots.txt
        try:
            r = self.session.get(
                f"https://{self.target}/robots.txt",
                timeout=10
            )
            if r.status_code == 200:
                content = r.text
                sensitive_patterns = [
                    'admin', 'api', 'private', 'secret',
                    'backup', 'config', 'dashboard',
                    'internal', 'staging', 'dev',
                    'test', 'temp', 'old', 'hidden'
                ]
                sensitive_paths = []
                for line in content.split('\n'):
                    if 'disallow' in line.lower():
                        for pattern in sensitive_patterns:
                            if pattern in line.lower():
                                sensitive_paths.append(
                                    line.strip()
                                )

                findings['robots_txt'] = {
                    'exists': True,
                    'content': content[:2000],
                    'sensitive_paths_found': (
                        sensitive_paths
                    ),
                    'risk': (
                        'MEDIUM'
                        if sensitive_paths
                        else 'LOW'
                    ),
                    'note': (
                        'Sensitive paths listed in '
                        'Disallow may reveal hidden '
                        'endpoints'
                        if sensitive_paths
                        else 'No sensitive paths found'
                    )
                }
            else:
                findings['robots_txt'] = {
                    'exists': False,
                    'status_code': r.status_code
                }
        except Exception as e:
            findings['robots_txt'] = {
                'exists': False,
                'error': str(e)
            }

        # sitemap.xml
        sitemap_paths = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap.php',
            '/sitemap.txt'
        ]

        for path in sitemap_paths:
            try:
                r = self.session.get(
                    f"https://{self.target}{path}",
                    timeout=10
                )
                if r.status_code == 200:
                    url_count = r.text.count('<url>')
                    findings['sitemap'] = {
                        'exists': True,
                        'path': path,
                        'url_count': url_count,
                        'note': (
                            f'Found {url_count} URLs '
                            f'in sitemap'
                        )
                    }
                    break
            except:
                pass
        else:
            findings['sitemap'] = {
                'exists': False
            }

        self.results['robots_sitemap'] = findings
        print(
            f"  {Fore.GREEN}[✓] Robots/Sitemap "
            f"check complete{Style.RESET_ALL}"
        )
        return findings

    def exposed_paths_check(self):
        """Check for commonly exposed sensitive paths"""
        print(
            f"  {Fore.CYAN}[*] Checking exposed "
            f"paths...{Style.RESET_ALL}"
        )
        sensitive_paths = {
            '/.env': {
                'risk': 'CRITICAL',
                'description': 'Environment file exposed'
            },
            '/.git/config': {
                'risk': 'CRITICAL',
                'description': 'Git repository exposed'
            },
            '/.git/HEAD': {
                'risk': 'CRITICAL',
                'description': 'Git HEAD file exposed'
            },
            '/phpinfo.php': {
                'risk': 'HIGH',
                'description': 'PHP info page exposed'
            },
            '/server-status': {
                'risk': 'HIGH',
                'description': 'Apache server status exposed'
            },
            '/server-info': {
                'risk': 'HIGH',
                'description': 'Apache server info exposed'
            },
            '/.htaccess': {
                'risk': 'HIGH',
                'description': 'Apache config file exposed'
            },
            '/web.config': {
                'risk': 'HIGH',
                'description': 'IIS config file exposed'
            },
            '/wp-admin/': {
                'risk': 'MEDIUM',
                'description': 'WordPress admin panel exposed'
            },
            '/wp-config.php': {
                'risk': 'CRITICAL',
                'description': 'WordPress config exposed'
            },
            '/wp-login.php': {
                'risk': 'MEDIUM',
                'description': 'WordPress login page'
            },
            '/admin/': {
                'risk': 'HIGH',
                'description': 'Admin panel exposed'
            },
            '/administrator/': {
                'risk': 'HIGH',
                'description': 'Admin panel exposed'
            },
            '/backup/': {
                'risk': 'CRITICAL',
                'description': 'Backup directory exposed'
            },
            '/backup.zip': {
                'risk': 'CRITICAL',
                'description': 'Backup file exposed'
            },
            '/backup.sql': {
                'risk': 'CRITICAL',
                'description': 'Database backup exposed'
            },
            '/api/docs': {
                'risk': 'MEDIUM',
                'description': 'API documentation exposed'
            },
            '/swagger-ui.html': {
                'risk': 'MEDIUM',
                'description': 'Swagger UI exposed'
            },
            '/swagger.json': {
                'risk': 'MEDIUM',
                'description': 'Swagger definition exposed'
            },
            '/openapi.json': {
                'risk': 'MEDIUM',
                'description': 'OpenAPI spec exposed'
            },
            '/graphql': {
                'risk': 'MEDIUM',
                'description': 'GraphQL endpoint exposed'
            },
            '/actuator': {
                'risk': 'HIGH',
                'description': 'Spring Boot actuator exposed'
            },
            '/actuator/health': {
                'risk': 'LOW',
                'description': 'Health endpoint exposed'
            },
            '/actuator/env': {
                'risk': 'CRITICAL',
                'description': 'Spring environment exposed'
            },
            '/.well-known/security.txt': {
                'risk': 'INFO',
                'description': 'Security contact info'
            },
            '/package.json': {
                'risk': 'MEDIUM',
                'description': 'Package.json exposed'
            },
            '/composer.json': {
                'risk': 'MEDIUM',
                'description': 'Composer config exposed'
            },
            '/.DS_Store': {
                'risk': 'MEDIUM',
                'description': 'Mac OS DS_Store exposed'
            },
            '/crossdomain.xml': {
                'risk': 'MEDIUM',
                'description': 'Crossdomain policy exposed'
            },
            '/elmah.axd': {
                'risk': 'HIGH',
                'description': 'ELMAH error log exposed'
            },
            '/trace.axd': {
                'risk': 'HIGH',
                'description': 'ASP.NET trace exposed'
            },
            '/config.json': {
                'risk': 'HIGH',
                'description': 'Config file exposed'
            },
            '/debug': {
                'risk': 'HIGH',
                'description': 'Debug endpoint exposed'
            },
            '/test': {
                'risk': 'LOW',
                'description': 'Test endpoint exists'
            },
        }

        exposed = []
        checked = 0

        for path, info in sensitive_paths.items():
            try:
                r = self.session.get(
                    f"https://{self.target}{path}",
                    timeout=5,
                    allow_redirects=False
                )
                checked += 1
                if r.status_code in [200, 403]:
                    exposed.append({
                        'path': path,
                        'status_code': r.status_code,
                        'content_length': len(r.content),
                        'risk': info['risk'],
                        'description': info['description'],
                        'accessible': (
                            r.status_code == 200
                        ),
                        'note': (
                            'Returns 403 - exists but '
                            'protected'
                            if r.status_code == 403
                            else 'Publicly accessible!'
                        )
                    })
            except Exception:
                pass

        result = {
            'checked_count': checked,
            'exposed_count': len(exposed),
            'exposed_paths': exposed,
            'critical': [
                e for e in exposed
                if e['risk'] == 'CRITICAL'
            ],
            'high': [
                e for e in exposed
                if e['risk'] == 'HIGH'
            ],
            'medium': [
                e for e in exposed
                if e['risk'] == 'MEDIUM'
            ],
        }

        self.results['exposed_paths'] = result
        print(
            f"  {Fore.GREEN}[✓] Found {len(exposed)} "
            f"exposed paths{Style.RESET_ALL}"
        )
        return result

    def whois_lookup(self):
        """WHOIS information gathering"""
        print(
            f"  {Fore.CYAN}[*] Running WHOIS "
            f"lookup...{Style.RESET_ALL}"
        )
        try:
            w = whois.whois(self.target)
            result = {
                'registrar': str(
                    w.registrar or 'Unknown'
                ),
                'creation_date': str(
                    w.creation_date or 'Unknown'
                ),
                'expiration_date': str(
                    w.expiration_date or 'Unknown'
                ),
                'updated_date': str(
                    w.updated_date or 'Unknown'
                ),
                'name_servers': (
                    w.name_servers
                    if isinstance(w.name_servers, list)
                    else [str(w.name_servers)]
                ),
                'status': str(w.status or 'Unknown'),
                'emails': (
                    w.emails
                    if isinstance(w.emails, list)
                    else [str(w.emails)]
                    if w.emails
                    else []
                ),
                'organization': str(
                    w.org or 'Unknown'
                ),
                'country': str(
                    w.country or 'Unknown'
                ),
            }
            self.results['whois'] = result
            print(
                f"  {Fore.GREEN}[✓] WHOIS "
                f"complete{Style.RESET_ALL}"
            )
            return result
        except Exception as e:
            result = {
                'error': str(e),
                'status': 'failed'
            }
            self.results['whois'] = result
            return result

    def run_full_recon(self):
        """Run all reconnaissance checks"""
        print(
            f"\n{Fore.YELLOW}[RECON AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        self.tech_stack_detection()
        self.subdomain_enumeration()
        self.robots_sitemap_check()
        self.exposed_paths_check()
        self.whois_lookup()
        print(
            f"{Fore.GREEN}[RECON AGENT] "
            f"Complete!{Style.RESET_ALL}"
        )
        return self.results
