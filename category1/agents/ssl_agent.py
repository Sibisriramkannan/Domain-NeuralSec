"""
SSL/TLS Security Agent
Checks certificate validity and TLS configuration
Safe passive check
"""

import ssl
import socket
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class SSLAgent:
    def __init__(self, target_domain):
        self.target = target_domain.replace(
            'https://', ''
        ).replace('http://', '').strip('/')
        self.results = {}

    def full_ssl_check(self):
        """Complete SSL/TLS security analysis"""
        print(
            f"\n{Fore.YELLOW}[SSL AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        print(
            f"  {Fore.CYAN}[*] Analyzing SSL/TLS "
            f"configuration...{Style.RESET_ALL}"
        )

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                (self.target, 443), timeout=15
            ) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=self.target
                ) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

            # Parse dates
            not_after = datetime.strptime(
                cert['notAfter'],
                '%b %d %H:%M:%S %Y %Z'
            )
            not_before = datetime.strptime(
                cert['notBefore'],
                '%b %d %H:%M:%S %Y %Z'
            )
            days_until_expiry = (
                not_after - datetime.now()
            ).days

            # Parse SANs
            sans = []
            for san_type, san_value in cert.get(
                'subjectAltName', []
            ):
                sans.append(
                    f"{san_type}: {san_value}"
                )

            # Parse issuer and subject
            issuer = {}
            for item in cert.get('issuer', []):
                for key, value in item:
                    issuer[key] = value

            subject = {}
            for item in cert.get('subject', []):
                for key, value in item:
                    subject[key] = value

            # Check issues
            issues = []

            if days_until_expiry < 0:
                issues.append({
                    'issue': 'Certificate EXPIRED',
                    'severity': 'CRITICAL',
                    'days': days_until_expiry,
                    'description': (
                        'SSL certificate has expired. '
                        'Browsers will show security warning'
                    ),
                    'fix': (
                        'Renew SSL certificate immediately'
                    ),
                    'business_impact': (
                        'Users cannot access your site '
                        'securely - major trust issue'
                    )
                })
            elif days_until_expiry < 14:
                issues.append({
                    'issue': (
                        f'Certificate expiring in '
                        f'{days_until_expiry} days'
                    ),
                    'severity': 'CRITICAL',
                    'description': (
                        'Certificate expires very soon'
                    ),
                    'fix': 'Renew SSL certificate TODAY',
                    'business_impact': (
                        'Site will go down for users soon'
                    )
                })
            elif days_until_expiry < 30:
                issues.append({
                    'issue': (
                        f'Certificate expiring in '
                        f'{days_until_expiry} days'
                    ),
                    'severity': 'HIGH',
                    'description': (
                        'Certificate expires within 30 days'
                    ),
                    'fix': (
                        'Renew SSL certificate this week'
                    ),
                    'business_impact': (
                        'Risk of unexpected downtime'
                    )
                })

            # Protocol version check
            weak_protocols = ['TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3']
            if version in weak_protocols:
                issues.append({
                    'issue': f'Weak TLS version: {version}',
                    'severity': 'HIGH',
                    'description': (
                        f'{version} has known vulnerabilities'
                    ),
                    'fix': 'Upgrade to TLS 1.2 or TLS 1.3',
                    'business_impact': (
                        'Traffic can be decrypted by attackers'
                    )
                })

            # Cipher suite check
            weak_ciphers = [
                'RC4', 'DES', '3DES', 'MD5',
                'NULL', 'EXPORT', 'anon'
            ]
            cipher_name = cipher[0] if cipher else ''
            if any(w in cipher_name for w in weak_ciphers):
                issues.append({
                    'issue': f'Weak cipher suite: {cipher_name}',
                    'severity': 'HIGH',
                    'description': (
                        'Weak cipher can be broken by attackers'
                    ),
                    'fix': (
                        'Configure strong cipher suites only'
                    ),
                    'business_impact': (
                        'Encrypted traffic may be compromised'
                    )
                })

            self.results = {
                'status': 'success',
                'https_enabled': True,
                'certificate': {
                    'subject': subject,
                    'issuer': issuer,
                    'valid_from': str(not_before),
                    'valid_until': str(not_after),
                    'days_until_expiry': days_until_expiry,
                    'is_expired': days_until_expiry < 0,
                    'expiry_status': (
                        'EXPIRED'
                        if days_until_expiry < 0
                        else 'CRITICAL'
                        if days_until_expiry < 14
                        else 'WARNING'
                        if days_until_expiry < 30
                        else 'OK'
                    ),
                    'san_domains': sans,
                    'san_count': len(sans),
                    'serial_number': cert.get(
                        'serialNumber', 'N/A'
                    ),
                },
                'tls': {
                    'version': version,
                    'cipher_suite': (
                        cipher[0] if cipher else 'Unknown'
                    ),
                    'cipher_bits': (
                        cipher[2] if cipher else 0
                    ),
                    'protocol_secure': (
                        version not in weak_protocols
                    ),
                },
                'issues': issues,
                'issue_count': len(issues),
                'overall_status': (
                    'CRITICAL'
                    if any(
                        i['severity'] == 'CRITICAL'
                        for i in issues
                    )
                    else 'HIGH'
                    if any(
                        i['severity'] == 'HIGH'
                        for i in issues
                    )
                    else 'GOOD'
                    if not issues
                    else 'MEDIUM'
                )
            }

        except ssl.SSLCertVerificationError as e:
            self.results = {
                'status': 'ssl_error',
                'https_enabled': True,
                'error': str(e),
                'issues': [{
                    'issue': 'SSL Certificate Verification Failed',
                    'severity': 'CRITICAL',
                    'description': (
                        'Certificate cannot be verified - '
                        'may be self-signed or expired'
                    ),
                    'fix': (
                        'Install valid SSL certificate '
                        'from trusted CA'
                    ),
                    'business_impact': (
                        'Browsers show security warnings, '
                        'users leave'
                    )
                }]
            }
        except ConnectionRefusedError:
            self.results = {
                'status': 'no_https',
                'https_enabled': False,
                'issues': [{
                    'issue': 'HTTPS Not Available',
                    'severity': 'CRITICAL',
                    'description': (
                        'Server is not listening on port 443'
                    ),
                    'fix': 'Install SSL certificate and enable HTTPS',
                    'business_impact': (
                        'All traffic unencrypted, '
                        'major security risk'
                    )
                }]
            }
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

        print(
            f"  {Fore.GREEN}[✓] SSL analysis "
            f"complete{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}[SSL AGENT] "
            f"Complete!{Style.RESET_ALL}"
        )
        return self.results
