import base64
import hashlib
import hmac
import json
import re
import requests
from colorama import Fore, Style, init

init(autoreset=True)


class JWTAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 (Authorized Assessment)'
            )
        })
        self.findings = []

    def find_jwts(self, response):
        jwt_pattern = (
            r'eyJ[A-Za-z0-9_-]+'
            r'\.'
            r'eyJ[A-Za-z0-9_-]+'
            r'\.'
            r'[A-Za-z0-9_-]*'
        )
        all_text = (
            str(response.headers) + response.text
        )
        return list(set(re.findall(jwt_pattern, all_text)))

    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            def decode_part(part):
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                return json.loads(
                    base64.urlsafe_b64decode(part)
                )

            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            signature = parts[2]
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw': token
            }
        except Exception:
            return None

    def analyze_token(self, token_data):
        findings = []
        header = token_data.get('header', {})
        payload = token_data.get('payload', {})
        algorithm = header.get('alg', '')

        if algorithm == 'none':
            findings.append({
                'type': 'JWT Algorithm None',
                'category': 'jwt',
                'risk': 'CRITICAL',
                'description': (
                    'JWT uses "none" algorithm - '
                    'signature not verified'
                ),
                'business_impact': (
                    'Attacker can forge any JWT token - '
                    'complete authentication bypass'
                ),
                'fix': (
                    '1. Never accept "none" algorithm\n'
                    '2. Use algorithm allowlist\n'
                    '3. Enforce RS256 or ES256'
                ),
                'cvss_score': 9.8,
                'cwe': 'CWE-347'
            })

        if algorithm == 'HS256':
            findings.append({
                'type': 'JWT Symmetric Algorithm (HS256)',
                'category': 'jwt',
                'risk': 'MEDIUM',
                'description': (
                    'JWT uses HS256 - symmetric signing. '
                    'Weak secrets are brute-forceable.'
                ),
                'fix': (
                    '1. Consider RS256 for asymmetric\n'
                    '2. Use strong random secret 256-bit\n'
                    '3. Rotate secrets regularly'
                ),
                'cvss_score': 5.0,
                'cwe': 'CWE-327'
            })

        sensitive_fields = [
            'password', 'secret', 'key',
            'credit_card', 'ssn', 'pwd', 'pass'
        ]
        found_sensitive = [
            f for f in sensitive_fields
            if f in str(payload).lower()
        ]
        if found_sensitive:
            findings.append({
                'type': 'Sensitive Data in JWT Payload',
                'category': 'jwt',
                'risk': 'HIGH',
                'description': (
                    f'Sensitive fields in payload: '
                    f'{found_sensitive}. '
                    f'JWT is base64 NOT encrypted.'
                ),
                'business_impact': (
                    'Anyone with the token can '
                    'decode and read sensitive data'
                ),
                'fix': (
                    '1. Remove sensitive data from JWT\n'
                    '2. Use JWE (encrypted JWT) if needed'
                ),
                'cvss_score': 7.5,
                'cwe': 'CWE-312'
            })

        exp = payload.get('exp')
        iat = payload.get('iat')

        if not exp:
            findings.append({
                'type': 'JWT Without Expiration',
                'category': 'jwt',
                'risk': 'HIGH',
                'description': (
                    'No expiration claim - token valid forever'
                ),
                'business_impact': (
                    'Stolen tokens remain valid indefinitely'
                ),
                'fix': (
                    '1. Always set exp claim\n'
                    '2. Use short expiry (15-60 min)\n'
                    '3. Implement token refresh'
                ),
                'cvss_score': 7.2,
                'cwe': 'CWE-613'
            })
        elif exp and iat:
            lifetime = exp - iat
            if lifetime > 86400 * 7:
                findings.append({
                    'type': 'JWT Long Expiration',
                    'category': 'jwt',
                    'risk': 'MEDIUM',
                    'description': (
                        f'JWT expires after '
                        f'{lifetime // 86400} days'
                    ),
                    'fix': (
                        'Access tokens: 15-60 minutes. '
                        'Refresh tokens: 7-30 days max'
                    ),
                    'cvss_score': 4.0,
                    'cwe': 'CWE-613'
                })

        return findings

    def test_weak_secret(self, token):
        common_secrets = [
            'secret', 'password', '123456',
            'changeme', 'admin', 'jwt_secret',
            'mysecret', 'key', 'test',
            'development', 'your-secret-key',
            'supersecret', 'secretkey',
            'my_secret', 'app_secret'
        ]
        try:
            parts = token.split('.')
            header_payload = (
                f"{parts[0]}.{parts[1]}"
            ).encode()
            actual_sig = parts[2]

            for secret in common_secrets:
                test_sig = (
                    base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            header_payload,
                            hashlib.sha256
                        ).digest()
                    ).rstrip(b'=').decode()
                )
                if test_sig == actual_sig:
                    return {
                        'type': 'JWT Weak Secret Found',
                        'category': 'jwt',
                        'risk': 'CRITICAL',
                        'weak_secret': secret,
                        'description': (
                            f'JWT signed with weak '
                            f'secret: "{secret}"'
                        ),
                        'business_impact': (
                            'Attacker forges tokens and '
                            'impersonates any user/admin'
                        ),
                        'fix': (
                            '1. Rotate JWT secret immediately\n'
                            '2. Use cryptographic random '
                            'secret (256+ bits)\n'
                            '3. Invalidate all existing tokens'
                        ),
                        'cvss_score': 9.8,
                        'cwe': 'CWE-521'
                    }
        except Exception:
            pass
        return None

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[JWT AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        print(
            f"  {Fore.CYAN}[*] Looking for JWT "
            f"tokens...{Style.RESET_ALL}"
        )
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            tokens = self.find_jwts(r)
            print(
                f"  {Fore.CYAN}[*] Found "
                f"{len(tokens)} token(s){Style.RESET_ALL}"
            )
            for token in tokens:
                decoded = self.decode_jwt(token)
                if decoded:
                    alg_findings = self.analyze_token(
                        decoded
                    )
                    self.findings.extend(alg_findings)
                    weak = self.test_weak_secret(token)
                    if weak:
                        self.findings.append(weak)
                        print(
                            f"  {Fore.RED}[!!!] WEAK SECRET "
                            f"FOUND!{Style.RESET_ALL}"
                        )
        except Exception:
            pass
        print(
            f"{Fore.GREEN}[JWT AGENT] Complete - "
            f"{len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
