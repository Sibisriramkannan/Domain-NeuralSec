"""
Email Security Agent
Checks SPF, DKIM, DMARC records
Safe DNS-based passive check
"""

import json
from colorama import Fore, Style, init

init(autoreset=True)


class EmailSecurityAgent:
    def __init__(self, target_domain):
        self.target = target_domain.replace(
            'https://', ''
        ).replace('http://', '').strip('/')
        self.results = {}

    def check_spf(self):
        """Check and analyze SPF record"""
        print(
            f"  {Fore.CYAN}[*] Checking SPF "
            f"record...{Style.RESET_ALL}"
        )
        try:
            import dns.resolver
            answers = dns.resolver.resolve(
                self.target, 'TXT'
            )
            spf_records = [
                str(r).strip('"')
                for r in answers
                if 'v=spf1' in str(r)
            ]

            if spf_records:
                spf = spf_records[0]
                issues = []
                recommendations = []

                if '+all' in spf:
                    issues.append({
                        'issue': 'SPF uses +all - allows everyone',
                        'risk': 'CRITICAL',
                        'description': (
                            '+all means anyone can send '
                            'email as your domain'
                        ),
                        'fix': (
                            'Change +all to -all for '
                            'strict enforcement'
                        )
                    })
                elif '~all' in spf:
                    issues.append({
                        'issue': (
                            'SPF uses ~all (softfail) - '
                            'not strict'
                        ),
                        'risk': 'MEDIUM',
                        'description': (
                            '~all means unauthorized emails '
                            'are marked as spam but not rejected'
                        ),
                        'fix': 'Consider changing ~all to -all'
                    })
                elif '?all' in spf:
                    issues.append({
                        'issue': 'SPF uses ?all (neutral)',
                        'risk': 'HIGH',
                        'description': (
                            '?all provides no protection '
                            'against email spoofing'
                        ),
                        'fix': (
                            'Change ?all to -all immediately'
                        )
                    })

                # Count DNS lookups (max 10 allowed)
                lookup_count = (
                    spf.count(' include:')
                    + spf.count(' a ')
                    + spf.count(' mx ')
                    + spf.count(' ptr ')
                    + spf.count(' exists:')
                    + spf.count(' redirect=')
                )
                if lookup_count > 8:
                    issues.append({
                        'issue': (
                            f'Too many DNS lookups: '
                            f'{lookup_count}/10'
                        ),
                        'risk': 'MEDIUM',
                        'description': (
                            'Exceeding 10 DNS lookups '
                            'causes SPF to fail'
                        ),
                        'fix': (
                            'Flatten SPF record to reduce '
                            'DNS lookups'
                        )
                    })

                if len(spf_records) > 1:
                    issues.append({
                        'issue': 'Multiple SPF records found',
                        'risk': 'HIGH',
                        'description': (
                            'Only one SPF record allowed per domain. '
                            'Multiple records cause SPF to fail'
                        ),
                        'fix': (
                            'Merge all SPF records into one'
                        )
                    })

                return {
                    'exists': True,
                    'record': spf,
                    'all_mechanism': (
                        '+all'
                        if '+all' in spf
                        else '-all'
                        if '-all' in spf
                        else '~all'
                        if '~all' in spf
                        else '?all'
                        if '?all' in spf
                        else 'none'
                    ),
                    'multiple_records': len(spf_records) > 1,
                    'dns_lookup_count': lookup_count,
                    'issues': issues,
                    'status': (
                        'SECURE'
                        if '-all' in spf and not issues
                        else 'VULNERABLE'
                    )
                }
            else:
                return {
                    'exists': False,
                    'risk': 'HIGH',
                    'description': (
                        'No SPF record found. Attackers can '
                        'send emails pretending to be '
                        'from your domain'
                    ),
                    'business_impact': (
                        'Phishing emails can be sent '
                        'using your domain name - '
                        'damages brand reputation'
                    ),
                    'fix': (
                        'Add SPF record: v=spf1 '
                        'include:yourprovider.com -all'
                    ),
                    'status': 'MISSING'
                }
        except ImportError:
            return {
                'error': 'dnspython not installed',
                'fix': 'pip install dnspython'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }

    def check_dmarc(self):
        """Check and analyze DMARC record"""
        print(
            f"  {Fore.CYAN}[*] Checking DMARC "
            f"record...{Style.RESET_ALL}"
        )
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(
                    f'_dmarc.{self.target}', 'TXT'
                )
                dmarc_records = [
                    str(r).strip('"')
                    for r in answers
                    if 'v=DMARC1' in str(r)
                ]
            except dns.resolver.NXDOMAIN:
                dmarc_records = []

            if dmarc_records:
                dmarc = dmarc_records[0]
                issues = []

                # Parse DMARC tags
                tags = {}
                for tag in dmarc.split(';'):
                    tag = tag.strip()
                    if '=' in tag:
                        key, value = tag.split('=', 1)
                        tags[key.strip()] = value.strip()

                policy = tags.get('p', 'none')
                sp_policy = tags.get('sp', policy)
                pct = int(tags.get('pct', 100))

                if policy == 'none':
                    issues.append({
                        'issue': 'DMARC policy is none',
                        'risk': 'HIGH',
                        'description': (
                            'Policy=none means DMARC only '
                            'monitors - no enforcement'
                        ),
                        'fix': (
                            'Change to p=quarantine '
                            'or p=reject'
                        )
                    })
                elif policy == 'quarantine' and pct < 100:
                    issues.append({
                        'issue': (
                            f'DMARC pct={pct}% - '
                            f'not full enforcement'
                        ),
                        'risk': 'MEDIUM',
                        'description': (
                            f'Only {pct}% of emails '
                            f'are subject to DMARC policy'
                        ),
                        'fix': (
                            'Increase pct to 100 '
                            'after monitoring'
                        )
                    })

                if 'rua' not in tags:
                    issues.append({
                        'issue': (
                            'No aggregate reporting '
                            'configured'
                        ),
                        'risk': 'LOW',
                        'description': (
                            'rua= missing means you '
                            'get no email authentication reports'
                        ),
                        'fix': (
                            'Add rua=mailto:'
                            'dmarc@yourdomain.com'
                        )
                    })

                return {
                    'exists': True,
                    'record': dmarc,
                    'tags': tags,
                    'policy': policy,
                    'subdomain_policy': sp_policy,
                    'percentage': pct,
                    'has_reporting': 'rua' in tags,
                    'has_forensic_reporting': 'ruf' in tags,
                    'issues': issues,
                    'enforcement_level': (
                        'FULL'
                        if policy == 'reject'
                        else 'PARTIAL'
                        if policy == 'quarantine'
                        else 'NONE'
                    ),
                    'status': (
                        'SECURE'
                        if policy == 'reject'
                        and pct == 100
                        and not issues
                        else 'PARTIAL'
                        if policy in ['quarantine', 'reject']
                        else 'VULNERABLE'
                    )
                }
            else:
                return {
                    'exists': False,
                    'risk': 'HIGH',
                    'description': (
                        'No DMARC record found. '
                        'Email spoofing not prevented'
                    ),
                    'business_impact': (
                        'Brand reputation at risk from '
                        'phishing campaigns using your domain'
                    ),
                    'fix': (
                        'Add: _dmarc.yourdomain.com TXT '
                        '"v=DMARC1; p=reject; '
                        'rua=mailto:dmarc@yourdomain.com"'
                    ),
                    'status': 'MISSING'
                }
        except ImportError:
            return {
                'error': 'dnspython not installed'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }

    def check_dkim(self):
        """Check common DKIM selectors"""
        print(
            f"  {Fore.CYAN}[*] Checking DKIM "
            f"selectors...{Style.RESET_ALL}"
        )
        try:
            import dns.resolver
            common_selectors = [
                'default', 'google', 'selector1',
                'selector2', 'k1', 'k2', 'mail',
                'dkim', 's1', 's2', 'mandrill',
                'everlytickey1', 'mxvault', 'smtp',
                'email', 'key1', 'key2', 'pm',
                'mailchimp', 'sendgrid', 'ses',
                'amazonses', 'mailjet', 'postmark',
            ]

            found_selectors = []
            checked_count = 0

            for selector in common_selectors:
                try:
                    dkim_domain = (
                        f"{selector}._domainkey."
                        f"{self.target}"
                    )
                    answers = dns.resolver.resolve(
                        dkim_domain, 'TXT'
                    )
                    record = str(list(answers)[0])
                    checked_count += 1

                    # Parse key type
                    key_type = 'RSA'
                    if 'k=rsa' in record.lower():
                        key_type = 'RSA'
                    elif 'k=ed25519' in record.lower():
                        key_type = 'Ed25519'

                    found_selectors.append({
                        'selector': selector,
                        'domain': dkim_domain,
                        'record_preview': record[:100],
                        'key_type': key_type,
                        'status': 'FOUND'
                    })
                except dns.resolver.NXDOMAIN:
                    checked_count += 1
                except Exception:
                    pass

            if found_selectors:
                return {
                    'exists': True,
                    'selectors_found': found_selectors,
                    'selector_count': len(found_selectors),
                    'status': 'FOUND',
                    'note': (
                        f'Found {len(found_selectors)} '
                        f'DKIM selector(s)'
                    )
                }
            else:
                return {
                    'exists': False,
                    'checked_selectors': len(common_selectors),
                    'risk': 'MEDIUM',
                    'description': (
                        'No common DKIM selectors found. '
                        'Custom selectors may exist'
                    ),
                    'note': (
                        'DKIM may be configured with '
                        'a custom selector not in our list'
                    ),
                    'fix': (
                        'Ensure DKIM is configured '
                        'for your email provider'
                    ),
                    'status': 'NOT_FOUND'
                }
        except ImportError:
            return {
                'error': 'dnspython not installed'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }

    def check_mx_records(self):
        """Check MX records"""
        print(
            f"  {Fore.CYAN}[*] Checking MX "
            f"records...{Style.RESET_ALL}"
        )
        try:
            import dns.resolver
            answers = dns.resolver.resolve(
                self.target, 'MX'
            )
            mx_records = []

            for r in answers:
                mx_str = str(r.exchange).rstrip('.')
                provider = self._identify_email_provider(
                    mx_str
                )
                mx_records.append({
                    'priority': r.preference,
                    'server': mx_str,
                    'provider': provider
                })

            mx_records.sort(key=lambda x: x['priority'])

            return {
                'exists': True,
                'records': mx_records,
                'primary_mx': (
                    mx_records[0]['server']
                    if mx_records
                    else 'Unknown'
                ),
                'email_provider': (
                    mx_records[0]['provider']
                    if mx_records
                    else 'Unknown'
                )
            }
        except Exception as e:
            return {
                'exists': False,
                'error': str(e)
            }

    def _identify_email_provider(self, mx):
        """Identify email provider from MX record"""
        mx_lower = mx.lower()
        providers = {
            'google': 'Google Workspace',
            'googlemail': 'Google Workspace',
            'outlook': 'Microsoft 365',
            'hotmail': 'Microsoft 365',
            'office365': 'Microsoft 365',
            'protection.outlook': 'Microsoft 365',
            'zoho': 'Zoho Mail',
            'yahoodns': 'Yahoo Mail',
            'protonmail': 'ProtonMail',
            'mailgun': 'Mailgun',
            'sendgrid': 'SendGrid',
            'amazonses': 'Amazon SES',
            'mailchimp': 'Mailchimp',
            'fastmail': 'Fastmail',
        }

        for key, provider in providers.items():
            if key in mx_lower:
                return provider
        return 'Custom/Unknown'

    def run_full_check(self):
        """Run all email security checks"""
        print(
            f"\n{Fore.YELLOW}[EMAIL SECURITY AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )

        spf = self.check_spf()
        dmarc = self.check_dmarc()
        dkim = self.check_dkim()
        mx = self.check_mx_records()

        # Calculate email security score
        score = 0
        if spf.get('exists'):
            score += 30
            if spf.get('status') == 'SECURE':
                score += 5
        if dmarc.get('exists'):
            score += 35
            if dmarc.get('enforcement_level') == 'FULL':
                score += 10
        if dkim.get('exists'):
            score += 30

        self.results = {
            'spf': spf,
            'dmarc': dmarc,
            'dkim': dkim,
            'mx_records': mx,
            'email_security_score': {
                'score': min(score, 100),
                'grade': (
                    'A' if score >= 90
                    else 'B' if score >= 70
                    else 'C' if score >= 50
                    else 'D' if score >= 30
                    else 'F'
                ),
                'summary': {
                    'spf_configured': spf.get(
                        'exists', False
                    ),
                    'dmarc_configured': dmarc.get(
                        'exists', False
                    ),
                    'dkim_detected': dkim.get(
                        'exists', False
                    ),
                    'fully_protected': (
                        spf.get('exists', False)
                        and dmarc.get('exists', False)
                        and dkim.get('exists', False)
                    )
                }
            }
        }

        print(
            f"  {Fore.GREEN}[✓] Email security score: "
            f"{min(score, 100)}/100{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}[EMAIL SECURITY AGENT] "
            f"Complete!{Style.RESET_ALL}"
        )
        return self.results
