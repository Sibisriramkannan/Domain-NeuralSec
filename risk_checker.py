"""
Risk Checker - Analyzes target before scan
Determines if anti-track protection needed
"""

import os
import re
import socket
import requests
import json
from colorama import Fore, Style, init

init(autoreset=True)


class RiskChecker:
    """
    Checks target domain risk level.
    Determines if anti-tracking needed.
    """

    def __init__(self, target):
        self.target = (
            target
            .replace('https://', '')
            .replace('http://', '')
            .strip('/')
            .split('/')[0]
        )
        self.risk_score = 0
        self.risk_factors = []
        self.risk_level = 'LOW'

    def check_target_type(self):
        """
        Is this a government, law enforcement,
        financial, or sensitive target?
        """
        high_risk_tlds = [
            '.gov', '.mil', '.edu',
            '.gov.in', '.gov.uk', '.gov.au',
            '.police', '.fed', '.state',
        ]
        medium_risk_tlds = [
            '.bank', '.finance',
            '.healthcare', '.hospital',
            '.pharma',
        ]

        high_risk_keywords = [
            'government', 'police', 'military',
            'defense', 'intelligence', 'fbi',
            'cia', 'nsa', 'interpol', 'dea',
            'ministry', 'federal', 'national',
            'security', 'army', 'navy', 'airforce',
        ]
        medium_risk_keywords = [
            'bank', 'finance', 'insurance',
            'healthcare', 'hospital', 'medical',
            'legal', 'law', 'court', 'justice',
            'crypto', 'blockchain', 'payment',
        ]

        target_lower = self.target.lower()

        for tld in high_risk_tlds:
            if target_lower.endswith(tld):
                self.risk_score += 40
                self.risk_factors.append(
                    f'High-risk TLD: {tld}'
                )

        for tld in medium_risk_tlds:
            if target_lower.endswith(tld):
                self.risk_score += 20
                self.risk_factors.append(
                    f'Medium-risk TLD: {tld}'
                )

        for kw in high_risk_keywords:
            if kw in target_lower:
                self.risk_score += 30
                self.risk_factors.append(
                    f'High-risk keyword: {kw}'
                )
                break

        for kw in medium_risk_keywords:
            if kw in target_lower:
                self.risk_score += 15
                self.risk_factors.append(
                    f'Medium-risk keyword: {kw}'
                )
                break

    def check_ip_reputation(self):
        """
        Check if target IP has security monitoring.
        """
        try:
            ip = socket.gethostbyname(self.target)

            # Check if it's a CDN/WAF
            cdn_indicators = [
                'cloudflare', 'akamai', 'fastly',
                'cloudfront', 'incapsula', 'sucuri',
                'imperva', 'f5', 'barracuda',
            ]

            try:
                r = requests.get(
                    f'https://{self.target}',
                    timeout=5
                )
                headers_str = str(
                    r.headers
                ).lower()

                for cdn in cdn_indicators:
                    if cdn in headers_str:
                        self.risk_score += 20
                        self.risk_factors.append(
                            f'WAF/CDN detected: {cdn}'
                        )
                        break

                # Check for security headers
                # indicating active monitoring
                monitoring_headers = [
                    'x-request-id',
                    'x-correlation-id',
                    'x-trace-id',
                    'x-amzn-trace-id',
                ]
                for h in monitoring_headers:
                    if h in r.headers:
                        self.risk_score += 10
                        self.risk_factors.append(
                            f'Request tracking: {h}'
                        )
                        break

            except Exception:
                pass

        except Exception:
            pass

    def check_threat_intel(self):
        """
        Basic threat intelligence check.
        Is this target known to monitor scanners?
        """
        # Known targets that actively
        # monitor and report scanners
        known_monitored = [
            'shodan.io', 'censys.io',
            'zoomeye.org', 'fofa.info',
            'binaryedge.io', 'criminalip.io',
            'greynoise.io',
        ]

        honeypot_indicators = [
            'honeypot', 'canary', 'trap',
            'ips.', 'ids.', 'siem.',
            'monitor.', 'detect.',
        ]

        target_lower = self.target.lower()

        for domain in known_monitored:
            if domain in target_lower:
                self.risk_score += 50
                self.risk_factors.append(
                    f'Known security monitor: {domain}'
                )

        for indicator in honeypot_indicators:
            if indicator in target_lower:
                self.risk_score += 25
                self.risk_factors.append(
                    f'Possible honeypot indicator: '
                    f'{indicator}'
                )

    def check_bug_bounty_scope(self):
        """
        Check if target is a bug bounty target.
        Bug bounty = lower risk (authorized).
        """
        bug_bounty_platforms = [
            'hackerone.com', 'bugcrowd.com',
            'intigriti.com', 'yeswehack.com',
            'synack.com',
        ]
        target_lower = self.target.lower()

        for platform in bug_bounty_platforms:
            if platform in target_lower:
                self.risk_score -= 20
                self.risk_factors.append(
                    f'Bug bounty platform: {platform}'
                )

    def assess(self):
        """
        Run all checks and return risk level.
        """
        print(
            f"\n{Fore.CYAN}[*] Assessing target "
            f"risk level: {self.target}"
            + Style.RESET_ALL
        )

        self.check_target_type()
        self.check_ip_reputation()
        self.check_threat_intel()
        self.check_bug_bounty_scope()

        # Normalize score 0-100
        self.risk_score = max(
            0, min(100, self.risk_score)
        )

        # Determine risk level
        if self.risk_score >= 60:
            self.risk_level = 'HIGH'
        elif self.risk_score >= 30:
            self.risk_level = 'MEDIUM'
        else:
            self.risk_level = 'LOW'

        self._print_result()
        return self.risk_level, self.risk_factors

    def _print_result(self):
        color = {
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN,
        }.get(self.risk_level, Fore.WHITE)

        print(
            f"\n{Fore.CYAN}  Risk Assessment Result:"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.WHITE}Target    : "
            f"{Fore.CYAN}{self.target}"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.WHITE}Risk Score: "
            f"{color}{self.risk_score}/100"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.WHITE}Risk Level: "
            f"{color}{self.risk_level}"
            + Style.RESET_ALL
        )

        if self.risk_factors:
            print(
                f"\n  {Fore.WHITE}Risk Factors:"
                + Style.RESET_ALL
            )
            for factor in self.risk_factors:
                print(
                    f"    {color}⚠ {factor}"
                    + Style.RESET_ALL
                )

        # Tell user what will happen
        if self.risk_level == 'HIGH':
            print(
                f"\n  {Fore.RED}→ HIGH RISK DETECTED"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.RED}  Anti-tracking "
                "ENABLED automatically"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.RED}  Smart connection "
                "selection ENABLED"
                + Style.RESET_ALL
            )
        elif self.risk_level == 'MEDIUM':
            print(
                f"\n  {Fore.YELLOW}→ MEDIUM RISK"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.YELLOW}  Basic anti-tracking"
                " ENABLED"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.YELLOW}  Monitoring connection"
                " stability"
                + Style.RESET_ALL
            )
        else:
            print(
                f"\n  {Fore.GREEN}→ LOW RISK"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.GREEN}  Normal scan mode"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.GREEN}  Anti-tracking: OFF"
                + Style.RESET_ALL
            )
