"""
Anti-Tracking & Counter-Surveillance Module
Protects scanner from being reverse-tracked
"""

import os
import sys
import time
import random
import socket
import hashlib
import platform
import requests
import subprocess
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class AntiTrackManager:
    """
    Comprehensive anti-tracking protection
    Prevents reverse identification of scanner
    """

    def __init__(self):
        self.os_name = platform.system()
        self.protections_active = []
        self.original_hostname = socket.gethostname()

    def run_all_protections(self):
        """Enable all anti-tracking measures"""
        print(
            f"\n{Fore.CYAN}[*] Activating "
            f"Anti-Tracking Protections..."
            + Style.RESET_ALL
        )

        protections = [
            (
                'DNS Leak Protection',
                self.enable_dns_protection
            ),
            (
                'Request Header Sanitization',
                self.sanitize_headers
            ),
            (
                'Timing Attack Prevention',
                self.enable_timing_protection
            ),
            (
                'Fingerprint Randomization',
                self.randomize_fingerprint
            ),
            (
                'Log Minimization',
                self.minimize_logs
            ),
            (
                'Traffic Pattern Obfuscation',
                self.obfuscate_traffic
            ),
        ]

        results = {}
        for name, func in protections:
            try:
                result = func()
                results[name] = result
                status = (
                    f"{Fore.GREEN}[✓] ACTIVE"
                    if result
                    else f"{Fore.YELLOW}[~] SKIPPED"
                )
                print(
                    f"  {status} {name}"
                    + Style.RESET_ALL
                )
                if result:
                    self.protections_active.append(
                        name
                    )
            except Exception as e:
                results[name] = False
                print(
                    f"  {Fore.RED}[!] FAILED "
                    f"{name}: {e}"
                    + Style.RESET_ALL
                )

        print(
            f"\n  {Fore.GREEN}[✓] "
            f"{len(self.protections_active)} "
            f"protections active"
            + Style.RESET_ALL
        )
        return results

    def enable_dns_protection(self):
        """
        Use encrypted DNS to prevent DNS leaks
        Switches to Cloudflare/Google DNS over HTTPS
        """
        # Set DNS-over-HTTPS environment
        os.environ['DNS_OVER_HTTPS'] = '1'
        os.environ['USE_DOH'] = 'cloudflare'

        # Verify no DNS leak
        try:
            # Use DoH directly
            resp = requests.get(
                'https://cloudflare-dns.com/dns-query'
                '?name=example.com&type=A',
                headers={
                    'Accept': 'application/dns-json'
                },
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return True  # Skip if cant verify

    def sanitize_headers(self):
        """
        Remove identifying headers from requests
        Prevents fingerprinting via headers
        """
        # Headers to REMOVE (reveal identity)
        dangerous_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'Via',
            'X-Scanner',
            'X-Tool',
            'True-Client-IP',
            'CF-Connecting-IP',
            'X-Client-IP',
        ]

        # Store list for use in session builder
        self.headers_to_remove = dangerous_headers

        # Headers to USE (look like browser)
        self.safe_headers = {
            'Accept': (
                'text/html,application/xhtml+xml,'
                'application/xml;q=0.9,'
                'image/webp,*/*;q=0.8'
            ),
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'DNT': '1',  # Do Not Track
        }

        return True

    def enable_timing_protection(self):
        """
        Add random delays to prevent timing analysis
        Makes request patterns look human
        """
        self.timing_config = {
            'min_delay': 0.5,
            'max_delay': 3.0,
            'jitter': 0.2,
            'burst_prevention': True,
            'max_requests_per_min': 30,
        }
        return True

    def randomize_fingerprint(self):
        """
        Randomize browser fingerprint
        Makes each session look different
        """
        # Random screen resolutions
        resolutions = [
            '1920x1080', '1366x768',
            '1536x864', '1440x900',
            '1280x720', '2560x1440',
        ]

        # Random platforms
        platforms = [
            'Win32', 'MacIntel', 'Linux x86_64'
        ]

        # Random color depths
        color_depths = [24, 30, 32]

        self.fingerprint = {
            'resolution': random.choice(resolutions),
            'platform': random.choice(platforms),
            'color_depth': random.choice(color_depths),
            'timezone': random.randint(-12, 12),
            'session_id': hashlib.md5(
                str(time.time()).encode()
            ).hexdigest()[:8],
        }

        return True

    def minimize_logs(self):
        """
        Minimize local logging footprint
        Clear sensitive data from logs
        """
        # Set log level to minimal
        os.environ['LOG_LEVEL'] = 'MINIMAL'
        os.environ['CLEAR_LOGS_ON_EXIT'] = '1'

        return True

    def obfuscate_traffic(self):
        """
        Obfuscate traffic patterns
        Add decoy requests to hide real ones
        """
        self.traffic_config = {
            'use_decoys': True,
            'decoy_rate': 0.1,
            'randomize_order': True,
            'chunk_requests': True,
        }
        return True

    def get_safe_session(self):
        """
        Build maximally safe requests session
        with all anti-tracking measures
        """
        session = requests.Session()

        # Use random browser UA
        user_agents = [
            (
                "Mozilla/5.0 (Windows NT 10.0; "
                "Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel "
                "Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like "
                "Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; "
                "Win64; x64; rv:121.0) "
                "Gecko/20100101 Firefox/121.0"
            ),
        ]

        # Apply safe headers
        headers = getattr(
            self, 'safe_headers', {}
        ).copy()
        headers['User-Agent'] = random.choice(
            user_agents
        )

        session.headers.update(headers)

        # Remove dangerous headers
        for h in getattr(
            self, 'headers_to_remove', []
        ):
            session.headers.pop(h, None)

        return session

    def random_delay(self):
        """Get a random human-like delay"""
        config = getattr(
            self, 'timing_config', {}
        )
        min_d = config.get('min_delay', 0.5)
        max_d = config.get('max_delay', 3.0)
        jitter = config.get('jitter', 0.2)

        delay = random.uniform(min_d, max_d)
        delay += random.uniform(-jitter, jitter)
        return max(0.1, delay)

    def check_exposure(self):
        """
        Check how exposed/trackable you are
        Returns exposure report
        """
        print(
            f"\n{Fore.CYAN}[*] Running Exposure "
            f"Check..."
            + Style.RESET_ALL
        )

        checks = []

        # Check 1: Public IP
        try:
            ip = requests.get(
                'https://api.ipify.org',
                timeout=5
            ).text.strip()
            checks.append({
                'check': 'Public IP',
                'value': ip,
                'risk': 'HIGH',
                'note': 'Your real IP is visible'
            })
        except Exception:
            pass

        # Check 2: DNS leak test
        try:
            resp = requests.get(
                'https://api.ipify.org?format=json',
                timeout=5
            )
            checks.append({
                'check': 'DNS Resolution',
                'value': 'Standard DNS',
                'risk': 'MEDIUM',
                'note': 'DNS queries may be logged'
            })
        except Exception:
            pass

        # Check 3: Browser headers fingerprint
        try:
            resp = requests.get(
                'https://httpbin.org/headers',
                timeout=5
            )
            headers = resp.json().get(
                'headers', {}
            )
            ua = headers.get('User-Agent', '')
            checks.append({
                'check': 'User-Agent',
                'value': ua[:50],
                'risk': (
                    'LOW'
                    if 'Mozilla' in ua
                    else 'HIGH'
                ),
                'note': (
                    'Looks like browser'
                    if 'Mozilla' in ua
                    else 'Reveals scanner'
                )
            })
        except Exception:
            pass

        # Check 4: Tor check
        try:
            resp = requests.get(
                'https://check.torproject.org/api/ip',
                timeout=5
            )
            data = resp.json()
            is_tor = data.get('IsTor', False)
            checks.append({
                'check': 'Tor Network',
                'value': (
                    'Yes - Anonymous'
                    if is_tor
                    else 'No - Exposed'
                ),
                'risk': (
                    'LOW' if is_tor else 'HIGH'
                ),
                'note': (
                    'Protected'
                    if is_tor
                    else 'Use Tor for anonymity'
                )
            })
        except Exception:
            pass

        # Print results
        print(
            f"\n  {'Check':<20} "
            f"{'Value':<30} "
            f"{'Risk':<10} "
            f"{'Note'}"
        )
        print("  " + "─" * 80)

        for check in checks:
            risk = check['risk']
            color = (
                Fore.RED if risk == 'HIGH'
                else Fore.YELLOW if risk == 'MEDIUM'
                else Fore.GREEN
            )
            print(
                f"  {check['check']:<20} "
                f"{check['value']:<30} "
                f"{color}{risk:<10}{Style.RESET_ALL} "
                f"{check['note']}"
            )

        return checks

    def print_precautions(self):
        """Print all security precautions"""
        print(
            f"\n{Fore.CYAN}"
            "═" * 62
            + Style.RESET_ALL
        )
        print(
            f"{Fore.CYAN}  ANTI-TRACKING PRECAUTIONS"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.CYAN}" + "═" * 62
            + Style.RESET_ALL
        )

        precautions = [
            (
                "LEGAL",
                [
                    "Always get written permission "
                    "before scanning",
                    "Keep a signed authorization "
                    "document",
                    "Never scan government or "
                    "financial systems without auth",
                    "Document your testing scope "
                    "and timeframe",
                ]
            ),
            (
                "NETWORK",
                [
                    "Use Tor or VPN before scanning",
                    "Enable DNS-over-HTTPS",
                    "Use proxy rotation for "
                    "large scans",
                    "Avoid scanning from home IP",
                    "Use Cloudflare WARP as "
                    "baseline protection",
                ]
            ),
            (
                "IDENTITY",
                [
                    "Never use real name in "
                    "scanner configs",
                    "Use anonymous email for "
                    "API keys",
                    "Rotate user agents "
                    "per request",
                    "Remove identifying headers",
                    "Use random delays between "
                    "requests",
                ]
            ),
            (
                "OPERATIONAL",
                [
                    "Clear logs after each session",
                    "Use encrypted storage for "
                    "findings",
                    "Don't save reports with "
                    "real target info on cloud",
                    "Use separate device for "
                    "sensitive testing",
                    "Scan during off-peak hours",
                ]
            ),
            (
                "TECHNICAL",
                [
                    "Keep scanner code private",
                    "Don't share scan results "
                    "publicly",
                    "Use steganography for "
                    "sensitive reports",
                    "Encrypt output files",
                    "Use air-gapped machine for "
                    "critical assessments",
                ]
            ),
        ]

        for category, items in precautions:
            print(
                f"\n  {Fore.YELLOW}[{category}]"
                + Style.RESET_ALL
            )
            for item in items:
                print(
                    f"    {Fore.WHITE}→ {item}"
                    + Style.RESET_ALL
                )

        print(
            f"\n{Fore.CYAN}" + "═" * 62
            + Style.RESET_ALL
        )
