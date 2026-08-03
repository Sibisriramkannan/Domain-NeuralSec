"""
Smart Connection Manager
Automatically selects best connection method
based on target risk and connectivity tests.
"""

import time
import requests
import socket
from colorama import Fore, Style, init

init(autoreset=True)


class SmartConnection:
    """
    Automatically determines best connection method.

    Logic:
    1. Test direct connection to target
    2. If blocked/slow → try proxy
    3. If proxy fails → try Tor
    4. Risk level determines aggressiveness
    """

    def __init__(self, target, risk_level='LOW'):
        self.target = (
            target
            .replace('https://', '')
            .replace('http://', '')
            .strip('/')
        )
        self.risk_level = risk_level
        self.selected_method = 'direct'
        self.session = None
        self.connection_info = {}

    def _test_direct(self):
        """Test direct connection to target."""
        print(
            f"  {Fore.CYAN}[*] Testing direct "
            "connection..."
            + Style.RESET_ALL
        )
        try:
            start = time.time()
            r = requests.get(
                f'https://{self.target}',
                timeout=8,
                headers={
                    'User-Agent': (
                        'Mozilla/5.0 '
                        '(Windows NT 10.0; Win64; x64)'
                    )
                }
            )
            elapsed = round(time.time() - start, 2)

            if r.status_code < 500:
                print(
                    f"  {Fore.GREEN}[✓] Direct OK "
                    f"[{r.status_code}] "
                    f"{elapsed}s"
                    + Style.RESET_ALL
                )
                return True, elapsed
            else:
                print(
                    f"  {Fore.YELLOW}[!] Direct weak "
                    f"[{r.status_code}]"
                    + Style.RESET_ALL
                )
                return False, elapsed

        except requests.exceptions.ConnectionError:
            print(
                f"  {Fore.RED}[✗] Direct blocked"
                + Style.RESET_ALL
            )
            return False, 999
        except Exception as e:
            print(
                f"  {Fore.RED}[✗] Direct failed: {e}"
                + Style.RESET_ALL
            )
            return False, 999

    def _test_proxy(self):
        """Try to get a working proxy."""
        print(
            f"  {Fore.CYAN}[*] Testing proxy "
            "connection..."
            + Style.RESET_ALL
        )
        try:
            from proxy_manager import FreeProxyManager
            pm = FreeProxyManager()
            pm.fetch_proxies()
            proxies = pm.find_working_proxies(
                max_proxies=3
            )
            if proxies:
                proxy = proxies[0]
                print(
                    f"  {Fore.GREEN}[✓] Proxy found: "
                    f"{proxy}"
                    + Style.RESET_ALL
                )
                session = requests.Session()
                session.proxies = {
                    'http': f'http://{proxy}',
                    'https': f'http://{proxy}',
                }
                return True, session, proxy
            else:
                print(
                    f"  {Fore.YELLOW}[!] No working "
                    "proxies found"
                    + Style.RESET_ALL
                )
                return False, None, None
        except ImportError:
            print(
                f"  {Fore.YELLOW}[!] proxy_manager "
                "not available"
                + Style.RESET_ALL
            )
            return False, None, None
        except Exception as e:
            print(
                f"  {Fore.RED}[✗] Proxy failed: {e}"
                + Style.RESET_ALL
            )
            return False, None, None

    def _test_tor(self):
        """Try Tor connection."""
        print(
            f"  {Fore.CYAN}[*] Testing Tor "
            "connection..."
            + Style.RESET_ALL
        )
        try:
            session = requests.Session()
            session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050',
            }
            r = session.get(
                'https://check.torproject.org',
                timeout=10
            )
            if 'Congratulations' in r.text:
                print(
                    f"  {Fore.GREEN}[✓] Tor connected"
                    + Style.RESET_ALL
                )
                return True, session
            else:
                print(
                    f"  {Fore.YELLOW}[!] Tor port open"
                    " but not routing"
                    + Style.RESET_ALL
                )
                return False, None
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] Tor not "
                f"available: {e}"
                + Style.RESET_ALL
            )
            return False, None

    def _make_direct_session(self):
        """Make a plain requests session."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 '
                '(Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36'
            )
        })
        return session

    def get_session(self):
        """
        Main method.
        Returns best session based on risk + connectivity.
        """
        print(
            f"\n{Fore.CYAN}[*] Smart Connection "
            f"Analysis (Risk: {self.risk_level})"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.CYAN}" + "─" * 40
            + Style.RESET_ALL
        )

        # LOW risk → try direct first, use if OK
        if self.risk_level == 'LOW':
            ok, elapsed = self._test_direct()
            if ok:
                self.selected_method = 'direct'
                self.session = (
                    self._make_direct_session()
                )
                self.connection_info = {
                    'method': 'direct',
                    'response_time': elapsed,
                    'risk_level': self.risk_level,
                }
                self._print_selection()
                return self.session

            # Direct failed → try proxy
            print(
                f"  {Fore.YELLOW}[!] Direct failed, "
                "trying proxy..."
                + Style.RESET_ALL
            )
            proxy_ok, proxy_session, proxy = (
                self._test_proxy()
            )
            if proxy_ok:
                self.selected_method = 'proxy'
                self.session = proxy_session
                self.connection_info = {
                    'method': 'proxy',
                    'proxy': proxy,
                    'risk_level': self.risk_level,
                }
                self._print_selection()
                return self.session

            # Both failed → direct anyway
            print(
                f"  {Fore.YELLOW}[!] Using direct "
                "(best available)"
                + Style.RESET_ALL
            )
            self.selected_method = 'direct_fallback'
            self.session = self._make_direct_session()
            self.connection_info = {
                'method': 'direct_fallback',
                'risk_level': self.risk_level,
            }
            self._print_selection()
            return self.session

        # MEDIUM risk → prefer proxy
        elif self.risk_level == 'MEDIUM':
            # Test direct first to know baseline
            direct_ok, elapsed = self._test_direct()

            # Try proxy first for medium risk
            proxy_ok, proxy_session, proxy = (
                self._test_proxy()
            )
            if proxy_ok:
                self.selected_method = 'proxy'
                self.session = proxy_session
                self.connection_info = {
                    'method': 'proxy',
                    'proxy': proxy,
                    'risk_level': self.risk_level,
                    'reason': 'Medium risk - '
                              'using proxy for privacy',
                }
                self._print_selection()
                return self.session

            # Proxy failed → try Tor
            tor_ok, tor_session = self._test_tor()
            if tor_ok:
                self.selected_method = 'tor'
                self.session = tor_session
                self.connection_info = {
                    'method': 'tor',
                    'risk_level': self.risk_level,
                    'reason': 'Medium risk, '
                              'proxy failed, using Tor',
                }
                self._print_selection()
                return self.session

            # Nothing available → direct
            if direct_ok:
                print(
                    f"  {Fore.YELLOW}[!] Privacy tools "
                    "unavailable. Using direct."
                    + Style.RESET_ALL
                )
            self.selected_method = 'direct'
            self.session = self._make_direct_session()
            self.connection_info = {
                'method': 'direct',
                'risk_level': self.risk_level,
                'warning': 'Privacy tools not available',
            }
            self._print_selection()
            return self.session

        # HIGH risk → prefer Tor, then proxy
        elif self.risk_level == 'HIGH':
            print(
                f"  {Fore.RED}[!] HIGH RISK TARGET - "
                "Prioritizing Tor..."
                + Style.RESET_ALL
            )

            # Try Tor first for high risk
            tor_ok, tor_session = self._test_tor()
            if tor_ok:
                self.selected_method = 'tor'
                self.session = tor_session
                self.connection_info = {
                    'method': 'tor',
                    'risk_level': self.risk_level,
                    'reason': 'High risk - Tor selected',
                }
                self._print_selection()
                return self.session

            # Tor failed → try proxy
            print(
                f"  {Fore.YELLOW}[!] Tor unavailable, "
                "trying proxy..."
                + Style.RESET_ALL
            )
            proxy_ok, proxy_session, proxy = (
                self._test_proxy()
            )
            if proxy_ok:
                self.selected_method = 'proxy'
                self.session = proxy_session
                self.connection_info = {
                    'method': 'proxy',
                    'proxy': proxy,
                    'risk_level': self.risk_level,
                    'warning': 'Tor unavailable, '
                               'using proxy',
                }
                self._print_selection()
                return self.session

            # Both failed → direct with warning
            print(
                f"\n  {Fore.RED}⚠ WARNING: High risk "
                "target but no privacy tools available!"
                + Style.RESET_ALL
            )
            print(
                f"  {Fore.RED}  Install Tor Browser "
                "or configure proxy for protection."
                + Style.RESET_ALL
            )

            confirm = input(
                f"\n  {Fore.YELLOW}Continue with "
                "direct connection? (yes/no): "
                + Style.RESET_ALL
            ).strip().lower()

            if confirm != 'yes':
                print(
                    f"  {Fore.RED}Scan cancelled."
                    + Style.RESET_ALL
                )
                return None

            self.selected_method = 'direct_high_risk'
            self.session = self._make_direct_session()
            self.connection_info = {
                'method': 'direct',
                'risk_level': self.risk_level,
                'warning': 'HIGH RISK - no privacy '
                           'protection active!',
            }
            self._print_selection()
            return self.session

        # Default fallback
        self.session = self._make_direct_session()
        return self.session

    def _print_selection(self):
        """Print final connection selection."""
        method = self.connection_info.get(
            'method', 'unknown'
        )
        color = {
            'direct': Fore.GREEN,
            'proxy': Fore.YELLOW,
            'tor': Fore.CYAN,
            'direct_fallback': Fore.YELLOW,
            'direct_high_risk': Fore.RED,
        }.get(method, Fore.WHITE)

        icon = {
            'direct': '→',
            'proxy': '⇒',
            'tor': '⊕',
            'direct_fallback': '→',
            'direct_high_risk': '⚠',
        }.get(method, '→')

        print(
            f"\n  {color}{icon} Connection: "
            f"{method.upper()}"
            + Style.RESET_ALL
        )

        warning = self.connection_info.get('warning')
        if warning:
            print(
                f"  {Fore.RED}⚠ {warning}"
                + Style.RESET_ALL
            )

        reason = self.connection_info.get('reason')
        if reason:
            print(
                f"  {Fore.WHITE}  Reason: {reason}"
                + Style.RESET_ALL
            )

    def rotate(self):
        """
        Rotate connection on block detection.
        Called when 403/429/blocked detected.
        """
        print(
            f"\n{Fore.YELLOW}[*] Connection rotation "
            "triggered..."
            + Style.RESET_ALL
        )

        current = self.selected_method

        if current == 'direct':
            # Escalate to proxy
            proxy_ok, proxy_session, proxy = (
                self._test_proxy()
            )
            if proxy_ok:
                self.session = proxy_session
                self.selected_method = 'proxy'
                print(
                    f"  {Fore.GREEN}[✓] Rotated to proxy"
                    + Style.RESET_ALL
                )
                return self.session

            # Then Tor
            tor_ok, tor_session = self._test_tor()
            if tor_ok:
                self.session = tor_session
                self.selected_method = 'tor'
                print(
                    f"  {Fore.GREEN}[✓] Rotated to Tor"
                    + Style.RESET_ALL
                )
                return self.session

        elif current == 'proxy':
            # Try different proxy
            proxy_ok, proxy_session, proxy = (
                self._test_proxy()
            )
            if proxy_ok:
                self.session = proxy_session
                print(
                    f"  {Fore.GREEN}[✓] Rotated proxy"
                    + Style.RESET_ALL
                )
                return self.session

            # Escalate to Tor
            tor_ok, tor_session = self._test_tor()
            if tor_ok:
                self.session = tor_session
                self.selected_method = 'tor'
                print(
                    f"  {Fore.GREEN}[✓] Escalated to Tor"
                    + Style.RESET_ALL
                )
                return self.session

        elif current == 'tor':
            # Try new Tor circuit
            try:
                from connection_manager import (
                    TorManager
                )
                tm = TorManager()
                tm.rotate_circuit()
                print(
                    f"  {Fore.GREEN}[✓] Tor circuit "
                    "rotated"
                    + Style.RESET_ALL
                )
            except Exception:
                print(
                    f"  {Fore.YELLOW}[!] Circuit "
                    "rotation failed"
                    + Style.RESET_ALL
                )

        return self.session
