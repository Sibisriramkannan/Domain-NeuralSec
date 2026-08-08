# proxy_manager.py - Updated with logging support

import requests
import random
import time
from bs4 import BeautifulSoup


class FreeProxyManager:
    """
    Fetches and rotates free proxies
    from public proxy lists
    """

    def __init__(self, log_writer=None):
        self.proxies = []
        self.working_proxies = []
        self.current_index = 0
        self.log_writer = log_writer  # ✅ NEW

    def _w(self, msg, lvl='INFO'):
        """Write to log + print."""
        # Print to terminal
        prefix = {
            'INFO': '  [*]',
            'SUCCESS': '  [✓]',
            'WARN': '  [!]',
            'ERROR': '  [!]',
        }.get(lvl, '  [*]')
        print(f"{prefix} {msg}")

        # Also write to monitor log
        if self.log_writer:
            try:
                self.log_writer(
                    f"[PROXY] {msg}", lvl
                )
            except:
                pass

    def fetch_proxies(self):
        """Fetch proxies from multiple sources."""
        self._w('Fetching free proxies...', 'INFO')
        all_proxies = []

        # Source 1: free-proxy-list.net
        try:
            resp = requests.get(
                'https://free-proxy-list.net/',
                timeout=10
            )
            soup = BeautifulSoup(
                resp.text, 'html.parser'
            )
            table = soup.find('table')
            if table:
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) >= 7:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        https = cols[6].text.strip()
                        if https == 'yes':
                            all_proxies.append(
                                f"http://{ip}:{port}"
                            )
            self._w(
                f'Source 1 (free-proxy-list): '
                f'{len(all_proxies)} proxies',
                'SUCCESS'
            )
        except Exception as e:
            self._w(
                f'Source 1 failed: {e}', 'WARN'
            )

        prev = len(all_proxies)

        # Source 2: geonode API
        try:
            resp = requests.get(
                'https://proxylist.geonode.com/api/'
                'proxy-list?limit=50&page=1'
                '&sort_by=lastChecked'
                '&sort_type=desc'
                '&protocols=https',
                timeout=10
            )
            data = resp.json()
            for proxy in data.get('data', []):
                ip = proxy.get('ip', '')
                port = proxy.get('port', '')
                if ip and port:
                    all_proxies.append(
                        f"http://{ip}:{port}"
                    )
            added = len(all_proxies) - prev
            self._w(
                f'Source 2 (geonode): '
                f'{added} proxies added',
                'SUCCESS'
            )
            prev = len(all_proxies)
        except Exception as e:
            self._w(
                f'Source 2 failed: {e}', 'WARN'
            )

        # Source 3: proxyscrape API
        try:
            resp = requests.get(
                'https://api.proxyscrape.com/v2/'
                '?request=getproxies'
                '&protocol=https'
                '&timeout=5000'
                '&country=all'
                '&ssl=all'
                '&anonymity=all',
                timeout=10
            )
            for line in resp.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and len(line) < 25:
                    all_proxies.append(
                        f"http://{line}"
                    )
            added = len(all_proxies) - prev
            self._w(
                f'Source 3 (proxyscrape): '
                f'{added} proxies added',
                'SUCCESS'
            )
            prev = len(all_proxies)
        except Exception as e:
            self._w(
                f'Source 3 failed: {e}', 'WARN'
            )

        # Source 4: GitHub proxy list
        try:
            resp = requests.get(
                'https://raw.githubusercontent.com/'
                'TheSpeedX/PROXY-List/master/'
                'https.txt',
                timeout=10
            )
            for line in resp.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and len(line) < 25:
                    all_proxies.append(
                        f"http://{line}"
                    )
            added = len(all_proxies) - prev
            self._w(
                f'Source 4 (GitHub): '
                f'{added} proxies added',
                'SUCCESS'
            )
        except Exception as e:
            self._w(
                f'Source 4 failed: {e}', 'WARN'
            )

        # Deduplicate
        self.proxies = list(set(all_proxies))
        self._w(
            f'Total unique proxies: '
            f'{len(self.proxies)}',
            'SUCCESS'
        )
        return self.proxies

    def test_proxy(self, proxy, timeout=5):
        """Test if proxy works."""
        try:
            resp = requests.get(
                'https://httpbin.org/ip',
                proxies={
                    'http': proxy,
                    'https': proxy
                },
                timeout=timeout
            )
            if resp.status_code == 200:
                ip = resp.json().get('origin', '')
                return True, ip
        except Exception:
            pass
        return False, None

    def find_working_proxies(
        self, max_test=30, need=5
    ):
        """Test proxies, collect working ones."""
        self._w(
            f'Testing proxies '
            f'(need={need} max_test={max_test})...',
            'INFO'
        )
        random.shuffle(self.proxies)
        tested = 0
        found = 0

        for proxy in self.proxies:
            if found >= need:
                break
            if tested >= max_test:
                break

            tested += 1
            working, ip = self.test_proxy(proxy)

            if working:
                self.working_proxies.append(proxy)
                found += 1
                self._w(
                    f'Working #{found}: '
                    f'{proxy[:40]} → {ip}',
                    'SUCCESS'
                )
            # Silent on dead - reduce noise

        self._w(
            f'Working proxies: '
            f'{len(self.working_proxies)}',
            'SUCCESS'
        )
        return self.working_proxies

    def get_random_proxy(self):
        """Get random working proxy."""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)

    def get_next_proxy(self):
        """Rotate through working proxies."""
        if not self.working_proxies:
            return None
        proxy = self.working_proxies[
            self.current_index
            % len(self.working_proxies)
        ]
        self.current_index += 1
        return proxy

    def remove_proxy(self, proxy):
        """Remove dead proxy."""
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            self._w(
                f'Removed dead: {proxy[:35]}',
                'WARN'
            )

    def rotate_on_block(self):
        """
        Called when current proxy is blocked.
        Returns next working proxy or None.
        """
        # Mark current as failed
        if self.working_proxies:
            current_idx = (
                (self.current_index - 1)
                % len(self.working_proxies)
            )
            dead = self.working_proxies[current_idx]
            self.remove_proxy(dead)

        # Get next
        next_proxy = self.get_next_proxy()
        if next_proxy:
            self._w(
                f'Rotated to: {next_proxy[:40]}',
                'INFO'
            )
        else:
            self._w(
                'No more working proxies!',
                'WARN'
            )
        return next_proxy

    def setup(self, need=5):
        """Full setup - fetch and test."""
        self.fetch_proxies()
        self.find_working_proxies(
            max_test=50, need=need
        )
        return len(self.working_proxies) > 0

    def get_stats(self):
        """Return current stats."""
        return {
            'total_fetched': len(self.proxies),
            'working': len(self.working_proxies),
            'current_index': self.current_index,
        }
