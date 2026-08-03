# proxy_manager.py - Add to your project root

import requests
import random
import time
from bs4 import BeautifulSoup


class FreeProxyManager:
    """
    Fetches and rotates free proxies
    from public proxy lists
    """

    def __init__(self):
        self.proxies = []
        self.working_proxies = []
        self.current_index = 0

    def fetch_proxies(self):
        """Fetch proxies from multiple free sources"""
        print("  [*] Fetching free proxies...")
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
            print(
                f"  [✓] Source 1: "
                f"{len(all_proxies)} proxies"
            )
        except Exception as e:
            print(f"  [!] Source 1 failed: {e}")

        # Source 2: proxylist.geonode.com (API)
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
            print(
                f"  [✓] Source 2: "
                f"geonode proxies added"
            )
        except Exception as e:
            print(f"  [!] Source 2 failed: {e}")

        # Source 3: proxyscrape API (free)
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
                if ':' in line:
                    all_proxies.append(
                        f"http://{line}"
                    )
            print(
                f"  [✓] Source 3: "
                f"proxyscrape added"
            )
        except Exception as e:
            print(f"  [!] Source 3 failed: {e}")

        # Source 4: github proxy list
        try:
            resp = requests.get(
                'https://raw.githubusercontent.com/'
                'TheSpeedX/PROXY-List/master/'
                'https.txt',
                timeout=10
            )
            for line in resp.text.strip().split('\n'):
                line = line.strip()
                if ':' in line:
                    all_proxies.append(
                        f"http://{line}"
                    )
            print(
                f"  [✓] Source 4: "
                f"github list added"
            )
        except Exception as e:
            print(f"  [!] Source 4 failed: {e}")

        self.proxies = list(set(all_proxies))
        print(
            f"  [✓] Total proxies fetched: "
            f"{len(self.proxies)}"
        )
        return self.proxies

    def test_proxy(self, proxy, timeout=5):
        """Test if a proxy is working"""
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
        """Test proxies and collect working ones"""
        print(
            f"  [*] Testing proxies "
            f"(need {need} working)..."
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
                print(
                    f"  [✓] Working proxy "
                    f"#{found}: {proxy} "
                    f"→ IP: {ip}"
                )
            else:
                print(
                    f"  [~] Dead: {proxy[:30]}..."
                )

        print(
            f"  [✓] Found {len(self.working_proxies)}"
            f" working proxies"
        )
        return self.working_proxies

    def get_random_proxy(self):
        """Get a random working proxy"""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)

    def get_next_proxy(self):
        """Rotate through working proxies"""
        if not self.working_proxies:
            return None
        proxy = self.working_proxies[
            self.current_index
            % len(self.working_proxies)
        ]
        self.current_index += 1
        return proxy

    def remove_proxy(self, proxy):
        """Remove a dead proxy"""
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            print(
                f"  [!] Removed dead proxy: "
                f"{proxy[:30]}"
            )

    def setup(self, need=5):
        """Full setup - fetch and test"""
        self.fetch_proxies()
        self.find_working_proxies(
            max_test=50, need=need
        )
        return len(self.working_proxies) > 0
