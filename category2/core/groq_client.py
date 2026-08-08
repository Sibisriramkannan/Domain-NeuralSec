"""
groq_client.py
Groq API caller with auto-retry + proxy bypass
403 / network block auto-handle
"""

import os
import time
import random
import requests
from colorama import Fore, Style, init

init(autoreset=True)

# ── Browser User Agents ──────────────────────────
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        " AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X"
        " 10_15_7) AppleWebKit/537.36 (KHTML, like"
        " Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64;"
        " rv:121.0) Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64)"
        " AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120.0.0.0 Safari/537.36"
    ),
]

# ── Groq API Endpoints (fallback list) ───────────
GROQ_ENDPOINTS = [
    "https://api.groq.com/openai/v1/chat/completions",
]

# ── Free Proxy Sources ───────────────────────────
PROXY_SOURCES = [
    (
        "https://api.proxyscrape.com/v2/"
        "?request=getproxies&protocol=https"
        "&timeout=5000&country=all"
        "&anonymity=elite"
    ),
    (
        "https://raw.githubusercontent.com/"
        "TheSpeedX/PROXY-List/master/https.txt"
    ),
    (
        "https://raw.githubusercontent.com/"
        "ShiftyTR/Proxy-List/master/https.txt"
    ),
]


class GroqClient:
    """
    Groq API client with:
    - Auto retry on 403/network errors
    - Free proxy rotation
    - User agent randomization
    - Exponential backoff
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.working_proxies = []
        self.current_proxy_idx = 0
        self.session = self._build_session()
        self.max_retries = 5
        self.proxies_fetched = False

    def _build_session(
        self, proxy: str = None
    ) -> requests.Session:
        """Build requests session"""
        session = requests.Session()

        # Random browser UA
        ua = random.choice(USER_AGENTS)
        session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': ua,
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

        if proxy:
            session.proxies = {
                'http': proxy,
                'https': proxy
            }

        return session

    def _fetch_proxies(self):
        """Fetch free proxies from public sources"""
        if self.proxies_fetched:
            return

        print(
            f"  {Fore.CYAN}[*] Fetching free "
            f"proxies for Groq bypass..."
            + Style.RESET_ALL
        )

        proxies = []
        temp_session = requests.Session()
        temp_session.headers['User-Agent'] = (
            random.choice(USER_AGENTS)
        )

        for url in PROXY_SOURCES:
            try:
                resp = temp_session.get(
                    url, timeout=8
                )
                for line in (
                    resp.text.strip().split('\n')
                ):
                    line = line.strip()
                    if ':' in line and len(line) < 25:
                        proxies.append(
                            f"https://{line}"
                        )
            except Exception:
                continue

        # Deduplicate
        proxies = list(set(proxies))
        random.shuffle(proxies)

        print(
            f"  {Fore.CYAN}[*] Testing proxies "
            f"({len(proxies)} found)..."
            + Style.RESET_ALL
        )

        # Test proxies quickly
        tested = 0
        for proxy in proxies:
            if tested >= 30:
                break
            if len(self.working_proxies) >= 5:
                break

            tested += 1
            try:
                test_session = requests.Session()
                test_session.proxies = {
                    'http': proxy,
                    'https': proxy
                }
                resp = test_session.get(
                    'https://api.groq.com',
                    timeout=4,
                    verify=False
                )
                # Any response = proxy works
                self.working_proxies.append(proxy)
                print(
                    f"  {Fore.GREEN}[✓] Working: "
                    f"{proxy[:40]}"
                    + Style.RESET_ALL
                )
            except Exception:
                continue

        self.proxies_fetched = True

        if self.working_proxies:
            print(
                f"  {Fore.GREEN}[✓] "
                f"{len(self.working_proxies)} "
                f"working proxies ready"
                + Style.RESET_ALL
            )
        else:
            print(
                f"  {Fore.YELLOW}[!] No working "
                f"proxies found - trying direct"
                + Style.RESET_ALL
            )

    def _get_next_proxy(self):
        """Rotate to next working proxy"""
        if not self.working_proxies:
            return None
        proxy = self.working_proxies[
            self.current_proxy_idx
            % len(self.working_proxies)
        ]
        self.current_proxy_idx += 1
        return proxy

    def _try_tor(self):
        """Try Tor SOCKS5 if available"""
        try:
            test = requests.get(
                'https://api.groq.com',
                proxies={
                    'http': 'socks5h://127.0.0.1:9050',
                    'https': 'socks5h://127.0.0.1:9050'
                },
                timeout=5
            )
            return True
        except Exception:
            return False

    def chat(
        self,
        messages: list,
        model: str = "llama-3.3-70b-versatile",
        temperature: float = 0.3,
        max_tokens: int = 4000
    ) -> str:
        """
        Send chat request to Groq.
        Auto-retries with proxy rotation on 403.
        """
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                print(
                    f"  {Fore.CYAN}[*] Sending "
                    f"data to Groq AI... "
                    f"(attempt {attempt})"
                    + Style.RESET_ALL
                )

                resp = self.session.post(
                    GROQ_ENDPOINTS[0],
                    json=payload,
                    timeout=60
                )

                # ── SUCCESS ──────────────────────
                if resp.status_code == 200:
                    data = resp.json()
                    content = (
                        data['choices'][0]
                        ['message']['content']
                    )
                    print(
                        f"  {Fore.GREEN}[✓] "
                        f"Groq response received!"
                        + Style.RESET_ALL
                    )
                    return content

                # ── 403 BLOCKED ──────────────────
                elif resp.status_code == 403:
                    print(
                        f"  {Fore.RED}[!] Groq 403"
                        f" blocked (attempt {attempt})"
                        + Style.RESET_ALL
                    )
                    last_error = f"403: {resp.text[:100]}"
                    self._handle_block(attempt)

                # ── 429 RATE LIMIT ───────────────
                elif resp.status_code == 429:
                    wait = 30 * attempt
                    print(
                        f"  {Fore.YELLOW}[!] Rate "
                        f"limited. Waiting {wait}s..."
                        + Style.RESET_ALL
                    )
                    time.sleep(wait)

                # ── 401 BAD KEY ──────────────────
                elif resp.status_code == 401:
                    print(
                        f"  {Fore.RED}[!] Invalid "
                        f"API key!"
                        + Style.RESET_ALL
                    )
                    raise ValueError(
                        "Invalid Groq API key"
                    )

                # ── OTHER ERROR ──────────────────
                else:
                    print(
                        f"  {Fore.YELLOW}[!] HTTP "
                        f"{resp.status_code} - "
                        f"retrying..."
                        + Style.RESET_ALL
                    )
                    last_error = (
                        f"HTTP {resp.status_code}"
                    )
                    time.sleep(5 * attempt)

            except requests.exceptions.SSLError:
                # Try without SSL verify
                print(
                    f"  {Fore.YELLOW}[!] SSL error"
                    f" - retrying without verify..."
                    + Style.RESET_ALL
                )
                self.session.verify = False
                time.sleep(2)

            except requests.exceptions.ConnectionError:
                print(
                    f"  {Fore.YELLOW}[!] Connection"
                    f" error - switching proxy..."
                    + Style.RESET_ALL
                )
                last_error = "ConnectionError"
                self._handle_block(attempt)

            except requests.exceptions.Timeout:
                print(
                    f"  {Fore.YELLOW}[!] Timeout - "
                    f"retrying..."
                    + Style.RESET_ALL
                )
                last_error = "Timeout"
                time.sleep(5)

            except ValueError:
                raise

            except Exception as e:
                last_error = str(e)
                print(
                    f"  {Fore.RED}[!] Error: {e}"
                    + Style.RESET_ALL
                )
                time.sleep(5)

        # All retries failed
        print(
            f"  {Fore.RED}[!] All {self.max_retries}"
            f" attempts failed: {last_error}"
            + Style.RESET_ALL
        )
        return None

    def _handle_block(self, attempt: int):
        """Handle IP block - rotate proxy"""

        # Attempt 1: Try Tor first
        if attempt == 1:
            print(
                f"  {Fore.CYAN}[*] Checking "
                f"Tor network..."
                + Style.RESET_ALL
            )
            if self._try_tor():
                print(
                    f"  {Fore.GREEN}[✓] Tor "
                    f"available - routing through Tor"
                    + Style.RESET_ALL
                )
                self.session = self._build_session()
                self.session.proxies = {
                    'http': (
                        'socks5h://127.0.0.1:9050'
                    ),
                    'https': (
                        'socks5h://127.0.0.1:9050'
                    )
                }
                return

        # Attempt 2+: Fetch and use free proxies
        if not self.proxies_fetched:
            self._fetch_proxies()

        proxy = self._get_next_proxy()
        if proxy:
            print(
                f"  {Fore.CYAN}[*] Switching to "
                f"proxy: {proxy[:40]}..."
                + Style.RESET_ALL
            )
            self.session = self._build_session(
                proxy=proxy
            )
        else:
            # No proxy - just wait and retry direct
            wait = 10 * attempt
            print(
                f"  {Fore.YELLOW}[*] No proxy - "
                f"waiting {wait}s before retry..."
                + Style.RESET_ALL
            )
            self.session = self._build_session()
            time.sleep(wait)
