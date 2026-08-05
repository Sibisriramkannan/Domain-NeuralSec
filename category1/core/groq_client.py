"""
groq_client.py
403 bypass - proxy rotation + retry
"""

import time
import random
import requests
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        " AppleWebKit/537.36 Chrome/120.0.0.0"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X"
        " 10_15_7) AppleWebKit/537.36"
        " Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64;"
        " rv:121.0) Gecko/20100101 Firefox/121.0"
    ),
]

GROQ_URL = (
    "https://api.groq.com/openai/v1"
    "/chat/completions"
)

PROXY_SOURCES = [
    (
        "https://api.proxyscrape.com/v2/"
        "?request=getproxies&protocol=https"
        "&timeout=5000&country=all&anonymity=elite"
    ),
    (
        "https://raw.githubusercontent.com/"
        "TheSpeedX/PROXY-List/master/https.txt"
    ),
]


class GroqClient:
    """
    Drop-in replacement for groq.Groq
    Auto-retries with proxy on 403
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.working_proxies = []
        self.proxy_idx = 0
        self.proxies_fetched = False
        self.session = self._make_session()

        # ── Mimic groq library structure ────────────
        self.chat = _ChatCompletions(self)

    def _make_session(self, proxy=None):
        s = requests.Session()
        s.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json",
        })
        if proxy:
            s.proxies = {
                "http": proxy,
                "https": proxy
            }
        return s

    def _fetch_proxies(self):
        if self.proxies_fetched:
            return
        print(
            f"  {Fore.CYAN}[*] Fetching proxies "
            f"to bypass 403..."
            + Style.RESET_ALL
        )
        raw = []
        tmp = requests.Session()
        tmp.headers["User-Agent"] = random.choice(
            USER_AGENTS
        )
        for url in PROXY_SOURCES:
            try:
                r = tmp.get(url, timeout=8)
                for line in r.text.strip().split("\n"):
                    line = line.strip()
                    if ":" in line and len(line) < 22:
                        raw.append(
                            f"http://{line}"
                        )
            except Exception:
                continue

        random.shuffle(raw)
        print(
            f"  {Fore.CYAN}[*] Testing "
            f"{min(len(raw), 40)} proxies..."
            + Style.RESET_ALL
        )

        for proxy in raw[:40]:
            if len(self.working_proxies) >= 5:
                break
            try:
                requests.get(
                    "https://api.groq.com",
                    proxies={"https": proxy},
                    timeout=4,
                    verify=False
                )
                self.working_proxies.append(proxy)
                print(
                    f"  {Fore.GREEN}[✓] "
                    f"{proxy[:45]}"
                    + Style.RESET_ALL
                )
            except Exception:
                continue

        self.proxies_fetched = True
        if self.working_proxies:
            print(
                f"  {Fore.GREEN}[✓] "
                f"{len(self.working_proxies)} "
                f"proxies ready"
                + Style.RESET_ALL
            )
        else:
            print(
                f"  {Fore.YELLOW}[!] No proxies - "
                f"will retry direct"
                + Style.RESET_ALL
            )

    def _next_proxy(self):
        if not self.working_proxies:
            return None
        p = self.working_proxies[
            self.proxy_idx % len(self.working_proxies)
        ]
        self.proxy_idx += 1
        return p

    def _try_tor(self):
        try:
            requests.get(
                "https://api.groq.com",
                proxies={
                    "https": "socks5h://127.0.0.1:9050"
                },
                timeout=5
            )
            return True
        except Exception:
            return False

    def _call(self, payload: dict) -> str:
        """
        Core API call with retry + proxy rotation
        Returns content string or None
        """
        for attempt in range(1, 6):
            try:
                r = self.session.post(
                    GROQ_URL,
                    json=payload,
                    timeout=90
                )

                if r.status_code == 200:
                    print(
                        f"  {Fore.GREEN}[✓] "
                        f"Groq AI response received!"
                        + Style.RESET_ALL
                    )
                    return (
                        r.json()["choices"][0]
                        ["message"]["content"]
                    )

                elif r.status_code == 403:
                    print(
                        f"  {Fore.RED}[!] 403 blocked"
                        f" (attempt {attempt}/5)"
                        + Style.RESET_ALL
                    )
                    # Try Tor first
                    if attempt == 1:
                        if self._try_tor():
                            print(
                                f"  {Fore.GREEN}[✓] "
                                f"Tor available!"
                                + Style.RESET_ALL
                            )
                            self.session = (
                                self._make_session()
                            )
                            self.session.proxies = {
                                "http": (
                                    "socks5h://"
                                    "127.0.0.1:9050"
                                ),
                                "https": (
                                    "socks5h://"
                                    "127.0.0.1:9050"
                                )
                            }
                            continue

                    # Fetch + rotate proxies
                    if not self.proxies_fetched:
                        self._fetch_proxies()
                    proxy = self._next_proxy()
                    if proxy:
                        print(
                            f"  {Fore.CYAN}[*] "
                            f"Trying proxy: "
                            f"{proxy[:40]}"
                            + Style.RESET_ALL
                        )
                        self.session = (
                            self._make_session(proxy)
                        )
                    else:
                        wait = 15 * attempt
                        print(
                            f"  {Fore.YELLOW}[*] "
                            f"Waiting {wait}s..."
                            + Style.RESET_ALL
                        )

                elif r.status_code == 429:
                    wait = 30 * attempt
                    print(
                        f"  {Fore.YELLOW}[!] "
                        f"Rate limited. "
                        f"Wait {wait}s..."
                        + Style.RESET_ALL
                    )

                elif r.status_code == 401:
                    print(
                        f"  {Fore.RED}[!] "
                        f"Invalid API key!"
                        + Style.RESET_ALL
                    )
                    return None

                else:
                    print(
                        f"  {Fore.YELLOW}[!] "
                        f"HTTP {r.status_code} - "
                        f"retry {attempt}..."
                        + Style.RESET_ALL
                    )

            except requests.exceptions.SSLError:
                self.session.verify = False

            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout
            ) as e:
                print(
                    f"  {Fore.YELLOW}[!] {type(e).__name__}"
                    f" - retry {attempt}..."
                    + Style.RESET_ALL
                )

            except Exception as e:
                print(
                    f"  {Fore.RED}[!] Error: {e}"
                    + Style.RESET_ALL
                )

        return None


class _Completions:
    """Mimics groq.resources.chat.Completions"""

    def __init__(self, client: GroqClient):
        self._client = client

    def create(
        self,
        model: str,
        messages: list,
        max_tokens: int = 4000,
        temperature: float = 0.3,
        **kwargs
    ):
        """
        Same signature as groq library .create()
        Returns mock response object
        """
        print(
            f"  {Fore.CYAN}[*] Sending data "
            f"to Groq AI..."
            + Style.RESET_ALL
        )

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        content = self._client._call(payload)

        if content is None:
            raise Exception(
                "Groq API failed after all retries"
            )

        # Return mock object matching groq library
        return _MockResponse(content)


class _ChatCompletions:
    """Mimics groq.resources.Chat"""

    def __init__(self, client: GroqClient):
        self.completions = _Completions(client)


class _MockMessage:
    def __init__(self, content: str):
        self.content = content


class _MockChoice:
    def __init__(self, content: str):
        self.message = _MockMessage(content)


class _MockResponse:
    def __init__(self, content: str):
        self.choices = [_MockChoice(content)]
