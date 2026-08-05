"""
patch_groq.py
Patches all report_generators to use GroqClient
Run once: python patch_groq.py
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GROQ_CLIENT_CODE = '''"""
groq_client.py - Auto-bypass 403 blocks
"""
import os, time, random, requests
from colorama import Fore, Style, init
init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=5000&country=all&anonymity=elite",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
]


class GroqClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.working_proxies = []
        self.proxy_idx = 0
        self.session = self._build_session()
        self.proxies_fetched = False

    def _build_session(self, proxy=None):
        s = requests.Session()
        s.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json",
        })
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        return s

    def _fetch_proxies(self):
        if self.proxies_fetched:
            return
        print(f"  {Fore.CYAN}[*] Fetching proxies for Groq bypass...{Style.RESET_ALL}")
        proxies = []
        for url in PROXY_SOURCES:
            try:
                r = requests.get(url, timeout=8)
                for line in r.text.strip().split("\\n"):
                    line = line.strip()
                    if ":" in line and len(line) < 25:
                        proxies.append(f"https://{line}")
            except:
                continue
        random.shuffle(proxies)
        for proxy in proxies[:30]:
            if len(self.working_proxies) >= 5:
                break
            try:
                requests.get("https://api.groq.com", proxies={"https": proxy}, timeout=4, verify=False)
                self.working_proxies.append(proxy)
                print(f"  {Fore.GREEN}[✓] Proxy: {proxy[:40]}{Style.RESET_ALL}")
            except:
                continue
        self.proxies_fetched = True

    def _next_proxy(self):
        if not self.working_proxies:
            return None
        p = self.working_proxies[self.proxy_idx % len(self.working_proxies)]
        self.proxy_idx += 1
        return p

    def chat(self, messages, model="llama-3.3-70b-versatile", temperature=0.3, max_tokens=4000):
        payload = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
        for attempt in range(1, 6):
            try:
                print(f"  {Fore.CYAN}[*] Sending to Groq AI... (attempt {attempt}){Style.RESET_ALL}")
                r = self.session.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    json=payload, timeout=60
                )
                if r.status_code == 200:
                    print(f"  {Fore.GREEN}[✓] Groq response received!{Style.RESET_ALL}")
                    return r.json()["choices"][0]["message"]["content"]
                elif r.status_code == 403:
                    print(f"  {Fore.RED}[!] 403 blocked - rotating...{Style.RESET_ALL}")
                    if not self.proxies_fetched:
                        self._fetch_proxies()
                    proxy = self._next_proxy()
                    self.session = self._build_session(proxy)
                elif r.status_code == 429:
                elif r.status_code == 401:
                    raise ValueError("Invalid API key")
                else:
            except ValueError:
                raise
            except requests.exceptions.SSLError:
                self.session.verify = False
            except Exception as e:
                print(f"  {Fore.YELLOW}[!] {e}{Style.RESET_ALL}")
        return None
'''

def patch_category(cat_dir, cat_name):
    core_dir = os.path.join(cat_dir, 'core')
    if not os.path.exists(core_dir):
        print(f"[!] {cat_name}/core not found - skip")
        return

    # Write groq_client.py
    gc_path = os.path.join(core_dir, 'groq_client.py')
    with open(gc_path, 'w', encoding='utf-8') as f:
        f.write(GROQ_CLIENT_CODE)
    print(f"[✓] Written: {gc_path}")

def main():
    cats = [
        (os.path.join(BASE_DIR, 'category1'), 'Cat1'),
        (os.path.join(BASE_DIR, 'category2'), 'Cat2'),
        (os.path.join(BASE_DIR, 'category3'), 'Cat3'),
    ]
    for cat_dir, cat_name in cats:
        patch_category(cat_dir, cat_name)
    print("\n[✓] Done! GroqClient ready in all categories.")
    print("[→] Now update report_generator.py files")
    print("    to use: from core.groq_client import GroqClient")

if __name__ == "__main__":
    main()
