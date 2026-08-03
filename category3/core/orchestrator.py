import json
import os
import sys
import time
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
    """
    Prints detailed real-time logs
    for every action happening in backend.
    """

    def __init__(self, agent_name, agent_num, total):
        self.agent_name = agent_name
        self.agent_num = agent_num
        self.total = total
        self.step_count = 0
        self.start_time = time.time()

    def header(self):
        elapsed = round(time.time() - self.start_time, 1)
        print(
            f"\n{Fore.MAGENTA}"
            + "═" * 62
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}  [{self.agent_num}/{self.total}] "
            f"{self.agent_name}"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            + "═" * 62
            + Style.RESET_ALL
        )

    def step(self, msg):
        self.step_count += 1
        elapsed = round(time.time() - self.start_time, 1)
        print(
            f"  {Fore.CYAN}[STEP {self.step_count}] "
            f"{msg} "
            f"{Fore.WHITE}({elapsed}s)"
            + Style.RESET_ALL
        )

    def info(self, msg):
        print(
            f"    {Fore.WHITE}│ {msg}"
            + Style.RESET_ALL
        )

    def found(self, msg):
        print(
            f"    {Fore.GREEN}│ ✓ {msg}"
            + Style.RESET_ALL
        )

    def warn(self, msg):
        print(
            f"    {Fore.YELLOW}│ ⚠ {msg}"
            + Style.RESET_ALL
        )

    def critical(self, msg):
        print(
            f"    {Fore.RED}│ ⚠⚠ CRITICAL: {msg}"
            + Style.RESET_ALL
        )

    def high(self, msg):
        print(
            f"    {Fore.RED}│ !! HIGH: {msg}"
            + Style.RESET_ALL
        )

    def medium(self, msg):
        print(
            f"    {Fore.YELLOW}│ !  MEDIUM: {msg}"
            + Style.RESET_ALL
        )

    def low(self, msg):
        print(
            f"    {Fore.GREEN}│ -  LOW: {msg}"
            + Style.RESET_ALL
        )

    def testing(self, what, value=''):
        val_str = (
            f" → {Fore.WHITE}{value[:50]}"
            if value else ''
        )
        print(
            f"    {Fore.CYAN}│ ▶ Testing: "
            f"{Fore.WHITE}{what}"
            f"{val_str}"
            + Style.RESET_ALL
        )

    def skip(self, msg):
        print(
            f"    {Fore.WHITE}│ ○ Skip: {msg}"
            + Style.RESET_ALL
        )

    def done(self, finding_count):
        elapsed = round(time.time() - self.start_time, 1)
        color = (
            Fore.RED
            if finding_count > 0
            else Fore.GREEN
        )
        icon = '⚠' if finding_count > 0 else '✓'
        print(
            f"\n  {color}{icon} {self.agent_name} "
            f"DONE — "
            f"{finding_count} finding(s) | "
            f"{elapsed}s"
            + Style.RESET_ALL
        )

    def error(self, msg):
        print(
            f"    {Fore.RED}│ ✗ ERROR: {msg}"
            + Style.RESET_ALL
        )

    def finding(self, risk, ftype, detail=''):
        risk_upper = risk.upper()
        if risk_upper == 'CRITICAL':
            self.critical(f"{ftype} | {detail}")
        elif risk_upper == 'HIGH':
            self.high(f"{ftype} | {detail}")
        elif risk_upper == 'MEDIUM':
            self.medium(f"{ftype} | {detail}")
        else:
            self.low(f"{ftype} | {detail}")


# ════════════════════════════════════════════════════
#  VERBOSE AGENT RUNNERS
# ════════════════════════════════════════════════════

def run_auth_verbose(target_url, session, log):
    """Authentication agent with full live logging."""
    from agents.auth_agent import AuthAgent
    from urllib.parse import urljoin
    from bs4 import BeautifulSoup

    findings = []

    # ── Step 1: Detect login pages ───────────────────
    log.step("Scanning for login pages")

    login_paths = [
        '/login', '/signin', '/auth',
        '/admin', '/admin/login',
        '/user/login', '/account/login',
        '/wp-login.php', '/wp-admin',
        '/administrator', '/panel',
        '/dashboard', '/portal',
        '/api/login', '/api/auth',
        '/api/v1/login', '/api/v2/login',
        '/member/login', '/user/signin',
        '/auth/login', '/auth/signin',
    ]

    log.info(
        f"Probing {len(login_paths)} common paths..."
    )
    found_pages = []

    for path in login_paths:
        url = urljoin(target_url, path)
        log.testing("Login path", path)
        try:
            r = session.get(
                url, timeout=6,
                allow_redirects=True
            )
            if r.status_code == 200:
                soup = BeautifulSoup(
                    r.text, 'html.parser'
                )
                forms = soup.find_all('form')
                has_pwd = any(
                    inp.get('type') == 'password'
                    for form in forms
                    for inp in form.find_all('input')
                )
                if has_pwd or 'login' in r.text.lower():
                    found_pages.append({
                        'url': url,
                        'has_form': bool(forms),
                        'has_password_field': has_pwd
                    })
                    log.found(
                        f"Login page found: {path}"
                    )
                else:
                    log.info(
                        f"[{r.status_code}] "
                        f"No login form: {path}"
                    )
            else:
                log.info(
                    f"[{r.status_code}] {path}"
                )
        except Exception as e:
            log.info(f"Timeout/Error: {path}")

    log.info(
        f"Total login pages found: {len(found_pages)}"
    )

    if not found_pages:
        log.warn(
            "No login pages found. "
            "Skipping auth tests."
        )
        findings.append({
            'type': 'No Login Page Found',
            'category': 'authentication',
            'risk': 'INFO',
            'description': (
                'No standard login pages detected'
            ),
            'note': 'Custom auth paths may exist'
        })
        return findings

    # ── Step 2: Default credentials ──────────────────
    log.step("Testing default credentials")

    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', 'admin123'),
        ('admin', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('administrator', 'administrator'),
        ('test', 'test'),
        ('guest', 'guest'),
        ('user', 'user'),
        ('admin', 'letmein'),
    ]

    log.info(
        f"Testing {len(default_creds)} "
        f"credential pairs on "
        f"{min(3, len(found_pages))} pages..."
    )

    success_indicators = [
        'dashboard', 'logout', 'welcome',
        'profile', 'settings', 'account',
        'signed in', 'logged in',
    ]
    failure_indicators = [
        'invalid', 'incorrect', 'wrong',
        'failed', 'error', 'denied',
        'unauthorized', 'bad credentials',
    ]

    for page in found_pages[:3]:
        url = page['url']
        log.info(f"Target form: {url}")
        try:
            r = session.get(url, timeout=8)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                log.skip("No form found on page")
                continue

            inputs = form.find_all('input')
            user_field = None
            pass_field = None
            for inp in inputs:
                itype = inp.get('type', '').lower()
                iname = inp.get('name', '').lower()
                if itype in ['text', 'email'] or any(
                    k in iname for k in [
                        'user', 'email', 'login',
                        'name', 'id'
                    ]
                ):
                    user_field = inp.get('name')
                elif itype == 'password':
                    pass_field = inp.get('name')

            if not user_field or not pass_field:
                log.skip(
                    "Could not identify "
                    "username/password fields"
                )
                continue

            log.info(
                f"Fields detected → "
                f"user: '{user_field}' | "
                f"pass: '{pass_field}'"
            )

            action = form.get('action', url)
            if not action.startswith('http'):
                action = urljoin(url, action)

            for username, password in default_creds[:8]:
                log.testing(
                    "Credentials",
                    f"{username}:{password}"
                )
                data = {
                    user_field: username,
                    pass_field: password
                }
                try:
                    resp = session.post(
                        action, data=data,
                        timeout=10,
                        allow_redirects=True
                    )
                    resp_lower = resp.text.lower()
                    success = any(
                        s in resp_lower
                        for s in success_indicators
                    )
                    failure = any(
                        f in resp_lower
                        for f in failure_indicators
                    )
                    if success and not failure:
                        log.critical(
                            f"Default credentials work: "
                            f"{username}:{password}"
                        )
                        finding = {
                            'type': (
                                'Default Credentials Accepted'
                            ),
                            'category': 'authentication',
                            'risk': 'CRITICAL',
                            'url': action,
                            'username': username,
                            'password': password,
                            'description': (
                                f'Default credentials '
                                f'"{username}:{password}" '
                                f'accepted'
                            ),
                            'business_impact': (
                                'Full account takeover. '
                                'Immediate admin access.'
                            ),
                            'fix': (
                                '1. Change all default passwords\n'
                                '2. Enforce strong policy\n'
                                '3. Implement lockout\n'
                                '4. Enable MFA'
                            ),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-798'
                        }
                        findings.append(finding)
                        log.finding(
                            'CRITICAL',
                            'Default Credentials',
                            f"{username}:{password}"
                        )
                    else:
                        log.info(
                            f"Rejected: "
                            f"{username}:{password}"
                        )
                    time.sleep(0.3)
                except Exception as e:
                    log.error(f"Request failed: {e}")
        except Exception as e:
            log.error(f"Form parse error: {e}")

    # ── Step 3: Account lockout ───────────────────────
    log.step("Testing account lockout policy")
    log.info(
        "Sending 10 failed login attempts..."
    )

    for page in found_pages[:2]:
        url = page['url']
        try:
            r = session.get(url, timeout=8)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                continue

            inputs = form.find_all('input')
            user_field = None
            pass_field = None
            for inp in inputs:
                itype = inp.get('type', '').lower()
                iname = inp.get('name', '').lower()
                if itype in ['text', 'email'] or any(
                    k in iname for k in [
                        'user', 'email', 'login'
                    ]
                ):
                    user_field = inp.get('name')
                elif itype == 'password':
                    pass_field = inp.get('name')

            if not user_field or not pass_field:
                continue

            action = form.get('action', url)
            if not action.startswith('http'):
                action = urljoin(url, action)

            lockout_detected = False
            for i in range(10):
                log.testing(
                    f"Failed attempt {i+1}/10",
                    f"wrong_password_{i}"
                )
                data = {
                    user_field: 'lockout_test_user',
                    pass_field: f'wrong_password_{i}'
                }
                try:
                    resp = session.post(
                        action, data=data,
                        timeout=8
                    )
                    resp_lower = resp.text.lower()
                    if any(
                        k in resp_lower for k in [
                            'locked', 'too many',
                            'blocked', 'suspended',
                            'temporarily', 'limit'
                        ]
                    ):
                        lockout_detected = True
                        log.found(
                            f"Lockout triggered "
                            f"at attempt {i+1}"
                        )
                        break
                    if resp.status_code == 429:
                        lockout_detected = True
                        log.found(
                            f"Rate limit (429) "
                            f"at attempt {i+1}"
                        )
                        break
                    log.info(
                        f"Attempt {i+1}: "
                        f"status={resp.status_code}"
                    )
                except Exception:
                    pass
                time.sleep(0.2)

            if not lockout_detected:
                log.high(
                    "No lockout after 10 attempts!"
                )
                findings.append({
                    'type': 'Missing Account Lockout',
                    'category': 'authentication',
                    'risk': 'HIGH',
                    'url': url,
                    'description': (
                        'No lockout after '
                        '10 failed login attempts'
                    ),
                    'business_impact': (
                        'Brute force attacks unrestricted'
                    ),
                    'fix': (
                        '1. Lock after 5 failed attempts\n'
                        '2. Progressive delay\n'
                        '3. Add CAPTCHA\n'
                        '4. Alert on failures'
                    ),
                    'cvss_score': 7.5,
                    'cwe': 'CWE-307'
                })
                log.finding(
                    'HIGH', 'Missing Account Lockout',
                    url
                )
            else:
                log.found("Lockout policy active - GOOD")
        except Exception as e:
            log.error(f"Lockout test error: {e}")

    # ── Step 4: MFA detection ─────────────────────────
    log.step("Checking for MFA indicators")
    mfa_indicators = [
        'two-factor', '2fa', 'totp',
        'authenticator', 'otp', 'verification code',
        'one-time', 'sms code', 'email code'
    ]

    for page in found_pages[:3]:
        log.testing("MFA indicators", page['url'])
        try:
            r = session.get(page['url'], timeout=8)
            resp_lower = r.text.lower()
            found_mfa = [
                m for m in mfa_indicators
                if m in resp_lower
            ]
            if found_mfa:
                log.found(
                    f"MFA detected: {found_mfa}"
                )
            else:
                log.medium(
                    "No MFA indicators found"
                )
                findings.append({
                    'type': 'No MFA Detected',
                    'category': 'authentication',
                    'risk': 'MEDIUM',
                    'url': page['url'],
                    'description': (
                        'No MFA indicators on login page'
                    ),
                    'business_impact': (
                        'Password compromise = '
                        'full account access'
                    ),
                    'fix': (
                        '1. Implement TOTP\n'
                        '2. Add SMS/Email OTP\n'
                        '3. Enforce MFA for admin'
                    ),
                    'cvss_score': 6.5,
                    'cwe': 'CWE-308'
                })
                log.finding(
                    'MEDIUM', 'No MFA', page['url']
                )
        except Exception as e:
            log.error(f"MFA check error: {e}")

    return findings


def run_command_injection_verbose(
    target_url, session, log
):
    """Command injection with live logging."""
    import os as _os
    from urllib.parse import quote, urlparse

    findings = []

    def load_payloads():
        path = _os.path.join(
            'payloads',
            'command_injection_payloads.txt'
        )
        try:
            with open(path, 'r') as f:
                return [
                    l.strip() for l in f
                    if l.strip()
                    and not l.startswith('#')
                ]
        except FileNotFoundError:
            return [
                '; ls', '| ls', '& ls',
                '; whoami', '| whoami',
                '; sleep 5', '| sleep 5',
                '$(id)', '`id`'
            ]

    payloads = load_payloads()
    log.step(
        f"Loaded {len(payloads)} command injection payloads"
    )

    os_indicators = [
        'uid=', 'gid=', 'groups=',
        'root:', 'daemon:', '/bin/sh',
        'volume serial', 'windows ip',
        'directory of', 'total 0',
        '/usr/bin', '/usr/local',
        'drwxr', '-rwxr'
    ]

    parsed = urlparse(target_url)
    if not parsed.query:
        log.skip(
            "No URL parameters found. "
            "Trying common param names..."
        )
        test_urls = [
            f"{target_url}?cmd=ls",
            f"{target_url}?exec=ls",
            f"{target_url}?command=ls",
            f"{target_url}?run=ls",
            f"{target_url}?ping=127.0.0.1",
            f"{target_url}?host=localhost",
            f"{target_url}?ip=127.0.0.1",
        ]
        log.info(
            f"Testing {len(test_urls)} "
            f"common command params..."
        )
    else:
        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v
        test_urls = [target_url]
        log.info(
            f"URL params found: "
            f"{list(params.keys())}"
        )

    # Error-based
    log.step("Phase 1: Error-based command injection")
    log.info(
        f"Testing {len(payloads[:8])} payloads..."
    )

    for url in test_urls[:3]:
        parsed = urlparse(url)
        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v

        for param in list(params.keys())[:3]:
            log.info(f"Parameter: '{param}'")
            for payload in payloads[:8]:
                log.testing(
                    f"Payload on '{param}'",
                    payload
                )
                test_params = params.copy()
                test_params[param] = (
                    params[param] + payload
                )
                q = '&'.join(
                    f'{k}={quote(str(v), safe="")}'
                    for k, v in test_params.items()
                )
                test_url = (
                    f"{parsed.scheme}://"
                    f"{parsed.netloc}"
                    f"{parsed.path}?{q}"
                )
                try:
                    r = session.get(
                        test_url, timeout=10
                    )
                    for indicator in os_indicators:
                        if indicator in r.text:
                            log.critical(
                                f"OS output detected! "
                                f"Indicator: '{indicator}' "
                                f"in param '{param}'"
                            )
                            findings.append({
                                'type': (
                                    'Command Injection '
                                    '- Error Based'
                                ),
                                'category': (
                                    'command_injection'
                                ),
                                'risk': 'CRITICAL',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': indicator,
                                'description': (
                                    f'OS output in "{param}"'
                                ),
                                'business_impact': (
                                    'RCE - Server compromised'
                                ),
                                'fix': (
                                    '1. Never pass input '
                                    'to OS commands\n'
                                    '2. Use safe APIs\n'
                                    '3. Whitelist input'
                                ),
                                'cvss_score': 10.0,
                                'cwe': 'CWE-78'
                            })
                            log.finding(
                                'CRITICAL',
                                'Command Injection',
                                f"param={param}"
                            )
                            break
                    else:
                        log.info(
                            f"No OS output detected "
                            f"[status={r.status_code}]"
                        )
                    time.sleep(0.2)
                except Exception as e:
                    log.error(f"Request error: {e}")

    # Time-based
    log.step("Phase 2: Time-based blind command injection")
    log.info("Testing sleep/delay payloads...")

    time_payloads = [
        '; sleep 5',
        '| sleep 5',
        '& sleep 5',
        '; ping -c 5 127.0.0.1',
    ]

    for url in test_urls[:2]:
        parsed = urlparse(url)
        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v

        for param in list(params.keys())[:2]:
            try:
                log.testing(
                    "Baseline response time",
                    url
                )
                start = time.time()
                session.get(url, timeout=12)
                baseline = time.time() - start
                log.info(
                    f"Baseline: {round(baseline, 2)}s"
                )
            except Exception:
                continue

            for payload in time_payloads[:3]:
                log.testing(
                    f"Time payload on '{param}'",
                    payload
                )
                test_params = params.copy()
                test_params[param] = (
                    params[param] + payload
                )
                q = '&'.join(
                    f'{k}={quote(str(v), safe="")}'
                    for k, v in test_params.items()
                )
                test_url = (
                    f"{parsed.scheme}://"
                    f"{parsed.netloc}"
                    f"{parsed.path}?{q}"
                )
                try:
                    start = time.time()
                    session.get(
                        test_url, timeout=15
                    )
                    elapsed = time.time() - start
                    log.info(
                        f"Response time: "
                        f"{round(elapsed, 2)}s "
                        f"(baseline: "
                        f"{round(baseline, 2)}s)"
                    )

                    if elapsed > baseline + 4:
                        delay = round(
                            elapsed - baseline, 1
                        )
                        log.critical(
                            f"TIME DELAY DETECTED! "
                            f"+{delay}s delay "
                            f"→ param='{param}'"
                        )
                        findings.append({
                            'type': (
                                'Command Injection '
                                '- Time Based Blind'
                            ),
                            'category': (
                                'command_injection'
                            ),
                            'risk': 'CRITICAL',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'baseline_time': round(
                                baseline, 2
                            ),
                            'actual_time': round(
                                elapsed, 2
                            ),
                            'description': (
                                f'Blind CMDi in '
                                f'"{param}". '
                                f'Delay: +{delay}s'
                            ),
                            'business_impact': (
                                'Blind RCE possible'
                            ),
                            'fix': (
                                '1. Avoid OS calls\n'
                                '2. Use safe APIs\n'
                                '3. Input whitelist'
                            ),
                            'cvss_score': 10.0,
                            'cwe': 'CWE-78'
                        })
                        log.finding(
                            'CRITICAL',
                            'Blind Command Injection',
                            f"delay=+{delay}s"
                        )
                    else:
                        log.info(
                            "No significant delay"
                        )
                except Exception as e:
                    log.error(f"Error: {e}")
                time.sleep(0.3)

    return findings


def run_generic_agent_verbose(
    agent_class, target_url,
    session, log, *args, **kwargs
):
    """
    Generic wrapper - runs any agent and
    logs each finding in real-time.
    """
    try:
        agent = agent_class(target_url, session)

        # Monkey-patch session to log requests
        original_get = session.get
        original_post = session.post
        request_count = [0]

        def logged_get(url, **kw):
            request_count[0] += 1
            log.info(
                f"GET [{request_count[0]}] "
                f"{url[:70]}"
            )
            r = original_get(url, **kw)
            log.info(
                f"    → [{r.status_code}] "
                f"{len(r.content)} bytes"
            )
            return r

        def logged_post(url, **kw):
            request_count[0] += 1
            log.info(
                f"POST [{request_count[0]}] "
                f"{url[:70]}"
            )
            r = original_post(url, **kw)
            log.info(
                f"    → [{r.status_code}] "
                f"{len(r.content)} bytes"
            )
            return r

        session.get = logged_get
        session.post = logged_post

        findings = agent.run_full_scan(
            *args, **kwargs
        )

        # Restore original methods
        session.get = original_get
        session.post = original_post

        # Log each finding
        if findings:
            log.info(
                f"Findings breakdown:"
            )
            for f in findings:
                risk = f.get('risk', 'INFO')
                ftype = f.get('type', 'Unknown')
                url = f.get('url', '')
                log.finding(
                    risk, ftype,
                    url[:50] if url else ''
                )
        else:
            log.found("No vulnerabilities detected")

        return findings if findings else []

    except Exception as e:
        log.error(f"Agent failed: {e}")
        import traceback
        traceback.print_exc()
        return []


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
        self.shared_session = None

    def print_banner(self):
        date_str = datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        print(f"\n{Fore.MAGENTA}" + "═" * 62)
        print(
            "  AI ADVANCED SECURITY ASSESSMENT AGENT"
        )
        print(
            "  Category 3 — Detailed Live Scanning"
        )
        print("═" * 62)
        print(f"  Target   : {self.target[:42]}")
        print(f"  Date     : {date_str}")
        print(
            "  Mode     : ADVANCED + LIVE LOGGING"
        )
        print(
            "  Agents   : 14 Specialized Agents"
        )
        print(
            "  Logging  : Every request logged"
        )
        print("═" * 62 + Style.RESET_ALL)

    def _get_consent(self):
        print(f"\n{Fore.RED}" + "═" * 62)
        print("  LEGAL WARNING")
        print("═" * 62)
        print(
            "  Advanced scanning requires"
        )
        print(
            "  WRITTEN AUTHORIZATION."
        )
        print("═" * 62 + Style.RESET_ALL)

        print(
            f"\n{Fore.YELLOW}Target: "
            f"{Fore.CYAN}{self.target}"
            + Style.RESET_ALL
        )

        try:
            resp = input(
                f"\n{Fore.YELLOW}Do you have written "
                f"authorization? (yes/no): "
                + Style.RESET_ALL
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(
                f"\n{Fore.RED}[!] Cancelled."
                + Style.RESET_ALL
            )
            return False

        if resp != 'yes':
            print(
                f"{Fore.RED}[!] Consent not given."
                + Style.RESET_ALL
            )
            return False

        print(
            f"\n{Fore.GREEN}[✓] Consent confirmed."
            + Style.RESET_ALL
        )
        return True

    def _print_scan_start(self):
        """Print what's about to happen."""
        print(
            f"\n{Fore.CYAN}" + "═" * 62
        )
        print(
            "  SCAN PLAN — 14 AGENTS"
        )
        print("═" * 62)

        agents_plan = [
            (1,  "Authentication",
             "Default creds | Lockout | MFA"),
            (2,  "Command Injection",
             "Error-based | Time-based blind"),
            (3,  "File Upload",
             "Extension bypass | MIME bypass"),
            (4,  "SSRF",
             "Internal IPs | Cloud metadata"),
            (5,  "XXE Injection",
             "File read | SSRF via XML"),
            (6,  "NoSQL Injection",
             "JSON operators | Param injection"),
            (7,  "SSTI",
             "Jinja2 | Twig | Freemarker | ERB"),
            (8,  "CSRF",
             "Token check | SameSite cookie"),
            (9,  "WebSocket",
             "WS discovery | Encryption check"),
            (10, "HTTP Host Header",
             "Injection | Reset poisoning"),
            (11, "Web Cache",
             "Cache headers | Deception test"),
            (12, "OAuth",
             "State param | Redirect URI"),
            (13, "Prototype Pollution",
             "Client-side | Server-side"),
            (14, "Access Control",
             "Admin access | Method bypass | "
             "Header bypass"),
        ]

        for num, name, coverage in agents_plan:
            print(
                f"  {Fore.MAGENTA}[{num:02d}]"
                f"{Fore.WHITE} {name:<25}"
                f"{Fore.CYAN}{coverage}"
                + Style.RESET_ALL
            )

        print("═" * 62 + Style.RESET_ALL)
        print(
            f"\n{Fore.YELLOW}Starting scan in 2s..."
            + Style.RESET_ALL
        )
        time.sleep(2)

    def _make_session(self):
        s = requests.Session()
        s.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 '
                '(Authorized Assessment)'
            )
        })
        return s

    def run_assessment(self, skip_consent=False):
        self.print_banner()

        if not skip_consent:
            if not self._get_consent():
                return None

        self._print_scan_start()

        self.start_time = datetime.now()
        self.shared_session = self._make_session()
        total = 14

        # ════════════════════════════════════════════
        #  AGENT 1: AUTHENTICATION
        # ════════════════════════════════════════════
        log = LiveLogger("AUTHENTICATION", 1, total)
        log.header()
        log.info("Checking for login forms...")
        log.info("Will test: default creds, "
                 "lockout policy, MFA indicators")
        try:
            self.results['authentication'] = (
                run_auth_verbose(
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['authentication'] = []
        log.done(len(
            self.results['authentication']
        ))

        # ════════════════════════════════════════════
        #  AGENT 2: COMMAND INJECTION
        # ════════════════════════════════════════════
        log = LiveLogger(
            "COMMAND INJECTION", 2, total
        )
        log.header()
        log.info(
            "Testing OS command injection via "
            "URL parameters"
        )
        log.info(
            "Payloads: ; ls | ls & ls ; whoami "
            "sleep/ping time-based"
        )
        try:
            self.results['command_injection'] = (
                run_command_injection_verbose(
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['command_injection'] = []
        log.done(len(
            self.results['command_injection']
        ))

        # ════════════════════════════════════════════
        #  AGENT 3: FILE UPLOAD
        # ════════════════════════════════════════════
        log = LiveLogger("FILE UPLOAD", 3, total)
        log.header()
        log.info(
            "Discovering upload endpoints..."
        )
        log.info(
            "Tests: .php .asp .jsp extensions, "
            "MIME type bypass"
        )
        try:
            self.results['file_upload'] = (
                run_generic_agent_verbose(
                    FileUploadAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['file_upload'] = []
        log.done(len(self.results['file_upload']))

        # ════════════════════════════════════════════
        #  AGENT 4: SSRF
        # ════════════════════════════════════════════
        log = LiveLogger("SSRF", 4, total)
        log.header()
        log.info(
            "Looking for SSRF-prone parameters..."
        )
        log.info(
            "Targets: 127.0.0.1, localhost, "
            "169.254.169.254 (AWS metadata)"
        )
        log.info(
            "Params checked: url, uri, link, "
            "src, dest, redirect, callback..."
        )
        try:
            self.results['ssrf'] = (
                run_generic_agent_verbose(
                    SSRFAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['ssrf'] = []
        log.done(len(self.results['ssrf']))

        # ════════════════════════════════════════════
        #  AGENT 5: XXE
        # ════════════════════════════════════════════
        log = LiveLogger("XXE INJECTION", 5, total)
        log.header()
        log.info(
            "Searching for XML/SOAP endpoints..."
        )
        log.info(
            "Payloads: file:///etc/passwd, "
            "SSRF via entity, blind XXE"
        )
        try:
            self.results['xxe'] = (
                run_generic_agent_verbose(
                    XXEAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['xxe'] = []
        log.done(len(self.results['xxe']))

        # ════════════════════════════════════════════
        #  AGENT 6: NoSQL INJECTION
        # ════════════════════════════════════════════
        log = LiveLogger("NOSQL INJECTION", 6, total)
        log.header()
        log.info(
            "Testing MongoDB operator injection..."
        )
        log.info(
            "Payloads: {$gt:''} {$ne:null} "
            "{$regex:.*} [$ne]=1 [$gt]=0"
        )
        log.info(
            "Methods: JSON body + URL params"
        )
        try:
            self.results['nosql_injection'] = (
                run_generic_agent_verbose(
                    NoSQLAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['nosql_injection'] = []
        log.done(len(
            self.results['nosql_injection']
        ))

        # ════════════════════════════════════════════
        #  AGENT 7: SSTI
        # ════════════════════════════════════════════
        log = LiveLogger("SSTI", 7, total)
        log.header()
        log.info(
            "Testing Server-Side Template Injection..."
        )
        log.info(
            "Engines: Jinja2 {{7*7}}, "
            "Twig {{7*7}}, Freemarker ${7*7}, "
            "ERB <%=7*7%>"
        )
        log.info(
            "Detection: math expression evaluation "
            "(expects output: 49)"
        )
        try:
            self.results['ssti'] = (
                run_generic_agent_verbose(
                    SSTIAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['ssti'] = []
        log.done(len(self.results['ssti']))

        # ════════════════════════════════════════════
        #  AGENT 8: CSRF
        # ════════════════════════════════════════════
        log = LiveLogger("CSRF", 8, total)
        log.header()
        log.info(
            "Analyzing forms for CSRF protection..."
        )
        log.info(
            "Checks: csrf_token, _token, "
            "authenticity_token, "
            "csrfmiddlewaretoken"
        )
        log.info(
            "Pages: login, register, profile, "
            "settings, account"
        )
        try:
            self.results['csrf'] = (
                run_generic_agent_verbose(
                    CSRFAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['csrf'] = []
        log.done(len(self.results['csrf']))

        # ════════════════════════════════════════════
        #  AGENT 9: WEBSOCKET
        # ════════════════════════════════════════════
        log = LiveLogger("WEBSOCKET", 9, total)
        log.header()
        log.info(
            "Scanning for WebSocket endpoints..."
        )
        log.info(
            "Paths: /ws /websocket /socket.io "
            "/realtime /live /stream"
        )
        log.info(
            "Checks: wss:// vs ws://, "
            "auth on connection"
        )
        try:
            self.results['websocket'] = (
                run_generic_agent_verbose(
                    WebSocketAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['websocket'] = []
        log.done(len(self.results['websocket']))

        # ════════════════════════════════════════════
        #  AGENT 10: HTTP HOST HEADER
        # ════════════════════════════════════════════
        log = LiveLogger(
            "HTTP HOST HEADER", 10, total
        )
        log.header()
        log.info(
            "Injecting malicious Host headers..."
        )
        log.info(
            "Evil hosts: evil-attacker.com, "
            "attacker.com"
        )
        log.info(
            "Checking: reflection in response, "
            "password reset poisoning"
        )
        try:
            self.results['http_host_header'] = (
                run_generic_agent_verbose(
                    HTTPHostHeaderAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['http_host_header'] = []
        log.done(len(
            self.results['http_host_header']
        ))

        # ════════════════════════════════════════════
        #  AGENT 11: WEB CACHE
        # ════════════════════════════════════════════
        log = LiveLogger("WEB CACHE", 11, total)
        log.header()
        log.info(
            "Analyzing cache configuration..."
        )
        log.info(
            "Checks: Cache-Control, Vary header, "
            "sensitive pages caching"
        )
        log.info(
            "Cache deception: appending "
            ".css .js .jpg to sensitive paths"
        )
        try:
            self.results['web_cache'] = (
                run_generic_agent_verbose(
                    WebCacheAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['web_cache'] = []
        log.done(len(self.results['web_cache']))

        # ════════════════════════════════════════════
        #  AGENT 12: OAUTH
        # ════════════════════════════════════════════
        log = LiveLogger("OAUTH", 12, total)
        log.header()
        log.info(
            "Discovering OAuth endpoints..."
        )
        log.info(
            "Paths: /oauth /oauth2 /authorize "
            "/connect /.well-known/openid-configuration"
        )
        log.info(
            "Checks: state parameter, "
            "redirect_uri validation"
        )
        try:
            self.results['oauth'] = (
                run_generic_agent_verbose(
                    OAuthAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['oauth'] = []
        log.done(len(self.results['oauth']))

        # ════════════════════════════════════════════
        #  AGENT 13: PROTOTYPE POLLUTION
        # ════════════════════════════════════════════
        log = LiveLogger(
            "PROTOTYPE POLLUTION", 13, total
        )
        log.header()
        log.info(
            "Scanning JS source for "
            "dangerous patterns..."
        )
        log.info(
            "Patterns: __proto__, "
            "constructor.prototype, "
            "Object.prototype, lodash.merge"
        )
        log.info(
            "Server-side: testing __proto__ "
            "in JSON body"
        )
        try:
            self.results['prototype_pollution'] = (
                run_generic_agent_verbose(
                    PrototypePollutionAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['prototype_pollution'] = []
        log.done(len(
            self.results['prototype_pollution']
        ))

        # ════════════════════════════════════════════
        #  AGENT 14: ACCESS CONTROL
        # ════════════════════════════════════════════
        log = LiveLogger(
            "ACCESS CONTROL", 14, total
        )
        log.header()
        log.info(
            "Testing unauthorized access to "
            "admin endpoints..."
        )
        log.info(
            "Paths: /admin /administrator "
            "/panel /superadmin /api/admin"
        )
        log.info(
            "Bypass methods: HTTP method override, "
            "header-based bypass"
        )
        log.info(
            "Headers: X-Original-URL, "
            "X-Forwarded-For, X-Real-IP"
        )
        try:
            self.results['access_control'] = (
                run_generic_agent_verbose(
                    AccessControlAgent,
                    self.target_url,
                    self.shared_session,
                    log
                )
            )
        except Exception as e:
            log.error(str(e))
            self.results['access_control'] = []
        log.done(len(
            self.results['access_control']
        ))

        # ════════════════════════════════════════════
        #  FINAL STATS
        # ════════════════════════════════════════════
        self.end_time = datetime.now()
        duration = (
            self.end_time - self.start_time
        ).seconds

        total_findings = sum(
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

        print(
            f"\n{Fore.GREEN}" + "═" * 62
        )
        print("  CATEGORY 3 COMPLETE")
        print("═" * 62)
        print(f"  Target   : {self.target}")
        print(f"  Duration : {duration}s")
        print(f"  Total    : {total_findings} findings")
        print(
            f"  {Fore.RED}Critical : {critical}"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.YELLOW}High     : {high}"
            + Style.RESET_ALL
        )
        print(
            f"  {Fore.YELLOW}Medium   : {medium}"
            + Style.RESET_ALL
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
            f"\n{Fore.CYAN}[*] Generating AI report..."
            + Style.RESET_ALL
        )

        duration = 0
        if self.start_time and self.end_time:
            duration = (
                self.end_time - self.start_time
            ).seconds

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
        target_clean = self.target.replace('.', '_')
        base = os.path.join(
            'output',
            f"{target_clean}_{timestamp}"
        )

        with open(
            f"{base}.md", 'w', encoding='utf-8'
        ) as f:
            f.write(report['markdown'])
        print(
            f"  {Fore.GREEN}[✓] Markdown: {base}.md"
            + Style.RESET_ALL
        )

        with open(
            f"{base}_raw.json", 'w', encoding='utf-8'
        ) as f:
            json.dump(
                self.results, f,
                indent=2, default=str
            )
        print(
            f"  {Fore.GREEN}[✓] JSON: "
            f"{base}_raw.json"
            + Style.RESET_ALL
        )

        try:
            generator.generate_pdf(
                report['markdown'],
                f"{base}.pdf"
            )
            print(
                f"  {Fore.GREEN}[✓] PDF: {base}.pdf"
                + Style.RESET_ALL
            )
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] PDF failed: {e}"
                + Style.RESET_ALL
            )

        return report
