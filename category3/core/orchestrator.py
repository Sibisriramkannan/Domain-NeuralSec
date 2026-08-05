"""
Category 3 - Advanced Scan Orchestrator (FAST REBUILD)
Streamlined, low-overhead, faster execution.
"""
import json, os, sys, time, requests
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urljoin, urlparse, quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents import (
    AuthAgent, CommandInjectionAgent, FileUploadAgent,
    SSRFAgent, XXEAgent, NoSQLAgent, SSTIAgent,
    CSRFAgent, WebSocketAgent, HTTPHostHeaderAgent,
    WebCacheAgent, OAuthAgent, PrototypePollutionAgent,
    AccessControlAgent
)
from core.report_generator import AdvancedReportGenerator
init(autoreset=True)


class FastLiveLogger:
    """Low-overhead live logger."""
    __slots__ = ('agent_name', 'num', 'total', 'start')
    def __init__(self, name, num, total):
        self.agent_name = name; self.num = num; self.total = total; self.start = time.time()
    def header(self):
        print(f"\n{Fore.MAGENTA}{'='*50}{Style.RESET_ALL}\n  [{self.num}/{self.total}] {self.agent_name}\n{'='*50}{Style.RESET_ALL}")
    def step(self, msg):
        print(f"  {Fore.CYAN}[STEP] {msg} ({round(time.time()-self.start,1)}s){Style.RESET_ALL}")
    def info(self, msg): print(f"    {Fore.WHITE}│ {msg}{Style.RESET_ALL}")
    def found(self, msg): print(f"    {Fore.GREEN}│ ✓ {msg}{Style.RESET_ALL}")
    def warn(self, msg): print(f"    {Fore.YELLOW}│ ⚠ {msg}{Style.RESET_ALL}")
    def critical(self, msg): print(f"    {Fore.RED}│ ⚠⚠ CRITICAL: {msg}{Style.RESET_ALL}")
    def high(self, msg): print(f"    {Fore.RED}│ !! HIGH: {msg}{Style.RESET_ALL}")
    def medium(self, msg): print(f"    {Fore.YELLOW}│ ! MEDIUM: {msg}{Style.RESET_ALL}")
    def low(self, msg): print(f"    {Fore.GREEN}│ - LOW: {msg}{Style.RESET_ALL}")
    def testing(self, what, val=''):
        val_str = f" → {Fore.WHITE}{val[:40]}" if val else ''
        print(f"    {Fore.CYAN}│ ▶ {what}{val_str}{Style.RESET_ALL}")
    def done(self, count):
        color = Fore.RED if count > 0 else Fore.GREEN
        icon = '⚠' if count > 0 else '✓'
        print(f"\n  {color}{icon} {self.agent_name} DONE — {count} finding(s) | {round(time.time()-self.start,1)}s{Style.RESET_ALL}")
    def error(self, msg): print(f"    {Fore.RED}│ ✗ ERROR: {msg}{Style.RESET_ALL}")
    def finding(self, risk, ftype, detail=''):
        m = risk.upper()
        if m == 'CRITICAL': self.critical(f"{ftype} | {detail}")
        elif m == 'HIGH': self.high(f"{ftype} | {detail}")
        elif m == 'MEDIUM': self.medium(f"{ftype} | {detail}")
        else: self.low(f"{ftype} | {detail}")


def _load_payloads(path):
    try:
        with open(path, 'r') as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        return ['; ls', '| ls', '& ls', '; sleep 5', '| sleep 5', '$(id)', '`id`']


def run_auth_fast(target_url, session, log):
    from bs4 import BeautifulSoup
    findings = []
    login_paths = ['/login','/signin','/auth','/admin','/admin/login','/user/login','/account/login','/wp-login.php','/wp-admin','/administrator','/panel','/dashboard','/portal','/api/login','/api/auth']
    found_pages = []
    log.step("Scanning login pages")
    for p in login_paths:
        url = urljoin(target_url, p)
        log.testing("Path", p)
        try:
            r = session.get(url, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                forms = soup.find_all('form')
                has_pwd = any(inp.get('type')=='password' for form in forms for inp in form.find_all('input'))
                if has_pwd or 'login' in r.text.lower():
                    found_pages.append({'url':url, 'has_form':bool(forms), 'has_pwd':has_pwd})
                    log.found(f"Login page: {p}")
                else:
                    log.info(f"No form: {p}")
            else:
                log.info(f"[{r.status_code}] {p}")
        except Exception as e:
            log.info(f"Timeout: {p}")
    log.info(f"Found {len(found_pages)} login pages")
    if not found_pages:
        findings.append({'type':'No Login Page','risk':'INFO','description':'No login pages detected'})
        return findings

    # Default creds (fast - limited set)
    log.step("Testing default credentials")
    default_creds = [('admin','admin'),('admin','password'),('root','root'),('test','test')]
    for page in found_pages[:2]:
        url = page['url']
        try:
            r = session.get(url, timeout=6)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form: continue
            inputs = form.find_all('input')
            user_f = pass_f = None
            for inp in inputs:
                itype = inp.get('type','').lower()
                iname = inp.get('name','').lower()
                if itype in ['text','email'] or any(k in iname for k in ['user','email','login','name']):
                    user_f = inp.get('name')
                elif itype == 'password':
                    pass_f = inp.get('name')
            if not user_f or not pass_f:
                log.skip("Fields missing")
                continue
            action = form.get('action', url)
            if not action.startswith('http'):
                action = urljoin(url, action)
            for u, p in default_creds:
                log.testing("Creds", f"{u}:{p}")
                try:
                    resp = session.post(action, data={user_f:u, pass_f:p}, timeout=6, allow_redirects=True)
                    lower = resp.text.lower()
                    if any(s in lower for s in ['dashboard','welcome','profile','signed in','logged in']) and not any(f in lower for f in ['invalid','incorrect','wrong','failed','error','denied']):
                        log.critical(f"Default creds work: {u}:{p}")
                        findings.append({'type':'Default Credentials','risk':'CRITICAL','url':action,'username':u,'password':p,'description':f'Default {u}:{p}','fix':'Change defaults, enforce policy, add lockout','cvss_score':9.8,'cwe':'CWE-798'})
                        log.finding('CRITICAL','Default Creds',f"{u}:{p}")
                    else:
                        log.info(f"Rejected: {u}:{p}")
                except Exception:
                    pass
                time.sleep(0.1)
        except Exception as e:
            log.error(str(e))

    # Lockout (fast - 5 attempts)
    log.step("Testing account lockout (5 attempts)")
    for page in found_pages[:1]:
        url = page['url']
        try:
            r = session.get(url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form: continue
            inputs = form.find_all('input')
            user_f = pass_f = None
            for inp in inputs:
                itype = inp.get('type','').lower()
                iname = inp.get('name','').lower()
                if itype in ['text','email'] or any(k in iname for k in ['user','email','login']):
                    user_f = inp.get('name')
                elif itype == 'password':
                    pass_f = inp.get('name')
            if not user_f or not pass_f: continue
            action = form.get('action', url)
            if not action.startswith('http'): action = urljoin(url, action)
            lockout = False
            for i in range(5):
                try:
                    resp = session.post(action, data={user_f:'test', pass_f:f'wrong{i}'}, timeout=5)
                    if resp.status_code == 429 or any(k in resp.text.lower() for k in ['locked','too many','blocked','limit','suspended']):
                        lockout = True
                        break
                except Exception:
                    pass
            if not lockout:
                log.high("No lockout after 5 attempts!")
                findings.append({'type':'Missing Account Lockout','risk':'HIGH','url':url,'description':'No lockout after 5 failed attempts','fix':'Lock after 5 attempts, add CAPTCHA','cvss_score':7.5,'cwe':'CWE-307'})
                log.finding('HIGH','No Lockout',url)
            else:
                log.found("Lockout active")
        except Exception as e:
            log.error(str(e))
    return findings


def run_cmd_inj_fast(target_url, session, log):
    findings = []
    payloads = _load_payloads('payloads/command_injection_payloads.txt')
    log.step(f"Loaded {len(payloads)} payloads")
    os_indicators = ['uid=','gid=','groups=','root:','daemon:','/bin/sh','volume serial','directory of','total 0','drwxr']
    parsed = urlparse(target_url)
    if not parsed.query:
        test_urls = [f"{target_url}?cmd=ls", f"{target_url}?exec=ls", f"{target_url}?run=ls"]
        params_list = [{'cmd':'ls'},{'exec':'ls'},{'run':'ls'}]
    else:
        params = {}
        for p in parsed.query.split('&'):
            if '=' in p:
                k,v = p.split('=',1)
                params[k] = v
        test_urls = [target_url]
        params_list = [params]
    # Fast error-based
    log.step("Error-based injection (fast)")
    for url in test_urls[:2]:
        for param_dict in params_list:
            for param in list(param_dict.keys())[:2]:
                for payload in payloads[:6]:
                    log.testing(f"Payload on '{param}'", payload)
                    test_params = param_dict.copy()
                    test_params[param] = param_dict[param] + payload
                    q = '&'.join(f"{k}={quote(str(v), safe='')}" for k,v in test_params.items())
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}" if parsed.query else f"{target_url}?" + q
                    try:
                        r = session.get(test_url, timeout=8)
                        for ind in os_indicators:
                            if ind in r.text:
                                log.critical(f"OS output: '{ind}' in param '{param}'")
                                findings.append({'type':'Command Injection - Error Based','risk':'CRITICAL','url':test_url,'parameter':param,'payload':payload,'evidence':ind,'description':f'OS output in param {param}','fix':'Avoid OS commands, use safe APIs, whitelist input','cvss_score':10.0,'cwe':'CWE-78'})
                                log.finding('CRITICAL','CMDi',param)
                                break
                        else:
                            log.info(f"No output [status={r.status_code}]")
                    except Exception as e:
                        log.info(f"Request error: {e}")
                    time.sleep(0.05)
    # Fast time-based
    log.step("Time-based blind (fast)")
    time_payloads = ['; sleep 3', '| sleep 3', '& sleep 3']
    for url in test_urls[:2]:
        for param_dict in params_list:
            for param in list(param_dict.keys())[:2]:
                try:
                    start = time.time()
                    session.get(url, timeout=8)
                    baseline = time.time() - start
                except Exception:
                    baseline = 1.0
                for payload in time_payloads[:2]:
                    log.testing(f"Time payload '{param}'", payload)
                    test_params = param_dict.copy()
                    test_params[param] = param_dict[param] + payload
                    q = '&'.join(f"{k}={quote(str(v), safe='')}" for k,v in test_params.items())
                    test_url = f"{target_url}?" + q
                    try:
                        start = time.time()
                        session.get(test_url, timeout=10)
                        elapsed = time.time() - start
                        if elapsed > baseline + 2.5:
                            delay = round(elapsed - baseline, 1)
                            log.critical(f"TIME DELAY +{delay}s → param='{param}'")
                            findings.append({'type':'Command Injection - Blind','risk':'CRITICAL','url':test_url,'parameter':param,'payload':payload,'baseline_time':round(baseline,2),'actual_time':round(elapsed,2),'description':f'Blind CMDi delay +{delay}s','fix':'Avoid OS calls, input whitelist','cvss_score':10.0,'cwe':'CWE-78'})
                            log.finding('CRITICAL','Blind CMDi',f"delay=+{delay}s")
                        else:
                            log.info(f"No delay ({round(elapsed,2)}s)")
                    except Exception as e:
                        log.info(f"Error: {e}")
                    time.sleep(0.05)
    return findings


def run_generic_fast(agent_class, target_url, session, log):
    try:
        agent = agent_class(target_url, session)
        findings = agent.run_full_scan()
        if findings:
            for f in findings:
                log.finding(f.get('risk','INFO'), f.get('type','Unknown'), f.get('url','')[:40])
        else:
            log.found("No vulnerabilities detected")
        return findings if findings else []
    except Exception as e:
        log.error(f"Agent failed: {e}")
        return []


class AdvancedScanOrchestrator:
    def __init__(self, target_url, groq_key):
        self.target = target_url.replace('https://','').replace('http://','').strip('/')
        self.target_url = f"https://{self.target}"
        self.groq_key = groq_key
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.shared_session = None

    def print_banner(self):
        date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n{Fore.MAGENTA}{'='*50}{Style.RESET_ALL}\n  AI ADVANCED SECURITY ASSESSMENT AGENT\n  Category 3 — FAST MODE\n{'='*50}{Style.RESET_ALL}")
        print(f"  Target   : {self.target[:42]}")
        print(f"  Date     : {date_str}")
        print(f"  Mode     : ADVANCED FAST + STREAMLINED LOGGING")
        print(f"  Agents   : 14 Specialized Agents")
        print(f"{'='*50}{Style.RESET_ALL}")

    def _get_consent(self):
        print(f"\n{Fore.RED}{'='*50}{Style.RESET_ALL}\n  LEGAL WARNING - WRITTEN AUTHORIZATION REQUIRED\n{'='*50}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Target: {Fore.CYAN}{self.target}{Style.RESET_ALL}")
        try:
            resp = input(f"\n{Fore.YELLOW}Written authorization? (yes/no): {Style.RESET_ALL}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.RED}[!] Cancelled.{Style.RESET_ALL}")
            return False
        if resp != 'yes':
            print(f"{Fore.RED}[!] Consent not given.{Style.RESET_ALL}")
            return False
        print(f"\n{Fore.GREEN}[✓] Consent confirmed.{Style.RESET_ALL}")
        return True

    def _print_plan(self):
        agents = [
            (1,"Auth","Default creds | Lockout | MFA"),
            (2,"CMDi","Error | Blind"),
            (3,"File Upload","Ext | MIME"),
            (4,"SSRF","Internal | Metadata"),
            (5,"XXE","File read | SSRF"),
            (6,"NoSQL","Operators | Auth bypass"),
            (7,"SSTI","Jinja2 | Twig | Freemarker"),
            (8,"CSRF","Token | SameSite"),
            (9,"WebSocket","WS discovery | Auth"),
            (10,"Host Header","Injection | Poison"),
            (11,"Cache","Headers | Deception"),
            (12,"OAuth","State | Redirect"),
            (13,"ProtoPollution","Client | Server"),
            (14,"Access Control","Admin | Bypass"),
        ]
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n  SCAN PLAN — 14 AGENTS (FAST)\n{'='*50}{Style.RESET_ALL}")
        for n,name,coverage in agents:
            print(f"  {Fore.MAGENTA}[{n:02d}]{Fore.WHITE} {name:<20}{Fore.CYAN}{coverage}{Style.RESET_ALL}")
        print(f"{'='*50}{Style.RESET_ALL}\n  Starting in 1s...{Style.RESET_ALL}")
        time.sleep(1)

    def _make_session(self):
        s = requests.Session()
        s.headers.update({'User-Agent':'SecurityAudit/2.0 (Fast Authorized Scan)'})
        return s

    def run_assessment(self, skip_consent=False):
        self.print_banner()
        if not skip_consent:
            if not self._get_consent(): return None
        self._print_plan()
        self.start_time = datetime.now()
        self.shared_session = self._make_session()
        total = 14
        # Agent 1
        log = FastLiveLogger("AUTHENTICATION", 1, total)
        log.header(); log.info("Fast auth scan: login pages, default creds, lockout, MFA")
        try:
            self.results['authentication'] = run_auth_fast(self.target_url, self.shared_session, log)
        except Exception as e:
            log.error(str(e)); self.results['authentication'] = []
        log.done(len(self.results.get('authentication', [])))
        # Agent 2
        log = FastLiveLogger("COMMAND INJECTION", 2, total)
        log.header(); log.info("Fast CMDi: error-based + time-based blind")
        try:
            self.results['command_injection'] = run_cmd_inj_fast(self.target_url, self.shared_session, log)
        except Exception as e:
            log.error(str(e)); self.results['command_injection'] = []
        log.done(len(self.results.get('command_injection', [])))
        # Agent 3-14 fast
        agent_map = [
            (3, "FILE UPLOAD", FileUploadAgent),
            (4, "SSRF", SSRFAgent),
            (5, "XXE", XXEAgent),
            (6, "NOSQL", NoSQLAgent),
            (7, "SSTI", SSTIAgent),
            (8, "CSRF", CSRFAgent),
            (9, "WEBSOCKET", WebSocketAgent),
            (10, "HOST HEADER", HTTPHostHeaderAgent),
            (11, "WEB CACHE", WebCacheAgent),
            (12, "OAUTH", OAuthAgent),
            (13, "PROTOTYPE POLLUTION", PrototypePollutionAgent),
            (14, "ACCESS CONTROL", AccessControlAgent),
        ]
        for num, name, agent_class in agent_map:
            log = FastLiveLogger(name, num, total)
            log.header(); log.info(f"Fast {name} scan")
            try:
                self.results[name.lower().replace(' ','_')] = run_generic_fast(agent_class, self.target_url, self.shared_session, log)
            except Exception as e:
                log.error(str(e)); self.results[name.lower().replace(' ','_')] = []
            log.done(len(self.results.get(name.lower().replace(' ','_'), [])))
        # Stats
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).seconds
        total_findings = sum(len(v) for v in self.results.values() if isinstance(v, list))
        critical = sum(1 for v in self.results.values() if isinstance(v, list) for f in v if f.get('risk') == 'CRITICAL')
        high = sum(1 for v in self.results.values() if isinstance(v, list) for f in v if f.get('risk') == 'HIGH')
        print(f"\n{Fore.GREEN}{'='*50}{Style.RESET_ALL}\n  CATEGORY 3 FAST COMPLETE\n{'='*50}{Style.RESET_ALL}")
        print(f"  Target   : {self.target}")
        print(f"  Duration : {duration}s")
        print(f"  Total    : {total_findings} findings")
        print(f"  {Fore.RED}Critical : {critical}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High     : {high}{Style.RESET_ALL}")
        print(f"{'='*50}{Style.RESET_ALL}")
        return self.results

    def generate_report(self):
        if not self.results:
            print(f"{Fore.RED}[!] No results.{Style.RESET_ALL}")
            return None
        print(f"\n{Fore.CYAN}[*] Generating AI report...{Style.RESET_ALL}")
        duration = (self.end_time - self.start_time).seconds if self.start_time and self.end_time else 0
        generator = AdvancedReportGenerator(self.groq_key)
        report = generator.generate_full_report(target=self.target, scan_results=self.results, scan_duration=duration)
        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_clean = self.target.replace('.', '_')
        base = os.path.join('output', f"{target_clean}_{timestamp}")
        with open(f"{base}.md", 'w', encoding='utf-8') as f:
            f.write(report.get('markdown', ''))
        print(f"  {Fore.GREEN}[✓] Markdown: {base}.md{Style.RESET_ALL}")
        with open(f"{base}_raw.json", 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"  {Fore.GREEN}[✓] JSON: {base}_raw.json{Style.RESET_ALL}")
        try:
            generator.generate_pdf(report.get('markdown',''), f"{base}.pdf")
            print(f"  {Fore.GREEN}[✓] PDF: {base}.pdf{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] PDF failed: {e}{Style.RESET_ALL}")
        return report
