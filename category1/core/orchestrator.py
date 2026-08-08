import json
import os
import time
import threading
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init
from agents import ReconAgent, SecurityHeadersAgent, SSLAgent, EmailSecurityAgent
from core.report_generator import ReportGenerator

init(autoreset=True)

class LiveLogger:
    _lock = threading.Lock()
    def __init__(self, name, num, total, writer=None):
        self.name=name; self.num=num; self.total=total
        self.start=time.time(); self.steps=0; self.writer=writer
    def _w(self, msg, level='INFO'):
        if self.writer:
            try:
                self.writer(msg, level)
            except:
                pass
    def _p(self, colored, plain, level='INFO'):
        with LiveLogger._lock:
            print(colored)
        self._w(plain, level)
    def header(self):
        c = f"\n{Fore.CYAN}{'═'*58}\n  [{self.num}/{self.total}] {self.name}\n{'═'*58}{Style.RESET_ALL}"
        p = f"[{self.num}/{self.total}] {self.name}"
        self._p(c,p,'AGENT')
    def step(self, msg):
        self.steps+=1
        e=round(time.time()-self.start,1)
        c=f"  {Fore.YELLOW}[►] {msg} {Fore.WHITE}({e}s){Style.RESET_ALL}"
        self._p(c,f"[STEP {self.steps}] {msg} ({e}s)",'AGENT')
    def info(self, msg):
        self._p(f"    {Fore.WHITE}│ {msg}{Style.RESET_ALL}", msg, 'INFO')
    def ok(self, msg):
        self._p(f"    {Fore.GREEN}│ ✓ {msg}{Style.RESET_ALL}", f"✓ {msg}", 'SUCCESS')
    def warn(self, msg):
        self._p(f"    {Fore.YELLOW}│ ⚠ {msg}{Style.RESET_ALL}", f"⚠ {msg}", 'WARN')
    def finding(self, risk, title, detail=''):
        c = { 'CRITICAL':Fore.RED,'HIGH':Fore.RED,'MEDIUM':Fore.YELLOW,'LOW':Fore.GREEN }.get(risk.upper(), Fore.WHITE)
        msg = f"{title} | {detail}" if detail else title
        self._p(f"    {c}│ [{risk}] {msg}{Style.RESET_ALL}", f"[{risk}] {msg}", 'WARN' if risk in ['CRITICAL','HIGH'] else 'INFO')
    def done(self, count, dur=None):
        d=dur or round(time.time()-self.start,1)
        col=Fore.RED if count>0 else Fore.GREEN
        icon='⚠' if count>0 else '✓'
        self._p(f"\n  {col}{icon} {self.name} DONE → {count} | {d}s{Style.RESET_ALL}", f"{self.name} DONE → {count} | {d}s", 'SUCCESS')
    def error(self, msg):
        self._p(f"    {Fore.RED}│ ✗ ERROR: {msg}{Style.RESET_ALL}", f"ERROR: {msg}", 'ERROR')

def run_recon_verbose(target, session, log):
    log.step("Reconnaissance - WHOIS | DNS | Subdomains | Tech | Robots | Paths")
    try:
        agent = ReconAgent(target)
        result = agent.run_full_recon()
        subs = result.get('subdomains', {})
        found = subs.get('found_count',0)
        if found>0:
            log.finding('MEDIUM','Subdomains Found', f"{found} subdomains")
            for s in subs.get('found',[])[:5]:
                log.info(f"  → {s}")
        else:
            log.ok("No subdomains")
        exp = result.get('exposed_paths', {}).get('exposed_paths', [])
        for p in exp:
            log.finding(p.get('risk','LOW'), f"Exposed: {p['path']}", p.get('description',''))
        if not exp:
            log.ok("No exposed paths")
        tech = result.get('tech_stack', {}).get('header_indicators',{}).get('Server','')
        if tech:
            log.info(f"Server: {tech}")
        return result
    except Exception as e:
        log.error(str(e))
        return {'error':str(e)}

def run_headers_verbose(target, session, log):
    log.step("Security Headers - CSP | HSTS | X-Frame | CORS")
    try:
        agent = SecurityHeadersAgent(target)
        if session:
            agent.session = session
        result = agent.analyze_headers()
        for h_name,h_data in result.get('security_headers',{}).items():
            if h_data.get('present'):
                log.ok(f"{h_name}: Present")
            else:
                risk = h_data.get('risk_if_missing','LOW')
                if risk in ['CRITICAL','HIGH']:
                    log.finding(risk, f"Missing: {h_name}", h_data.get('attack',''))
                else:
                    log.warn(f"Missing: {h_name} [{risk}]")
        score=result.get('score',{})
        log.info(f"Score: {score.get('value',0)}/100 Grade: {score.get('grade','F')}")
        disc=result.get('information_disclosure',{})
        for k,v in disc.items():
            log.finding('MEDIUM', f"Info Disclosed: {k}", str(v.get('value',''))[:50])
        cors=result.get('cors',{})
        if cors.get('misconfigured'):
            log.finding('HIGH','CORS Misconfigured')
        else:
            log.ok("CORS: OK")
        return result
    except Exception as e:
        log.error(str(e))
        return {'error':str(e)}

def run_ssl_verbose(target, session, log):
    log.step("SSL/TLS - Cert | TLS | Cipher | Vulns")
    try:
        agent = SSLAgent(target)
        result = agent.full_ssl_check()
        cert=result.get('certificate',{})
        issuer=cert.get('issuer',{}).get('commonName','Unknown')
        log.info(f"Issuer: {issuer}")
        days=cert.get('days_until_expiry',0)
        if isinstance(days,int):
            if days<30:
                log.finding('HIGH','Cert Expiring Soon', f"{days} days")
            elif days<90:
                log.warn(f"Cert expires in {days} days")
            else:
                log.ok(f"Cert valid: {days} days")
        if cert.get('is_expired'):
            log.finding('CRITICAL','Certificate EXPIRED!')
        tls=result.get('tls',{})
        version=tls.get('version','Unknown')
        cipher=tls.get('cipher_suite','Unknown')
        log.info(f"TLS: {version} Cipher: {cipher}")
        if tls.get('protocol_secure'):
            log.ok(f"TLS {version} Secure")
        else:
            log.finding('HIGH', f"Weak TLS: {version}")
        for issue in result.get('issues',[]):
            log.finding(issue.get('severity','MEDIUM'), issue.get('description',''))
        if not result.get('issues',[]):
            log.ok("No SSL issues")
        return result
    except Exception as e:
        log.error(str(e))
        return {'error':str(e)}

def run_email_verbose(target, session, log):
    log.step("Email Security - SPF | DMARC | DKIM | MX")
    try:
        agent = EmailSecurityAgent(target)
        result = agent.run_full_check()
        spf=result.get('spf',{})
        if spf.get('exists'):
            log.ok(f"SPF Found: {str(spf.get('record',''))[:60]}")
        else:
            log.finding('HIGH','SPF Missing')
        dmarc=result.get('dmarc',{})
        if dmarc.get('exists'):
            log.ok(f"DMARC Found: {dmarc.get('policy','')}")
        else:
            log.finding('HIGH','DMARC Missing')
        dkim=result.get('dkim',{})
        if dkim.get('exists'):
            log.ok("DKIM: Found")
        else:
            log.finding('MEDIUM','DKIM Not Found')
        mx=result.get('mx_records',{})
        if mx.get('exists'):
            log.ok(f"MX: {len(mx.get('records',[]))} records")
        else:
            log.warn("MX: No records")
        score=result.get('email_security_score',{})
        log.info(f"Score: {score.get('score',0)}/100 Grade: {score.get('grade','F')}")
        return result
    except Exception as e:
        log.error(str(e))
        return {'error':str(e)}

class PassiveSecurityOrchestrator:
    def __init__(self, target_domain, openai_key):
        self.target = target_domain.replace('https://','').replace('http://','').strip('/')
        self.openai_key = openai_key
        self.results={}
        self.start_time=None
        self.end_time=None
        self._write_log=None
        self.shared_session=None
        self.session=None

    def print_banner(self):
        print(f"\n{Fore.GREEN}"+"═"*58)
        print("  AI PASSIVE SECURITY ASSESSMENT AGENT")
        print("  Category 1 — Parallel Passive Scan")
        print("═"*58)
        print(f"  Target  : {self.target[:42]}")
        print(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("  Mode    : PASSIVE (Safe)")
        print("  Agents  : 4 Parallel")
        print("═"*58+Style.RESET_ALL)

    def _print_scan_plan(self):
        print(f"\n{Fore.CYAN}"+"═"*58)
        print("  SCAN PLAN — 4 AGENTS (PARALLEL)")
        print("═"*58)
        for num,name,cov in [(1,"Reconnaissance","WHOIS|DNS|Subdomains|Tech|Robots"),(2,"Security Headers","CSP|HSTS|X-Frame|CORS"),(3,"SSL/TLS","Cert|TLS|Cipher|Vulns"),(4,"Email Security","SPF|DMARC|DKIM|MX")]:
            print(f"  {Fore.GREEN}[{num:02d}]{Fore.WHITE} {name:<22}{Fore.CYAN}{cov}"+Style.RESET_ALL)
        print("═"*58+Style.RESET_ALL)

    def run_assessment(self):
        self.print_banner()
        self._print_scan_plan()
        self.start_time=datetime.now()
        def _log(msg,level='INFO'):
            if self._write_log:
                self._write_log(msg,level)
        _log('Cat1: All 4 agents simultaneous','AGENT')

        agents = [
            ('reconnaissance', run_recon_verbose, (self.target, self.shared_session or self.session), "RECONNAISSANCE", 1),
            ('security_headers', run_headers_verbose, (self.target, self.shared_session or self.session), "SECURITY HEADERS", 2),
            ('ssl_tls', run_ssl_verbose, (self.target, self.shared_session or self.session), "SSL/TLS", 3),
            ('email_security', run_email_verbose, (self.target, self.shared_session or self.session), "EMAIL SECURITY", 4),
        ]

        completed=[0]
        lock=threading.Lock()

        def run_agent(info):
            key,func,args,label,num = info
            log = LiveLogger(label, num, 4, writer=self._write_log)
            log.header()
            start=time.time()
            try:
                result=func(*args, log)
                dur=round(time.time()-start,1)
                count=0
                if isinstance(result, dict):
                    if 'exposed_paths' in result:
                        count+=len(result.get('exposed_paths',{}).get('exposed_paths',[]))
                    if 'issues' in result:
                        count+=len(result.get('issues',[]))
                    if 'missing_critical' in result:
                        count+=len(result.get('missing_critical',[]))
                log.done(count,dur)
                with lock:
                    completed[0]+=1
                    _log(f'Cat1 progress: {completed[0]}/4 done','AGENT')
                return key,result
            except Exception as e:
                log.error(f"Crashed: {e}")
                return key,{'error':str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures={executor.submit(run_agent,a):a[0] for a in agents}
            for fut in concurrent.futures.as_completed(futures):
                key=futures[fut]
                try:
                    rk,res=fut.result(timeout=120)
                    self.results[rk]=res
                    status="ERROR" if 'error' in str(res) else "DONE"
                    col=Fore.RED if status=="ERROR" else Fore.GREEN
                    print(f"  {col}[✓] {rk}: {status}"+Style.RESET_ALL)
                    _log(f"Cat1 [{rk}]: {status}", 'SUCCESS' if status=="DONE" else 'ERROR')
                except Exception as e:
                    self.results[key]={'error':str(e)}
                    print(f"  {Fore.RED}[!] {key}: {e}"+Style.RESET_ALL)
                    _log(f"Cat1 [{key}] FAILED: {e}", 'ERROR')

        self.end_time=datetime.now()
        duration=(self.end_time-self.start_time).seconds
        print(f"\n{Fore.GREEN}"+"═"*58)
        print(f"  CATEGORY 1 COMPLETE - {duration}s")
        print("═"*58+Style.RESET_ALL)
        _log(f"Cat1 COMPLETE: {duration}s", 'SUCCESS')
        return self.results

    def generate_report(self):
        print(f"\n{Fore.CYAN}[*] Generating AI report..."+Style.RESET_ALL)
        generator=ReportGenerator(self.openai_key)
        report=generator.generate_full_report(target=self.target, scan_results=self.results, scan_duration=(self.end_time-self.start_time).seconds if self.end_time else 0)
        timestamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs('output',exist_ok=True)
        base=os.path.join('output', f"{self.target.replace('.','_')}_{timestamp}")
        with open(f"{base}.md",'w',encoding='utf-8') as f:
            f.write(report['markdown'])
        print(f"  {Fore.GREEN}[✓] Markdown: {base}.md"+Style.RESET_ALL)
        with open(f"{base}_raw.json",'w',encoding='utf-8') as f:
            json.dump(self.results,f,indent=2,default=str)
        try:
            generator.generate_pdf(report['markdown'], f"{base}.pdf")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] PDF: {e}"+Style.RESET_ALL)
        return report
