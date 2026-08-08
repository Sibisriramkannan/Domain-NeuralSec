import json
import os
import time
import threading
import concurrent.futures
import requests
from datetime import datetime
from colorama import Fore, Style, init
from agents import SQLiAgent, XSSAgent, PathTraversalAgent, CORSAgent, GraphQLAgent, JWTAgent, APIAgent
from core.report_generator import ActiveReportGenerator

init(autoreset=True)

class LiveLogger:
    _lock=threading.Lock()
    def __init__(self,name,num,total,writer=None):
        self.name=name; self.num=num; self.total=total; self.start=time.time(); self.steps=0; self.writer=writer
    def _w(self,msg,level='INFO'):
        if self.writer:
            try:
                self.writer(msg,level)
            except:
                pass
    def _p(self,col,plain,level='INFO'):
        with LiveLogger._lock:
            print(col)
        self._w(plain,level)
    def header(self):
        self._p(f"\n{Fore.RED}{'═'*58}\n  [{self.num}/{self.total}] {self.name}\n{'═'*58}{Style.RESET_ALL}", f"[{self.num}/{self.total}] {self.name}", 'AGENT')
    def step(self,msg):
        self.steps+=1
        e=round(time.time()-self.start,1)
        self._p(f"  {Fore.YELLOW}[►] {msg} {Fore.WHITE}({e}s){Style.RESET_ALL}", f"[STEP {self.steps}] {msg} ({e}s)", 'AGENT')
    def info(self,msg): self._p(f"    {Fore.WHITE}│ {msg}{Style.RESET_ALL}", msg, 'INFO')
    def ok(self,msg): self._p(f"    {Fore.GREEN}│ ✓ {msg}{Style.RESET_ALL}", f"✓ {msg}", 'SUCCESS')
    def warn(self,msg): self._p(f"    {Fore.YELLOW}│ ⚠ {msg}{Style.RESET_ALL}", f"⚠ {msg}", 'WARN')
    def finding(self,risk,title,detail=''):
        c={ 'CRITICAL':Fore.RED,'HIGH':Fore.RED,'MEDIUM':Fore.YELLOW,'LOW':Fore.GREEN }.get(risk.upper(),Fore.WHITE)
        msg=f"{title} | {detail}" if detail else title
        self._p(f"    {c}│ [{risk}] {msg}{Style.RESET_ALL}", f"[{risk}] {msg}", 'WARN')
    def testing(self,what,val=''): self._p(f"    {Fore.CYAN}│ ▶ {what} → {str(val)[:45]}{Style.RESET_ALL}", f"Testing {what} {val}", 'AGENT')
    def done(self,count,dur=None):
        d=dur or round(time.time()-self.start,1)
        col=Fore.RED if count>0 else Fore.GREEN
        icon='⚠' if count>0 else '✓'
        self._p(f"\n  {col}{icon} {self.name} DONE → {count} | {d}s{Style.RESET_ALL}", f"{self.name} DONE → {count} | {d}s", 'SUCCESS')
    def error(self,msg): self._p(f"    {Fore.RED}│ ✗ {msg}{Style.RESET_ALL}", f"ERROR: {msg}", 'ERROR')
    def skip(self,msg): self._p(f"    {Fore.WHITE}│ ○ Skip: {msg}{Style.RESET_ALL}", f"Skip: {msg}", 'INFO')

def run_sqli_verbose(target_url, session, log):
    log.step("SQL Injection - Error | Time-blind | Union")
    log.info("Payloads: ' OR 1=1 | ' UNION SELECT | '; SLEEP(5)")
    try:
        agent=SQLiAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','HIGH'), f.get('type','SQLi'), f.get('parameter',''))
        if not findings:
            log.ok("No SQLi found")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_xss_verbose(target_url, session, log):
    log.step("XSS - Reflected | DOM | HTML injection")
    try:
        agent=XSSAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','HIGH'), f.get('type','XSS'), f.get('parameter',''))
        if not findings:
            log.ok("No XSS found")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_path_traversal_verbose(target_url, session, log):
    log.step("Path Traversal - Unix | Windows | Encoded")
    try:
        agent=PathTraversalAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','HIGH'), f.get('type','PathTraversal'), f.get('parameter',''))
        if not findings:
            log.ok("No PathTraversal")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_cors_verbose(target_url, session, log):
    log.step("CORS - Origin reflection | Wildcard | Null | Creds")
    log.testing("Injecting","Origin: evil-attacker.com")
    try:
        agent=CORSAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','HIGH'), f.get('type','CORS'), str(f.get('description',''))[:50])
        if not findings:
            log.ok("CORS OK")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_graphql_verbose(target_url, session, log):
    log.step("GraphQL - Introspection | Batching | Depth")
    try:
        agent=GraphQLAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','MEDIUM'), f.get('type','GraphQL'), str(f.get('description',''))[:50])
        if not findings:
            log.ok("No GraphQL issues")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_jwt_verbose(target_url, session, log):
    log.step("JWT - None alg | Weak secret | RS→HS")
    try:
        agent=JWTAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','HIGH'), f.get('type','JWT'), str(f.get('description',''))[:50])
        if not findings:
            log.ok("No JWT issues")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

def run_api_verbose(target_url, session, log):
    log.step("API - BOLA | Methods | Rate | Version | Sensitive data")
    try:
        agent=APIAgent(target_url, session)
        findings=agent.run_full_scan()
        for f in findings or []:
            log.finding(f.get('risk','MEDIUM'), f.get('type','API'), str(f.get('description',''))[:50])
        if not findings:
            log.ok("No API issues")
        return findings or []
    except Exception as e:
        log.error(str(e)); return []

class ActiveScanOrchestrator:
    def __init__(self, target_url, groq_key):
        self.target = target_url.replace('https://','').replace('http://','').strip('/')
        self.target_url = f"https://{self.target}"
        self.groq_key = groq_key
        self.results={}
        self.start_time=None
        self.end_time=None
        self._write_log=None
        self.shared_session=None
        self.session=None

    def print_banner(self):
        print(f"\n{Fore.RED}"+"═"*58)
        print("  AI ACTIVE SECURITY ASSESSMENT AGENT")
        print("  Category 2 — Parallel Active Scan (No Consent)")
        print("═"*58)
        print(f"  Target  : {self.target[:42]}")
        print(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("  Mode    : ACTIVE - DIRECT (Consent Disabled)")
        print("  Agents  : 7 Parallel")
        print("═"*58+Style.RESET_ALL)

    def _get_consent(self):
        return True

    def _print_scan_plan(self):
        print(f"\n{Fore.CYAN}"+"═"*58)
        print("  SCAN PLAN — 7 AGENTS (PARALLEL)")
        print("═"*58)
        for num,name,cov in [(1,"SQL Injection","Error|Time-blind|Union"),(2,"XSS","Reflected|DOM|HTML"),(3,"Path Traversal","Unix|Windows|Encoded"),(4,"CORS","Origin|Null|Creds"),(5,"GraphQL","Introspect|Batch|Depth"),(6,"JWT","None alg|Weak secret"),(7,"API Security","BOLA|Methods|Rate")]:
            print(f"  {Fore.RED}[{num:02d}]{Fore.WHITE} {name:<20}{Fore.CYAN}{cov}"+Style.RESET_ALL)
        print("═"*58+Style.RESET_ALL)

    def _make_session(self):
        s=requests.Session()
        s.headers.update({'User-Agent':'SecurityAudit/1.0 (Authorized Assessment)'})
        return s

    def run_assessment(self, skip_consent=True):
        self.print_banner()
        self._print_scan_plan()
        self.start_time=datetime.now()

        def _log(msg,level='INFO'):
            if self._write_log:
                self._write_log(msg,level)

        _log('Cat2: All 7 agents starting parallel','AGENT')

        agent_defs = [
            ('sql_injection', run_sqli_verbose, "SQL INJECTION", 1),
            ('xss', run_xss_verbose, "XSS", 2),
            ('path_traversal', run_path_traversal_verbose, "PATH TRAVERSAL", 3),
            ('cors', run_cors_verbose, "CORS", 4),
            ('graphql', run_graphql_verbose, "GRAPHQL", 5),
            ('jwt', run_jwt_verbose, "JWT", 6),
            ('api', run_api_verbose, "API SECURITY", 7),
        ]

        completed=[0]
        lock=threading.Lock()

        def run_agent(info):
            key,func,label,num = info
            log=LiveLogger(label,num,7,writer=self._write_log)
            log.header()
            session = self.shared_session or self.session or self._make_session()
            _log(f'Cat2: Agent [{label}] starting','AGENT')
            start=time.time()
            try:
                findings=func(self.target_url, session, log)
                dur=round(time.time()-start,1)
                log.done(len(findings),dur)
                count=len(findings)
                if count>0:
                    _log(f'Cat2 [{key}]: {count} findings | {dur}s','WARN')
                else:
                    _log(f'Cat2 [{key}]: clean | {dur}s','SUCCESS')
                with lock:
                    completed[0]+=1
                    _log(f'Cat2 progress: {completed[0]}/7 done','AGENT')
                return key,findings
            except Exception as e:
                log.error(f"Crashed: {e}")
                _log(f'Cat2 [{key}] error: {e}','ERROR')
                return key,[]

        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            futures={executor.submit(run_agent,a):a[0] for a in agent_defs}
            for fut in concurrent.futures.as_completed(futures):
                key=futures[fut]
                try:
                    rk,res=fut.result(timeout=120)
                    self.results[rk]=res
                except Exception as e:
                    self.results[key]=[]
                    _log(f'Cat2 [{key}] failed: {e}','ERROR')

        self.end_time=datetime.now()
        duration=(self.end_time-self.start_time).seconds
        total_f=sum(len(v) for v in self.results.values() if isinstance(v,list))
        _log(f'Cat2 COMPLETE: {total_f} findings in {duration}s','SUCCESS')
        print(f"\n{Fore.GREEN}"+"═"*58)
        print(f"  CATEGORY 2 COMPLETE - {duration}s - {total_f} findings")
        print("═"*58+Style.RESET_ALL)
        return self.results

    def generate_report(self):
        print(f"\n{Fore.CYAN}[*] Generating AI report..."+Style.RESET_ALL)
        duration=(self.end_time-self.start_time).seconds if self.start_time and self.end_time else 0
        generator=ActiveReportGenerator(self.groq_key)
        report=generator.generate_full_report(target=self.target, scan_results=self.results, scan_duration=duration)
        os.makedirs('output',exist_ok=True)
        timestamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        base=os.path.join('output', f"{self.target.replace('.','_')}_{timestamp}")
        with open(f"{base}.md",'w',encoding='utf-8') as f:
            f.write(report['markdown'])
        with open(f"{base}_raw.json",'w',encoding='utf-8') as f:
            json.dump(self.results,f,indent=2,default=str)
        try:
            generator.generate_pdf(report['markdown'], f"{base}.pdf")
        except:
            pass
        return report
