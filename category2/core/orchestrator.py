import json
import os
import requests
from datetime import datetime
from colorama import Fore, Style, init

from agents import (
    SQLiAgent,
    XSSAgent,
    PathTraversalAgent,
    CORSAgent,
    GraphQLAgent,
    JWTAgent,
    APIAgent
)
from core.report_generator import ActiveReportGenerator

init(autoreset=True)


class ActiveScanOrchestrator:
    def __init__(self, target_url, groq_key):
        self.target = target_url
        self.target = self.target.replace(
            'https://', ''
        ).replace('http://', '').strip('/')
        self.target_url = f"https://{self.target}"
        self.groq_key = groq_key
        self.results = {}
        self.start_time = None
        self.end_time = None

    def print_banner(self):
        date_str = datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        target_display = self.target[:40]
        print(f"\n{Fore.RED}" + "=" * 58)
        print(
            "  AI ACTIVE SECURITY ASSESSMENT AGENT"
        )
        print(
            "  Category 2 - Semi-Active Scanning"
        )
        print("=" * 58)
        print(
            f"  Target  : {target_display}"
        )
        print(f"  Date    : {date_str}")
        print(
            "  Mode    : ACTIVE (Consent Required)"
        )
        print(
            "  Agents  : SQLi | XSS | PathTraversal"
            " | CORS"
        )
        print(
            "            GraphQL | JWT | API"
        )
        print("=" * 58 + Style.RESET_ALL)

    def _get_consent(self):
        print(
            f"\n{Fore.RED}"
            "=" * 58
        )
        print("  LEGAL WARNING - READ CAREFULLY")
        print("=" * 58)
        print(
            "  Active scanning without written"
        )
        print(
            "  permission is ILLEGAL."
        )
        print(
            "  Ensure you have explicit written"
        )
        print(
            "  authorization before proceeding."
        )
        print("=" * 58 + Style.RESET_ALL)

        confirmations = [
            (
                "1. I own or have WRITTEN PERMISSION "
                "to scan this target"
            ),
            (
                "2. I understand this is an ACTIVE "
                "security test"
            ),
            (
                "3. I take full legal responsibility"
            ),
            (
                "4. I will keep all findings CONFIDENTIAL"
            ),
        ]

        for confirm in confirmations:
            resp = input(
                f"{Fore.YELLOW}{confirm}\n"
                f"Confirm (yes/no): {Style.RESET_ALL}"
            ).strip().lower()
            if resp != 'yes':
                return False

        print(
            f"\n{Fore.GREEN}[✓] Consent confirmed. "
            f"Proceeding...{Style.RESET_ALL}"
        )
        return True

    def run_assessment(self, skip_consent=False):
        self.print_banner()

        if not skip_consent:
            consented = self._get_consent()
            if not consented:
                print(
                    f"{Fore.RED}[!] Scan cancelled - "
                    f"no consent given.{Style.RESET_ALL}"
                )
                return None

        self.start_time = datetime.now()

        shared_session = requests.Session()
        shared_session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 '
                '(Authorized Assessment)'
            )
        })

        print(
            f"\n{Fore.YELLOW}Starting active scan - "
            f"7 agents{Style.RESET_ALL}\n"
        )

        # Agent 1: SQLi
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 1/7: SQL INJECTION"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            sqli = SQLiAgent(
                self.target_url, shared_session
            )
            self.results['sql_injection'] = (
                sqli.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] SQLi error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['sql_injection'] = []

        # Agent 2: XSS
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 2/7: CROSS-SITE SCRIPTING"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            xss = XSSAgent(
                self.target_url, shared_session
            )
            self.results['xss'] = (
                xss.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] XSS error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['xss'] = []

        # Agent 3: Path Traversal
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 3/7: PATH TRAVERSAL"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            pt = PathTraversalAgent(
                self.target_url, shared_session
            )
            self.results['path_traversal'] = (
                pt.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] PathTraversal error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['path_traversal'] = []

        # Agent 4: CORS
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 4/7: CORS MISCONFIGURATION"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            cors = CORSAgent(
                self.target_url, shared_session
            )
            self.results['cors'] = (
                cors.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] CORS error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['cors'] = []

        # Agent 5: GraphQL
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 5/7: GRAPHQL SECURITY"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            graphql = GraphQLAgent(
                self.target_url, shared_session
            )
            self.results['graphql'] = (
                graphql.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] GraphQL error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['graphql'] = []

        # Agent 6: JWT
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 6/7: JWT ANALYSIS"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            jwt = JWTAgent(
                self.target_url, shared_session
            )
            self.results['jwt'] = (
                jwt.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] JWT error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['jwt'] = []

        # Agent 7: API
        print(
            f"\n{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}"
            "Agent 7/7: API SECURITY"
            + Style.RESET_ALL
        )
        print(
            f"{Fore.MAGENTA}" + "=" * 58
            + Style.RESET_ALL
        )
        try:
            api = APIAgent(
                self.target_url, shared_session
            )
            self.results['api'] = (
                api.run_full_scan()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] API error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['api'] = []

        self.end_time = datetime.now()
        duration = (
            self.end_time - self.start_time
        ).seconds

        total = sum(
            len(v) for v in self.results.values()
            if isinstance(v, list)
        )

        print(
            f"\n{Fore.GREEN}" + "=" * 58
        )
        print(
            f"All agents complete! "
            f"Time: {duration}s | "
            f"Total findings: {total}"
        )
        print("=" * 58 + Style.RESET_ALL)

        return self.results

    def generate_report(self):
        if not self.results:
            print(
                f"{Fore.RED}[!] No results to report."
                f"{Style.RESET_ALL}"
            )
            return None

        print(
            f"\n{Fore.CYAN}[*] Generating AI "
            f"report...{Style.RESET_ALL}"
        )

        duration = 0
        if self.start_time and self.end_time:
            duration = (
                self.end_time - self.start_time
            ).seconds

        generator = ActiveReportGenerator(self.groq_key)
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

        # Save markdown
        md_path = f"{base}.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(report['markdown'])
        print(
            f"  {Fore.GREEN}[✓] Markdown: "
            f"{md_path}{Style.RESET_ALL}"
        )

        # Save raw JSON
        json_path = f"{base}_raw.json"
        with open(
            json_path, 'w', encoding='utf-8'
        ) as f:
            json.dump(self.results, f, indent=2)
        print(
            f"  {Fore.GREEN}[✓] JSON: "
            f"{json_path}{Style.RESET_ALL}"
        )

        # Save PDF
        pdf_path = f"{base}.pdf"
        try:
            generator.generate_pdf(
                report['markdown'], pdf_path
            )
            print(
                f"  {Fore.GREEN}[✓] PDF: "
                f"{pdf_path}{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] PDF failed: "
                f"{e}{Style.RESET_ALL}"
            )

        return report
