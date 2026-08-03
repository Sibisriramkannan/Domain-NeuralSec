"""
Master Orchestrator for Category 1
Coordinates all passive security agents
"""

import json
import os
from datetime import datetime
from colorama import Fore, Style, init

from agents import (
    ReconAgent,
    SecurityHeadersAgent,
    SSLAgent,
    EmailSecurityAgent
)
from core.report_generator import ReportGenerator

init(autoreset=True)


class PassiveSecurityOrchestrator:
    def __init__(self, target_domain, openai_key):
        self.target = target_domain.replace(
            'https://', ''
        ).replace('http://', '').strip('/')
        self.openai_key = openai_key  # now holds Groq key
        self.results = {}
        self.start_time = None
        self.end_time = None

    def print_banner(self):
        """Print assessment banner"""
        banner = (
            f"\n{Fore.RED}"
            f"╔══════════════════════════════════════════════════════╗\n"
            f"║       AI PASSIVE SECURITY ASSESSMENT AGENT           ║\n"
            f"║              Category 1 - Safe Passive Scan          ║\n"
            f"╠══════════════════════════════════════════════════════╣\n"
            f"║  Target  : {self.target:<42}║\n"
            f"║  Date    : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<42}║\n"
            f"║  Mode    : PASSIVE (No active scanning)              ║\n"
            f"║  Legal   : Public information only - Safe to use     ║\n"
            f"╚══════════════════════════════════════════════════════╝"
            f"{Style.RESET_ALL}"
        )
        print(banner)

    def run_assessment(self):
        """Run complete passive security assessment"""
        self.print_banner()
        self.start_time = datetime.now()

        print(
            f"{Fore.YELLOW}Starting assessment... "
            f"4 agents will run{Style.RESET_ALL}\n"
        )

        # Agent 1: Reconnaissance
        print(f"{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Agent 1/4: RECONNAISSANCE{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        try:
            recon = ReconAgent(self.target)
            # ✅ Save with correct key name
            self.results['reconnaissance'] = (
                recon.run_full_recon()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] Recon agent error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['reconnaissance'] = {
                'error': str(e)
            }

        # Agent 2: Security Headers
        print(f"\n{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        print(
            f"{Fore.MAGENTA}Agent 2/4: "
            f"SECURITY HEADERS{Style.RESET_ALL}"
        )
        print(f"{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        try:
            headers = SecurityHeadersAgent(self.target)
            # ✅ Save with correct key name
            self.results['security_headers'] = (
                headers.analyze_headers()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] Headers agent error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['security_headers'] = {
                'error': str(e)
            }

        # Agent 3: SSL/TLS
        print(f"\n{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        print(
            f"{Fore.MAGENTA}Agent 3/4: "
            f"SSL/TLS ANALYSIS{Style.RESET_ALL}"
        )
        print(f"{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        try:
            ssl_check = SSLAgent(self.target)
            # ✅ Save with correct key name
            self.results['ssl_tls'] = (
                ssl_check.full_ssl_check()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] SSL agent error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['ssl_tls'] = {
                'error': str(e)
            }

        # Agent 4: Email Security
        print(f"\n{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        print(
            f"{Fore.MAGENTA}Agent 4/4: "
            f"EMAIL SECURITY{Style.RESET_ALL}"
        )
        print(f"{Fore.MAGENTA}{'='*54}{Style.RESET_ALL}")
        try:
            email = EmailSecurityAgent(self.target)
            # ✅ Save with correct key name
            self.results['email_security'] = (
                email.run_full_check()
            )
        except Exception as e:
            print(
                f"  {Fore.RED}[!] Email agent error: "
                f"{e}{Style.RESET_ALL}"
            )
            self.results['email_security'] = {
                'error': str(e)
            }

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).seconds

        print(f"\n{Fore.GREEN}{'='*54}{Style.RESET_ALL}")
        print(
            f"{Fore.GREEN}All agents complete! "
            f"Time: {duration}s{Style.RESET_ALL}"
        )
        print(f"{Fore.GREEN}{'='*54}{Style.RESET_ALL}")

        return self.results

    def generate_report(self):
        """Generate AI-powered security report using Groq"""
        print(
            f"\n{Fore.CYAN}[*] Generating AI "
            f"report (Groq AI)...{Style.RESET_ALL}"
        )

        # Pass Groq key (stored in openai_key variable)
        generator = ReportGenerator(self.openai_key)

        report = generator.generate_full_report(
            target=self.target,
            scan_results=self.results,  # ✅ has correct keys now
            scan_duration=(
                (self.end_time - self.start_time).seconds
                if self.end_time
                else 0
            )
        )

        # Save outputs
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = 'output'
        os.makedirs(output_dir, exist_ok=True)
        base_filename = (
            f"{output_dir}/"
            f"{self.target.replace('.', '_')}"
            f"_{timestamp}"
        )

        # Save markdown
        with open(
            f"{base_filename}.md", 'w', encoding='utf-8'
        ) as f:
            f.write(report['markdown'])
        print(
            f"  {Fore.GREEN}[✓] Markdown: "
            f"{base_filename}.md{Style.RESET_ALL}"
        )

        # Save JSON
        with open(
            f"{base_filename}_raw.json", 'w', encoding='utf-8'
        ) as f:
            json.dump(self.results, f, indent=2)
        print(
            f"  {Fore.GREEN}[✓] Raw JSON: "
            f"{base_filename}_raw.json{Style.RESET_ALL}"
        )

        # Generate PDF
        try:
            pdf_path = generator.generate_pdf(
                report['markdown'],
                f"{base_filename}.pdf"
            )
            print(
                f"  {Fore.GREEN}[✓] PDF Report: "
                f"{pdf_path}{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"  {Fore.YELLOW}[!] PDF failed: "
                f"{e}{Style.RESET_ALL}"
            )

        return report
