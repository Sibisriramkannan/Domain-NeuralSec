"""
Category 1: Passive Security Assessment Agent
Main entry point
"""

import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init
from core.orchestrator import PassiveSecurityOrchestrator

init(autoreset=True)
load_dotenv()


def main():
    print(
        f"{Fore.CYAN}{'='*54}{Style.RESET_ALL}"
    )
    print(
        f"{Fore.CYAN}  PASSIVE SECURITY ASSESSMENT AGENT{Style.RESET_ALL}"
    )
    print(
        f"{Fore.CYAN}{'='*54}{Style.RESET_ALL}"
    )

    # Get target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(
            f"\n{Fore.YELLOW}Enter target domain "
            f"(e.g., example.com): {Style.RESET_ALL}"
        ).strip()

    if not target:
        print(
            f"{Fore.RED}[!] No target provided. "
            f"Exiting.{Style.RESET_ALL}"
        )
        sys.exit(1)

    # ✅ Changed from OPENAI_API_KEY to GROQ_API_KEY
    groq_key = os.getenv('GROQ_API_KEY', '')

    if not groq_key:
        print(
            f"{Fore.YELLOW}[!] No GROQ_API_KEY found "
            f"in .env file{Style.RESET_ALL}"
        )
        groq_key = input(
            f"{Fore.YELLOW}Enter Groq API key "
            f"(free from console.groq.com) "
            f"or press Enter to skip AI report: "
            f"{Style.RESET_ALL}"
        ).strip()

    # Show key status
    if groq_key:
        # Show masked key for confirmation
        masked = (
            groq_key[:8] + "****" + groq_key[-4:]
            if len(groq_key) > 12
            else "****"
        )
        print(
            f"{Fore.GREEN}[✓] Groq key loaded: "
            f"{masked}{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.YELLOW}[!] No Groq key - "
            f"will save raw JSON only{Style.RESET_ALL}"
        )

    # Confirm before running
    print(
        f"\n{Fore.YELLOW}Target: {target}{Style.RESET_ALL}"
    )
    print(
        f"{Fore.YELLOW}This is a PASSIVE scan - "
        f"public information only{Style.RESET_ALL}"
    )
    print(
        f"{Fore.YELLOW}AI Engine: "
        f"{'Groq AI (Llama 3.3 70B) - FREE' if groq_key else 'None - Raw JSON only'}"
        f"{Style.RESET_ALL}"
    )
    confirm = input(
        f"{Fore.YELLOW}Proceed? (y/n): {Style.RESET_ALL}"
    )

    if confirm.lower() != 'y':
        print(
            f"{Fore.RED}Cancelled.{Style.RESET_ALL}"
        )
        sys.exit(0)

    # Run assessment - pass groq_key instead of openai_key
    orchestrator = PassiveSecurityOrchestrator(
        target, groq_key       # ✅ groq_key here
    )
    results = orchestrator.run_assessment()

    # Generate report
    if groq_key:
        report = orchestrator.generate_report()
        print(
            f"\n{Fore.GREEN}[✓] Report generated "
            f"successfully!{Style.RESET_ALL}"
        )
    else:
        # No key - save raw JSON only
        print(
            f"\n{Fore.YELLOW}No Groq key - "
            f"skipping AI report. "
            f"Raw JSON saved to output/{Style.RESET_ALL}"
        )
        os.makedirs('output', exist_ok=True)

        # Clean target name for filename
        clean_target = (
            target
            .replace('https://', '')
            .replace('http://', '')
            .replace('/', '_')
            .replace('.', '_')
        )
        filename = (
            f"output/{clean_target}"
            f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f"_raw.json"
        )
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(
            f"{Fore.GREEN}[✓] Raw results: "
            f"{filename}{Style.RESET_ALL}"
        )

    print(
        f"\n{Fore.GREEN}Assessment complete!{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    main()
