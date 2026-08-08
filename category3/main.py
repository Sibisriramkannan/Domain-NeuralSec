import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init

from core.orchestrator import AdvancedScanOrchestrator

init(autoreset=True)
load_dotenv()


def main():
    print(
        f"{Fore.MAGENTA}" + "=" * 58 + Style.RESET_ALL
    )
    print(
        f"{Fore.MAGENTA}"
        "  ADVANCED SECURITY ASSESSMENT AGENT"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.MAGENTA}"
        "  Category 3 - Advanced Active Scanning"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.MAGENTA}" + "=" * 58 + Style.RESET_ALL
    )

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(
            f"\n{Fore.YELLOW}Target URL: "
            + Style.RESET_ALL
        ).strip()

    if not target:
        print(f"{Fore.RED}[!] No target.{Style.RESET_ALL}")
        sys.exit(1)

    groq_key = os.getenv('GROQ_API_KEY', '').strip()

    if groq_key:
        masked = groq_key[:8] + '....' + groq_key[-4:]
        print(
            f"\n{Fore.GREEN}[✓] Groq Key  : {masked}"
        )
        print(
            f"{Fore.GREEN}[✓] AI Engine : "
            f"Groq AI (Llama 3.3 70B) - FREE"
            + Style.RESET_ALL
        )
    else:
        print(
            f"\n{Fore.YELLOW}[!] No GROQ_API_KEY. "
            f"Raw JSON only.{Style.RESET_ALL}"
        )

    orchestrator = AdvancedScanOrchestrator(
        target, groq_key
    )
    results = orchestrator.run_assessment(
        skip_consent=False
    )

    if results is None:
        print(
            f"{Fore.RED}[!] Cancelled.{Style.RESET_ALL}"
        )
        sys.exit(0)

    if groq_key:
        orchestrator.generate_report()
        print(
            f"\n{Fore.GREEN}" + "=" * 58
        )
        print("  CATEGORY 3 ASSESSMENT COMPLETE!")
        print("=" * 58 + Style.RESET_ALL)
    else:
        os.makedirs('output', exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        tc = (
            target.replace('https://', '')
            .replace('http://', '')
            .replace('.', '_')
        )
        path = f"output/{tc}_{ts}_raw.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(
            f"\n{Fore.YELLOW}[!] JSON saved: {path}"
            + Style.RESET_ALL
        )


if __name__ == "__main__":
    main()
