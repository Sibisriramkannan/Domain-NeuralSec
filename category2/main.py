import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init

from core.orchestrator import ActiveScanOrchestrator

init(autoreset=True)
load_dotenv()


def main():
    print(
        f"{Fore.RED}" + "=" * 58 + Style.RESET_ALL
    )
    print(
        f"{Fore.RED}  ACTIVE SECURITY ASSESSMENT AGENT"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.RED}  Category 2 - Semi-Active Scanning"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.RED}  REQUIRES WRITTEN AUTHORIZATION"
        + Style.RESET_ALL
    )
    print(
        f"{Fore.RED}" + "=" * 58 + Style.RESET_ALL
    )

    # Get target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(
            f"\n{Fore.YELLOW}Enter target URL "
            f"(e.g., https://example.com): "
            f"{Style.RESET_ALL}"
        ).strip()

    if not target:
        print(
            f"{Fore.RED}[!] No target provided. "
            f"Exiting.{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Get Groq API key
    groq_key = os.getenv('GROQ_API_KEY', '').strip()

    if groq_key:
        masked = (
            groq_key[:8] + '....' + groq_key[-4:]
        )
        print(
            f"\n{Fore.GREEN}[✓] Groq API Key: "
            f"{masked}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}[✓] AI Engine: "
            f"Groq AI (Llama 3.3 70B) - FREE"
            f"{Style.RESET_ALL}"
        )
    else:
        print(
            f"\n{Fore.YELLOW}[!] No GROQ_API_KEY found. "
            f"Raw JSON only.{Style.RESET_ALL}"
        )

    # Run assessment
    orchestrator = ActiveScanOrchestrator(
        target, groq_key
    )

    results = orchestrator.run_assessment(
        skip_consent=False
    )

    if results is None:
        print(
            f"{Fore.RED}[!] Assessment cancelled."
            f"{Style.RESET_ALL}"
        )
        sys.exit(0)

    # Generate report or save raw JSON
    if groq_key:
        report = orchestrator.generate_report()
        if report:
            print(
                f"\n{Fore.GREEN}" + "=" * 58
                + Style.RESET_ALL
            )
            print(
                f"{Fore.GREEN}"
                "  ASSESSMENT COMPLETE!"
                + Style.RESET_ALL
            )
            print(
                f"{Fore.GREEN}" + "=" * 58
                + Style.RESET_ALL
            )
    else:
        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime(
            '%Y%m%d_%H%M%S'
        )
        target_clean = (
            target.replace('https://', '')
            .replace('http://', '')
            .replace('/', '_')
            .replace('.', '_')
        )
        json_path = os.path.join(
            'output',
            f"{target_clean}_{timestamp}_raw.json"
        )
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(
            f"\n{Fore.YELLOW}[!] Raw findings saved: "
            f"{json_path}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.YELLOW}[!] Add GROQ_API_KEY to "
            f".env for AI report.{Style.RESET_ALL}"
        )

    print(
        f"\n{Fore.GREEN}Done!{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    main()
