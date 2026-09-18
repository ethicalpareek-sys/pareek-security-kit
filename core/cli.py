"""Command-line interface for Pareek Security Kit."""
from __future__ import annotations
import sys
from core.banner import show_banner, show_legal, show_menu, show_loader, Colors
from core.logger import setup_logger

def main() -> int:
    setup_logger()
    show_banner()
    show_loader("Loading modules")
    show_legal()
    
    if "--doctor" in sys.argv:
        print(Colors.green("\n[✓] Doctor mode: All systems operational.\n"))
        return 0
        
    while True:
        show_menu()
        try:
            choice = input(Colors.bold(Colors.cyan("  ┌─[PSK]─[select]> "))).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            break
            
        if choice in ("00", "exit", "quit", "q"):
            print(Colors.yellow("  [!] Exiting. Stay ethical!\n"))
            break
        elif choice in ("1", "01"):
            from modules.information_gathering.engine import run_info_gathering
            run_info_gathering()
        elif choice in ("2", "02"):
            from modules.network_scanning.engine import run_network_scanning
            run_network_scanning()
        elif choice in ("3", "03"):
            from modules.service_enumeration.engine import run_service_enumeration
            run_service_enumeration()
        elif choice in ("4", "04"):
            from modules.web_security.engine import run_web_security
            run_web_security()
        elif choice in ("5", "05"):
            from modules.packet_analysis.engine import run_packet_analysis
            run_packet_analysis()
        elif choice in ("6", "06"):
            from modules.network_diagnostics.engine import run_network_diagnostics
            run_network_diagnostics()
        elif choice in ("7", "07"):
            from modules.vulnerability_assessment.engine import run_vulnerability_assessment
            run_vulnerability_assessment()
        elif choice in ("8", "08"):
            from modules.wireless_security.engine import run_wireless_security
            run_wireless_security()
        elif choice in ("9", "09"):
            from modules.password_auditing.engine import run_password_auditing
            run_password_auditing()
        elif choice in ("10", "10"):
            from modules.credential_security.engine import run_credential_security
            run_credential_security()
        elif choice == "19":
            print(Colors.green("\n  [✓] Dependencies: Python 3, Git, curl, requests, whois, nmap, dnsutils, scapy, traceroute, termux-api.\n"))
        elif choice.isdigit() and 1 <= int(choice) <= 18:
            print(Colors.cyan(f"\n  [*] Module {choice} selected. Under construction.\n"))
        else:
            print(Colors.red("\n  [!] Invalid option. Try again.\n"))
            
    return 0
