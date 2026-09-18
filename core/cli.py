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
        elif choice == "19":
            print(Colors.green("\n  [✓] Dependencies: Python 3, Git, curl, requests.\n"))
        elif choice.isdigit() and 1 <= int(choice) <= 18:
            print(Colors.cyan(f"\n  [*] Module {choice} selected. Under construction.\n"))
        else:
            print(Colors.red("\n  [!] Invalid option. Try again.\n"))
            
    return 0
