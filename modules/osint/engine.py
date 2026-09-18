"""Module 14: ADVANCED OSINT ENGINE (Legal & Ethical - Public Sources)."""
from __future__ import annotations
import os, sys, json, requests, concurrent.futures, re
from core.banner import Colors

try:
    import phonenumbers
    PHONE_LIB = True
except ImportError:
    PHONE_LIB = False

# --- 1. USERNAME & EMAIL BREACH CHECKER (XposedOrNot) ---
def check_breach_email(email: str):
    print(f"\n{Colors.cyan('[+]')} Checking Email Breaches: {Colors.bold(email)}")
    try:
        resp = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            breaches = data.get("breaches", [])
            if breaches:
                print(f"  {Colors.red('[!] FOUND IN BREACHES:')}")
                for b in breaches[0]:
                    print(f"    {Colors.yellow('•')} {b}")
            else:
                print(f"  {Colors.green('[+] No breaches found for this email.')}")
        else:
            print(f"  {Colors.yellow('[?] API returned: {resp.status_code}')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. PASSWORD BREACH CHECKER (HIBP k-Anonymity) ---
def check_password_breach(password: str):
    print(f"\n{Colors.cyan('[+]')} Checking Password Breach (HIBP)...")
    import hashlib
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    print(f"  {Colors.red('[!] VULNERABLE:')} Password found in {count} breaches!")
                    return
            print(f"  {Colors.green('[+] Password not found in known breaches.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. USERNAME OSINT (WhatsMyName - Public Profiles) ---
def check_username(site_url: str, site_name: str, username: str):
    try:
        url = site_url.replace("{account}", username)
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            return f"  {Colors.green('[+] Found on:')} {site_name} -> {url}"
    except:
        pass
    return None

def username_osint(username: str):
    print(f"\n{Colors.cyan('[+]')} Username OSINT: {Colors.bold(username)}")
    sites = [
        ("https://github.com/{account}", "GitHub"),
        ("https://twitter.com/{account}", "Twitter/X"),
        ("https://instagram.com/{account}", "Instagram"),
        ("https://reddit.com/user/{account}", "Reddit"),
        ("https://t.me/{account}", "Telegram"),
        ("https://medium.com/@{account}", "Medium"),
        ("https://www.pinterest.com/{account}", "Pinterest"),
        ("https://www.tiktok.com/@{account}", "TikTok"),
    ]
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_username, url, name, username): name for url, name in sites}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(res)
                found = True
    if not found:
        print(f"  {Colors.yellow('[-] Username not found on common platforms.')}")

# --- 4. INDIAN PHONE NUMBER OSINT (Public Info Only) ---
def phone_osint(phone: str):
    print(f"\n{Colors.cyan('[+]')} Phone Number OSINT: {Colors.bold(phone)}")
    if not PHONE_LIB:
        print(f"  {Colors.red('[!] Install phonenumbers: pip install phonenumbers')}"); return
    try:
        parsed = phonenumbers.parse(phone, "IN")
        if phonenumbers.is_valid_number(parsed):
            print(f"  {Colors.green('Valid Number:')} Yes")
            print(f"  {Colors.green('Country:')} {phonenumbers.region_code_for_number(parsed)}")
            print(f"  {Colors.green('Carrier (Public):')} {phonenumbers.carrier.name_for_number(parsed, 'en')}")
            print(f"  {Colors.green('Type:')} {phonenumbers.number_type(parsed)}")
            print(f"  {Colors.dim('Note: Owner name and address are PRIVATE and not available legally.')}")
        else:
            print(f"  {Colors.red('[!] Invalid phone number.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_osint():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 14: ADVANCED OSINT (Legal & Ethical)')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Email Breach Checker (XposedOrNot)")
        print(f"  {Colors.green('2.')} Password Breach Checker (HIBP)")
        print(f"  {Colors.green('3.')} Username OSINT (WhatsMyName)")
        print(f"  {Colors.green('4.')} Indian Phone Number OSINT (Public Info)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [OSINT]> "))).strip()
        if choice == "0": break
        elif choice == "1":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Email: "))).strip()
            if target: check_breach_email(target)
        elif choice == "2":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Password: "))).strip()
            if target: check_password_breach(target)
        elif choice == "3":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Username: "))).strip()
            if target: username_osint(target)
        elif choice == "4":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Phone (+91XXXXXXXXXX): "))).strip()
            if target: phone_osint(target)
        else: print(f"  {Colors.red('[!] Invalid option.')}")
