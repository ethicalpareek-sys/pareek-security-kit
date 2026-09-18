"""Module 14: ADVANCED OSINT ENGINE (Legal & Ethical)."""
from __future__ import annotations
import os, sys, json, requests, concurrent.futures, re
from core.banner import Colors

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
    PHONE_LIB = True
except ImportError:
    PHONE_LIB = False

# --- 1. EMAIL BREACH CHECKER ---
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

# --- 2. PASSWORD BREACH CHECKER (HIBP) ---
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

# --- 3. USERNAME OSINT ---
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

# --- 4. ADVANCED INDIAN PHONE OSINT ---
def phone_osint(phone: str):
    print(f"\n{Colors.cyan('[+]')} Advanced Phone Number OSINT: {Colors.bold(phone)}")
    if not PHONE_LIB:
        print(f"  {Colors.red('[!] Install phonenumbers: pip install phonenumbers')}"); return
    try:
        parsed = phonenumbers.parse(phone, "IN")
        if not phonenumbers.is_valid_number(parsed):
            print(f"  {Colors.red('[!] Invalid phone number.')}"); return
        
        print(f"\n  {Colors.magenta('--- Basic Information ---')}")
        print(f"  {Colors.green('Valid Number:')} Yes")
        print(f"  {Colors.green('Country Code:')} +{parsed.country_code}")
        print(f"  {Colors.green('Country:')} {phonenumbers.region_code_for_number(parsed)}")
        print(f"  {Colors.green('International:')} {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"  {Colors.green('E164 Format:')} {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        
        print(f"\n  {Colors.magenta('--- Telecom Provider (Public Info) ---')}")
        carr = carrier.name_for_number(parsed, "en")
        print(f"  {Colors.green('Operator (ISP):')} {carr if carr else 'Unknown/Portable'}")
        
        print(f"\n  {Colors.magenta('--- Location (Telecom Circle) ---')}")
        region = geocoder.description_for_number(parsed, "en")
        print(f"  {Colors.green('State/Circle:')} {region if region else 'Unknown'}")
        
        print(f"\n  {Colors.magenta('--- Timezone ---')}")
        for tz in timezone.time_zones_for_number(parsed):
            print(f"  {Colors.green('Timezone:')} {tz}")
        
        print(f"\n  {Colors.magenta('--- Number Type ---')}")
        ntype = number_type(parsed)
        type_map = {
            PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Landline",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile", PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.TOLL_FREE: "Toll Free", PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            PhoneNumberType.UNKNOWN: "Unknown"
        }
        print(f"  {Colors.green('Type:')} {type_map.get(ntype, 'Unknown')}")
        
        print(f"\n  {Colors.yellow('--- PRIVACY NOTICE ---')}")
        print(f"  {Colors.dim('Owner Name and Address are PRIVATE data.')}")
        print(f"  {Colors.dim('Protected under IT Act 2000 and DPDP Act.')}")
        print(f"  {Colors.dim('Only Police/Court can access this data legally.')}")
        
        if not os.path.exists("reports"): os.makedirs("reports")
        report_file = f"reports/phone_osint_{parsed.national_number}.json"
        data = {"phone": phone, "valid": True, "country": phonenumbers.region_code_for_number(parsed), "operator": carr, "region": region, "timezone": list(timezone.time_zones_for_number(parsed)), "type": type_map.get(ntype, "Unknown")}
        with open(report_file, "w") as f: json.dump(data, f, indent=2)
        print(f"\n  {Colors.green('[+] Report saved:')} {report_file}")
        
    except phonenumbers.phonenumberutil.NumberParseException as e:
        print(f"  {Colors.red('[!] Parse Error:')} {e}")

# --- MENU ---
def run_osint():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 14: ADVANCED OSINT (Legal & Ethical)')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Email Breach Checker (XposedOrNot)")
        print(f"  {Colors.green('2.')} Password Breach Checker (HIBP)")
        print(f"  {Colors.green('3.')} Username OSINT (WhatsMyName)")
        print(f"  {Colors.green('4.')} Advanced Indian Phone OSINT")
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
