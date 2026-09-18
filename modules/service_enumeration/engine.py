"""Module 03: FUTURISTIC SERVICE ENUMERATION ENGINE."""
from __future__ import annotations
import socket, subprocess, shutil, sys, requests, ssl, concurrent.futures, re
from core.banner import Colors

# --- 1. ADVANCED HTTP/HTTPS ENUMERATION ---
def check_url(url):
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code in [200, 301, 302, 401, 403]:
            return f"  {Colors.green('[+] Found:')} {url} (Status: {resp.status_code})"
    except:
        pass
    return None

def http_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} Advanced HTTP/HTTPS Enumeration: {Colors.bold(target)}")
    if not target.startswith(("http://", "https://")): target = "https://" + target
    try:
        resp = requests.get(target, timeout=10, allow_redirects=True)
        print(f"  {Colors.green('Server:')} {resp.headers.get('Server', 'Unknown')}")
        print(f"  {Colors.green('Powered By:')} {resp.headers.get('X-Powered-By', 'Unknown')}")
        print(f"  {Colors.green('Status Code:')} {resp.status_code}")
        
        # HTTP Methods Check
        methods = ["OPTIONS", "HEAD", "TRACE"]
        print(f"\n  {Colors.magenta('--- HTTP Methods ---')}")
        for m in methods:
            try:
                r = requests.request(m, target, timeout=5)
                print(f"  {Colors.green(m + ':')} Allowed (Status: {r.status_code})")
            except:
                print(f"  {Colors.dim(m + ':')} Not Allowed / Blocked")
        
        # Directory Busting
        print(f"\n  {Colors.magenta('--- Common Directories ---')}")
        dirs = ["admin", "login", "api", "backup", "config", ".git", "robots.txt", "sitemap.xml", "dashboard", "uploads"]
        urls = [f"{target.rstrip('/')}/{d}" for d in dirs]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_url, u): u for u in urls}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res: print(res)
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. FTP ENUMERATION ---
def ftp_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} FTP Enumeration: {Colors.bold(target)}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 21))
        banner = s.recv(1024).decode(errors='ignore').strip()
        print(f"  {Colors.green('Banner:')} {banner}")
        
        # Anonymous Login Check
        s.send(b'USER anonymous\r\n')
        resp = s.recv(1024).decode(errors='ignore')
        s.send(b'PASS anonymous@test.com\r\n')
        resp2 = s.recv(1024).decode(errors='ignore')
        if "230" in resp2:
            print(f"  {Colors.red('[!] VULNERABLE: Anonymous FTP login allowed!')}")
        else:
            print(f"  {Colors.green('[+] Anonymous login not allowed.')}")
        s.close()
    except Exception as e:
        print(f"  {Colors.red('[!] FTP Error:')} {e}")

# --- 3. SSH ENUMERATION ---
def ssh_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} SSH Enumeration: {Colors.bold(target)}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 22))
        banner = s.recv(1024).decode(errors='ignore').strip()
        print(f"  {Colors.green('SSH Banner:')} {banner}")
        s.close()
    except Exception as e:
        print(f"  {Colors.red('[!] SSH Error:')} {e}")

# --- 4. SMTP ENUMERATION ---
def smtp_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} SMTP Enumeration: {Colors.bold(target)}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 25))
        banner = s.recv(1024).decode(errors='ignore').strip()
        print(f"  {Colors.green('Banner:')} {banner}")
        
        # VRFY Command Check
        s.send(b'VRFY root\r\n')
        resp = s.recv(1024).decode(errors='ignore').strip()
        print(f"  {Colors.green('VRFY root:')} {resp}")
        
        s.send(b'EXPN root\r\n')
        resp2 = s.recv(1024).decode(errors='ignore').strip()
        print(f"  {Colors.green('EXPN root:')} {resp2}")
        s.close()
    except Exception as e:
        print(f"  {Colors.red('[!] SMTP Error:')} {e}")

# --- 5. SMB ENUMERATION ---
def smb_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} SMB Probe: {Colors.bold(target)}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 445))
        print(f"  {Colors.green('[+] SMB Port 445 is OPEN.')}")
        print(f"  {Colors.dim('Use nmap --script smb-os-discovery for more details.')}")
        s.close()
    except Exception as e:
        print(f"  {Colors.red('[!] SMB Error:')} {e}")

# --- 6. DNS SERVICE ENUMERATION ---
def dns_service_enum(target: str):
    print(f"\n{Colors.cyan('[+]')} DNS Service Enumeration (SRV & Zone Transfer): {Colors.bold(target)}")
    if not shutil.which("dig"):
        print(f"  {Colors.yellow('[!] Install dnsutils: pkg install dnsutils')}"); return
    try:
        # SRV Records
        srv_records = ["_sip._tcp", "_ldap._tcp", "_kerberos._tcp", "_gc._tcp"]
        for srv in srv_records:
            result = subprocess.run(["dig", "+short", "SRV", f"{srv}.{target}"], capture_output=True, text=True, timeout=10)
            if result.stdout.strip():
                print(f"  {Colors.green('[+] SRV Found:')} {srv} -> {result.stdout.strip()}")
                
        # Zone Transfer Attempt
        ns_result = subprocess.run(["dig", "+short", "NS", target], capture_output=True, text=True, timeout=10)
        if ns_result.stdout.strip():
            ns_server = ns_result.stdout.strip().split('\n')[0]
            print(f"\n  {Colors.magenta('--- Zone Transfer Attempt ---')}")
            axfr = subprocess.run(["dig", "AXFR", target, f"@{ns_server}"], capture_output=True, text=True, timeout=15)
            if "Transfer failed" in axfr.stdout or "failed" in axfr.stderr:
                print(f"  {Colors.green('[+] Zone transfer refused (Secure).')}")
            else:
                print(f"  {Colors.red('[!] VULNERABLE: Zone transfer allowed!')}")
                print(f"  {Colors.dim(axfr.stdout[:500])}")
    except Exception as e:
        print(f"  {Colors.red('[!] DNS Error:')} {e}")

# --- MENU ---
def run_service_enumeration():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 03: FUTURISTIC SERVICE ENUMERATION')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Advanced HTTP/HTTPS Enumeration")
        print(f"  {Colors.green('2.')} FTP Enumeration (Anonymous Check)")
        print(f"  {Colors.green('3.')} SSH Enumeration (Banner Grab)")
        print(f"  {Colors.green('4.')} SMTP Enumeration (VRFY/EXPN)")
        print(f"  {Colors.green('5.')} SMB Probe (Port 445)")
        print(f"  {Colors.green('6.')} DNS Service Enumeration (SRV/AXFR)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [ServiceEnum]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target IP/Domain: "))).strip()
            if not target: continue
            try:
                if choice == "1": http_enum(target)
                elif choice == "2": ftp_enum(target)
                elif choice == "3": ssh_enum(target)
                elif choice == "4": smtp_enum(target)
                elif choice == "5": smb_enum(target)
                elif choice == "6": dns_service_enum(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
