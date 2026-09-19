"""Module 01: Advanced Information Gathering & OSINT."""
from __future__ import annotations
import socket, subprocess, shutil, sys, requests, ssl, concurrent.futures
from core.banner import Colors
from core.validators import validate_domain

def resolve_dns(domain: str):
    print(f"\n{Colors.cyan('[+]')} Resolving DNS for: {Colors.bold(domain)}")
    try:
        ips = socket.gethostbyname_ex(domain)
        print(f"  {Colors.green('Hostname:')} {ips[0]}")
        print(f"  {Colors.green('IPs:')} {', '.join(ips[2])}")
    except socket.gaierror as e:
        print(f"  {Colors.red('[!] DNS Resolution failed:')} {e}")

def whois_lookup(domain: str):
    print(f"\n{Colors.cyan('[+]')} WHOIS Lookup for: {Colors.bold(domain)}")
    if not shutil.which("whois"):
        print(f"  {Colors.yellow('[!] Install whois: pkg install whois')}"); return
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            for line in result.stdout.splitlines()[:25]:
                if line.strip(): print(f"  {Colors.dim(line)}")
            print(f"  {Colors.dim('... (truncated)')}")
    except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")

def grab_headers(url: str):
    print(f"\n{Colors.cyan('[+]')} HTTP Headers for: {Colors.bold(url)}")
    try:
        if not url.startswith(("http://", "https://")): url = "https://" + url
        resp = requests.get(url, timeout=10, allow_redirects=True)
        for k, v in resp.headers.items(): print(f"  {Colors.green(k + ':')} {v}")
        print(f"  {Colors.green('Status Code:')} {resp.status_code}")
    except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")

def nmap_scan(target: str):
    print(f"\n{Colors.cyan('[+]')} Running Nmap Scan on: {Colors.bold(target)}")
    if not shutil.which("nmap"):
        print(f"  {Colors.yellow('[!] Install nmap: pkg install nmap')}"); return
    try:
        print(f"  {Colors.dim('Scanning (this may take time)...')}")
        subprocess.run(["nmap", "-sV", "-sC", "-T4", target])
    except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")

def check_subdomain(sub: str, domain: str):
    target = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return f"  {Colors.green('[+] Found:')} {target} -> {ip}"
    except socket.gaierror:
        return None

def subdomain_finder(domain: str):
    print(f"\n{Colors.cyan('[+]')} Fast Subdomain Scan for: {Colors.bold(domain)}")
    subdomains = ["www", "mail", "ftp", "admin", "blog", "api", "dev", "test", "portal", "webmail", "ns1", "ns2", "vpn", "mysql", "cpanel"]
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(res)
                found = True
    if not found: print(f"  {Colors.yellow('[-] No common subdomains found.')}")

def ip_info(ip: str):
    print(f"\n{Colors.cyan('[+]')} OSINT Info for IP: {Colors.bold(ip)}")
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            print(f"  {Colors.green('Country:')} {data['country']} ({data['countryCode']})")
            print(f"  {Colors.green('City:')} {data['city']}, {data['regionName']}")
            print(f"  {Colors.green('ISP:')} {data['isp']}")
            print(f"  {Colors.green('Org:')} {data['org']}")
            print(f"  {Colors.green('Coords:')} {data['lat']}, {data['lon']}")
    except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")

def ssl_cert_info(domain: str):
    print(f"\n{Colors.cyan('[+]')} SSL/TLS Certificate Info for: {Colors.bold(domain)}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"  {Colors.green('Subject:')} {dict(x[0] for x in cert['subject'])}")
            print(f"  {Colors.green('Issuer:')} {dict(x[0] for x in cert['issuer'])}")
            print(f"  {Colors.green('Valid From:')} {cert['notBefore']}")
            print(f"  {Colors.green('Valid Until:')} {cert['notAfter']}")
    except Exception as e: print(f"  {Colors.red('[!] SSL Error:')} {e}")

def dns_records(domain: str):
    print(f"\n{Colors.cyan('[+]')} DNS Records for: {Colors.bold(domain)}")
    if not shutil.which("dig"):
        print(f"  {Colors.yellow('[!] Install dnsutils: pkg install dnsutils')}"); return
    for record in ["A", "MX", "NS", "TXT"]:
        print(f"\n  {Colors.magenta('--- ' + record + ' ---')}")
        try:
            result = subprocess.run(["dig", "+short", "-type=" + record, domain], capture_output=True, text=True, timeout=10)
            print(f"  {Colors.dim(result.stdout.strip()) if result.stdout.strip() else '  No records'}")
        except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")

def run_info_gathering():
    while True:
        print(f"\n{Colors.magenta('═' * 55)}")
        print(f"  {Colors.bold('MODULE 01: ADVANCED INFO GATHERING & OSINT')}")
        print(f"{Colors.magenta('═' * 55)}")
        print(f"  {Colors.green('1.')} DNS Lookup           {Colors.green('5.')} Subdomain Finder")
        print(f"  {Colors.green('2.')} WHOIS Lookup         {Colors.green('6.')} IP Geolocation (OSINT)")
        print(f"  {Colors.green('3.')} HTTP Header Grabber  {Colors.green('7.')} DNS Records (MX, TXT)")
        print(f"  {Colors.green('4.')} Nmap Port Scanner    {Colors.green('8.')} SSL/TLS Cert Checker")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 55)}")
        
        choice = input(Colors.bold(Colors.cyan("  [InfoGathering]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6","7","8"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target: "))).strip()
            if not target: continue
            try:
                if choice == "1": resolve_dns(validate_domain(target))
                elif choice == "2": whois_lookup(validate_domain(target))
                elif choice == "3": grab_headers(target)
                elif choice == "4": nmap_scan(target)
                elif choice == "5": subdomain_finder(validate_domain(target))
                elif choice == "6": ip_info(target)
                elif choice == "7": dns_records(validate_domain(target))
                elif choice == "8": ssl_cert_info(validate_domain(target))
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
