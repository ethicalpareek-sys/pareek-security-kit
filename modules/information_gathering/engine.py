"""Module 01: FUTURISTIC INFORMATION GATHERING & OSINT ENGINE."""
from __future__ import annotations
import socket, subprocess, shutil, sys, requests, ssl, concurrent.futures, re, json
import dns.resolver
from core.banner import Colors
from core.validators import validate_domain

# --- ADVANCED DNS ---
def advanced_dns(domain: str):
    print(f"\n{Colors.cyan('[+]')} Advanced DNS Enumeration: {Colors.bold(domain)}")
    records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    for rec in records:
        try:
            answers = dns.resolver.resolve(domain, rec)
            print(f"  {Colors.green('[' + rec + ']')}")
            for rdata in answers:
                print(f"    {Colors.dim(str(rdata))}")
        except Exception:
            pass

# --- FAST SUBDOMAIN SCANNER ---
def check_sub(sub, domain):
    try:
        ip = socket.gethostbyname(f"{sub}.{domain}")
        return f"  {Colors.green('[+] Found:')} {sub}.{domain} -> {ip}"
    except socket.gaierror:
        return None

def subdomain_scan(domain: str):
    print(f"\n{Colors.cyan('[+]')} Fast Subdomain Discovery: {Colors.bold(domain)}")
    subs = ["www", "mail", "ftp", "admin", "blog", "api", "dev", "test", "portal", "webmail", "ns1", "ns2", "vpn", "mysql", "cpanel", "shop", "secure", "login", "support", "cdn"]
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_sub, s, domain): s for s in subs}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(res)
                found = True
    if not found: print(f"  {Colors.yellow('[-] No common subdomains found.')}")

# --- WEB TECH FINGERPRINTING ---
def web_tech(url: str):
    print(f"\n{Colors.cyan('[+]')} Web Technology Fingerprinting: {Colors.bold(url)}")
    try:
        if not url.startswith(("http://", "https://")): url = "https://" + url
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers
        html = resp.text.lower()
        
        techs = []
        if 'cloudflare' in str(headers).lower(): techs.append("Cloudflare CDN")
        if 'nginx' in str(headers).lower(): techs.append("Nginx Server")
        if 'apache' in str(headers).lower(): techs.append("Apache Server")
        if 'wp-content' in html or 'wordpress' in html: techs.append("WordPress CMS")
        if 'react' in html: techs.append("React.js")
        if 'jquery' in html: techs.append("jQuery")
        if 'google-analytics' in html: techs.append("Google Analytics")
        
        print(f"  {Colors.green('Detected Technologies:')} {', '.join(techs) if techs else 'None detected'}")
        print(f"  {Colors.green('Server:')} {headers.get('Server', 'Unknown')}")
        print(f"  {Colors.green('Powered By:')} {headers.get('X-Powered-By', 'Unknown')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- SSL DEEP ANALYSIS ---
def ssl_deep(domain: str):
    print(f"\n{Colors.cyan('[+]')} SSL/TLS Deep Analysis: {Colors.bold(domain)}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"  {Colors.green('Issuer:')} {dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')}")
            print(f"  {Colors.green('Valid Until:')} {cert['notAfter']}")
            print(f"  {Colors.green('SANs:')} {len(cert.get('subjectAltName', []))} domains found")
    except Exception as e:
        print(f"  {Colors.red('[!] SSL Error:')} {e}")

# --- FAST PORT SCANNER ---
def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.close()
        return port
    except:
        return None

def fast_port_scan(target: str):
    print(f"\n{Colors.cyan('[+]')} Fast Port Scanning: {Colors.bold(target)}")
    try:
        ip = socket.gethostbyname(target)
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443]
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                    print(f"  {Colors.green('[OPEN]')} Port {res}")
        if not open_ports: print(f"  {Colors.yellow('[-] No common ports open.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- OSINT & WEB RECON ---
def osint_recon(domain: str):
    print(f"\n{Colors.cyan('[+]')} OSINT & Web Recon: {Colors.bold(domain)}")
    try:
        # Robots.txt
        r = requests.get(f"https://{domain}/robots.txt", timeout=5)
        if r.status_code == 200:
            print(f"  {Colors.green('[+] robots.txt found:')}")
            print(f"    {Colors.dim(r.text[:200])}")
        
        # Security.txt
        s = requests.get(f"https://{domain}/.well-known/security.txt", timeout=5)
        if s.status_code == 200:
            print(f"  {Colors.green('[+] security.txt found!')}")
            
        # IP Info
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if resp.get("status") == "success":
            print(f"  {Colors.green('IP Geolocation:')} {resp['city']}, {resp['country']} | ISP: {resp['isp']}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_info_gathering():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 01: FUTURISTIC INFO GATHERING & OSINT')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Advanced DNS (A, MX, TXT, NS, SOA)")
        print(f"  {Colors.green('2.')} Fast Subdomain Scanner (20+ domains)")
        print(f"  {Colors.green('3.')} Web Tech Fingerprinting (CMS, Server)")
        print(f"  {Colors.green('4.')} SSL/TLS Deep Analysis")
        print(f"  {Colors.green('5.')} Fast Port Scanner (20+ ports)")
        print(f"  {Colors.green('6.')} OSINT Recon (Robots.txt, IP Geo)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [InfoGathering]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target (domain/IP): "))).strip()
            if not target: continue
            try:
                if choice == "1": advanced_dns(validate_domain(target))
                elif choice == "2": subdomain_scan(validate_domain(target))
                elif choice == "3": web_tech(target)
                elif choice == "4": ssl_deep(validate_domain(target))
                elif choice == "5": fast_port_scan(target)
                elif choice == "6": osint_recon(validate_domain(target))
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
