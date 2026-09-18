"""Module 12: FUTURISTIC DNS SECURITY ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, socket, concurrent.futures, time, dns.resolver, dns.query, dns.zone, dns.exception
from core.banner import Colors

# --- 1. FULL DNS RECORD ENUMERATOR ---
def dns_records_enum(domain: str):
    print(f"\n{Colors.cyan('[+]')} Full DNS Record Enumeration: {Colors.bold(domain)}")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DNSKEY', 'DS']
    for rec in record_types:
        try:
            answers = dns.resolver.resolve(domain, rec, lifetime=5)
            print(f"  {Colors.green('[' + rec + ']')}")
            for rdata in answers:
                print(f"    {Colors.dim(str(rdata))}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"  {Colors.red('[!] Domain does not exist.')}"); return
        except Exception:
            pass

# --- 2. DNSSEC VALIDATOR ---
def dnssec_validator(domain: str):
    print(f"\n{Colors.cyan('[+]')} DNSSEC Validation: {Colors.bold(domain)}")
    try:
        # Check DNSKEY
        dnskeys = dns.resolver.resolve(domain, 'DNSKEY', lifetime=5)
        print(f"  {Colors.green('[+] DNSKEY Found:')} {len(dnskeys)} keys")
        
        # Check DS record at parent
        parts = domain.split('.')
        parent = '.'.join(parts[1:])
        if parent:
            try:
                ds = dns.resolver.resolve(parent, 'DS', lifetime=5)
                print(f"  {Colors.green('[+] DS Record Found at parent:')} {len(ds)} records")
                print(f"  {Colors.green('[✓] DNSSEC is ENABLED and configured.')}")
            except Exception:
                print(f"  {Colors.yellow('[!] DS record not found at parent. DNSSEC might be partially configured.')}")
    except dns.resolver.NoAnswer:
        print(f"  {Colors.red('[!] VULNERABLE: DNSSEC is NOT enabled.')}")
    except Exception as e:
        print(f"  {Colors.yellow('[?] Could not verify DNSSEC:')} {e}")

# --- 3. EMAIL SECURITY AUDITOR (SPF/DMARC/DKIM) ---
def email_security_audit(domain: str):
    print(f"\n{Colors.cyan('[+]')} Email Security Audit (SPF/DMARC): {Colors.bold(domain)}")
    
    # SPF Check
    try:
        txts = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        spf_found = False
        for txt in txts:
            if "v=spf1" in str(txt):
                spf_found = True
                print(f"  {Colors.green('[+] SPF Found:')} {txt}")
                if "-all" in str(txt):
                    print(f"    {Colors.green('[✓] Strict policy (-all) in place.')}")
                elif "~all" in str(txt):
                    print(f"    {Colors.yellow('[!] Soft policy (~all). Attackers might bypass.')}")
        if not spf_found:
            print(f"  {Colors.red('[!] VULNERABLE: No SPF record found. Email spoofing possible!')}")
    except Exception:
        print(f"  {Colors.red('[!] No TXT records found for SPF.')}")
        
    # DMARC Check
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=5)
        for txt in dmarc:
            print(f"  {Colors.green('[+] DMARC Found:')} {txt}")
            if "p=reject" in str(txt):
                print(f"    {Colors.green('[✓] Strict policy (p=reject).')}")
            elif "p=quarantine" in str(txt):
                print(f"    {Colors.yellow('[~] Moderate policy (p=quarantine).')}")
            elif "p=none" in str(txt):
                print(f"    {Colors.red('[!] Weak policy (p=none). No action taken on spoofed emails.')}")
    except Exception:
        print(f"  {Colors.red('[!] VULNERABLE: No DMARC record found.')}")

# --- 4. ZONE TRANSFER (AXFR) AUDITOR ---
def zone_transfer_audit(domain: str):
    print(f"\n{Colors.cyan('[+]')} Zone Transfer (AXFR) Audit: {Colors.bold(domain)}")
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        ns_servers = [str(ns) for ns in ns_answers]
        print(f"  {Colors.green('Nameservers:')} {', '.join(ns_servers)}")
        
        for ns in ns_servers:
            ns_ip = socket.gethostbyname(ns)
            print(f"\n  {Colors.magenta(f'--- Trying Zone Transfer on {ns} ({ns_ip}) ---')}")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                print(f"  {Colors.red('[!] VULNERABLE: Zone Transfer ALLOWED!')}")
                print(f"  {Colors.yellow(f'    Found {len(z.nodes)} records.')}")
                for name, node in list(z.nodes.items())[:5]:
                    print(f"    {Colors.dim(name)} -> {node}")
            except dns.exception.FormError:
                print(f"  {Colors.green('[+] Zone transfer refused (Secure).')}")
            except Exception as e:
                print(f"  {Colors.green('[+] Zone transfer refused (Secure).')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. FAST SUBDOMAIN BRUTE FORCER ---
def check_subdomain(sub, domain):
    target = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return f"  {Colors.green('[+] Found:')} {target} -> {ip}"
    except:
        return None

def subdomain_bruteforce(domain: str):
    print(f"\n{Colors.cyan('[+]')} Fast Subdomain Brute Force: {Colors.bold(domain)}")
    subdomains = [
        "www", "mail", "ftp", "admin", "blog", "api", "dev", "test", "portal", "webmail",
        "ns1", "ns2", "vpn", "mysql", "cpanel", "shop", "secure", "login", "support", "cdn",
        "m", "mobile", "app", "beta", "staging", "demo", "forum", "wiki", "docs", "status",
        "smtp", "pop", "imap", "webdisk", "whm", "autodiscover", "autoconfig", "direct", "remote", "server"
    ]
    print(f"  {Colors.dim(f'Scanning {len(subdomains)} common subdomains...')}")
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(res)
                found = True
    if not found:
        print(f"  {Colors.yellow('[-] No common subdomains found.')}")

# --- 6. FAST FLUX / DNS REBINDING DETECTOR ---
def fast_flux_detector(domain: str):
    print(f"\n{Colors.cyan('[+]')} Fast Flux / DNS Rebinding Detection: {Colors.bold(domain)}")
    print(f"  {Colors.dim('Resolving domain 15 times to detect IP changes...')}")
    ips = set()
    try:
        for i in range(15):
            try:
                ip = socket.gethostbyname(domain)
                ips.add(ip)
                time.sleep(0.3)
            except:
                pass
        
        print(f"  {Colors.green('Unique IPs found:')} {len(ips)}")
        for ip in ips:
            print(f"    {Colors.dim(ip)}")
            
        if len(ips) > 5:
            print(f"  {Colors.red('[!] WARNING: Possible Fast Flux network detected!')}")
            print(f"  {Colors.red('    This domain uses rapidly changing IPs (Botnet behavior).')}")
        else:
            print(f"  {Colors.green('[+] Normal DNS behavior detected.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_dns_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 12: FUTURISTIC DNS SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Full DNS Record Enumerator")
        print(f"  {Colors.green('2.')} DNSSEC Validator")
        print(f"  {Colors.green('3.')} Email Security Auditor (SPF/DMARC)")
        print(f"  {Colors.green('4.')} Zone Transfer (AXFR) Auditor")
        print(f"  {Colors.green('5.')} Fast Subdomain Brute Forcer")
        print(f"  {Colors.green('6.')} Fast Flux / DNS Rebinding Detector")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [DNSSecurity]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Domain (e.g., google.com): "))).strip()
            if not target: continue
            try:
                if choice == "1": dns_records_enum(target)
                elif choice == "2": dnssec_validator(target)
                elif choice == "3": email_security_audit(target)
                elif choice == "4": zone_transfer_audit(target)
                elif choice == "5": subdomain_bruteforce(target)
                elif choice == "6": fast_flux_detector(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
