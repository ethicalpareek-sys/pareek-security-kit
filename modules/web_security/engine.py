"""Module 04: FUTURISTIC WEB SECURITY TESTING ENGINE."""
from __future__ import annotations
import socket, ssl, sys, requests, concurrent.futures, re, urllib.parse
from core.banner import Colors

# --- 1. SECURITY HEADERS ANALYZER ---
def check_headers(url: str):
    print(f"\n{Colors.cyan('[+]')} Security Headers Analysis: {Colors.bold(url)}")
    try:
        if not url.startswith(("http://", "https://")): url = "https://" + url
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers
        
        required = {
            "Strict-Transport-Security": "HSTS (Forces HTTPS)",
            "Content-Security-Policy": "CSP (Prevents XSS)",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Referrer-Policy": "Controls Referrer Info"
        }
        
        for h, desc in required.items():
            if h in headers:
                print(f"  {Colors.green('[✓]')} {h}: {Colors.dim(headers[h][:50])}")
            else:
                print(f"  {Colors.red('[✗] MISSING:')} {h} ({desc})")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. SSL/TLS MISCONFIGURATION CHECK ---
def check_ssl_misconfig(domain: str):
    print(f"\n{Colors.cyan('[+]')} SSL/TLS Misconfiguration Check: {Colors.bold(domain)}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"  {Colors.green('Issuer:')} {dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')}")
            print(f"  {Colors.green('Valid Until:')} {cert['notAfter']}")
            print(f"  {Colors.green('TLS Version:')} {s.version()}")
            
            # Check for weak protocols (Basic check)
            if "TLSv1.0" in s.version() or "TLSv1.1" in s.version():
                print(f"  {Colors.red('[!] VULNERABLE: Weak TLS version detected!')}")
            else:
                print(f"  {Colors.green('[+] Strong TLS version in use.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] SSL Error:')} {e}")

# --- 3. BASIC SQL INJECTION SCANNER ---
def sqli_scan(url: str):
    print(f"\n{Colors.cyan('[+]')} Basic SQL Injection Scan: {Colors.bold(url)}")
    if "?" not in url:
        print(f"  {Colors.yellow('[!] URL must contain parameters (e.g., ?id=1) for SQLi test.')}")
        return
    payloads = ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL--"]
    errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL query failed", "SQLite3::query"]
    
    for payload in payloads:
        try:
            test_url = url + urllib.parse.quote(payload)
            resp = requests.get(test_url, timeout=10)
            for err in errors:
                if err.lower() in resp.text.lower():
                    print(f"  {Colors.red('[!] VULNERABLE: SQLi detected with payload:')} {payload}")
                    return
        except:
            pass
    print(f"  {Colors.green('[+] No basic SQLi errors detected.')}")

# --- 4. REFLECTED XSS SCANNER ---
def xss_scan(url: str):
    print(f"\n{Colors.cyan('[+]')} Reflected XSS Scan: {Colors.bold(url)}")
    if "?" not in url:
        print(f"  {Colors.yellow('[!] URL must contain parameters for XSS test.')}")
        return
    payload = "<script>alert(1)</script>"
    try:
        test_url = url + urllib.parse.quote(payload)
        resp = requests.get(test_url, timeout=10)
        if payload in resp.text:
            print(f"  {Colors.red('[!] VULNERABLE: XSS payload reflected in response!')}")
        else:
            print(f"  {Colors.green('[+] No basic reflected XSS detected.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. DIRECTORY TRAVERSAL / LFI SCANNER ---
def lfi_scan(url: str):
    print(f"\n{Colors.cyan('[+]')} Directory Traversal / LFI Scan: {Colors.bold(url)}")
    payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    indicators = ["root:x:", "[extensions]", "[fonts]"]
    
    for payload in payloads:
        try:
            test_url = url + urllib.parse.quote(payload)
            resp = requests.get(test_url, timeout=10)
            for ind in indicators:
                if ind in resp.text:
                    print(f"  {Colors.red('[!] VULNERABLE: LFI detected with payload:')} {payload}")
                    return
        except:
            pass
    print(f"  {Colors.green('[+] No basic LFI detected.')}")

# --- 6. WAF DETECTION ---
def waf_detect(url: str):
    print(f"\n{Colors.cyan('[+]')} WAF Detection: {Colors.bold(url)}")
    try:
        # Send a malicious-looking request to trigger WAF
        headers = {"User-Agent": "sqlmap/1.0"}
        resp = requests.get(url, headers=headers, timeout=10)
        
        wafs = {
            "cloudflare": "Cloudflare",
            "sucuri": "Sucuri",
            "akamai": "Akamai",
            "incapsula": "Imperva Incapsula",
            "aws": "AWS WAF"
        }
        
        server = resp.headers.get("Server", "").lower()
        detected = False
        for key, name in wafs.items():
            if key in server:
                print(f"  {Colors.green('[+] WAF Detected:')} {name}")
                detected = True
                break
        if not detected:
            print(f"  {Colors.yellow('[-] No obvious WAF detected (or it is well-hidden).')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_web_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 04: FUTURISTIC WEB SECURITY TESTING')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Security Headers Analyzer")
        print(f"  {Colors.green('2.')} SSL/TLS Misconfiguration Check")
        print(f"  {Colors.green('3.')} SQL Injection Scanner (Basic)")
        print(f"  {Colors.green('4.')} Reflected XSS Scanner")
        print(f"  {Colors.green('5.')} Directory Traversal / LFI Scanner")
        print(f"  {Colors.green('6.')} WAF Detection")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [WebSecurity]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target URL (e.g., https://example.com/page.php?id=1): "))).strip()
            if not target: continue
            try:
                if choice == "1": check_headers(target)
                elif choice == "2": check_ssl_misconfig(target.replace("https://", "").replace("http://", "").split("/")[0])
                elif choice == "3": sqli_scan(target)
                elif choice == "4": xss_scan(target)
                elif choice == "5": lfi_scan(target)
                elif choice == "6": waf_detect(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
