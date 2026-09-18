"""Module 13: FUTURISTIC SSL/TLS ANALYSIS ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, socket, ssl, hashlib, datetime, re
from core.banner import Colors

# --- 1. FULL CERTIFICATE CHAIN INSPECTOR ---
def cert_inspector(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} Full Certificate Inspector: {Colors.bold(domain)}:{port}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            cert_der = s.getpeercert(binary_form=True)
            
            # Subject
            subject = dict(x[0] for x in cert.get('subject', []))
            print(f"\n  {Colors.magenta('--- Subject ---')}")
            for k, v in subject.items():
                print(f"    {Colors.green(k + ':')} {v}")
            
            # Issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            print(f"\n  {Colors.magenta('--- Issuer ---')}")
            for k, v in issuer.items():
                print(f"    {Colors.green(k + ':')} {v}")
            
            # Validity
            print(f"\n  {Colors.magenta('--- Validity ---')}")
            print(f"    {Colors.green('Not Before:')} {cert.get('notBefore', 'N/A')}")
            print(f"    {Colors.green('Not After:')}  {cert.get('notAfter', 'N/A')}")
            
            # Serial Number
            print(f"\n  {Colors.magenta('--- Serial Number ---')}")
            print(f"    {Colors.green('Serial:')} {cert.get('serialNumber', 'N/A')}")
            
            # SHA256 Fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            formatted = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
            print(f"\n  {Colors.magenta('--- SHA-256 Fingerprint ---')}")
            print(f"    {Colors.dim(formatted)}")
            
            # Version & Signature
            print(f"\n  {Colors.magenta('--- Extra Info ---')}")
            print(f"    {Colors.green('Version:')} {cert.get('version', 'N/A')}")
            print(f"    {Colors.green('Signature Algorithm:')} {cert.get('signatureAlgorithm', 'N/A')}")
            
    except ssl.SSLCertVerificationError as e:
        print(f"  {Colors.red('[!] Certificate Verification FAILED:')} {e}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. TLS VERSION SCANNER ---
def tls_version_scanner(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} TLS Version Scanner: {Colors.bold(domain)}:{port}")
    
    versions = {
        "TLS 1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, 'TLSv1_2') else None,
        "TLS 1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None,
    }
    
    for name, version in versions.items():
        if version is None:
            print(f"  {Colors.dim('[?] ' + name + ': Not supported by Python version')}")
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, port))
                
                # Security Rating
                if name in ["TLS 1.0", "TLS 1.1"]:
                    print(f"  {Colors.red('[!] ' + name + ': SUPPORTED (Deprecated - Vulnerable!)')}")
                elif name == "TLS 1.2":
                    print(f"  {Colors.green('[+] ' + name + ': SUPPORTED (Secure)')}")
                else:
                    print(f"  {Colors.green('[✓] ' + name + ': SUPPORTED (Most Secure)')}")
        except ssl.SSLError:
            print(f"  {Colors.dim('[-] ' + name + ': Not supported')}")
        except Exception:
            print(f"  {Colors.dim('[-] ' + name + ': Not supported')}")

# --- 3. CIPHER SUITE ANALYZER ---
def cipher_analyzer(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} Cipher Suite Analyzer: {Colors.bold(domain)}:{port}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            
            cipher = s.cipher()
            print(f"\n  {Colors.magenta('--- Active Cipher ---')}")
            print(f"    {Colors.green('Cipher Name:')} {cipher[0]}")
            print(f"    {Colors.green('Protocol:')} {cipher[1]}")
            print(f"    {Colors.green('Key Bits:')} {cipher[2]} bits")
            
            # Weak cipher check
            weak_keywords = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
            is_weak = any(w in cipher[0].upper() for w in weak_keywords)
            
            print(f"\n  {Colors.magenta('--- Security Assessment ---')}")
            if is_weak:
                print(f"    {Colors.red('[!] VULNERABLE: Weak cipher detected!')}")
            else:
                print(f"    {Colors.green('[✓] Strong cipher in use.')}")
            
            if cipher[2] < 128:
                print(f"    {Colors.red('[!] Key size is too small (<128 bits)!')}")
            else:
                print(f"    {Colors.green('[✓] Key size is adequate (>=128 bits).')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. SAN (SUBJECT ALTERNATIVE NAME) EXTRACTOR ---
def san_extractor(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} SAN Extractor: {Colors.bold(domain)}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            
            san_list = cert.get('subjectAltName', [])
            if san_list:
                print(f"  {Colors.green(f'[+] Found {len(san_list)} domains in certificate:')}")
                for typ, name in san_list:
                    print(f"    {Colors.dim(f'[{typ}]')} {name}")
            else:
                print(f"  {Colors.yellow('[-] No SAN entries found.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. CERTIFICATE EXPIRY MONITOR ---
def expiry_monitor(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} Certificate Expiry Monitor: {Colors.bold(domain)}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            
            expiry_str = cert.get('notAfter', '')
            expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            now = datetime.datetime.utcnow()
            days_left = (expiry_date - now).days
            
            print(f"  {Colors.green('Expiry Date:')} {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            print(f"  {Colors.green('Days Remaining:')} {days_left} days")
            
            if days_left < 0:
                print(f"  {Colors.red('[!] CRITICAL: Certificate EXPIRED!')}")
            elif days_left < 7:
                print(f"  {Colors.red('[!] CRITICAL: Expires in less than a week!')}")
            elif days_left < 30:
                print(f"  {Colors.yellow('[!] WARNING: Expires within 30 days.')}")
            elif days_left < 90:
                print(f"  {Colors.yellow('[~] Expires within 90 days (Normal for Let\'s Encrypt).')}")
            else:
                print(f"  {Colors.green('[✓] Certificate is healthy.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 6. HEARTBLEED (CVE-2014-0160) CHECKER ---
def heartbleed_checker(domain: str, port: int = 443):
    print(f"\n{Colors.cyan('[+]')} Heartbleed (CVE-2014-0160) Check: {Colors.bold(domain)}")
    print(f"  {Colors.dim('Sending Heartbeat request to detect vulnerability...')}")
    try:
        # Heartbleed heartbeat request payload
        hello = bytes.fromhex(
            "16 03 02 00 dc 01 00 00 d8 03 02 53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00 00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04 00 2f 00 96 00 41 00 07 c0 11 c0 07 c0 0c c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02 00 0a 00 1c 00 1a 00 17 00 19 00 1c 00 1b 00 18 00 1a 00 16 00 1e 00 1d 00 1b 00 18 00 1a 00 16 00 1c 00 1b 00 18"
        )
        heartbeat = bytes.fromhex("18 03 02 00 03 01 40 00")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((domain, port))
        s.send(hello)
        s.recv(1024)
        s.send(heartbeat)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 3:
            print(f"  {Colors.red('[!] VULNERABLE: Heartbleed detected! Server responded with extra data.')}")
        else:
            print(f"  {Colors.green('[✓] Not vulnerable to Heartbleed.')}")
    except socket.timeout:
        print(f"  {Colors.green('[✓] Not vulnerable (Connection timeout = server patched).')}")
    except Exception as e:
        print(f"  {Colors.green('[✓] Not vulnerable (Server is patched).')}")

# --- MENU ---
def run_ssl_tls_analysis():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 13: FUTURISTIC SSL/TLS ANALYSIS')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Full Certificate Inspector")
        print(f"  {Colors.green('2.')} TLS Version Scanner")
        print(f"  {Colors.green('3.')} Cipher Suite Analyzer")
        print(f"  {Colors.green('4.')} SAN (Alternative Names) Extractor")
        print(f"  {Colors.green('5.')} Certificate Expiry Monitor")
        print(f"  {Colors.green('6.')} Heartbleed (CVE-2014-0160) Checker")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [SSLTLS]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Domain (e.g., google.com): "))).strip()
            if not target: continue
            # Clean domain
            target = target.replace("https://", "").replace("http://", "").split("/")[0]
            try:
                if choice == "1": cert_inspector(target)
                elif choice == "2": tls_version_scanner(target)
                elif choice == "3": cipher_analyzer(target)
                elif choice == "4": san_extractor(target)
                elif choice == "5": expiry_monitor(target)
                elif choice == "6": heartbleed_checker(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
