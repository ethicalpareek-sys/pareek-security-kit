"""Module 15: FUTURISTIC CLOUD SECURITY ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, socket, requests, concurrent.futures, re, json
import dns.resolver
from core.banner import Colors

# --- 1. CLOUD PROVIDER DETECTOR ---
def detect_cloud_provider(domain: str):
    print(f"\n{Colors.cyan('[+]')} Cloud Provider Detection: {Colors.bold(domain)}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  {Colors.green('Resolved IP:')} {ip}")
        
        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"  {Colors.green('Reverse DNS:')} {hostname}")
        except:
            hostname = ""
            
        # Provider signatures
        providers = {
            "amazonaws.com": "Amazon Web Services (AWS)",
            "cloudfront.net": "AWS CloudFront",
            "azure.com": "Microsoft Azure",
            "cloudapp.azure.com": "Azure Cloud App",
            "googleusercontent.com": "Google Cloud Platform",
            "googleapis.com": "Google APIs",
            "cloudflare.com": "Cloudflare CDN",
            "digitalocean.com": "DigitalOcean",
            "linode.com": "Linode",
            "heroku.com": "Heroku",
            "github.io": "GitHub Pages",
            "vercel.app": "Vercel",
            "netlify.app": "Netlify"
        }
        
        detected = False
        for sig, name in providers.items():
            if sig in hostname.lower():
                print(f"  {Colors.green('[+] Provider:')} {name}")
                detected = True
                break
                
        if not detected:
            # Try IP range check via ip-api
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if resp.get("status") == "success":
                    print(f"  {Colors.green('ISP:')} {resp.get('isp', 'Unknown')}")
                    print(f"  {Colors.green('Org:')} {resp.get('org', 'Unknown')}")
            except:
                pass
            print(f"  {Colors.yellow('[?] Provider not identified from signatures.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. S3 BUCKET SCANNER ---
def check_s3_bucket(bucket_name: str):
    variants = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
        f"https://{bucket_name}.s3.us-east-1.amazonaws.com",
    ]
    results = []
    for url in variants:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                results.append(f"  {Colors.red('[!] PUBLIC S3 BUCKET:')} {url}")
            elif resp.status_code == 403:
                results.append(f"  {Colors.yellow('[~] Bucket exists (private):')} {url}")
            elif resp.status_code == 301:
                results.append(f"  {Colors.yellow('[~] Bucket exists (redirect):')} {url}")
        except:
            pass
    return results

def s3_scanner(domain: str):
    print(f"\n{Colors.cyan('[+]')} S3 Bucket Scanner: {Colors.bold(domain)}")
    # Extract base name from domain
    base = domain.split('.')[0]
    common_names = [
        base, f"{base}-backup", f"{base}-dev", f"{base}-test", f"{base}-prod",
        f"{base}-data", f"{base}-files", f"{base}-uploads", f"{base}-public",
        f"{base}-assets", f"{base}-media", f"{base}-static", f"www-{base}",
        f"{base}-logs", f"{base}-archive", f"{base}-storage", f"backup-{base}"
    ]
    
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_s3_bucket, b): b for b in common_names}
        for future in concurrent.futures.as_completed(futures):
            results = future.result()
            for r in results:
                print(r)
                found = True
    if not found:
        print(f"  {Colors.green('[+] No public S3 buckets found.')}")

# --- 3. CLOUD METADATA ENDPOINT CHECKER (SSRF Detection) ---
def metadata_checker(url: str):
    print(f"\n{Colors.cyan('[+]')} Cloud Metadata Endpoint Check (SSRF): {Colors.bold(url)}")
    print(f"  {Colors.dim('Testing if the target exposes cloud metadata endpoints...')}")
    
    # Metadata endpoints for different clouds
    endpoints = {
        "AWS": "http://169.254.169.254/latest/meta-data/",
        "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "GCP": "http://metadata.google.internal/computeMetadata/v1/",
    }
    
    # Test URL parameter injection
    payloads = [
        f"{url}?url=http://169.254.169.254/latest/meta-data/",
        f"{url}?target=http://169.254.169.254/latest/meta-data/",
        f"{url}?redirect=http://169.254.169.254/",
    ]
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    for payload in payloads:
        try:
            resp = requests.get(payload, timeout=5)
            if "ami-id" in resp.text or "instance-id" in resp.text or "computeMetadata" in resp.text:
                print(f"  {Colors.red('[!] VULNERABLE: SSRF - Metadata endpoint reachable!')}")
                print(f"  {Colors.dim('    Payload: ' + payload)}")
                return
        except:
            pass
    print(f"  {Colors.green('[✓] No obvious SSRF vulnerability detected.')}")

# --- 4. CLOUD STORAGE PUBLIC ACCESS CHECKER ---
def cloud_storage_checker(domain: str):
    print(f"\n{Colors.cyan('[+]')} Cloud Storage Public Access Check: {Colors.bold(domain)}")
    base = domain.split('.')[0]
    
    storage_urls = [
        f"https://{base}.s3.amazonaws.com/",
        f"https://storage.googleapis.com/{base}/",
        f"https://{base}.blob.core.windows.net/",
        f"https://{base}.file.core.windows.net/",
    ]
    
    for url in storage_urls:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                print(f"  {Colors.red('[!] PUBLIC STORAGE:')} {url}")
            elif resp.status_code == 403:
                print(f"  {Colors.yellow('[~] Private Storage:')} {url}")
        except:
            pass
    print(f"  {Colors.green('[+] Cloud storage check complete.')}")

# --- 5. CLOUD SERVICE FINGERPRINTING ---
def cloud_fingerprint(domain: str):
    print(f"\n{Colors.cyan('[+]')} Cloud Service Fingerprinting: {Colors.bold(domain)}")
    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers
        
        # Check cloud-specific headers
        cloud_headers = {
            "x-amz-": "AWS S3/CloudFront",
            "x-azure-": "Microsoft Azure",
            "x-goog-": "Google Cloud",
            "cf-ray": "Cloudflare",
            "x-vercel-": "Vercel",
            "x-netlify-": "Netlify",
            "x-github-request": "GitHub Pages"
        }
        
        found = False
        for header_key, service in cloud_headers.items():
            for h in headers:
                if header_key in h.lower():
                    print(f"  {Colors.green('[+] Service:')} {service}")
                    print(f"    {Colors.dim(h + ': ' + headers[h][:80])}")
                    found = True
                    break
        
        # Check for cloud misconfigurations
        print(f"\n  {Colors.magenta('--- Security Headers ---')}")
        security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", 
                           "X-Frame-Options", "Content-Security-Policy"]
        for sh in security_headers:
            if sh in headers:
                print(f"  {Colors.green('[✓]')} {sh}")
            else:
                print(f"  {Colors.red('[✗] Missing:')} {sh}")
                
        if not found:
            print(f"  {Colors.yellow('[?] No cloud-specific headers found.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 6. SUBDOMAIN CLOUD TAKEOVER DETECTOR ---
def takeover_detector(subdomain: str):
    print(f"\n{Colors.cyan('[+]')} Subdomain Takeover Detection: {Colors.bold(subdomain)}")
    try:
        # Check CNAME
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
            for cname in answers:
                cname_str = str(cname).rstrip('.')
                print(f"  {Colors.green('CNAME:')} {cname_str}")
                
                # Check for vulnerable services
                takeover_signatures = {
                    "github.io": "GitHub Pages",
                    "herokuapp.com": "Heroku",
                    "s3.amazonaws.com": "AWS S3",
                    "cloudfront.net": "CloudFront",
                    "azurewebsites.net": "Azure",
                    "trafficmanager.net": "Azure Traffic Manager",
                    "wordpress.com": "WordPress",
                    "shopify.com": "Shopify",
                    "readthedocs.io": "ReadTheDocs",
                    "ghost.io": "Ghost"
                }
                
                for sig, service in takeover_signatures.items():
                    if sig in cname_str:
                        print(f"  {Colors.yellow('[?] Service:')} {service}")
                        print(f"  {Colors.dim('    Manual verification required.')}")
                        
                        # Try to fetch the subdomain
                        try:
                            resp = requests.get(f"http://{subdomain}", timeout=5)
                            if "404" in resp.text or "not found" in resp.text.lower():
                                print(f"  {Colors.red('[!] POSSIBLE TAKEOVER:')} {subdomain}")
                        except:
                            print(f"  {Colors.red('[!] POSSIBLE TAKEOVER:')} {subdomain} (unreachable)")
                        return
        except dns.resolver.NoAnswer:
            print(f"  {Colors.green('[+] No CNAME record (not vulnerable to takeover).')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_cloud_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 15: FUTURISTIC CLOUD SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Cloud Provider Detector")
        print(f"  {Colors.green('2.')} S3 Bucket Scanner")
        print(f"  {Colors.green('3.')} Cloud Metadata Endpoint Check (SSRF)")
        print(f"  {Colors.green('4.')} Cloud Storage Public Access Checker")
        print(f"  {Colors.green('5.')} Cloud Service Fingerprinting")
        print(f"  {Colors.green('6.')} Subdomain Cloud Takeover Detector")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [CloudSecurity]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target (domain/URL): "))).strip()
            if not target: continue
            try:
                if choice == "1": detect_cloud_provider(target.replace("https://", "").replace("http://", "").split("/")[0])
                elif choice == "2": s3_scanner(target.replace("https://", "").replace("http://", "").split("/")[0])
                elif choice == "3": metadata_checker(target)
                elif choice == "4": cloud_storage_checker(target.replace("https://", "").replace("http://", "").split("/")[0])
                elif choice == "5": cloud_fingerprint(target.replace("https://", "").replace("http://", "").split("/")[0])
                elif choice == "6": takeover_detector(target.replace("https://", "").replace("http://", "").split("/")[0])
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
