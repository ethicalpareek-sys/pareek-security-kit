"""Module 16: FUTURISTIC API SECURITY ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, base64, json, time, re, requests, concurrent.futures
from core.banner import Colors

# --- 1. API ENDPOINT DISCOVERY ---
def check_endpoint(base_url, path):
    url = base_url.rstrip('/') + path
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code in [200, 201, 301, 302, 401, 403, 405]:
            return f"  {Colors.green('[+] Found:')} {url} (Status: {resp.status_code})"
    except:
        pass
    return None

def discover_endpoints(base_url: str):
    print(f"\n{Colors.cyan('[+]')} API Endpoint Discovery: {Colors.bold(base_url)}")
    paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/admin",
        "/api/login", "/api/register", "/api/auth", "/api/token", "/api/health",
        "/api/status", "/api/config", "/api/info", "/api/data", "/api/products",
        "/api/orders", "/api/cart", "/api/payment", "/api/search", "/api/upload",
        "/graphql", "/graphiql", "/swagger", "/swagger.json", "/swagger-ui",
        "/openapi.json", "/api-docs", "/docs", "/redoc", "/rest", "/rest/api",
        "/v1", "/v2", "/xmlrpc.php", "/wp-json", "/jsonapi"
    ]
    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_endpoint, base_url, p): p for p in paths}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(res)
                found = True
    if not found:
        print(f"  {Colors.yellow('[-] No common API endpoints found.')}")

# --- 2. JWT ANALYZER ---
def jwt_analyzer(token: str):
    print(f"\n{Colors.cyan('[+]')} JWT Token Analyzer")
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print(f"  {Colors.red('[!] Invalid JWT format.')}"); return
        
        # Decode header
        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))
        print(f"\n  {Colors.magenta('--- Header ---')}")
        for k, v in header.items():
            print(f"    {Colors.green(k + ':')} {v}")
        
        # Decode payload
        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        print(f"\n  {Colors.magenta('--- Payload ---')}")
        for k, v in payload.items():
            print(f"    {Colors.green(k + ':')} {v}")
        
        # Vulnerability checks
        print(f"\n  {Colors.magenta('--- Vulnerability Check ---')}")
        alg = header.get('alg', '').lower()
        if alg == 'none':
            print(f"  {Colors.red('[!] CRITICAL: alg=none vulnerability!')}")
        elif alg in ['hs256', 'hs384', 'hs512']:
            print(f"  {Colors.yellow('[~] HMAC algorithm. Test for weak secret.')}")
        elif alg in ['rs256', 'rs384', 'rs512']:
            print(f"  {Colors.green('[+] RSA algorithm (strong if key protected).')}")
        else:
            print(f"  {Colors.yellow('[?] Unknown algorithm:')} {alg}")
        
        # Check expiry
        if 'exp' in payload:
            import datetime
            exp = datetime.datetime.fromtimestamp(payload['exp'])
            now = datetime.datetime.now()
            if exp < now:
                print(f"  {Colors.red('[!] Token EXPIRED on:')} {exp}")
            else:
                print(f"  {Colors.green('[+] Token valid until:')} {exp}")
        else:
            print(f"  {Colors.yellow('[!] No expiry (exp) claim set!')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. REST vs GraphQL DETECTOR ---
def api_type_detector(base_url: str):
    print(f"\n{Colors.cyan('[+]')} API Type Detection: {Colors.bold(base_url)}")
    
    # Test for GraphQL
    graphql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"]
    for ep in graphql_endpoints:
        url = base_url.rstrip('/') + ep
        try:
            # GraphQL introspection query
            resp = requests.post(url, json={"query": "{__schema{types{name}}}"}, timeout=5)
            if resp.status_code == 200 and "__schema" in resp.text:
                print(f"  {Colors.green('[+] GraphQL Detected:')} {url}")
                return "GraphQL"
            elif resp.status_code == 200:
                print(f"  {Colors.yellow('[?] Possible GraphQL:')} {url}")
        except:
            pass
    
    # Test for REST
    rest_endpoints = ["/api", "/api/v1", "/rest", "/v1", "/v2"]
    for ep in rest_endpoints:
        url = base_url.rstrip('/') + ep
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in [200, 401, 403]:
                ctype = resp.headers.get('Content-Type', '')
                if 'json' in ctype:
                    print(f"  {Colors.green('[+] REST API Detected:')} {url} (JSON)")
                    return "REST"
        except:
            pass
    
    print(f"  {Colors.yellow('[-] API type not determined.')}")
    return "Unknown"

# --- 4. API AUTH CHECKER ---
def auth_checker(base_url: str):
    print(f"\n{Colors.cyan('[+]')} API Auth Checker: {Colors.bold(base_url)}")
    endpoints = ["/api/users", "/api/admin", "/api/config", "/api/data", "/api/health"]
    
    for ep in endpoints:
        url = base_url.rstrip('/') + ep
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print(f"  {Colors.red('[!] NO AUTH REQUIRED:')} {url}")
            elif resp.status_code == 401:
                print(f"  {Colors.green('[+] Protected (401):')} {url}")
            elif resp.status_code == 403:
                print(f"  {Colors.green('[+] Protected (403):')} {url}")
        except:
            pass
    print(f"  {Colors.green('[+] Auth check complete.')}")

# --- 5. HTTP METHODS TESTER ---
def http_methods_test(base_url: str):
    print(f"\n{Colors.cyan('[+]')} HTTP Methods Tester: {Colors.bold(base_url)}")
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    
    for method in methods:
        try:
            resp = requests.request(method, base_url, timeout=5, allow_redirects=False)
            if resp.status_code not in [404, 405, 501]:
                allowed = resp.headers.get('Allow', 'N/A')
                print(f"  {Colors.green('[' + method + ']')} Status: {resp.status_code} | Allow: {allowed}")
            else:
                print(f"  {Colors.dim('[' + method + ']')} Not Allowed ({resp.status_code})")
        except:
            print(f"  {Colors.dim('[' + method + ']')} Failed")

# --- 6. API RATE LIMIT TESTER ---
def rate_limit_tester(url: str, count: int = 30):
    print(f"\n{Colors.cyan('[+]')} Rate Limit Tester: {Colors.bold(url)}")
    print(f"  {Colors.dim(f'Sending {count} rapid requests...')}")
    
    statuses = {}
    start = time.time()
    for i in range(count):
        try:
            resp = requests.get(url, timeout=5)
            statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
            if resp.status_code == 429:
                print(f"  {Colors.green('[+] Rate limit hit at request #{i+1}!')}")
                break
        except:
            pass
    end = time.time()
    
    print(f"\n  {Colors.magenta('--- Status Distribution ---')}")
    for status, cnt in statuses.items():
        print(f"    {Colors.green(str(status) + ':')} {cnt}")
    print(f"  {Colors.green('Time Taken:')} {end - start:.2f} seconds")
    print(f"  {Colors.green('Requests/sec:')} {count / (end - start):.2f}")
    
    if 429 not in statuses:
        print(f"  {Colors.yellow('[!] No rate limit detected! (Potential DoS risk)')}")
    else:
        print(f"  {Colors.green('[✓] Rate limiting is active.')}")

# --- 7. SENSITIVE DATA LEAK DETECTOR ---
def sensitive_data_detector(url: str):
    print(f"\n{Colors.cyan('[+]')} Sensitive Data Leak Detector: {Colors.bold(url)}")
    try:
        resp = requests.get(url, timeout=10)
        body = resp.text.lower()
        
        patterns = {
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "API Key": r"(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}",
            "Password": r"(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{6,}",
            "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN.*PRIVATE KEY-----"
        }
        
        found = False
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found = True
                print(f"  {Colors.red('[!] EXPOSED:')} {name} ({len(matches)} occurrences)")
                for m in matches[:3]:
                    masked = str(m)[:20] + "..." if len(str(m)) > 20 else str(m)
                    print(f"    {Colors.dim(masked)}")
        
        if not found:
            print(f"  {Colors.green('[+] No obvious sensitive data in response.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_api_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 16: FUTURISTIC API SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} API Endpoint Discovery")
        print(f"  {Colors.green('2.')} JWT Token Analyzer")
        print(f"  {Colors.green('3.')} REST vs GraphQL Detector")
        print(f"  {Colors.green('4.')} API Auth Checker (No Auth Test)")
        print(f"  {Colors.green('5.')} HTTP Methods Tester")
        print(f"  {Colors.green('6.')} API Rate Limit Tester")
        print(f"  {Colors.green('7.')} Sensitive Data Leak Detector")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [APISecurity]> "))).strip()
        if choice == "0": break
        elif choice == "2":
            target = input(Colors.bold(Colors.yellow("  [?] Paste JWT Token: "))).strip()
            if target: jwt_analyzer(target)
        elif choice in ("1","3","4","5","6","7"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter API Base URL (e.g., https://api.example.com): "))).strip()
            if not target: continue
            try:
                if choice == "1": discover_endpoints(target)
                elif choice == "3": api_type_detector(target)
                elif choice == "4": auth_checker(target)
                elif choice == "5": http_methods_test(target)
                elif choice == "6": rate_limit_tester(target)
                elif choice == "7": sensitive_data_detector(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
