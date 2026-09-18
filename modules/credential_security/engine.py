"""Module 10: FUTURISTIC CREDENTIAL SECURITY ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, re, math, hashlib, secrets, base64, json, requests
from core.banner import Colors

# --- 1. SMART SECRET SCANNER (Regex + Heuristics) ---
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Generic Password": r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]{6,})"
}

def scan_file_for_secrets(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Scanning File for Secrets: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            
        found = False
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                found = True
                # Mask the secret for safety
                secret = match.group(0)
                masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:] if len(secret) > 8 else "***"
                print(f"  {Colors.red('[!] VULNERABLE:')} {name} found -> {masked}")
                
        if not found:
            print(f"  {Colors.green('[+] No obvious secrets found.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. ENTROPY ANALYZER ---
def calculate_entropy(data: str):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def entropy_scan(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Entropy Analysis on: {Colors.bold(filepath)}")
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if len(line) > 15:
                    ent = calculate_entropy(line)
                    if ent > 4.5: # High entropy threshold
                        print(f"  {Colors.yellow('[?] High Entropy String:')} {line[:30]}... (Entropy: {ent:.2f})")
        print(f"  {Colors.green('[+] Entropy scan complete.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. ENVIRONMENT AUDITOR ---
def audit_environment():
    print(f"\n{Colors.cyan('[+]')} Auditing Environment Variables...")
    sensitive_keywords = ["PASS", "SECRET", "TOKEN", "KEY", "API", "CRED"]
    found = False
    for key, value in os.environ.items():
        if any(k in key.upper() for k in sensitive_keywords):
            if value and len(value) > 4:
                found = True
                masked = value[:3] + "*" * (len(value) - 6) + value[-3:] if len(value) > 6 else "***"
                print(f"  {Colors.yellow('[!] Exposed:')} {key} = {masked}")
    if not found:
        print(f"  {Colors.green('[+] No sensitive environment variables found.')}")

# --- 4. PWNED PASSWORD CHECKER (k-Anonymity) ---
def check_pwned_password(password: str):
    print(f"\n{Colors.cyan('[+]')} Checking Password against Data Breaches...")
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if resp.status_code == 200:
            hashes = (line.split(':') for line in resp.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    print(f"  {Colors.red('[!] VULNERABLE:')} Password found in {count} data breaches!")
                    return
            print(f"  {Colors.green('[+] Good news! Password not found in known breaches.')}")
        else:
            print(f"  {Colors.yellow('[!] API Error:')} Status {resp.status_code}")
    except Exception as e:
        print(f"  {Colors.red('[!] Connection Error:')} {e}")

# --- 5. LOCAL ENCRYPTED VAULT ---
def encrypt_vault(data: str, master_key: str):
    key = hashlib.sha256(master_key.encode()).digest()
    encrypted = base64.b64encode(bytes([data.encode()[i] ^ key[i % len(key)] for i in range(len(data))])).decode()
    return encrypted

def decrypt_vault(encrypted_data: str, master_key: str):
    key = hashlib.sha256(master_key.encode()).digest()
    decoded = base64.b64decode(encrypted_data.encode())
    decrypted = bytes([decoded[i] ^ key[i % len(key)] for i in range(len(decoded))]).decode()
    return decrypted

def vault_manager():
    vault_file = "reports/vault.dat"
    if not os.path.exists("reports"): os.makedirs("reports")
    
    print(f"\n{Colors.cyan('[+]')} Local Encrypted Vault")
    print(f"  {Colors.green('1.')} Store New Credential")
    print(f"  {Colors.green('2.')} Retrieve Credential")
    choice = input(Colors.bold(Colors.cyan("  [Vault]> "))).strip()
    
    if choice == "1":
        service = input(Colors.bold(Colors.yellow("  [?] Service Name (e.g., Gmail): "))).strip()
        user = input(Colors.bold(Colors.yellow("  [?] Username: "))).strip()
        pwd = input(Colors.bold(Colors.yellow("  [?] Password: "))).strip()
        master = input(Colors.bold(Colors.yellow("  [?] Master Key (to encrypt): "))).strip()
        
        if service and user and pwd and master:
            data = f"{service}:{user}:{pwd}"
            encrypted = encrypt_vault(data, master)
            with open(vault_file, "a") as f:
                f.write(encrypted + "\n")
            print(f"  {Colors.green('[+] Credential securely saved!')}")
            
    elif choice == "2":
        master = input(Colors.bold(Colors.yellow("  [?] Enter Master Key to decrypt: "))).strip()
        if os.path.exists(vault_file):
            with open(vault_file, "r") as f:
                lines = f.readlines()
            print(f"\n  {Colors.magenta('--- Decrypted Credentials ---')}")
            for line in lines:
                try:
                    decrypted = decrypt_vault(line.strip(), master)
                    print(f"  {Colors.green('[+]')} {decrypted}")
                except:
                    print(f"  {Colors.red('[!] Failed to decrypt. Wrong master key?')}")
        else:
            print(f"  {Colors.yellow('[-] No vault file found.')}")

# --- 6. GIT CONFIG AUDITOR ---
def audit_git_config():
    print(f"\n{Colors.cyan('[+]')} Auditing Git Config...")
    git_config = os.path.join(".git", "config")
    if os.path.exists(git_config):
        with open(git_config, "r") as f:
            content = f.read()
        if "password" in content.lower() or "token" in content.lower():
            print(f"  {Colors.red('[!] VULNERABLE: Credentials found in .git/config!')}")
        else:
            print(f"  {Colors.green('[+] Git config looks clean.')}")
    else:
        print(f"  {Colors.yellow('[-] No .git/config found in current directory.')}")

# --- MENU ---
def run_credential_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 10: FUTURISTIC CREDENTIAL SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Smart Secret Scanner (Files)")
        print(f"  {Colors.green('2.')} Entropy Analyzer (Find Random Strings)")
        print(f"  {Colors.green('3.')} Environment Auditor")
        print(f"  {Colors.green('4.')} Pwned Password Checker (HIBP)")
        print(f"  {Colors.green('5.')} Local Encrypted Vault")
        print(f"  {Colors.green('6.')} Git Config Auditor")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [CredSecurity]> "))).strip()
        if choice == "0": break
        elif choice == "1":
            target = input(Colors.bold(Colors.yellow("  [?] Enter file path to scan (e.g., config.txt): "))).strip()
            if target: scan_file_for_secrets(target)
        elif choice == "2":
            target = input(Colors.bold(Colors.yellow("  [?] Enter file path: "))).strip()
            if target: entropy_scan(target)
        elif choice == "3": audit_environment()
        elif choice == "4":
            pwd = input(Colors.bold(Colors.yellow("  [?] Enter password to check: "))).strip()
            if pwd: check_pwned_password(pwd)
        elif choice == "5": vault_manager()
        elif choice == "6": audit_git_config()
        else: print(f"  {Colors.red('[!] Invalid option.')}")
