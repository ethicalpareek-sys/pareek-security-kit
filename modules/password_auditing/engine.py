"""Module 09: FUTURISTIC PASSWORD AUDITING ENGINE (Pure Python)."""
from __future__ import annotations
import hashlib, secrets, string, re, math, time, itertools, random, concurrent.futures
from core.banner import Colors

# --- 1. HASH IDENTIFIER ---
def identify_hash(hash_str: str):
    print(f"\n{Colors.cyan('[+]')} Identifying Hash: {Colors.bold(hash_str[:30])}...")
    h = hash_str.strip()
    length = len(h)
    
    if re.match(r'^\$2[aby]\$\d{2}\$', h):
        print(f"  {Colors.green('Type:')} bcrypt")
    elif re.match(r'^\$argon2', h):
        print(f"  {Colors.green('Type:')} Argon2")
    elif length == 32 and re.match(r'^[a-fA-F0-9]{32}$', h):
        print(f"  {Colors.green('Type:')} MD5")
    elif length == 40 and re.match(r'^[a-fA-F0-9]{40}$', h):
        print(f"  {Colors.green('Type:')} SHA-1")
    elif length == 64 and re.match(r'^[a-fA-F0-9]{64}$', h):
        print(f"  {Colors.green('Type:')} SHA-256")
    elif length == 128 and re.match(r'^[a-fA-F0-9]{128}$', h):
        print(f"  {Colors.green('Type:')} SHA-512")
    else:
        print(f"  {Colors.yellow('Type:')} Unknown or Custom Hash Format")

# --- 2. PASSWORD STRENGTH ANALYZER ---
def analyze_strength(password: str):
    print(f"\n{Colors.cyan('[+]')} Analyzing Password Strength...")
    
    length = len(password)
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 32
    
    if pool == 0:
        print(f"  {Colors.red('[!] Empty password.')}"); return
        
    entropy = length * math.log2(pool)
    
    print(f"  {Colors.green('Length:')} {length}")
    print(f"  {Colors.green('Character Pool:')} {pool}")
    print(f"  {Colors.green('Entropy:')} {entropy:.2f} bits")
    
    # Crack Time Estimation (10 Billion guesses/sec)
    combinations = pool ** length
    seconds = combinations / 1e10
    
    if seconds < 60: time_str = f"{seconds:.2f} seconds"
    elif seconds < 3600: time_str = f"{seconds/60:.2f} minutes"
    elif seconds < 86400: time_str = f"{seconds/3600:.2f} hours"
    elif seconds < 31536000: time_str = f"{seconds/86400:.2f} days"
    else: time_str = f"{seconds/31536000:.2f} years"
    
    print(f"  {Colors.magenta('Estimated Crack Time:')} {time_str} (at 10B guesses/sec)")
    
    if entropy < 40:
        print(f"  {Colors.red('[!] CRITICAL: Very Weak Password!')}")
    elif entropy < 60:
        print(f"  {Colors.yellow('[!] WARNING: Weak Password.')}")
    elif entropy < 80:
        print(f"  {Colors.green('[+] Good Password.')}")
    else:
        print(f"  {Colors.green('[✓] EXCELLENT: Very Strong Password.')}")

# --- 3. ADVANCED PASSWORD GENERATOR ---
def generate_password(length: int = 16, upper=True, lower=True, digits=True, symbols=True):
    print(f"\n{Colors.cyan('[+]')} Generating Secure Password...")
    chars = ""
    if upper: chars += string.ascii_uppercase
    if lower: chars += string.ascii_lowercase
    if digits: chars += string.digits
    if symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not chars:
        print(f"  {Colors.red('[!] No character sets selected.')}"); return
        
    password = "".join(secrets.choice(chars) for _ in range(length))
    print(f"  {Colors.green('Generated Password:')} {Colors.bold(password)}")

# --- 4. TARGETED WORDLIST GENERATOR ---
def generate_wordlist(base_word: str, year: str):
    print(f"\n{Colors.cyan('[+]')} Generating Targeted Wordlist for: {Colors.bold(base_word)}")
    variations = set()
    base = base_word.lower()
    
    # Common transformations
    variations.add(base)
    variations.add(base.capitalize())
    variations.add(base.upper())
    
    if year:
        variations.add(f"{base}{year}")
        variations.add(f"{base.capitalize()}{year}")
        variations.add(f"{base}@{year}")
        variations.add(f"{base}{year}!")
        
    # Common symbols
    for sym in ["!", "@", "#", "123", "1234", "12345"]:
        variations.add(f"{base}{sym}")
        variations.add(f"{base.capitalize()}{sym}")
        
    print(f"  {Colors.green('Generated:')} {len(variations)} variations.")
    print(f"  {Colors.magenta('--- Top 15 Words ---')}")
    for w in list(variations)[:15]:
        print(f"    {Colors.dim(w)}")
        
    if not os.path.exists("wordlists"): os.makedirs("wordlists")
    filename = f"wordlists/{base}_wordlist.txt"
    with open(filename, "w") as f:
        for w in variations: f.write(w + "\n")
    print(f"  {Colors.green('[+] Saved to:')} {filename}")

# --- 5. MULTI-THREADED HASH CRACKER ---
def crack_hash(target_hash: str, algorithm: str, wordlist_path: str):
    print(f"\n{Colors.cyan('[+]')} Starting Dictionary Attack...")
    print(f"  {Colors.dim(f'Algorithm: {algorithm} | Target: {target_hash[:20]}...')}")
    
    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"  {Colors.red('[!] Wordlist not found:')} {wordlist_path}"); return
        
    print(f"  {Colors.green('Loaded')} {len(words)} {Colors.green('words. Starting threads...')}")
    
    def check_word(word):
        if algorithm == "md5":
            h = hashlib.md5(word.encode()).hexdigest()
        elif algorithm == "sha1":
            h = hashlib.sha1(word.encode()).hexdigest()
        elif algorithm == "sha256":
            h = hashlib.sha256(word.encode()).hexdigest()
        else:
            return None
        return word if h == target_hash else None

    found = False
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_word, w): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(f"\n  {Colors.green('[+] PASSWORD FOUND!')} -> {Colors.bold(res)}")
                found = True
                break
                
    end = time.time()
    if not found:
        print(f"\n  {Colors.red('[-] Password not found in wordlist.')}")
    print(f"  {Colors.dim(f'Time taken: {end - start:.2f} seconds')}")

# --- 6. PASSPHRASE GENERATOR ---
def generate_passphrase(word_count: int = 4):
    print(f"\n{Colors.cyan('[+]')} Generating Memorable Passphrase...")
    words = ["cyber", "horse", "battery", "staple", "correct", "security", "network", "python", "shield", "matrix", "phoenix", "quantum", "galaxy", "dragon", "shadow", "cipher"]
    passphrase = "-".join(secrets.choice(words) for _ in range(word_count))
    print(f"  {Colors.green('Passphrase:')} {Colors.bold(passphrase)}")
    print(f"  {Colors.dim('Tip: Add a number or symbol to make it even stronger.')}")

# --- MENU ---
def run_password_auditing():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 09: FUTURISTIC PASSWORD AUDITING')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Hash Identifier")
        print(f"  {Colors.green('2.')} Password Strength Analyzer")
        print(f"  {Colors.green('3.')} Advanced Password Generator")
        print(f"  {Colors.green('4.')} Targeted Wordlist Generator")
        print(f"  {Colors.green('5.')} Multi-Threaded Hash Cracker (Local)")
        print(f"  {Colors.green('6.')} Memorable Passphrase Generator")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [PasswordAudit]> "))).strip()
        if choice == "0": break
        elif choice == "1":
            h = input(Colors.bold(Colors.yellow("  [?] Enter Hash: "))).strip()
            if h: identify_hash(h)
        elif choice == "2":
            p = input(Colors.bold(Colors.yellow("  [?] Enter Password to test: "))).strip()
            if p: analyze_strength(p)
        elif choice == "3":
            length = input(Colors.bold(Colors.yellow("  [?] Enter Length (default 16): "))).strip()
            generate_password(int(length) if length.isdigit() else 16)
        elif choice == "4":
            base = input(Colors.bold(Colors.yellow("  [?] Enter Base Word (e.g., name): "))).strip()
            year = input(Colors.bold(Colors.yellow("  [?] Enter Year (optional): "))).strip()
            if base: generate_wordlist(base, year)
        elif choice == "5":
            h = input(Colors.bold(Colors.yellow("  [?] Enter Target Hash: "))).strip()
            alg = input(Colors.bold(Colors.yellow("  [?] Algorithm (md5/sha1/sha256): "))).strip().lower()
            wl = input(Colors.bold(Colors.yellow("  [?] Wordlist Path (e.g., wordlists/bharat_wordlist.txt): "))).strip()
            if h and alg and wl: crack_hash(h, alg, wl)
        elif choice == "6":
            wc = input(Colors.bold(Colors.yellow("  [?] Number of words (default 4): "))).strip()
            generate_passphrase(int(wc) if wc.isdigit() else 4)
        else: print(f"  {Colors.red('[!] Invalid option.')}")
