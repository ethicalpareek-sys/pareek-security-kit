"""Module 17: FUTURISTIC FILE SECURITY ENGINE (Pure Python)."""
from __future__ import annotations
import os, sys, hashlib, math, json, time, re, stat, mimetypes, secrets
from datetime import datetime
from core.banner import Colors

# --- 1. MULTI-HASH CALCULATOR ---
def multi_hash(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Multi-Hash Calculator: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    try:
        hashes = {
            'MD5': hashlib.md5(),
            'SHA-1': hashlib.sha1(),
            'SHA-256': hashlib.sha256(),
            'SHA-512': hashlib.sha512(),
            'BLAKE2b': hashlib.blake2b()
        }
        size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                for h in hashes.values():
                    h.update(chunk)
        
        print(f"  {Colors.green('File Size:')} {size:,} bytes")
        print(f"  {Colors.magenta('--- Hashes ---')}")
        for name, h in hashes.items():
            print(f"  {Colors.green(name + ':')} {h.hexdigest()}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. FILE METADATA INSPECTOR ---
def file_metadata(filepath: str):
    print(f"\n{Colors.cyan('[+]')} File Metadata Inspector: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    try:
        s = os.stat(filepath)
        print(f"  {Colors.green('Name:')} {os.path.basename(filepath)}")
        print(f"  {Colors.green('Full Path:')} {os.path.abspath(filepath)}")
        print(f"  {Colors.green('Size:')} {s.st_size:,} bytes ({s.st_size/1024:.2f} KB)")
        print(f"  {Colors.green('Created:')} {datetime.fromtimestamp(s.st_ctime)}")
        print(f"  {Colors.green('Modified:')} {datetime.fromtimestamp(s.st_mtime)}")
        print(f"  {Colors.green('Accessed:')} {datetime.fromtimestamp(s.st_atime)}")
        print(f"  {Colors.green('Permissions:')} {stat.filemode(s.st_mode)}")
        print(f"  {Colors.green('Owner UID:')} {s.st_uid} | {Colors.green('GID:')} {s.st_gid}")
        
        mime, _ = mimetypes.guess_type(filepath)
        print(f"  {Colors.green('MIME Type:')} {mime or 'Unknown'}")
        
        # Hidden file check
        if os.path.basename(filepath).startswith('.'):
            print(f"  {Colors.yellow('[!] This is a HIDDEN file.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. MAGIC BYTES DETECTOR ---
MAGIC_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'GIF87a': 'GIF Image (87a)',
    b'GIF89a': 'GIF Image (89a)',
    b'%PDF': 'PDF Document',
    b'PK\x03\x04': 'ZIP Archive / Office File',
    b'Rar!\x1a\x07': 'RAR Archive',
    b'7z\xbc\xaf\x27\x1c': '7z Archive',
    b'\x1f\x8b': 'GZIP Compressed',
    b'MZ': 'Windows Executable (EXE/DLL)',
    b'\x7fELF': 'Linux Executable (ELF)',
    b'\xca\xfe\xba\xbe': 'Java Class File',
    b'#!': 'Script File (Shebang)',
    b'<?xml': 'XML Document',
    b'{\n': 'JSON (Possible)',
    b'RIFF': 'RIFF (WAV/AVI)',
    b'\x00\x00\x00\x18ftyp': 'MP4 Video',
    b'ID3': 'MP3 Audio',
    b'\x42\x5a\x68': 'BZIP2 Archive',
    b'\xfd7zXZ\x00': 'XZ Archive',
}

def magic_bytes_detector(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Magic Bytes Detector: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        detected = "Unknown"
        for sig, name in MAGIC_SIGNATURES.items():
            if header.startswith(sig):
                detected = name
                break
        
        actual_ext = os.path.splitext(filepath)[1].lower()
        print(f"  {Colors.green('Header (Hex):')} {header.hex()}")
        print(f"  {Colors.green('Detected Type:')} {detected}")
        print(f"  {Colors.green('File Extension:')} {actual_ext}")
        
        # Extension spoofing check
        spoof_map = {
            'PNG Image': ['.png'], 'JPEG Image': ['.jpg', '.jpeg'],
            'PDF Document': ['.pdf'], 'ZIP Archive / Office File': ['.zip', '.docx', '.xlsx', '.pptx', '.apk'],
            'Windows Executable (EXE/DLL)': ['.exe', '.dll'], 
            'Linux Executable (ELF)': ['.elf', '.so', ''],
            'GZIP Compressed': ['.gz'], 'RAR Archive': ['.rar']
        }
        
        if detected in spoof_map:
            if actual_ext not in spoof_map[detected]:
                print(f"  {Colors.red('[!] SUSPICIOUS: Extension does NOT match file type!')}")
                print(f"  {Colors.red('    Possible disguised malware!')}")
            else:
                print(f"  {Colors.green('[✓] Extension matches detected type.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. SHANNON ENTROPY ANALYZER ---
def calculate_entropy(data: bytes):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def entropy_analyzer(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Shannon Entropy Analyzer: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if not data:
            print(f"  {Colors.yellow('[!] Empty file.')}"); return
        
        entropy = calculate_entropy(data)
        print(f"  {Colors.green('File Size:')} {len(data):,} bytes")
        print(f"  {Colors.green('Entropy:')} {entropy:.4f} / 8.0 bits per byte")
        
        # Interpretation
        print(f"\n  {Colors.magenta('--- Interpretation ---')}")
        if entropy < 1.0:
            print(f"  {Colors.dim('Very Low: Mostly zeros / uniform data')}")
        elif entropy < 3.0:
            print(f"  {Colors.green('Low: Plain text or structured data')}")
        elif entropy < 5.0:
            print(f"  {Colors.green('Medium: Source code, HTML, compiled binaries')}")
        elif entropy < 7.0:
            print(f"  {Colors.yellow('High: Compressed or encrypted data')}")
        else:
            print(f"  {Colors.red('Very High: Likely encrypted or packed (Malware indicator!)')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. MALWARE PATTERN SCANNER ---
def malware_pattern_scan(filepath: str):
    print(f"\n{Colors.cyan('[+]')} Malware Pattern Scanner: {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    
    patterns = {
        "URLs": r"https?://[a-zA-Z0-9./?=_-]+",
        "IP Addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "Email Addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Shell Commands": r"(rm -rf|chmod \+x|curl|wget|nc |netcat|bash -i|/bin/sh)",
        "Base64 Blobs": r"[A-Za-z0-9+/]{100,}={0,2}",
        "Eval/Exec Calls": r"(eval|exec|system|popen|Runtime\.exec)\s*\(",
        "Crypto Wallets": r"(bitcoin|ethereum|wallet)[\s:=]+[a-zA-Z0-9]{26,}",
    }
    
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(10 * 1024 * 1024)  # 10 MB max
        
        try:
            content = raw.decode('utf-8', errors='ignore')
        except:
            content = str(raw)
        
        total_found = 0
        for name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                total_found += len(matches)
                print(f"\n  {Colors.red('[!] ' + name + ':')} {len(matches)} found")
                for m in matches[:5]:
                    m_str = m if isinstance(m, str) else m[0]
                    masked = m_str[:60] + "..." if len(m_str) > 60 else m_str
                    print(f"    {Colors.dim(masked)}")
        
        if total_found == 0:
            print(f"  {Colors.green('[+] No suspicious patterns detected.')}")
        else:
            print(f"\n  {Colors.yellow('Total suspicious items:')} {total_found}")
            print(f"  {Colors.yellow('Manual review recommended.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 6. FILE INTEGRITY MONITOR ---
def create_baseline(directory: str, output_file: str = "reports/integrity_baseline.json"):
    print(f"\n{Colors.cyan('[+]')} Creating Integrity Baseline: {Colors.bold(directory)}")
    if not os.path.exists("reports"): os.makedirs("reports")
    if not os.path.isdir(directory):
        print(f"  {Colors.red('[!] Directory not found.')}"); return
    
    baseline = {}
    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, 'rb') as file:
                    h = hashlib.sha256(file.read()).hexdigest()
                baseline[path] = {'hash': h, 'size': os.path.getsize(path), 'mtime': os.path.getmtime(path)}
            except:
                pass
    
    with open(output_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    print(f"  {Colors.green('[+] Baseline created with')} {len(baseline)} {Colors.green('files.')}")
    print(f"  {Colors.green('Saved to:')} {output_file}")

def verify_integrity(baseline_file: str = "reports/integrity_baseline.json"):
    print(f"\n{Colors.cyan('[+]')} Verifying File Integrity...")
    if not os.path.exists(baseline_file):
        print(f"  {Colors.red('[!] Baseline file not found. Create one first.')}"); return
    try:
        with open(baseline_file) as f:
            baseline = json.load(f)
        
        changed, missing, new = [], [], []
        current_paths = set()
        
        for path, info in baseline.items():
            if not os.path.exists(path):
                missing.append(path); continue
            current_paths.add(path)
            with open(path, 'rb') as file:
                h = hashlib.sha256(file.read()).hexdigest()
            if h != info['hash']:
                changed.append(path)
        
        for root, _, files in os.walk(os.path.dirname(list(baseline.keys())[0]) if baseline else "."):
            for f in files:
                p = os.path.join(root, f)
                if p not in current_paths:
                    new.append(p)
        
        print(f"\n  {Colors.magenta('--- Integrity Report ---')}")
        print(f"  {Colors.green('Unchanged:')} {len(baseline) - len(changed) - len(missing)}")
        print(f"  {Colors.red('Modified:')} {len(changed)}")
        print(f"  {Colors.red('Missing:')} {len(missing)}")
        print(f"  {Colors.yellow('New Files:')} {len(new)}")
        
        if changed:
            print(f"\n  {Colors.red('--- Modified Files ---')}")
            for p in changed[:10]: print(f"    {Colors.dim(p)}")
        if missing:
            print(f"\n  {Colors.red('--- Missing Files ---')}")
            for p in missing[:10]: print(f"    {Colors.dim(p)}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 7. SECURE FILE SHREDDER (DoD 5220.22-M 3-Pass) ---
def secure_shred(filepath: str, passes: int = 3):
    print(f"\n{Colors.cyan('[+]')} Secure File Shredder (DoD 5220.22-M): {Colors.bold(filepath)}")
    if not os.path.exists(filepath):
        print(f"  {Colors.red('[!] File not found.')}"); return
    
    confirm = input(Colors.bold(Colors.red("  [!] This will PERMANENTLY delete the file. Type 'SHRED' to confirm: "))).strip()
    if confirm != "SHRED":
        print(f"  {Colors.yellow('[-] Shred cancelled.')}"); return
    
    try:
        size = os.path.getsize(filepath)
        print(f"  {Colors.green('File Size:')} {size:,} bytes")
        print(f"  {Colors.green('Passes:')} {passes}")
        
        for p in range(passes):
            with open(filepath, 'wb') as f:
                # Pass 1: All 0x00
                if p == 0:
                    print(f"  {Colors.dim(f'Pass {p+1}: Overwriting with 0x00...')}")
                    f.write(b'\x00' * size)
                # Pass 2: All 0xFF
                elif p == 1:
                    print(f"  {Colors.dim(f'Pass {p+1}: Overwriting with 0xFF...')}")
                    f.write(b'\xFF' * size)
                # Pass 3: Random
                else:
                    print(f"  {Colors.dim(f'Pass {p+1}: Overwriting with random data...')}")
                    chunk_size = 65536
                    written = 0
                    while written < size:
                        chunk = secrets.token_bytes(min(chunk_size, size - written))
                        f.write(chunk)
                        written += len(chunk)
                f.flush()
                os.fsync(f.fileno())
        
        # Rename before deletion
        os.rename(filepath, filepath + ".shredded")
        os.remove(filepath + ".shredded")
        print(f"  {Colors.green('[+] File securely shredded!')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_file_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 17: FUTURISTIC FILE SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Multi-Hash Calculator (MD5, SHA1/256/512)")
        print(f"  {Colors.green('2.')} File Metadata Inspector")
        print(f"  {Colors.green('3.')} Magic Bytes Detector (True File Type)")
        print(f"  {Colors.green('4.')} Shannon Entropy Analyzer (Malware Detect)")
        print(f"  {Colors.green('5.')} Malware Pattern Scanner")
        print(f"  {Colors.green('6.')} File Integrity Monitor (Baseline)")
        print(f"  {Colors.green('7.')} Secure File Shredder (DoD 3-Pass)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [FileSecurity]> "))).strip()
        if choice == "0": break
        elif choice == "6":
            print(f"  {Colors.green('1.')} Create Baseline")
            print(f"  {Colors.green('2.')} Verify Integrity")
            sub = input(Colors.bold(Colors.cyan("  [Integrity]> "))).strip()
            if sub == "1":
                d = input(Colors.bold(Colors.yellow("  [?] Directory: "))).strip()
                if d: create_baseline(d)
            elif sub == "2": verify_integrity()
        elif choice in ("1","2","3","4","5","7"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter File Path: "))).strip()
            if not target: continue
            try:
                if choice == "1": multi_hash(target)
                elif choice == "2": file_metadata(target)
                elif choice == "3": magic_bytes_detector(target)
                elif choice == "4": entropy_analyzer(target)
                elif choice == "5": malware_pattern_scan(target)
                elif choice == "7": secure_shred(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
