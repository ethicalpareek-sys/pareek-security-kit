"""Module 06: FUTURISTIC NETWORK DIAGNOSTICS ENGINE."""
from __future__ import annotations
import os, sys, subprocess, socket, time, requests, concurrent.futures
from core.banner import Colors

# --- 1. ADVANCED ICMP PING ---
def icmp_ping(target: str, count: int = 4, size: int = 56):
    print(f"\n{Colors.cyan('[+]')} Advanced ICMP Ping: {Colors.bold(target)}")
    print(f"  {Colors.dim(f'Sending {count} packets of {size} bytes...')}")
    try:
        command = ["ping", "-c", str(count), "-s", str(size), "-W", "2", target]
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True, timeout=count*3)
        end_time = time.time()
        
        if result.returncode == 0:
            print(f"  {Colors.green('--- Ping Statistics ---')}")
            for line in result.stdout.splitlines()[-4:]:
                print(f"  {Colors.dim(line)}")
            print(f"  {Colors.green('Total Time:')} {end_time - start_time:.2f} seconds")
        else:
            print(f"  {Colors.red('[!] Ping failed:')} {result.stderr.strip()}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. TCP PING ---
def tcp_ping(target: str, port: int, count: int = 4):
    print(f"\n{Colors.cyan('[+]')} TCP Ping to {Colors.bold(target)}:{port} (Count: {count})")
    times = []
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        start = time.time()
        try:
            s.connect((target, port))
            end = time.time()
            latency = (end - start) * 1000
            times.append(latency)
            print(f"  {Colors.green(f'[+] Packet {i+1}:')} Connected in {latency:.2f} ms")
        except Exception as e:
            print(f"  {Colors.red(f'[!] Packet {i+1}: Failed - {e}')}")
        finally:
            s.close()
        time.sleep(1)
        
    if times:
        print(f"\n  {Colors.magenta('--- TCP Ping Stats ---')}")
        print(f"  {Colors.green('Min:')} {min(times):.2f} ms")
        print(f"  {Colors.green('Max:')} {max(times):.2f} ms")
        print(f"  {Colors.green('Avg:')} {sum(times)/len(times):.2f} ms")

# --- 3. TRACEROUTE ---
def run_traceroute(target: str):
    print(f"\n{Colors.cyan('[+]')} Traceroute to: {Colors.bold(target)}")
    if not shutil.which("traceroute"):
        print(f"  {Colors.yellow('[!] traceroute not found. Install: pkg install traceroute')}"); return
    try:
        print(f"  {Colors.dim('Tracing route (this may take a moment)...')}")
        subprocess.run(["traceroute", "-m", "20", target])
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. HTTP/WEB LATENCY TESTER ---
def web_latency(url: str):
    print(f"\n{Colors.cyan('[+]')} Web Latency Test: {Colors.bold(url)}")
    try:
        if not url.startswith(("http://", "https://")): url = "https://" + url
        start = time.time()
        resp = requests.get(url, timeout=10, allow_redirects=True)
        end = time.time()
        latency = (end - start) * 1000
        
        print(f"  {Colors.green('Status Code:')} {resp.status_code}")
        print(f"  {Colors.green('Response Time:')} {latency:.2f} ms")
        print(f"  {Colors.green('Server:')} {resp.headers.get('Server', 'Unknown')}")
        print(f"  {Colors.green('Content Length:')} {len(resp.content)} bytes")
        
        if latency < 300:
            print(f"  {Colors.green('[✓] Fast connection!')}")
        elif latency < 1000:
            print(f"  {Colors.yellow('[~] Moderate connection.')}")
        else:
            print(f"  {Colors.red('[!] Slow connection!')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. REVERSE DNS LOOKUP ---
def reverse_dns(ip: str):
    print(f"\n{Colors.cyan('[+]')} Reverse DNS Lookup for: {Colors.bold(ip)}")
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        print(f"  {Colors.green('Hostname:')} {hostname}")
        if aliases:
            print(f"  {Colors.green('Aliases:')} {', '.join(aliases)}")
    except socket.herror:
        print(f"  {Colors.yellow('[-] No reverse DNS record found for this IP.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 6. MTU DISCOVERY ---
def mtu_discovery(target: str):
    print(f"\n{Colors.cyan('[+]')} MTU Discovery for: {Colors.bold(target)}")
    print(f"  {Colors.dim('Finding maximum packet size...')}")
    low, high = 1000, 1500
    best_mtu = 0
    try:
        while low <= high:
            mid = (low + high) // 2
            command = ["ping", "-c", "1", "-s", str(mid), "-M", "do", "-W", "2", target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                best_mtu = mid
                low = mid + 1
            else:
                high = mid - 1
        if best_mtu > 0:
            print(f"  {Colors.green('[+] MTU Found:')} {best_mtu + 28} bytes (Payload: {best_mtu})")
        else:
            print(f"  {Colors.yellow('[-] Could not determine MTU. Target might be blocking ICMP.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_network_diagnostics():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 06: FUTURISTIC NETWORK DIAGNOSTICS')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Advanced ICMP Ping")
        print(f"  {Colors.green('2.')} TCP Ping (Bypass ICMP Block)")
        print(f"  {Colors.green('3.')} Traceroute (Network Path)")
        print(f"  {Colors.green('4.')} HTTP/Web Latency Tester")
        print(f"  {Colors.green('5.')} Reverse DNS Lookup")
        print(f"  {Colors.green('6.')} MTU Discovery (Network Tuning)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [NetDiagnostics]> "))).strip()
        if choice == "0": break
        elif choice in ("1","2","3","4","5","6"):
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target (IP/Domain/URL): "))).strip()
            if not target: continue
            try:
                if choice == "1": icmp_ping(target)
                elif choice == "2":
                    port = input(Colors.bold(Colors.yellow("  [?] Enter Port (e.g., 80, 443): "))).strip()
                    if port.isdigit(): tcp_ping(target, int(port))
                elif choice == "3": run_traceroute(target)
                elif choice == "4": web_latency(target)
                elif choice == "5": reverse_dns(target)
                elif choice == "6": mtu_discovery(target)
            except Exception as e: print(f"  {Colors.red('[!] Error:')} {e}")
        else: print(f"  {Colors.red('[!] Invalid option.')}")
