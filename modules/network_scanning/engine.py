"""Module 02: FUTURISTIC NETWORK SCANNING ENGINE."""
from __future__ import annotations
import socket, subprocess, shutil, sys, concurrent.futures, os, re, ipaddress
from core.banner import Colors

# --- 1. NETWORK INTERFACE INFO ---
def get_network_info():
    print(f"\n{Colors.cyan('[+]')} Local Network Interface Info:")
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"  {Colors.green('Hostname:')} {hostname}")
        print(f"  {Colors.green('Local IP:')} {local_ip}")
        # Gateway and MAC (Termux specific)
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[1] == '00000000':
                        print(f"  {Colors.green('Gateway:')} {socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])}")
                        break
        mac = subprocess.run(["cat", "/sys/class/net/wlan0/address"], capture_output=True, text=True)
        if mac.returncode == 0:
            print(f"  {Colors.green('MAC Address:')} {mac.stdout.strip()}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 2. FAST PING SWEEP ---
def ping_host(ip):
    param = '-c' if os.name != 'nt' else '-n'
    command = ['ping', param, '1', '-W', '1', str(ip)]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if result.returncode == 0:
            return str(ip)
    except:
        pass
    return None

def ping_sweep(subnet: str):
    print(f"\n{Colors.cyan('[+]')} Fast Ping Sweep on: {Colors.bold(subnet)}")
    print(f"  {Colors.dim('Scanning for live hosts (This may take a moment)...')}")
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())[:254] # Limit to 254 hosts
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, str(ip)): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    alive.append(res)
                    print(f"  {Colors.green('[ALIVE]')} {res}")
        print(f"\n  {Colors.magenta('Total Hosts Alive:')} {len(alive)}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. ADVANCED PORT SCANNER WITH BANNER GRABBING ---
def scan_port_banner(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = "Unknown Service"
            try:
                s.send(b'HEAD / HTTP/1.1\r\n\r\n')
                banner = s.recv(1024).decode(errors='ignore').strip().split('\n')[0][:50]
            except:
                pass
            s.close()
            return port, banner
        s.close()
    except:
        pass
    return None

def advanced_port_scan(target: str, ports: str):
    print(f"\n{Colors.cyan('[+]')} Advanced Port Scanning: {Colors.bold(target)}")
    try:
        ip = socket.gethostbyname(target)
        port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port_banner, ip, p): p for p in port_list}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res[0])
                    print(f"  {Colors.green('[OPEN]')} Port {res[0]} -> {Colors.dim(res[1])}")
        if not open_ports: print(f"  {Colors.yellow('[-] No open ports found.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. NMAP INTEGRATION ---
def nmap_scan(target: str, scan_type: str):
    print(f"\n{Colors.cyan('[+]')} Nmap Scan ({scan_type}) on: {Colors.bold(target)}")
    if not shutil.which("nmap"):
        print(f"  {Colors.yellow('[!] nmap not found. Install: pkg install nmap')}"); return
    try:
        if scan_type == "fast":
            subprocess.run(["nmap", "-F", "-T4", target])
        elif scan_type == "os":
            subprocess.run(["nmap", "-O", "-T4", target])
        elif scan_type == "version":
            subprocess.run(["nmap", "-sV", "-T4", target])
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. MAC ADDRESS LOOKUP ---
def mac_lookup(ip: str):
    print(f"\n{Colors.cyan('[+]')} MAC Address Lookup for: {Colors.bold(ip)}")
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            print(f"  {Colors.green('[+] Found:')} {result.stdout.strip()}")
        else:
            print(f"  {Colors.yellow('[-] MAC not found in ARP table. Host might be down.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_network_scanning():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 02: FUTURISTIC NETWORK SCANNING')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Local Network Interface Info")
        print(f"  {Colors.green('2.')} Fast Ping Sweep (Find Live Hosts)")
        print(f"  {Colors.green('3.')} Advanced Port Scanner (Banner Grabbing)")
        print(f"  {Colors.green('4.')} Nmap Integration (Fast, OS, Version)")
        print(f"  {Colors.green('5.')} MAC Address Lookup (Local ARP)")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [NetScanning]> "))).strip()
        if choice == "0": break
        elif choice == "1": get_network_info()
        elif choice == "2":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Subnet (e.g., 192.168.1.0/24): "))).strip()
            if target: ping_sweep(target)
        elif choice == "3":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target IP/Domain: "))).strip()
            ports = input(Colors.bold(Colors.yellow("  [?] Enter Ports (comma separated, e.g., 21,22,80,443): "))).strip()
            if target and ports: advanced_port_scan(target, ports)
        elif choice == "4":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target IP/Domain: "))).strip()
            if target:
                print(f"  {Colors.green('1.')} Fast Scan")
                print(f"  {Colors.green('2.')} OS Detection")
                print(f"  {Colors.green('3.')} Version Detection")
                st = input(Colors.bold(Colors.cyan("  [Nmap Type]> "))).strip()
                if st == "1": nmap_scan(target, "fast")
                elif st == "2": nmap_scan(target, "os")
                elif st == "3": nmap_scan(target, "version")
        elif choice == "5":
            target = input(Colors.bold(Colors.yellow("  [?] Enter Target IP: "))).strip()
            if target: mac_lookup(target)
        else: print(f"  {Colors.red('[!] Invalid option.')}")
