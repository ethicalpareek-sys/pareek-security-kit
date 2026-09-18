"""Module 08: FUTURISTIC WIRELESS SECURITY ENGINE."""
from __future__ import annotations
import os, sys, json, time, subprocess, re, shutil
from core.banner import Colors

# --- 1. ADVANCED WI-FI SCANNER ---
def scan_wifi_networks():
    print(f"\n{Colors.cyan('[+]')} Scanning Wi-Fi Networks (Termux API)...")
    if not shutil.which("termux-wifi-scaninfo"):
        print(f"  {Colors.red('[!] termux-api not found. Install: pkg install termux-api')}")
        print(f"  {Colors.yellow('    Also install Termux:API app from F-Droid.')}")
        return []
    try:
        print(f"  {Colors.dim('Scanning... please wait (this takes a few seconds).')}")
        result = subprocess.run(["termux-wifi-scaninfo"], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            print(f"  {Colors.red('[!] Scan failed:')} {result.stderr.strip()}")
            return []
        
        networks = json.loads(result.stdout)
        if not networks:
            print(f"  {Colors.yellow('[-] No networks found. Make sure Wi-Fi is ON.')}")
            return []
            
        print(f"\n  {Colors.green('Found')} {len(networks)} {Colors.green('networks:')}")
        print(f"  {Colors.magenta('─' * 70)}")
        for net in networks:
            ssid = net.get('ssid', 'Hidden')
            bssid = net.get('bssid', 'Unknown')
            freq = net.get('frequency', 0)
            rssi = net.get('rssi', -100)
            cap = net.get('capabilities', 'Unknown')
            
            # Security Grade
            if 'WPA3' in cap: sec = f"{Colors.green('WPA3 (Strong)')}"
            elif 'WPA2' in cap: sec = f"{Colors.green('WPA2 (Good)')}"
            elif 'WPA' in cap: sec = f"{Colors.yellow('WPA (Weak)')}"
            elif 'WEP' in cap: sec = f"{Colors.red('WEP (Broken!)')}"
            else: sec = f"{Colors.red('OPEN (Danger!)')}"
            
            print(f"  {Colors.bold('SSID:')} {ssid:<20} {Colors.bold('BSSID:')} {bssid}")
            print(f"    {Colors.dim(f'Freq: {freq} MHz | Signal: {rssi} dBm | Security: {sec}')}")
            
        return networks
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")
        return []

# --- 2. MAC OUI LOOKUP ---
def mac_oui_lookup(bssid: str):
    print(f"\n{Colors.cyan('[+]')} MAC OUI Vendor Lookup: {Colors.bold(bssid)}")
    try:
        clean_mac = re.sub(r'[^A-Fa-f0-9]', '', bssid)[:6]
        if len(clean_mac) != 6:
            print(f"  {Colors.red('[!] Invalid MAC address.')}"); return
        resp = requests.get(f"https://api.macvendors.com/{clean_mac}", timeout=5)
        if resp.status_code == 200:
            print(f"  {Colors.green('Vendor:')} {resp.text}")
        else:
            print(f"  {Colors.yellow('[-] Vendor not found in public database.')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 3. WPS PIN GENERATOR ---
def wps_pin_generator(bssid: str):
    print(f"\n{Colors.cyan('[+]')} WPS PIN Generation for: {Colors.bold(bssid)}")
    try:
        clean_mac = re.sub(r'[^A-Fa-f0-9]', '', bssid).upper()
        if len(clean_mac) < 12: 
            print(f"  {Colors.red('[!] Invalid BSSID.')}"); return
        
        # D-Link Algorithm
        nic = clean_mac[6:]
        pin = str(int(nic, 16) % 10000000).zfill(7)
        checksum = sum(int(d) * (3 if i % 2 == 0 else 1) for i, d in enumerate(pin)) % 10
        dlink_pin = pin + str(checksum)
        
        # Belkin Algorithm
        belkin_pin = clean_mac[6:] 
        
        print(f"  {Colors.green('[+] D-Link Default WPS PIN:')} {dlink_pin}")
        print(f"  {Colors.green('[+] Belkin Default WPS PIN:')} {belkin_pin}")
        print(f"  {Colors.dim('    (Note: Newer routers have WPS disabled by default)')}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. WI-FI SECURITY ANALYZER ---
def analyze_wifi_security():
    networks = scan_wifi_networks()
    if not networks: return
    
    print(f"\n{Colors.magenta('═' * 60)}")
    print(f"  {Colors.bold('WIRELESS SECURITY ANALYSIS REPORT')}")
    print(f"{Colors.magenta('═' * 60)}")
    
    open_nets = 0; wep_nets = 0; wpa_nets = 0; strong_nets = 0
    
    for net in networks:
        cap = net.get('capabilities', '')
        if 'WPA3' in cap: strong_nets += 1
        elif 'WPA2' in cap: wpa_nets += 1
        elif 'WPA' in cap: wpa_nets += 1
        elif 'WEP' in cap: wep_nets += 1
        else: open_nets += 1
        
    print(f"  {Colors.red('Open Networks (No Password):')} {open_nets}")
    print(f"  {Colors.red('WEP Networks (Broken):')} {wep_nets}")
    print(f"  {Colors.yellow('WPA/WPA2 Networks:')} {wpa_nets}")
    print(f"  {Colors.green('WPA3 Networks (Secure):')} {strong_nets}")
    
    if open_nets > 0 or wep_nets > 0:
        print(f"\n  {Colors.red('[!] WARNING: Insecure networks detected around you!')}")
    else:
        print(f"\n  {Colors.green('[+] No critically insecure networks detected.')}")

# --- 5. SIGNAL STRENGTH VISUALIZER ---
def signal_monitor():
    print(f"\n{Colors.cyan('[+]')} Signal Strength Visualizer (Press Ctrl+C to stop)")
    try:
        while True:
            result = subprocess.run(["termux-wifi-connectioninfo"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                rssi = data.get('rssi', -100)
                ssid = data.get('ssid', 'Unknown')
                
                # Map RSSI (-100 to -30) to a bar length
                bar_len = max(0, min(30, int((rssi + 100) * 30 / 70)))
                bar = "█" * bar_len + "░" * (30 - bar_len)
                
                if rssi > -50: color = Colors.green
                elif rssi > -70: color = Colors.yellow
                else: color = Colors.red
                
                sys.stdout.write(f"\r  {Colors.bold(ssid[:15]):<15} {color(bar)} {rssi} dBm")
                sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {Colors.yellow('[!] Monitoring stopped.')}")
    except Exception as e:
        print(f"\n  {Colors.red('[!] Error:')} {e}")

# --- 6. HANDSHAKE HASH GENERATOR ---
def hash_generator():
    print(f"\n{Colors.cyan('[+]')} WPA Handshake Hash Generator")
    print(f"  {Colors.dim('This creates a hash file for offline cracking (simulation).')}")
    ssid = input(Colors.bold(Colors.yellow("  [?] Enter SSID: "))).strip()
    bssid = input(Colors.bold(Colors.yellow("  [?] Enter BSSID (MAC): "))).strip()
    if ssid and bssid:
        if not os.path.exists("reports"): os.makedirs("reports")
        filename = f"reports/handshake_{ssid.replace(' ', '_')}.hash"
        with open(filename, "w") as f:
            f.write(f"{ssid}:{bssid}:PMKID_SIMULATED\n")
        print(f"  {Colors.green('[+] Hash file created:')} {filename}")
        print(f"  {Colors.dim('    Use hashcat/aircrack-ng on a PC to crack it.')}")

# --- MENU ---
def run_wireless_security():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 08: FUTURISTIC WIRELESS SECURITY')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Advanced Wi-Fi Scanner")
        print(f"  {Colors.green('2.')} MAC OUI Vendor Lookup")
        print(f"  {Colors.green('3.')} WPS PIN Generator")
        print(f"  {Colors.green('4.')} Wi-Fi Security Analyzer")
        print(f"  {Colors.green('5.')} Signal Strength Visualizer")
        print(f"  {Colors.green('6.')} Handshake Hash Generator")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [WirelessSec]> "))).strip()
        if choice == "0": break
        elif choice == "1": scan_wifi_networks()
        elif choice == "2":
            target = input(Colors.bold(Colors.yellow("  [?] Enter BSSID (MAC Address): "))).strip()
            if target: mac_oui_lookup(target)
        elif choice == "3":
            target = input(Colors.bold(Colors.yellow("  [?] Enter BSSID: "))).strip()
            if target: wps_pin_generator(target)
        elif choice == "4": analyze_wifi_security()
        elif choice == "5": signal_monitor()
        elif choice == "6": hash_generator()
        else: print(f"  {Colors.red('[!] Invalid option.')}")
