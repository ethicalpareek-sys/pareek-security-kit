"""Module 05: FUTURISTIC PACKET ANALYSIS ENGINE."""
from __future__ import annotations
import os, sys, subprocess, shutil, collections
from core.banner import Colors

# Check if scapy is installed
try:
    from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# --- 1. PCAP FILE ANALYZER ---
def analyze_pcap(file_path: str):
    print(f"\n{Colors.cyan('[+]')} Analyzing PCAP File: {Colors.bold(file_path)}")
    if not SCAPY_AVAILABLE:
        print(f"  {Colors.red('[!] Scapy not installed. Run: pip install scapy')}"); return
    if not os.path.exists(file_path):
        print(f"  {Colors.red('[!] File not found:')} {file_path}"); return
    try:
        packets = rdpcap(file_path)
        print(f"  {Colors.green('Total Packets:')} {len(packets)}")
        
        protocols = collections.Counter()
        src_ips = collections.Counter()
        dst_ips = collections.Counter()
        
        for pkt in packets:
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
                if TCP in pkt: protocols['TCP'] += 1
                elif UDP in pkt: protocols['UDP'] += 1
                elif ICMP in pkt: protocols['ICMP'] += 1
                if DNS in pkt: protocols['DNS'] += 1
                
        print(f"\n  {Colors.magenta('--- Protocol Distribution ---')}")
        for proto, count in protocols.most_common():
            print(f"    {Colors.green(proto + ':')} {count} packets")
            
        print(f"\n  {Colors.magenta('--- Top 5 Source IPs ---')}")
        for ip, count in src_ips.most_common(5):
            print(f"    {Colors.green(ip + ':')} {count} packets")
            
        print(f"\n  {Colors.magenta('--- Top 5 Destination IPs ---')}")
        for ip, count in dst_ips.most_common(5):
            print(f"    {Colors.green(ip + ':')} {count} packets")
            
    except Exception as e:
        print(f"  {Colors.red('[!] Error reading PCAP:')} {e}")

# --- 2. LIVE PACKET SNIFFER ---
def live_sniff(interface: str, count: int):
    print(f"\n{Colors.cyan('[+]')} Live Packet Capture on {Colors.bold(interface)} (Count: {count})")
    if not SCAPY_AVAILABLE:
        print(f"  {Colors.red('[!] Scapy not installed. Run: pip install scapy')}"); return
    
    if os.geteuid() != 0:
        print(f"  {Colors.yellow('[!] WARNING: Live sniffing usually requires root privileges.')}")
        print(f"  {Colors.yellow('[!] If it fails, try running Termux with root (tsu) or use tcpdump.')}")
        
    print(f"  {Colors.dim('Capturing packets... Press Ctrl+C to stop.')}")
    try:
        packets = sniff(iface=interface, count=count, timeout=30)
        print(f"\n  {Colors.green('[+] Captured')} {len(packets)} packets.")
        
        # Quick Summary
        ips = set()
        for pkt in packets:
            if IP in pkt: ips.add(pkt[IP].src); ips.add(pkt[IP].dst)
        print(f"  {Colors.green('Unique IPs involved:')} {len(ips)}")
        
        # Save to file
        from scapy.all import wrpcap
        filename = "capture.pcap"
        wrpcap(filename, packets)
        print(f"  {Colors.green('[+] Saved to:')} {filename}")
    except Exception as e:
        print(f"  {Colors.red('[!] Sniffing Error:')} {e}")
        print(f"  {Colors.yellow('Hint: Try using tcpdump directly: pkg install tcpdump && tcpdump -i wlan0 -c 10')}")

# --- 3. PROTOCOL STATISTICS (Offline) ---
def packet_stats(file_path: str):
    print(f"\n{Colors.cyan('[+]')} Detailed Packet Statistics: {Colors.bold(file_path)}")
    if not SCAPY_AVAILABLE:
        print(f"  {Colors.red('[!] Scapy not installed. Run: pip install scapy')}"); return
    try:
        packets = rdpcap(file_path)
        total_bytes = sum(len(pkt) for pkt in packets)
        print(f"  {Colors.green('Total Packets:')} {len(packets)}")
        print(f"  {Colors.green('Total Data:')} {total_bytes / 1024:.2f} KB")
        
        # TCP Flags analysis
        tcp_flags = collections.Counter()
        for pkt in packets:
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x02: tcp_flags['SYN'] += 1
                if flags & 0x10: tcp_flags['ACK'] += 1
                if flags & 0x01: tcp_flags['FIN'] += 1
                if flags & 0x04: tcp_flags['RST'] += 1
                
        print(f"\n  {Colors.magenta('--- TCP Flag Distribution ---')}")
        for flag, count in tcp_flags.most_common():
            print(f"    {Colors.green(flag + ':')} {count}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 4. TOP TALKERS (Offline) ---
def top_talkers(file_path: str):
    print(f"\n{Colors.cyan('[+]')} Top Talkers (Heaviest Data Transfer): {Colors.bold(file_path)}")
    if not SCAPY_AVAILABLE:
        print(f"  {Colors.red('[!] Scapy not installed. Run: pip install scapy')}"); return
    try:
        packets = rdpcap(file_path)
        ip_bytes = collections.Counter()
        for pkt in packets:
            if IP in pkt:
                ip_bytes[pkt[IP].src] += len(pkt)
                ip_bytes[pkt[IP].dst] += len(pkt)
                
        print(f"  {Colors.magenta('--- Top 10 IPs by Data Volume ---')}")
        for ip, bytes_count in ip_bytes.most_common(10):
            print(f"    {Colors.green(ip + ':')} {bytes_count / 1024:.2f} KB")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- 5. IP FILTER & EXTRACT ---
def filter_ip(file_path: str, target_ip: str):
    print(f"\n{Colors.cyan('[+]')} Filtering Packets for IP: {Colors.bold(target_ip)}")
    if not SCAPY_AVAILABLE:
        print(f"  {Colors.red('[!] Scapy not installed. Run: pip install scapy')}"); return
    try:
        packets = rdpcap(file_path)
        filtered = [pkt for pkt in packets if IP in pkt and (pkt[IP].src == target_ip or pkt[IP].dst == target_ip)]
        print(f"  {Colors.green('Found:')} {len(filtered)} packets related to {target_ip}")
        
        if filtered:
            from scapy.all import wrpcap
            out_file = f"filtered_{target_ip}.pcap"
            wrpcap(out_file, filtered)
            print(f"  {Colors.green('[+] Saved filtered packets to:')} {out_file}")
    except Exception as e:
        print(f"  {Colors.red('[!] Error:')} {e}")

# --- MENU ---
def run_packet_analysis():
    while True:
        print(f"\n{Colors.magenta('═' * 60)}")
        print(f"  {Colors.bold('MODULE 05: FUTURISTIC PACKET ANALYSIS')}")
        print(f"{Colors.magenta('═' * 60)}")
        print(f"  {Colors.green('1.')} Analyze PCAP File (Protocols, IPs)")
        print(f"  {Colors.green('2.')} Live Packet Sniffer (Requires Root)")
        print(f"  {Colors.green('3.')} Detailed Packet Statistics (TCP Flags)")
        print(f"  {Colors.green('4.')} Top Talkers (Heaviest IPs)")
        print(f"  {Colors.green('5.')} Filter PCAP by IP Address")
        print(f"  {Colors.red('0.')} Back to Main Menu")
        print(f"{Colors.magenta('─' * 60)}")
        
        choice = input(Colors.bold(Colors.cyan("  [PacketAnalysis]> "))).strip()
        if choice == "0": break
        elif choice == "1":
            target = input(Colors.bold(Colors.yellow("  [?] Enter PCAP file path (e.g., capture.pcap): "))).strip()
            if target: analyze_pcap(target)
        elif choice == "2":
            iface = input(Colors.bold(Colors.yellow("  [?] Enter Interface (e.g., wlan0): "))).strip()
            count = input(Colors.bold(Colors.yellow("  [?] Enter Packet Count (e.g., 50): "))).strip()
            if iface and count.isdigit(): live_sniff(iface, int(count))
        elif choice == "3":
            target = input(Colors.bold(Colors.yellow("  [?] Enter PCAP file path: "))).strip()
            if target: packet_stats(target)
        elif choice == "4":
            target = input(Colors.bold(Colors.yellow("  [?] Enter PCAP file path: "))).strip()
            if target: top_talkers(target)
        elif choice == "5":
            target = input(Colors.bold(Colors.yellow("  [?] Enter PCAP file path: "))).strip()
            ip = input(Colors.bold(Colors.yellow("  [?] Enter Target IP: "))).strip()
            if target and ip: filter_ip(target, ip)
        else: print(f"  {Colors.red('[!] Invalid option.')}")
