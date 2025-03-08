#!/usr/bin/env python3
from scapy.all import *
import argparse
import signal
import sys

# Global variables
captured_packets = []

def signal_handler(sig, frame):
    """Handle CTRL+C to save pcap"""
    print("\\n[!] Stopping sniffing...")
    if captured_packets:
        wrpcap("captured.pcap", captured_packets)
        print(f"[*] Saved {len(captured_packets)} packets to captured.pcap")
    sys.exit(0)

def packet_handler(packet):
    """Process each captured packet"""
    global captured_packets
    captured_packets.append(packet)

    # Basic protocol detection
    protocol = "Unknown"
    if packet.haslayer(IP):
        protocol = "IP"
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # Extract basic info
    src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
    src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
    dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else ""

    # Print summary
    print(f"[{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    # Show payload for small packets
    if packet.haslayer(Raw) and len(packet[Raw].load) < 100:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"    Payload: {payload[:80]}...")
        except:
            pass

def start_sniffing(interface, filter_exp=""):
    """Start packet capture"""
    print(f"[*] Starting packet sniffing on {interface}...")
    print(f"[*] Filter: {filter_exp if filter_exp else 'All traffic'}")
    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            filter=filter_exp,
            store=0
        )
    except PermissionError:
        print("[!] Error: Requires root privileges!")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Network Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-f", "--filter", help="BPF filter (tcp, port 80, etc.)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Requires root privileges. Use sudo!")
        sys.exit(1)

    start_sniffing(args.interface, args.filter)
