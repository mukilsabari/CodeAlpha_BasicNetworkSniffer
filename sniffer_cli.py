import argparse
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.utils import hexdump

# Function to parse command-line arguments
def parse_args():
    p = argparse.ArgumentParser(description="Basic Network Sniffer using Scapy")
    p.add_argument("-i", "--iface", required=True, 
                   help="Network interface to sniff on (e.g., eth0)")
    p.add_argument("-f", "--filter", default="", 
                   help="BPF filter string (e.g., 'tcp port 80')")
    p.add_argument("-c", "--count", type=int, default=0, 
                   help="Packet count (0 = unlimited)")
    return p.parse_args()

# Function to analyze and display captured packets
def packet_callback(packet):
    """Analyzes a packet and displays IPs, ports, flags, and payload."""
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print("\n--- New Packet Captured ---")
        print(f"Source IP: {ip_src} | Destination IP: {ip_dst}")
        
        # Determine the transport layer
        if TCP in packet:
            transport_layer = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            
            print(f"Protocol: {transport_layer} | Port: {src_port} -> {dst_port}")
            print(f"TCP Flags: {str(tcp_flags)}")
            
            # Payload Analysis
            if Raw in packet:
                payload = packet[Raw].load
                payload_len = len(payload)
                
                print(f"[Payload Analysis] Size: {payload_len} bytes")
                
                # Attempt to decode as text, otherwise use hex dump
                try:
                    text = payload.decode("utf-8", errors="ignore")
                    print("  Content Peek (Text):")
                    print(text[:100].strip())
                except Exception:
                    print("  Content Peek (Hex Dump):")
                    hexdump(payload[:64])
                    
        elif UDP in packet:
            transport_layer = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Protocol: {transport_layer} | Port: {src_port} -> {dst_port}")
            
        else:
            print(f"Protocol: Other IP ({protocol})")

        print("-" * 40)


def main():
    args = parse_args()
    
    print(f"Starting sniffer on interface: {args.iface}")
    if args.filter:
        print(f"Filter: '{args.filter}'")
    if args.count > 0:
        print(f"Limit: {args.count} packets")
    print("Press Ctrl+C to stop capture...")
    
    try:
        # Sniff packets indefinitely or until count is reached
        sniff(iface=args.iface, 
              filter=(args.filter if args.filter else None), 
              prn=packet_callback, 
              store=False, 
              count=args.count)
    except PermissionError:
        print("\nPermission Error: You must run the script with elevated privileges (sudo).")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")

if __name__ == "__main__":
    main()
