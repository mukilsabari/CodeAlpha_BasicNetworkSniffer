import argparse
import sys
import os
import signal
from scapy.all import sniff, IP, TCP, PcapWriter, PcapReader, conf, packet as scapy_packet

# --- Global Variables for State Management ---
# Global variables are necessary for the signal handler and packet counter
pcap_writer = None
packet_counter = 0
stats_counter = {
    'total': 0,
    'IP': 0,
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'ARP': 0
}
# ----------------------------------------------


def signal_handler(sig, frame):
    """Handles Ctrl+C (SIGINT) for graceful shutdown."""
    print("\n[INFO] Capture stopped by user (Ctrl+C).")
    global pcap_writer
    if pcap_writer:
        # Crucial step: Ensure the pcap file handle is closed safely
        pcap_writer.close()
        print(f"[INFO] Output file safely closed. Total packets captured: {stats_counter['total']}")
    
    # Check if analysis should run after capture
    if hasattr(frame, 'args') and frame.args.analyze_after_capture:
        print("[INFO] Starting analysis of captured file...")
        analyze_pcap_file(frame.args.output_file, quiet=frame.args.quiet)
    
    # Exit the program
    sys.exit(0)


def print_stats(quiet):
    """Periodically prints protocol statistics."""
    if not quiet:
        print("\n[STATS] Protocol Summary:")
        for proto, count in stats_counter.items():
            if count > 0:
                print(f"  > {proto:<5}: {count}")
        print("-" * 25)


def analyze_payload(packet, quiet):
    """Analyzes TCP payload for length and content peek."""
    global packet_counter
    packet_counter += 1
    
    # 1. Update stats based on packet type
    stats_counter['total'] += 1
    if IP in packet:
        stats_counter['IP'] += 1
        if TCP in packet:
            stats_counter['TCP'] += 1
        elif 'UDP' in packet:
            stats_counter['UDP'] += 1
        elif 'ICMP' in packet:
            stats_counter['ICMP'] += 1
    elif 'ARP' in packet:
        stats_counter['ARP'] += 1

    # 2. Check for periodic stats output (Goal: Stats every 20 packets)
    if packet_counter % 20 == 0:
        print_stats(quiet)

    # 3. Analyze TCP Payload
    if TCP in packet and not quiet:
        # Check if there is data after the TCP header (the payload)
        payload = bytes(packet[TCP].payload)
        payload_len = len(payload)
        
        # Determine flag names for better clarity
        tcp_flags = packet[TCP].flags
        
        # Scrutiny check: Distinguish between handshake and data packets
        if payload_len > 0:
            status = "DATA"
            # Show a peek of the payload (first 200 bytes)
            payload_peek = payload[:200].hex()
        elif str(tcp_flags) in ['S', 'SA', 'A']:
            status = "HANDSHAKE"
            payload_peek = ""
        else:
            status = "CONTROL"
            payload_peek = ""

        print(f"[{status}] {packet_counter:<5} | {packet[IP].src} -> {packet[IP].dst} | "
              f"Flags: {str(tcp_flags):<3} | Payload Len: {payload_len} bytes")
        
        if payload_len > 0:
            print(f"  [Payload Peek (Hex)]: {payload_peek[:80]}...")
            

def handle_packet(packet):
    """The callback function for sniff(): writes and analyzes packets."""
    global pcap_writer
    
    # 1. Write the packet to the PCAP file incrementally (sync=True ensures immediate write)
    if pcap_writer:
        pcap_writer.write(packet)
    
    # 2. Analyze and update stats
    analyze_payload(packet, args.quiet)


def analyze_pcap_file(file_path, quiet):
    """Analyzes an existing pcap file using PcapReader for safety."""
    print(f"\n[INFO] Analyzing file: {file_path}")
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return
        
    global packet_counter
    packet_counter = 0 # Reset counter for analysis run
    
    try:
        # Use PcapReader for streaming safety with large files
        for packet in PcapReader(file_path):
            analyze_payload(packet, quiet)
        print("\n[INFO] Analysis complete.")
    except Exception as e:
        print(f"[ERROR] Could not read pcap file: {e}")


def main():
    """Main function to parse arguments and start capture or analysis."""
    global args, pcap_writer, stats_counter
    
    parser = argparse.ArgumentParser(
        description="Kali Linux-ready packet sniffer using Scapy.",
        epilog="Requires root privileges for live capture."
    )
    
    # --- Feature implementation using ArgumentParser ---
    parser.add_argument('-i', '--interface', type=str, help='Network interface to sniff on (e.g., eth0).')
    parser.add_argument('-f', '--filter', type=str, default="", help='BPF filter string (e.g., "tcp port 80").')
    parser.add_argument('-o', '--output-file', type=str, default="capture.pcap", help='Output file path for saving packets.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress individual packet output, only show stats.')
    parser.add_argument('--analyze-after-capture', action='store_true', help='Automatically run analysis on the output file after capture stops.')
    parser.add_argument('--analyze-file', type=str, help='Analyze an existing pcap file instead of starting a new capture.')
    # ---------------------------------------------------
    
    args = parser.parse_args()

    # --- Mode Selection ---
    if args.analyze_file:
        analyze_pcap_file(args.analyze_file, args.quiet)
        return
        
    if not args.interface:
        print("[ERROR] Interface is required for live capture. Use -i or --analyze-file.")
        sys.exit(1)

    # --- Pre-Capture Setup ---
    print(f"[INFO] Starting live capture on interface: {args.interface}")
    print(f"[INFO] Filter: '{args.filter}' | Output: {args.output_file}")
    print("Press Ctrl+C to stop capture gracefully...")
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    # Pass arguments to the signal handler scope
    signal_handler.args = args 

    # Initialize PcapWriter for incremental writing (Feature 3)
    try:
        # Use sync=True for immediate saving to disk
        pcap_writer = PcapWriter(args.output_file, append=True, sync=True) 
    except Exception as e:
        print(f"[ERROR] Could not initialize PcapWriter: {e}")
        sys.exit(1)

    # --- Start Sniffing ---
    try:
        # Note: Must run with root privileges (sudo) for live capture
        sniff(iface=args.interface, filter=args.filter, prn=handle_packet, store=0)
    except OSError as e:
        print(f"\n[CRITICAL ERROR] Failed to start capture: {e}")
        print("[HINT] You need root privileges for live capture. Try running with 'sudo'.")
        if pcap_writer:
            pcap_writer.close()
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        if pcap_writer:
            pcap_writer.close()


if __name__ == "__main__":
    main()
