# (Keep all imports, parse_args, analyze_pcap, and stop function definitions as is)

# -------------------------
# Main sniffer logic - REFACTORED
# -------------------------
def main():
    args = parse_args()

    # If user requested only analysis of an existing file => run and exit
    if args.analyze_file:
        maxp = args.analyze_max if args.analyze_max > 0 else None
        analyze_pcap(args.analyze_file, max_packets=maxp)
        sys.exit(0)

    # --- Pre-Capture Setup (Interface and Warnings) ---
    if not conf.use_pcap:
        print("Warning: libpcap not available; BPF filters may not work as expected.")

    iface = args.iface
    if not iface:
        print("Available interfaces:", get_if_list())
        iface = input("Choose interface (e.g., eth0, wlan0mon): ").strip()
        if not iface:
            print("No interface chosen. Exiting.")
            sys.exit(1)

    print(f"Interface: {iface}")
    if args.filter:
        print(f"Filter: {args.filter!r}")
    print(f"Output file: {args.outfile}")
    # ... (other print statements remain the same) ...

    # Stats counters (lightweight)
    proto_counter = Counter()
    total_seen = 0

    # --- Signal Handler Setup ---
    # The 'writer' variable must be accessible to 'stop', so it is defined below
    writer = None 
    
    # Stop handler: close writer, optionally analyze
    # Note: Refactored 'stop' to use the globally-scoped 'writer'
    def stop(sig, frame):
        nonlocal writer # Declare nonlocal to modify the outer scope 'writer'
        print("\n[STOP] Signal received. Closing pcap and exiting...")
        try:
            if writer:
                writer.close()
        except Exception:
            pass

        # Analyze the output pcap if requested
        if args.analyze_after_capture:
            maxp = args.analyze_max if args.analyze_max > 0 else None
            analyze_pcap(args.outfile, max_packets=maxp)
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # Packet callback (remains the same, but must handle 'writer' as nonlocal)
    def pkt_cb(pkt):
        nonlocal total_seen, writer
        # ... (rest of your existing pkt_cb logic, using nonlocal writer) ...
        # (Your original logic is complex, but the 'nonlocal writer' fix is key here)
        
        try:
            total_seen += 1
            # ... (protocol counting/printing logic) ...

            # Write to pcap; USE NONLOCAL WRITER
            try:
                if writer: # Check if writer is initialized
                    writer.write(pkt) 
            except Exception as e:
                print("[WRITE ERROR]", e)
                
            # ... (periodic stats logic) ...
        except Exception as cb_e:
            print("[CALLBACK ERROR]", cb_e)


    # --- PcapWriter Context Manager and Sniffing ---
    sniff_count = args.count if args.count > 0 else 0
    
    try:
        # PcapWriter is opened using the Context Manager (the critical change)
        # This guarantees writer.close() is called on exit from this 'with' block.
        with PcapWriter(args.outfile, append=True, sync=True) as pw:
            # Assign the Context Manager's writer to the outer scope variable 
            # so the signal handler and callback can use it.
            writer = pw 
            
            # Run the sniff
            sniff(iface=iface,
                  filter=(args.filter if args.filter else None),
                  prn=pkt_cb,
                  store=False,
                  count=sniff_count)

    except PermissionError:
        print("Permission error: run the script with elevated privileges (sudo).")
        sys.exit(1)
    except OSError as e:
        print("OSError from sniff():", e)
        print("Possible causes: invalid interface, BPF filter issue, or missing libpcap.")
        sys.exit(1)
    except Exception as e:
        # Catch any other unexpected error during the sniff process
        print(f"[CRITICAL ERROR] An unexpected error occurred: {e}")
        sys.exit(1)

    # Analysis check for count-limited capture
    if args.analyze_after_capture:
        maxp = args.analyze_max if args.analyze_max > 0 else None
        analyze_pcap(args.outfile, max_packets=maxp)

    print("[DONE] Capture finished. Exiting.")


if __name__ == "__main__":
    main()
