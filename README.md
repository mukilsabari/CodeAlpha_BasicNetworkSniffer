# 🌐 CodeAlpha Basic Network Sniffer (TASK 1)

## 🎯 Project Overview
This Python script implements a **Command Line Interface (CLI) packet sniffer** using the **Scapy** library. It fulfills the requirement of capturing network traffic and performing basic analysis to understand packet structure and protocols.

## ⚙️ Key Features:
* **Live Capture:** Monitors a specified network interface.
* **BPF Filtering:** Supports standard Berkeley Packet Filter (BPF) syntax.
* **Detailed Analysis:** Extracts Source/Destination IP, Ports, Protocol, and analyzes **TCP Flags**.
* **Payload Inspection:** Attempts to decode and display the packet's raw payload content.

## 🚀 Requirements and Execution

### Prerequisites:
This script requires **root/administrator privileges** to access raw network sockets.

```bash
# Install Scapy
sudo apt update
sudo apt install python3-pip
python3 -m pip install scapy
