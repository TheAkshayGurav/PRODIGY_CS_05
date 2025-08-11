Python 3.8+

scapy (pip install scapy)

Linux/macOS: run with sudo (or root).

Windows: install Npcap (WinPcap is obsolete) and run as Administrator. Scapy works with Npcap.

Usage examples
Capture indefinitely on default interface and write to packets_log.csv:
sudo python3 simple_sniffer.py

Capture 100 packets on interface eth0:
sudo python3 simple_sniffer.py -i eth0 -c 100 -o mycapture.csv

Capture HTTP traffic only:
sudo python3 simple_sniffer.py -f "tcp port 80"

Capture for 60 seconds:
sudo python3 simple_sniffer.py -t 60

Notes & improvements you can make later
Add packet reassembly to view full TCP streams (look into scapy.sessions or modules that reassemble).

Add JSON output or PCAP writer (wrpcap) so you can open captures in Wireshark.

Add more detailed protocol parsing (DNS, TLS SNI, HTTP headers) — but be careful: parsing application data may reveal sensitive info.

Add rate-limiting or log rotation for heavy traffic.

Add GUI (e.g., a simple TUI or web UI) for nicer browsing.

What this sniffer does
Captures live packets on an interface.

Extracts timestamp, L2/L3/L4 info: source/destination IPs, protocol (ARP/ICMP/TCP/UDP/etc), ports when available.

Shows truncated payload (hex and ASCII) for quick analysis.

Prints a concise line per packet to console and appends structured rows to a CSV file for later analysis.

Supports optional BPF filter (like tcp port 80), packet count, duration, and output file.
