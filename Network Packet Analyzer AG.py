'''
#Task # 05
Network Packet Analyzer
'''
#!/usr/bin/env python3
"""
simple_sniffer.py
Educational packet sniffer using scapy.
Run as root/Administrator. Use ethically and with permission.

Only capture on NICs/VMs/networks you own or have explicit permission to monitor.
-------------------------------------------------
Ethics, legality & safety checklist (read this!)
-------------------------------------------------
Do not capture or exfiltrate other people's private data.
Follow organizational policies and local laws — some jurisdictions require notification/consent for monitoring.
For labs, use isolated networks (virtual machines or lab VLANs).
Use capture filters to reduce accidental collection of unrelated traffic.
If you find sensitive data during authorized capture, follow your org’s incident handling / data protection procedures.
"""

import csv
import argparse
import datetime
import sys
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, Ether

# --------- Helpers ----------
def safe_ascii(b: bytes, max_len=64):
    try:
        s = b.decode('utf-8', errors='replace')
    except Exception:
        s = str(b)
    # Replace non-printable chars with dot
    printable = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in s)
    return printable[:max_len]

def to_hex(b: bytes, max_len=64):
    if not b:
        return ''
    return b[:max_len].hex()

def get_protocol(pkt):
    if ARP in pkt:
        return 'ARP'
    if IP in pkt:
        proto = pkt[IP].proto
        if proto == 6:
            return 'TCP'
        elif proto == 17:
            return 'UDP'
        elif proto == 1:
            return 'ICMP'
        else:
            return f'IP_PROTO_{proto}'
    if IPv6 in pkt:
        return 'IPv6'
    return pkt.lastlayer().name

# --------- Packet handler ----------
class PacketLogger:
    def __init__(self, csvfile):
        self.csvfile = csvfile
        self.csvfh = open(csvfile, 'a', newline='', encoding='utf-8')
        self.writer = csv.writer(self.csvfh)
        # Write header if file empty
        try:
            self.csvfh.seek(0)
            if self.csvfh.read(1) == '':
                self.writer.writerow(['timestamp', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip',
                                      'l4_proto', 'src_port', 'dst_port', 'payload_hex', 'payload_ascii', 'summary'])
                self.csvfh.flush()
        except Exception:
            # just ensure header present
            self.writer.writerow(['timestamp', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip',
                                  'l4_proto', 'src_port', 'dst_port', 'payload_hex', 'payload_ascii', 'summary'])
            self.csvfh.flush()

    def close(self):
        self.csvfh.close()

    def handle(self, pkt):
        ts = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec='seconds')
        src_mac = pkt[Ether].src if Ether in pkt else ''
        dst_mac = pkt[Ether].dst if Ether in pkt else ''
        src_ip = ''
        dst_ip = ''
        l4_proto = get_protocol(pkt)
        src_port = ''
        dst_port = ''
        payload = b''
        summary = pkt.summary()

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                # ICMP does not have ports
                pass
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            # Similar port handling if needed for IPv6/TCP/UDP
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
        elif ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

        if Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                payload = b''

        payload_hex = to_hex(payload, max_len=128)
        payload_ascii = safe_ascii(payload, max_len=128)

        # Print summary to console
        line = f"{ts} | {l4_proto:5} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | len={len(payload)}"
        print(line)
        # Write to CSV
        self.writer.writerow([ts, src_mac, dst_mac, src_ip, dst_ip, l4_proto, src_port, dst_port, payload_hex, payload_ascii, summary])
        self.csvfh.flush()

# --------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Educational packet sniffer (Scapy). Use only on authorized networks.")
    parser.add_argument('-i', '--iface', help='Interface to sniff on (default: Scapy default)', default=None)
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture (0 means infinite)', default=0)
    parser.add_argument('-t', '--timeout', type=int, help='Timeout in seconds (0 means no timeout)', default=0)
    parser.add_argument('-f', '--filter', help='BPF filter (e.g. "tcp port 80")', default=None)
    parser.add_argument('-o', '--output', help='CSV output file', default='packets_log.csv')
    args = parser.parse_args()

    logger = PacketLogger(args.output)
    print("Starting sniffer. Press Ctrl+C to stop.")
    try:
        sniff_kwargs = {
            'prn': logger.handle,
            'store': False,
        }
        if args.iface:
            sniff_kwargs['iface'] = args.iface
        if args.count and args.count > 0:
            sniff_kwargs['count'] = args.count
        if args.timeout and args.timeout > 0:
            sniff_kwargs['timeout'] = args.timeout
        if args.filter:
            sniff_kwargs['filter'] = args.filter

        sniff(**sniff_kwargs)

    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("Permission denied: you likely need to run this script as root/Administrator.")
    except Exception as e:
        print("Error while sniffing:", e)
    finally:
        logger.close()
        print(f"Saved output to {args.output}")

if __name__ == '__main__':
    main()