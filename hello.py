from scapy.all import rdpcap, IP, IPv6
from collections import defaultdict
import socket

def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

# Load pcap file
packets = rdpcap("traffic.pcap")

# Dictionary to hold connections
connections = defaultdict(set)

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        continue  # Skip non-IP packets

    connections[src].add(dst)

# Print summary
print("\n[+] Device Connection Summary (IPv4 and IPv6):")
for src, dsts in connections.items():
    for dst in dsts:
        hostname = reverse_lookup(dst)
        print(f" - {src} connected to {dst} ({hostname})")
