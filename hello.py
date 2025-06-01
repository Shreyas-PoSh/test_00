from scapy.all import rdpcap, IP
from collections import defaultdict
import socket

def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

# Load packets
packets = rdpcap("traffic.pcap")

# Track connections
connections = defaultdict(set)

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        connections[src].add(dst)

# Display results
print("\n[+] Device Connection Summary with Hostnames:")
for src, dst_set in connections.items():
    for dst in dst_set:
        hostname = reverse_lookup(dst)
        print(f" - {src} connected to {dst} ({hostname})")
