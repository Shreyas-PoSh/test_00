#!/usr/bin/env python3

from scapy.all import rdpcap, IP, IPv6
from collections import defaultdict
import socket
import csv

# ----------------------------
# CONFIGURATION
# ----------------------------
PCAP_FILE = "traffic.pcap"
CSV_OUTPUT = "connection_report.csv"

# ----------------------------
# UTILITY FUNCTIONS
# ----------------------------
def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def is_local_ip(ip):
    return (
        ip.startswith("192.168.") or 
        ip.startswith("10.") or 
        ip.startswith("172.") or 
        ip.startswith("fe80") or 
        ip.startswith("fd")
    )

# ----------------------------
# LOAD AND PARSE PACKETS
# ----------------------------
try:
    packets = rdpcap(PCAP_FILE)
except FileNotFoundError:
    print(f"❌ Error: PCAP file '{PCAP_FILE}' not found.")
    exit(1)

connection_summary = defaultdict(lambda: {"hostname": "", "bytes": 0, "count": 0})
local_ips = set()

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        length = pkt[IP].len
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        length = len(pkt[IPv6])
    else:
        continue

    # Identify local device
    if is_local_ip(src):
        local_ips.add(src)
        remote = dst
    elif is_local_ip(dst):
        local_ips.add(dst)
        remote = src
    else:
        continue

    connection_summary[remote]["bytes"] += length
    connection_summary[remote]["count"] += 1

# ----------------------------
# REVERSE DNS LOOKUPS
# ----------------------------
for ip in connection_summary:
    connection_summary[ip]["hostname"] = reverse_lookup(ip)

# ----------------------------
# PRINT REPORT
# ----------------------------
print("\n🛰️  Network Summary Report")
print("----------------------------")

if len(local_ips) == 1:
    print(f"📍 Your Device IP: {list(local_ips)[0]}")
    print("📡 Connection type: Router or mobile hotspot")
else:
    print(f"📍 Detected Local IPs: {', '.join(local_ips)}")
    print("📡 Connection type: Multiple interfaces (Wi-Fi + mobile or VPN)")

print("\n🔗 External Connections (deduplicated):")
print("----------------------------------------")
for ip, info in connection_summary.items():
    print(f" - {ip:>15} ({info['hostname']}) | Packets: {info['count']}, Bytes: {info['bytes']}")

# ----------------------------
# EXPORT TO CSV
# ----------------------------
try:
    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["External IP", "Hostname", "Packets", "Total Bytes"])
        for ip, info in connection_summary.items():
            writer.writerow([ip, info["hostname"], info["count"], info["bytes"]])
    print(f"\n✅ CSV report saved to: {CSV_OUTPUT}")
except Exception as e:
    print(f"❌ Failed to save CSV: {e}")

print("\n✔️  Analysis complete. This script gives a human-readable summary of connections,")
print("   acting as a free alternative to tools like Wireshark/Fing for quick insight.\n")
