from scapy.all import rdpcap, IP, IPv6
from collections import defaultdict
import socket
import csv

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

# === Load the PCAP file ===
packets = rdpcap("traffic.pcap")

# Dictionary to store connection summaries
connection_summary = defaultdict(lambda: {"hostname": "", "bytes": 0, "count": 0})
local_ips = set()

# === Analyze packets ===
for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = pkt[IP].len
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        pkt_len = len(pkt[IPv6])
    else:
        continue

    # Identify local vs external
    if is_local_ip(src):
        local_ips.add(src)
        target_ip = dst
    elif is_local_ip(dst):
        local_ips.add(dst)
        target_ip = src
    else:
        continue

    connection_summary[target_ip]["bytes"] += pkt_len
    connection_summary[target_ip]["count"] += 1

# === Reverse DNS lookups ===
for ip in connection_summary:
    connection_summary[ip]["hostname"] = reverse_lookup(ip)

# === Display report ===
print("\n🛰️  Network Summary Report")
print("----------------------------")

if len(local_ips) == 1:
    print(f"📍 Your Device IP: {list(local_ips)[0]}")
    print("📡 You appear to be connected via a router or mobile hotspot.")
else:
    print(f"📍 Detected local IPs: {', '.join(local_ips)}")
    print("📡 Possibly using multiple interfaces (WiFi + mobile or VPN).")

print("\n🔗 Unique External Connections:")
for ip, data in connection_summary.items():
    print(f" - {ip} ({data['hostname']}): {data['count']} packets, {data['bytes']} bytes")

# === Save to CSV ===
with open("connection_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["External IP", "Hostname", "Packets", "Total Bytes"])
    for ip, data in connection_summary.items():
        writer.writerow([ip, data["hostname"], data["count"], data["bytes"]])

print("\n📁 CSV report saved as: connection_report.csv")
print("✅ Done.")
