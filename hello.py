from scapy.all import rdpcap, IP, IPv6
from collections import defaultdict
import socket

def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

# Load pcap file
packets = rdpcap("traffic.pcap")

# Set to hold unique connections (src, dst)
unique_connections = set()

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        continue

    # Store as sorted tuple to avoid duplicates from both sides
    if src != dst:
        unique_connections.add(tuple(sorted([src, dst])))

# Extract local device IPs
local_ips = set()
for conn in unique_connections:
    for ip in conn:
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip.startswith("fe80") or ip.startswith("fd"):
            local_ips.add(ip)

# Display summary
print("\n🛰️  Network Summary Report")
print("----------------------------")

if len(local_ips) == 1:
    local_ip = list(local_ips)[0]
    print(f"📍 Your Device IP: {local_ip}")
    print("📡 You appear to be connected via a local router or mobile hotspot.")
else:
    print(f"📍 Detected local IPs: {', '.join(local_ips)}")
    print("📡 Possibly multiple local interfaces (WiFi + mobile or VPN).")

print("\n🔗 Unique External Connections:")
external_connections = []

for conn in unique_connections:
    src, dst = conn
    for ip in conn:
        if ip not in local_ips:
            hostname = reverse_lookup(ip)
            external_connections.append((ip, hostname))
            break  # Only show one external per connection

# Deduplicate external connections
seen = set()
for ip, host in external_connections:
    if ip not in seen:
        seen.add(ip)
        print(f" - {ip} ({host})")

print("\n✅ This tool offers a simple way to understand where your device is connecting, similar to advanced tools like Wireshark or Fing, but it's 100% free and script-based.")
