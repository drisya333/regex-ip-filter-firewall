import re
from scapy.all import sniff, IP

# Regex pattern for IPs starting with 192.168.
ip_pattern = re.compile(r'^(192\.168|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}$')



def filter_ip(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if source or destination IP matches the pattern
        if ip_pattern.match(src_ip) or ip_pattern.match(dst_ip):
            print(f"Matched: {src_ip} -> {dst_ip}")
        else:
            print(f"Skipped: {src_ip} -> {dst_ip}")

# Sniff 10 packets for testing
sniff(count=10, prn=filter_ip)
