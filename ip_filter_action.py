import re
from scapy.all import sniff, IP

# Only allow 10.224.x.x subnet
ip_pattern = re.compile(r'^10\.224\.\d{1,3}\.\d{1,3}$')

def filter_ip(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if ip_pattern.match(src_ip) and ip_pattern.match(dst_ip):
            action = "ALLOW"
        else:
            action = "BLOCK"
        print(f"{action}: {src_ip} -> {dst_ip}")

sniff(count=10, prn=filter_ip)
