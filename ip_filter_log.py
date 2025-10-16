import re
from scapy.all import sniff, IP

ip_pattern = re.compile(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def filter_ip(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        log_entry = f"{src_ip} -> {dst_ip}\n"
        if ip_pattern.match(src_ip) or ip_pattern.match(dst_ip):
            print(f"Matched: {log_entry.strip()}")
            with open("matched_packets.log", "a") as log_file:
                log_file.write("MATCHED: " + log_entry)
        else:
            print(f"Skipped: {log_entry.strip()}")
            with open("skipped_packets.log", "a") as log_file:
                log_file.write("SKIPPED: " + log_entry)

sniff(count=10, prn=filter_ip)
