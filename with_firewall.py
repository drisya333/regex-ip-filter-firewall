import re
import subprocess
from scapy.all import sniff, IP

def simple_to_regex(pattern):
    pattern = pattern.replace('.', '\\.').replace('*', '\\d{1,3}')
    return f'^{pattern}$'

def add_firewall_block_rule(ip_address, rule_name="Block IP"):
    cmd = f'New-NetFirewallRule -DisplayName "{rule_name} {ip_address}" -Direction Inbound -RemoteAddress {ip_address} -Action Block'
    try:
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Added firewall block rule for {ip_address}")
        else:
            print(f"Failed to add firewall rule: {result.stderr.strip()}")
    except Exception as e:
        print(f"Error adding firewall rule: {e}")

pattern_str = input("Enter IP pattern (use * as wildcard, e.g. 10.224.*.*): ").strip()
regex_pattern = simple_to_regex(pattern_str)
ip_pattern = re.compile(regex_pattern)

print(
    "Apply pattern to:\n"
    "1. either (source or destination)\n"
    "2. both (source and destination)\n"
    "3. source only\n"
    "4. destination only"
)
mode = input("Type: either / both / source / destination: ").strip().lower()

allowed_count = 0
blocked_count = 0
blocked_ips = set()

def filter_ip(packet):
    global allowed_count, blocked_count
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if mode == "either":
            match = ip_pattern.match(src_ip) or ip_pattern.match(dst_ip)
        elif mode == "both":
            match = ip_pattern.match(src_ip) and ip_pattern.match(dst_ip)
        elif mode == "source":
            match = ip_pattern.match(src_ip)
        elif mode == "destination":
            match = ip_pattern.match(dst_ip)
        else:
            match = False

        if match:
            action = "ALLOW"
            allowed_count += 1
        else:
            action = "BLOCK"
            blocked_count += 1
            # Add firewall rule to block this IP if not already blocked
            if src_ip not in blocked_ips:
                add_firewall_block_rule(src_ip)
                blocked_ips.add(src_ip)

        print(f"{action}: {src_ip} -> {dst_ip}")

def print_stats():
    print(f"\nTotal Allowed: {allowed_count}")
    print(f"Total Blocked: {blocked_count}")

print("Starting packet capture... Press Ctrl+C to stop.")
try:
    sniff(prn=filter_ip, store=0)
except KeyboardInterrupt:
    print("\nCapture stopped by user.")
    print_stats()
