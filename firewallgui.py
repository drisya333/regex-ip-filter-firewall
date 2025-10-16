import re
import subprocess
import threading
from scapy.all import sniff, IP
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class FirewallPacketFilterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Regex Packet Filter with Firewall")

        tk.Label(root, text="IP Pattern (* wildcard):").grid(row=0, column=0, sticky="w")
        self.pattern_entry = tk.Entry(root, width=25)
        self.pattern_entry.grid(row=0, column=1)

        tk.Label(root, text="Match Mode:").grid(row=1, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(root, values=["either", "both", "source", "destination"], state="readonly", width=12)
        self.mode_combo.grid(row=1, column=1)
        self.mode_combo.current(0)

        self.start_btn = tk.Button(root, text="Start", command=self.start_sniffing)
        self.start_btn.grid(row=2, column=0)
        self.stop_btn = tk.Button(root, text="Stop", command=self.stop_sniffing, state="disabled")
        self.stop_btn.grid(row=2, column=1)

        self.unblock_btn = tk.Button(root, text="Unblock All", command=self.unblock_all)
        self.unblock_btn.grid(row=2, column=2)

        self.log_area = scrolledtext.ScrolledText(root, width=60, height=15)
        self.log_area.grid(row=3, column=0, columnspan=3)

        self.stat_label = tk.Label(root, text="Allowed: 0 | Blocked: 0")
        self.stat_label.grid(row=4, column=0, columnspan=3)

        self.allowed = 0
        self.blocked = 0
        self.blocked_ips = set()
        self.running = False

    def simple_to_regex(self, pattern):
        pattern = pattern.replace('.', '\\.').replace('*', '\\d{1,3}')
        return f'^{pattern}$'

    def add_firewall_block_rule(self, ip_address):
        rule_name = f"Block IP {ip_address}"
        cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -RemoteAddress {ip_address} -Action Block'
        try:
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            if result.returncode == 0:
                self.write_log(f"Added firewall block rule for {ip_address}")
            else:
                self.write_log(f"Failed to add firewall rule: {result.stderr.strip()}")
        except Exception as e:
            self.write_log(f"Error adding firewall rule: {e}")

    def unblock_all(self):
        cmd = 'Get-NetFirewallRule | Where-Object {$_.DisplayName -Like "Block IP*"} | Remove-NetFirewallRule'
        try:
            subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            self.write_log("All Block IP firewall rules have been removed.")
            self.blocked_ips.clear()
        except Exception as e:
            self.write_log(f"Error removing firewall rules: {e}")

    def write_log(self, text):
        self.log_area.insert(tk.END, text + "\n")
        self.log_area.see(tk.END)

    def update_stats(self):
        self.stat_label.config(text=f"Allowed: {self.allowed} | Blocked: {self.blocked}")

    def sniff_packets(self):
        mode = self.mode_combo.get()
        pattern_str = self.pattern_entry.get().strip()
        regex_pattern = self.simple_to_regex(pattern_str)
        ip_pattern = re.compile(regex_pattern)

        def process_packet(packet):
            if not self.running:
                return False
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                match = False
                if mode == "either":
                    match = ip_pattern.match(src_ip) or ip_pattern.match(dst_ip)
                elif mode == "both":
                    match = ip_pattern.match(src_ip) and ip_pattern.match(dst_ip)
                elif mode == "source":
                    match = ip_pattern.match(src_ip)
                elif mode == "destination":
                    match = ip_pattern.match(dst_ip)
                action = "ALLOW" if match else "BLOCK"
                if match:
                    self.allowed += 1
                else:
                    self.blocked += 1
                    if src_ip not in self.blocked_ips:
                        should_block = messagebox.askyesno(
                            "Firewall Block",
                            f"Block IP {src_ip}?\nThis will add a firewall rule and may block that device."
                        )
                        if should_block:
                            self.add_firewall_block_rule(src_ip)
                            self.blocked_ips.add(src_ip)
                        else:
                            self.write_log(f"Skipped blocking {src_ip}")
                self.write_log(f"{action}: {src_ip} -> {dst_ip}")
                self.update_stats()
            return self.running

        sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.running)

    def start_sniffing(self):
        self.allowed = 0
        self.blocked = 0
        self.blocked_ips = set()
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log_area.delete("1.0", tk.END)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.write_log("---- Stopped Packet Capture ----")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallPacketFilterGUI(root)
    root.mainloop()
