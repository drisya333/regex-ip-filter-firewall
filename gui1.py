import re
from scapy.all import sniff, IP
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

class PacketFilterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Regex Packet Filter")
        
        # Regex input
        tk.Label(root, text="IP Pattern (* as wildcard):").grid(row=0, column=0, sticky="w")
        self.pattern_entry = tk.Entry(root, width=30)
        self.pattern_entry.grid(row=0, column=1)
        
        # Match mode dropdown
        tk.Label(root, text="Match Mode:").grid(row=1, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(root, values=["either","both","source","destination"], state="readonly", width=13)
        self.mode_combo.grid(row=1, column=1)
        self.mode_combo.current(0)

        # Start/Stop buttons
        self.start_button = tk.Button(root, text="Start", command=self.start_sniffing)
        self.start_button.grid(row=2, column=0)
        self.stop_button = tk.Button(root, text="Stop", command=self.stop_sniffing, state="disabled")
        self.stop_button.grid(row=2, column=1)
        
        # Display area for output
        self.output_area = scrolledtext.ScrolledText(root, width=50, height=15)
        self.output_area.grid(row=3, column=0, columnspan=2)
        
        # Statistics
        self.stats_label = tk.Label(root, text="Allowed: 0 | Blocked: 0")
        self.stats_label.grid(row=4, column=0, columnspan=2)
        
        # Internal state
        self.running = False
        self.allowed = 0
        self.blocked = 0
        
    def start_sniffing(self):
        self.running = True
        self.allowed = 0
        self.blocked = 0
        self.output_area.delete(1.0, tk.END)
        self.stats_label.config(text="Allowed: 0 | Blocked: 0")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        threading.Thread(target=self.sniff_packets, daemon=True).start()
        
    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
    def simple_to_regex(self, pattern):
        pattern = pattern.replace('.', '\\.').replace('*', '\\d{1,3}')
        return f'^{pattern}$'
    
    def sniff_packets(self):
        mode = self.mode_combo.get()
        pattern_str = self.pattern_entry.get()
        regex_pattern = self.simple_to_regex(pattern_str)
        ip_pattern = re.compile(regex_pattern)

        def process_packet(packet):
            if not self.running:
                return False  # stop sniffing
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
                self.output_area.insert(tk.END, f"{action}: {src_ip} -> {dst_ip}\n")
                self.output_area.see(tk.END)
                self.stats_label.config(text=f"Allowed: {self.allowed} | Blocked: {self.blocked}")
            return self.running  # continue until stop_sniffing

        sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.running)

root = tk.Tk()
app = PacketFilterApp(root)
root.mainloop()
