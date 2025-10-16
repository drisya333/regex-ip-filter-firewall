# regex-ip-filter-firewall
Customizable Regex-Based IP Packet Filter &amp; Dynamic Firewall App
A Python project for interactive real-time network packet filtering and firewall automation with regex rules, live GUI, and user safety features.
__________________________________________________________
**Features**
Regex-based Filtering: Allow/block packets by user-set patterns (wildcards/regex).

Modes: Filter on source, destination, both, or either address fields.

Scapy Integration: Captures live network traffic at the OS level.

Interactive GUI: Tkinter interface with pattern inputs, live logs, and filtering controls.

Safe Dynamic Firewall Control: Adds/removes Windows Firewall rules for BLOCKed IPs (with user confirmation).

One-Click Unblock: Instantly remove all rules added in-session for peace of mind.

Statistics & Logging: View total allowed/blocked packets and event logs.

--------------------------------------

**File	Description**
ip_filter.py	Basic CLI IP filter with regex and logging.
ip_filter_action.py	Final CLI version with packet action modes.
gui1.py	GUI version: pattern input, stats, live logs.
with_firewall.py	Non-GUI script: packet filtering + auto-block in firewall.
firewallgui.py	Full GUI: regex filtering, live logs, confirmation, and unblock.
snifftest.py	Early test script for raw packet sniffing.
core.py	Minimal core filtering logic for reference.

------------------------------------------------------------

**Requirements**
Python 3.7+
Scapy
Tkinter (bundled with Python)
Windows OS for firewall automation (admin rights required)
npcap or WinPcap (for packet capture on Windows): download link

-------------------------------------------------------

**Usage**
See individual script comments.
For the most advanced features, run firewallgui.py as Administrator:
python firewallgui.py

----------------------------------------------------
**Safety Notes**
Always review/warn before blocking IPs—automated rules can disrupt network functions.
Use "Unblock All" to easily restore blocked connections.

-----------------------------------------

**Credits**
Developed by Drisya S.
Mentored and produced as a showcase in advanced Python scripting, network security, and GUI design.
