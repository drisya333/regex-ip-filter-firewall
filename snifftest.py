from scapy.all import sniff

def show_packet(pkt):
    print(pkt.summary())

sniff(count=5, prn=show_packet)
