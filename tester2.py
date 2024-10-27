from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_info = {
            "Source IP": ip_src,
            "Destination IP": ip_dst,
            "Protocol": packet[IP].proto,
            "Packet Length": len(packet)
        }
        
        if TCP in packet:
            packet_info["Source Port"] = packet[TCP].sport
            packet_info["Destination Port"] = packet[TCP].dport
        
        print(packet_info)

#print all packets
sniff(filter="ip", prn=packet_callback)
