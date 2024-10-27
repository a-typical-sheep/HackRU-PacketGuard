from scapy.all import IP, TCP, send

malicious_ip = "192.168.100.103"
malicious_port = 52259

packet = IP(src=malicious_ip, dst="192.168.1.1") / TCP(sport=malicious_port, dport=80)

print("Crafted Packet Details:")
packet.show() 

print("Sending simulated malicious packet...")
send(packet, count=1, verbose=True)