from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

proto_count = Counter()

def process_packet(packet):
    global proto_count
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"\n[IP Packet] {src} -> {dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"   TCP Packet | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
            proto_count["TCP"] += 1

        elif UDP in packet:
            print(f"   UDP Packet | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")
            proto_count["UDP"] += 1

        elif ICMP in packet:
            print("   ICMP Packet (Ping Request/Reply)")
            proto_count["ICMP"] += 1
        else:
            proto_count["Other"] += 1

        #print live stats
        print("Protocol Stats:", dict(proto_count))

#capturing only 30 packets
print("Starting Packet Sniffer...\n")
sniff(prn=process_packet, count=30)
