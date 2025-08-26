from scapy.all import sniff, wrpcap

print("Sniffing 50 packets...")

#capturing only 50 packets
packets = sniff(count=50)

#saving into a .pcap file
wrpcap("captured_packets.pcap", packets)

print("Packets saved to captured_packets.pcap")
