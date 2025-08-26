# Network Packet Sniffer (Python + Scapy)

A simple **network packet sniffer** built using Python and Scapy.  
It captures live packets, identifies protocols (TCP, UDP, ICMP).  
Packets can also be saved into a `.pcap` file for deeper analysis in **Wireshark**.

##  Features
- Captures live packets from network interfaces.
- Identifies and logs:
  - Source & Destination IPs
  - Protocols (TCP, UDP, ICMP, Others)
  - Port numbers
- Maintains real-time protocol statistics.
- Saves packets to `.pcap` format for Wireshark.

##  Installation
```bash
git clone https://github.com/YOUR_USERNAME/network-packet-sniffer.git
cd network-packet-sniffer
pip install -r requirements.txt
