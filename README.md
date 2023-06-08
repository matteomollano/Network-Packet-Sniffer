# Network Packet Sniffer

_Note: This code was implemented in Python using Kali Linux (will not work with macOS or Windows). 
Additionally, this code must be run using admin privileges:_ `sudo python3 packet_sniffer.py`

This project captures and analyzes network traffic using a packet sniffer approach.

Key Features:
- Creates a network socket for packet-level access and raw socket communication.
- Continuously captures packets and extracts information from the ethernet frame.
- Displays information about the ethernet frame, including the destination MAC address, source MAC address, and protocol type.
- If the protocol is IPv4, it extracts and analyzes the IPv4 packet, including the version, header length, TTL (Time To Live), protocol, source IP address, and target IP address.
- Furthermore, if the protocol is ICMP, it extracts and analyzes the ICMP packet, including the type, code, and checksum.
- If the protocol is TCP or UDP, it extracts and analyzes the corresponding segment, including ports, sequence numbers, flags, and data.

## Examples

### ICMP Packet
![ICMP Packet](/Images/ICMP_Packet.png)

### TCP Segment
![TCP Segment](/Images/TCP_Segment.png)

### UDP Segment
![UDP Segment](/Images/UDP_Segment.png)