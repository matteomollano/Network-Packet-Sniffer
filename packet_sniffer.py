import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    # creating the network socket object to monitor network traffic
    # socket.AF_PACKET:
    #   - indicates that the socket will be used for packet-level access in the networking stack
    # socket.SOCK_RAW:
    #   - indicates that the socket will be a raw socket, allowing direct access to the underlying network protocols
    # socket.ntohs(3):
    #   - converts a 16-bit number from network byte order to host byte order
    #   - in this case, 3 is passed as the protocol number
    #   - this value represents the ethertype of the desired protocol. Ethertype 3 corresponds to the Internet Protocol (IP)
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        # recvfrom() is used to receive data from the socket
        # 65536 specifies the maximum amount of data to be received in a single call (65536 bytes)
        # this method will return a tuple --> (data, address)
        #   - data = packet received data
        #   - address = IP address and port number from which the packet originated
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_protocol))
        
        # 8 for IPv4
        if eth_protocol == 8:
            version, header_length, ttl, protocol, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, src, target))

            # 1 for ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
	        
	        # 6 for TCP
            elif protocol == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
	        
	        # 17 for UDP
            elif protocol == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(format_multi_line(DATA_TAB_3, data))
	        
	        # Other protocols
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        
        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))
	            
# unpacks ethernet frame
# !  - data is interpreted in network byte order - aka Big Endian notation
# 6s - 6 byte string
# H  - unsigned short int (2 bytes)
def ethernet_frame(data):
    dest_mac, dest_src, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(dest_src), socket.htons(protocol), data[14:]

# returns the properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) # creates a list of two-digit hexadecimal values
    return ':'.join(bytes_str).upper() # joins each hexadecimal value in the list into a single string,
                                       # using ":" as the separator
    
# unpacks IPv4 packet
# 8x - skip the next 8 bytes
# B  - 1 unsigned byte
# 2x - skip the next 2 bytes
# 4s - 4 byte string
def ipv4_packet(data):
    version_header_length = data[0] # 1 byte (first 4 bits = version, last 4 bits = header length)
    version = version_header_length >> 4 # extract the higher 4 bits of the version/header_length byte, yielding the version
    header_length = (version_header_length & 15) * 4 # multiply the version_header_length byte by 15 (00001111 in binary)
                                                     # to get only the last 4 digits (which represents the header length)
                                                     # then we multiply by 4 to get the actual header length in bytes
                                                     # (this is because the header length is represented in 32-bit words, each being 4 bytes)
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]
    
# returns the properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr)) # convert each digit in the IP address list to a string,
                                    # then join them into a single string with "." as the separator
     
# unpacks ICMP packet
# B - 1 unsigned byte
# H - unsigned short int (2 bytes)
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
    
# unpacks TCP segment
# H - unsigned short int (2 bytes)
# L - unsigned long int (4 bytes)
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4 # discard the lower 12 bits and multiply by 4 to get offset size in bytes 
    
    # each of the following operations:
    #   - isolates the desired bit by using bitwise AND
    #   - shifts to the desired flag using arithmetic shift right
    # this is done in order to extract the intended flag
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
# unpacks UDP segment
# H  - unsigned short int (2 bytes)
# 2x - skip the next 2 bytes
def udp_segment(data):
   src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
   return src_port, dest_port, size, data[8:]
   
   
# format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
if __name__ == "__main__":
    main()