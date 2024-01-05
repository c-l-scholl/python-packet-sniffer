'''
	This code is based on a tutorial from thenewboston on YouTube
'''

import socket
import struct
import textwrap

# Tab presets
TAB_1 = '\t'
TAB_2 = '\t\t'
TAB_3 = '\t\t\t'
TAB_4 = '\t\t\t\t'

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'


def main():

	# modified to run on windows properly
	HOST = socket.gethostbyname('192.168.84.20')
	conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP) 
 
	# create a raw socket and bind it to the public interface
	conn.bind((HOST, 0))

	# Include IP headers
	conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	#receives all packets
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	while True:
		raw_data, addr = conn.recvfrom(65535)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\nEthernet Frame')
		print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

# unpack ethernet frame

def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# return properly formatted MAC address (AA:BB:CC:DD:EE:FF)

def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()

# unpack IPv4 packet
def ipv4_packet(ipv4_data):
    # header 
	version_header_length = ipv4_data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4

	# other information
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', ipv4_data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), ipv4_data[version_header_length:]

# Returns prperly formatted IPv4 address
def ipv4(ipv4_addr):
	return '.'.join(map(str, ipv4_addr))

# Unpacks ICMP Packet 
def icmp_packet(icmp_data):
	icmp_type, code, checksum = struct.unpack('! B B H', icmp_data[4:])
	return icmp_type, code, checksum, icmp_data[:4]

# Unpack TCP Packet
def tcp_packet(tcp_data):	
	src_port, desc_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', tcp_data[14:])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags >> 32) * 5
	flag_ack = (offset_reserved_flags >> 16) * 4
	flag_psh = (offset_reserved_flags >> 8) * 3
	flag_rst = (offset_reserved_flags >> 4) * 2
	flag_syn = (offset_reserved_flags >> 2) * 1
	flag_fin = (offset_reserved_flags >> 1)
	return src_port, desc_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data[offset:]

# Unpack udp packet (optional)
def udp_packet(udp_data):
	src_port, desc_port, size = struct.unpack('! H H 2x H', udp_data[:8])
	return src_port, desc_port, size, udp_data[8:]

# Formats multi-line data 
# Not related to packet sniffing, just readability
def multiline_format(prefix, string, size = 80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = '.'.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



if __name__ == "__main__":
	main() 