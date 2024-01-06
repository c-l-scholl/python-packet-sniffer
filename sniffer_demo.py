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
	HOST = socket.gethostbyname(socket.gethostname())
	conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) 
 
	# Create a raw socket and bind it to the public interface
	conn.bind((HOST, 0))

	# Include IP headers
	conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# receive all packets
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	while True:
		raw_data, addr = conn.recvfrom(65535)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\nEthernet Frame')
		print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

		# Use protocol 8 for IPv4 (regular internet traffic)
		if eth_proto == 8:
			(ipv4_vers, ipv4_header_len, ipv4_ttl, ipv4_proto, ipv4_src, ipv4_target, ipv4_data) = ipv4_packet(data)

			# print ivp4 packet info
			print(TAB_1 + 'IPv4 Packet:')
			print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(ipv4_vers, ipv4_header_len, ipv4_ttl))
			print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4_proto, ipv4_src, ipv4_target))

			# get type of packet by protocol

			# ICMP
			if ipv4_proto == 1:
				icmp_type, icmp_code, icmp_checksum, icmp_data = icmp_packet(ipv4_data)

				# print ICMP packet info
				print(TAB_1 + 'ICMP Packet:')
				print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, icmp_code, icmp_checksum))
				print(TAB_2 + 'Data:')
				print(multiline_format(DATA_TAB_3, icmp_data))

			# TCP
			elif ipv4_proto == 6:
				(tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data) = tcp_packet(ipv4_data)

				# print TCP Segment info
				print(TAB_1 + 'TCP Segment:')
				print(TAB_2 + 'Source: {}, Destination: {}'.format(tcp_src_port, tcp_dest_port))
				print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(tcp_sequence, tcp_acknowledgement))
				print(TAB_2 + 'Flags:')
				print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				print(TAB_2 + 'Data:')
				print(multiline_format(DATA_TAB_3, tcp_data))


			# UDP
			elif ipv4_proto == 17:
				udp_src_port, udp_dest_port, udp_length, udp_data = udp_packet(ipv4_data)

				# Print UDP Segment
				print(TAB_1 + 'UDP Segment:')
				print(TAB_2 + 'Source: {}, Destination: {}, Length: {}'.format(udp_src_port, udp_dest_port, udp_length))
				print(TAB_2 + 'Data:')
				print(multiline_format(DATA_TAB_3, udp_data))

			# Other protocols
			else:
				print(TAB_1 + 'Data:')
				print(multiline_format(DATA_TAB_2, ipv4_data))

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
	src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', tcp_data[14:])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags >> 32) * 5
	flag_ack = (offset_reserved_flags >> 16) * 4
	flag_psh = (offset_reserved_flags >> 8) * 3
	flag_rst = (offset_reserved_flags >> 4) * 2
	flag_syn = (offset_reserved_flags >> 2) * 1
	flag_fin = (offset_reserved_flags >> 1)
	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data[offset:]

# Unpack udp packet (optional)
def udp_packet(udp_data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', udp_data[:8])
	return src_port, dest_port, size, udp_data[8:]

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