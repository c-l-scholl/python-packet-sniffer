import socket
import struct
from textwrap import *


def main():

	# modified to run on windows
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
		print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

# unpack ethernet frame

def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# return properly formatted MAC address (AA:BB:CC:DD:EE:FF)

def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()

# unpack IPv4 packet
def ipv4_packet(data):
    # header 
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4

	# other information
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[version_header_length:]

# Returns prperly formatted IPv4 address
def ipv4(addr):
	return '.'.join(map(str, addr))

# Unpacks ICMP Packet 
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[4:])
	return icmp_type, code, checksum 

# Unpack TCP Packet
def tcp_packet(data):	
	src_port, desc_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[14:])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags >> 32) * 5
	flag_ack = (offset_reserved_flags >> 16) * 4
	flag_psh = (offset_reserved_flags >> 8) * 3
	flag_rst = (offset_reserved_flags >> 4) * 2
	flag_syn = (offset_reserved_flags >> 2) * 1
	flag_fin = (offset_reserved_flags >> 1)
	return src_port, desc_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack udp packet (optional)
def udp_packet(data):
	src_port, desc_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, desc_port, size, data[8:]



if __name__ == "__main__":
	main() 