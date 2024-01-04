from socket import *
import struct
from textwrap import *

# watch tutorial on sockets

# unpack ethernet frame
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# return properly formatted MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
	bytes_string = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_addr).upper()

