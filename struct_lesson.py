from struct import *


# first learn how to use struct (data to bytes)
# serialization
packed_data = pack('iif', 6, 19, 4.23)
#					iif means integer, integer, float
#					followed by comma separated values
print(packed_data)
print(calcsize('i'))
print(calcsize('f'))
print(calcsize('iif'))

# to return from byte to data
unpacked_data = unpack('iif', packed_data)
print(unpacked_data)

print(unpack('iif', b'\x06\x00\x00\x00\x13\x00\x00\x00)\\\x87@'))
# unpack() returns a tuple
# need leading b (not in quotes)