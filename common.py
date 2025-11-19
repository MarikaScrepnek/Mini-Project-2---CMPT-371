import struct

# defines packet structure, constants, and 

# use bit masks for flags (more efficient)
SYN = 1 # 001
ACK = 2 # 010
FIN = 4 # 100

# define the header of a packet
HEADER_FORMAT = "!I I B I" # header format - ! states big endian, I is 4 byte, B is 1 byte (seq, ack, flags, rwnd)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# function to construct a packet given seq, ack, flags, and payload
def packet_pack(seq, ack, flags, rwnd, payload=b""):
    if payload is None:
        payload=b""
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, rwnd)
    return header + payload

# function to parse a received packet
def packet_unpack(packet):
    header = packet[:HEADER_SIZE]
    payload = packet[HEADER_SIZE:]

    seq, ack, flags, rwnd = struct.unpack(HEADER_FORMAT, header)
    return seq, ack, flags, rwnd, payload