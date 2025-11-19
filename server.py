import socket
import common

# server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 9000
BUFFER_SIZE = 4096 # maximum number of bytes the server will read from the UDP socket at once
RWND = 10 * 1024

# create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

# server side of 3 way handshake to initiate connection
def accept_connection():
    while True:
        data, addr = server_socket.recvfrom(BUFFER_SIZE) # receive packet
        seq, ack, flags, rwnd, payload = common.packet_unpack(data) # unpack the packet

        if flags & common.SYN: # check if SYN bit is set
            print(f"Received SYN from {addr}, seq={seq}")
            server_seq = 1 # starting sequence number of 1

            syn_ack_packet = common.packet_pack(server_seq, seq + 1, common.SYN | common.ACK, RWND) # create a SYN-ACK packet
            server_socket.sendto(syn_ack_packet, addr) # send SYN-ACK packet
            print(f"Sent SYN-ACK to {addr}, seq={server_seq}, ack={seq+1}")

            data, addr2 = server_socket.recvfrom(BUFFER_SIZE) # receive packet
            seq2, ack2, flags2, rwnd2, payload2 = common.packet_unpack(data) # unpack the packet
            if flags2 & ACK: # if this packet is and ACK, connection is established
                print(f"Connection established with {addr}")
                return addr, server_seq


# receive data / FIN after connection initiated
def receive_data(addr, expected_seq = 0):
    while True:
        data, _ = server_socket.recvfrom(BUFFER_SIZE)
        seq, ack, flags, rwnd, payload = common.packet_unpack(data)

        if flags & common.FIN:
            # send an ACK for FIN
            print("Received FIN, closing connection")
            fin_ack_packet = common.packet_pack(0, seq+1, ACK, RWND)
            server_socket.sendto(fin_ack_packet, addr)

            # send server FIN
            server_fin = common.packet_pack(0, seq+1, FIN, RWND)
            server_socket.sendto(server_fin, addr)

            # wait for ACK of FIN
            data, _ = server_socket.recvfrom(BUFFER_SIZE)
            seq2, ack2, flags2, rwnd2, payload2 = common.packet_unpack(data)
            if flags2 & common.ACK:
                print("Connection closed")
                break
        
        # if expected packet arrives
        if seq == expected_seq:
            print(f"Received expected packet seq={seq}, payload={payload}")
            expected_seq += len(payload) # seq number is bytes not packets
            
            ack_packet = common.packet_pack(0, expected_seq, ACK, RWND)
            server_socket.sendto(ack_packet, addr)

        # out of order packet
        else:
            print(f"Out-of-order packet seq={seq}, expected={expected_seq}")
            ack_packet = common.packet_pack(0, expected_seq, ACK, RWND)
            server_socket.sendto(ack_packet, addr)


if __name__ == "__main__":
    client_addr, server_seq = accept_connection() # first need to initiate connection
    receive_data(client_addr) # then receive data