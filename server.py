import socket
import select
import time

import common


# server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 9000

MAX_INPUT_SIZE = 4096 # maximum number of bytes the server will read from the UDP socket at once
MAX_BUFFER = 10 * 1024 # size of payload buffer
PROCESS_RATE = 1024 # bytes per tick (this is used to simulate pipelining / speed of server)

# create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

# server side of 3 way handshake to initiate connection
def accept_connection():
    while True:
        data, addr = server_socket.recvfrom(MAX_INPUT_SIZE) # receive packet
        seq, ack, flags, _, _ = common.packet_unpack(data) # unpack the packet

        if flags & common.SYN: # check if SYN bit is set
            print(f"Received SYN from {addr}, seq={seq}")
            server_seq = 1 # starting sequence number of 1

            syn_ack_packet = common.packet_pack(server_seq, seq + 1, common.SYN | common.ACK, MAX_BUFFER) # create a SYN-ACK packet
            server_socket.sendto(syn_ack_packet, addr) # send SYN-ACK packet
            print(f"Sent SYN-ACK to {addr}, seq={server_seq}, ack={seq+1}")

            data, addr2 = server_socket.recvfrom(MAX_INPUT_SIZE) # receive packet
            seq2, ack2, flags2, _, _ = common.packet_unpack(data) # unpack the packet
            if flags2 & common.ACK: # if this packet is and ACK, connection is established
                print(f"Connection established with {addr}")
                return addr, server_seq


# receive data / FIN after connection initiated
def receive_data(addr):
    expected_seq = 1
    buffer = bytearray()
    fin_received = False

    while True:
        new_data = select.select([server_socket], [], [], 0.1)[0] # non blocking socket
        if not fin_received and new_data:
            data, _ = server_socket.recvfrom(MAX_INPUT_SIZE)
            seq, ack, flags, rwnd, payload = common.packet_unpack(data)

            if flags & common.FIN:
                fin_received = True
                buffer.extend(payload)

                # send an ACK for FIN
                print("Received FIN")
                fin_ack_packet = common.packet_pack(0, seq+1, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(fin_ack_packet, addr)
            
            # if expected packet arrives
            elif seq == expected_seq:
                buffer.extend(payload)

                print(f"Received expected packet seq={seq}, payload={payload}")
                expected_seq += len(payload) # seq number is bytes not packets
                
                ack_packet = common.packet_pack(0, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(ack_packet, addr)

            # out of order packet
            else:
                print(f"Out-of-order packet seq={seq}, expected={expected_seq}")
                ack_packet = common.packet_pack(0, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(ack_packet, addr)
        
        if len(buffer) > 0: # simulates how in real world scenarios, data needs to be processed
            to_process = min(PROCESS_RATE, len(buffer))
            time.sleep(0.01)
            buffer = buffer[to_process:]

        if fin_received and len(buffer) == 0:
            return expected_seq

def close_connection(addr, expected_seq):
    server_fin = common.packet_pack(0, expected_seq, common.FIN, MAX_BUFFER)
    server_socket.sendto(server_fin, addr)
    print("Server FIN sent, waiting for client ACK")

    server_socket.settimeout(5)

    data, _ = server_socket.recvfrom(MAX_INPUT_SIZE)
    seq, ack, flags, _, _ = common.packet_unpack(data)
    if flags & common.ACK and seq == expected_seq+1:
        print("Connection fully closed")
        return
    else:
        print("FIN ACK not received, closing connection anyway")
        return


if __name__ == "__main__":
    client_addr, server_seq = accept_connection() # first need to initiate connection
    expected_seq = receive_data(client_addr) # then receive data
    close_connection(client_addr, expected_seq)