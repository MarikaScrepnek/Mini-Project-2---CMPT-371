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

# receive data
def receive_data(addr):
    expected_seq = 1 # starting sequence number
    buffer = bytearray() # buffer to hold incoming payloads
    fin_received = False # bool saying if the client's FIN has been received

    while True:
        new_data = select.select([server_socket], [], [], 0.1)[0] # non blocking socket
        if new_data: # if there's new data to accept
            data, _ = server_socket.recvfrom(MAX_INPUT_SIZE) # accept new data
            seq, ack, flags, rwnd, payload = common.packet_unpack(data) # unpack header and payload of the incoming packet

            if flags & common.FIN and seq == expected_seq: # if the packet has FIN bit
                fin_received = True # set FIN receiving bool to true
                buffer.extend(payload) # add the payload to the data to process buffer

                # send an ACK for FIN
                print("Received FIN")
                fin_ack_packet = common.packet_pack(0, seq+1, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(fin_ack_packet, addr)

            # if expected packet arrives
            elif seq == expected_seq:
                buffer.extend(payload) # add payload to buffer to process

                print(f"Received expected packet seq={seq}, payload={payload}")
                expected_seq += len(payload) # seq number is bytes not packets
                
                # send an ack indicating want the next packet
                ack_packet = common.packet_pack(0, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(ack_packet, addr)

            # out of order packet
            else:
                print(f"Out-of-order packet seq={seq}, expected={expected_seq}")

                # resend ack for last correctly received packet
                ack_packet = common.packet_pack(0, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                server_socket.sendto(ack_packet, addr)
        
        if len(buffer) > 0: # simulates how in real world scenarios, data needs to be processed as well as accepted (allows for pipelining)
            to_process = min(PROCESS_RATE, len(buffer))
            time.sleep(0.01)
            buffer = buffer[to_process:]

        if fin_received and len(buffer) == 0: # FIN received and all payloads processed
            return expected_seq

# close connection after receiving a FIN and processing all payloads
def close_connection(addr, expected_seq):
    # send a FIN
    server_fin = common.packet_pack(0, expected_seq, common.FIN, MAX_BUFFER)
    server_socket.sendto(server_fin, addr)
    print("Server FIN sent, waiting for client ACK")

    # set a timeout for the socket incase FIN ACK never arrives
    server_socket.settimeout(5)

    # receive data from socket
    data, _ = server_socket.recvfrom(MAX_INPUT_SIZE)
    seq, ack, flags, _, _ = common.packet_unpack(data)

    # if ACK for FIN received, close connection
    if flags & common.ACK and seq == expected_seq:
        print("Connection fully closed")
        return
    # still close connection if FIN ACK isn't received
    else:
        print("FIN ACK not received, closing connection anyway")
        return


if __name__ == "__main__":
    client_addr, server_seq = accept_connection() # first need to initiate connection
    expected_seq = receive_data(client_addr) # then receive data
    close_connection(client_addr, expected_seq) # then close connection