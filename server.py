import socket
import select
import time
import common
import random

# server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 9000

MAX_INPUT_SIZE = 4096 # maximum number of bytes the server will read from the UDP socket at once
MAX_BUFFER = 10 * 1024 # size of payload buffer

PROCESS_RATE = 1024 # bytes per tick (this is used to simulate pipelining / speed of server)

LOSS_RATE = 0.2

# create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.settimeout(20)
server_socket.bind((SERVER_IP, SERVER_PORT))
print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

def unreliable_sendto(packet, addr):
    if random.random() < LOSS_RATE:
        print(f"Simulated packet loss for packet {packet}")
        return
    server_socket.sendto(packet, addr)

# server side of 3 way handshake to initiate connection
def accept_connection():
    while True: # if after timeout there's no activity, it's the client's responsibility to resend their packet. so here server just waits to receive packets
        data, addr = server_socket.recvfrom(MAX_INPUT_SIZE) # receive packet
        seq, ack, flags, _, _ = common.packet_unpack(data) # unpack the packet

        if flags & common.SYN: # check if SYN bit is set
            print(f"Received SYN from {addr}, seq={seq}")
            server_seq = 1 # starting sequence number of 1

            syn_ack_packet = common.packet_pack(server_seq, seq + 1, common.SYN | common.ACK, MAX_BUFFER) # create a SYN-ACK packet
            unreliable_sendto(syn_ack_packet, addr) # send SYN-ACK packet
            print(f"Sent SYN-ACK to {addr}, ack={seq+1}")
        elif flags & common.ACK: # check if ACK bit is set
            # Received ACK
            print(f"Connection established with {addr}")
            return addr, server_seq
        else: # if client started transmitting data, assume client ACK was lost but they did get server SYN-ACK
            print("ACK not received, but assume connection established anyway")
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
                fin_ack_packet = common.packet_pack(ack, expected_seq+1, common.ACK, MAX_BUFFER - len(buffer))
                unreliable_sendto(fin_ack_packet, addr)

            # if expected packet arrives
            elif seq == expected_seq:
                buffer.extend(payload) # add payload to buffer to process

                print(f"Received expected packet seq={seq}, payload={payload}")
                expected_seq += len(payload) # seq number is bytes not packets
                
                # send an ack indicating want the next packet
                ack_packet = common.packet_pack(ack, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                unreliable_sendto(ack_packet, addr)

            # out of order packet
            else:
                print(f"Out-of-order packet seq={seq}, expected={expected_seq}")

                # resend ack for last correctly received packet
                ack_packet = common.packet_pack(ack, expected_seq, common.ACK, MAX_BUFFER - len(buffer))
                unreliable_sendto(ack_packet, addr)
        
        if len(buffer) > 0: # simulates how in real world scenarios, data needs to be processed as well as accepted (allows for pipelining)
            to_process = min(PROCESS_RATE, len(buffer))
            time.sleep(0.01)
            buffer = buffer[to_process:]

        if fin_received and len(buffer) == 0: # FIN received and all payloads processed
            return ack, expected_seq + 1

# close connection after receiving a FIN and processing all payloads
def close_connection(addr, server_fin_seq, server_fin_ack):
    # send a FIN
    server_fin = common.packet_pack(server_fin_seq, server_fin_ack, common.FIN, MAX_BUFFER)
    unreliable_sendto(server_fin, addr)
    print("Server FIN sent, waiting for client ACK")

    while True:
        try:
            data, _ = server_socket.recvfrom(MAX_INPUT_SIZE)
            seq, ack, flags, _, _ = common.packet_unpack(data)

            # if we get another client FIN (both our FIN-ACK and FIN were lost) retransmit until we no longer get client FIN
            if flags & common.FIN:
                print("Received FIN again, resent server FIN")
                unreliable_sendto(server_fin, addr)
            elif flags & common.ACK and ack == server_fin_seq + 1: # if we get client ACK, close connection
                print("Received ACK for FIN from client")
                break
        except socket.timeout: # if client stops sending packets, close connection
            print("Wait for ACK from client timed out")
            break

    print("Connection closed (server)")
    return


if __name__ == "__main__":
    client_addr, server_seq = accept_connection() # first need to initiate connection
    fin_seq, fin_ack = receive_data(client_addr) # then receive data
    close_connection(client_addr, fin_seq, fin_ack) # then close connection