import socket
import time

import common

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9000
MAX_INPUT_SIZE = 4096
MAX_BUFFER = 10 * 1024
CHUNK_SIZE = 1024  # bytes per packet
TIME_WAIT = 2

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(5)

def connect():
    seq = 0
    syn_packet = common.packet_pack(seq, 0, common.SYN, MAX_BUFFER)
    client_socket.sendto(syn_packet, (SERVER_IP, SERVER_PORT))
    print("Sent SYN")

    data, addr = client_socket.recvfrom(MAX_INPUT_SIZE)
    srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)

    if (flags & (common.SYN | common.ACK)) == (common.SYN | common.ACK):
        print("Received SYN-ACK")

        ack_packet = common.packet_pack(seq + 1, srv_seq + 1, common.ACK, MAX_BUFFER)
        client_socket.sendto(ack_packet, addr)
        print("Sent ACK → connection established")

        return addr, srv_seq + 1, seq + 1
    
    else:
        raise RuntimeError("Did not receive SYN-ACK from server")

def send_data(addr, next_seq, data):
    seq = next_seq
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]

        pkt = common.packet_pack(seq, 0, 0, MAX_BUFFER, chunk)
        client_socket.sendto(pkt, addr)
        print(f"Sent packet seq={seq}")

        while True:
            try:
                pkt_data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
                srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(pkt_data)

                if flags & common.ACK and srv_ack == seq + len(chunk):
                    print(f"Received ACK for seq={seq}")
                    seq += len(chunk)
                    break
                else:
                    print(f"Received wrong ACK (ack={srv_ack}), resending")
                    client_socket.sendto(pkt, addr)

            except socket.timeout:
                print("ACK timeout, resending packet")
                client_socket.sendto(pkt, addr)
    return seq

def send_fin(addr, seq):
    fin_pkt = common.packet_pack(seq, 0, common.FIN, MAX_BUFFER)
    retries = 0
    max_retries = 5

    while retries < max_retries:
        client_socket.sendto(fin_pkt, addr)
        print(f"Sent FIN seq={seq}")

        try:
            data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
            srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)

            if flags & common.ACK:
                print("Received ACK for FIN")
                return True

        except socket.timeout:
            retries += 1
            print(f"Timeout waiting for FIN-ACK, retry {retries}/{max_retries}")

    print("FIN ACK never received → closing anyway")
    return False

def close_connection(addr):
    try:
        data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
    except socket.timeout:
        print("No server FIN → closing")
        return

    seq, ack, flags, rwnd, payload = common.packet_unpack(data)

    if flags & common.FIN:
        print("Received server FIN")

        ack_pkt = common.packet_pack(0, seq + 1, common.ACK, MAX_BUFFER)
        client_socket.sendto(ack_pkt, addr)
        print("Sent ACK for server FIN")

        # TIME-WAIT
        print(f"Entering TIME-WAIT for {TIME_WAIT} seconds...")
        time.sleep(TIME_WAIT)

        print("Connection closed (client)")



if __name__ == "__main__":
    addr, srv_seq, next_seq = connect()

    # put data to test sending here (each as seperate message)
    test_data = [
        b"Hello server!",
        b"This is a second message."
    ]

    for data in test_data:
        next_seq = send_data(addr, next_seq, data)

    send_fin(addr, next_seq)
    close_connection(addr)