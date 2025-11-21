import socket
import time

import common

# server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9000

MAX_INPUT_SIZE = 4096 # maximum number of bytes the client will read from the UDP socket at once
MAX_BUFFER = 10 * 1024
CHUNK_SIZE = 1024  # bytes per packet
TIME_WAIT = 2 # wait time once send final ACK

# create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(5)

def connect():
    seq = 0 # set initial sequence number

    # send initial SYN to server
    syn_packet = common.packet_pack(seq, 0, common.SYN, 0)
    client_socket.sendto(syn_packet, (SERVER_IP, SERVER_PORT))
    print("Sent SYN")

    seq += 1

    # receive server response to SYN
    data, addr = client_socket.recvfrom(MAX_INPUT_SIZE)
    srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)

    # if response is a SYN-ACK with correct ack number
    if (flags & (common.SYN | common.ACK)) == (common.SYN | common.ACK) and srv_ack == seq:
        print("Received SYN-ACK")

        # send ACK for SYN-ACK
        ack_packet = common.packet_pack(seq, srv_seq + 1, common.ACK, 0)
        client_socket.sendto(ack_packet, addr)
        print("Sent ACK → connection established")

        return addr, seq
    
    # if didn't receive SYN-ACK abort
    else:
        raise RuntimeError("Did not receive SYN-ACK from server")

def send_data(addr, next_seq, data):
    seq = next_seq # sequence number of next byte to send
    send_base = seq # sequence number of the oldest unacknowledged bye
    buffer = {} # keeps track of packets that have been sent but not acknowledged - key is sequence number
    dup_acks = 0  # counts duplicate acks
    cwnd = 1.0 # initial cwnd
    data_len = len(data)
    offset = 0 # current position in data payload
    rwnd = MAX_BUFFER  # initialize rwnd to max, will update with server ACKs
    ssthresh = 8192

    while send_base < next_seq + data_len or buffer:
        # send as many packets as window allows (cwnd and rwnd)
        while offset < data_len and sum(length for (_, length) in buffer.values()) < min(cwnd, rwnd):
            chunk = data[offset:offset+CHUNK_SIZE]
            pkt = common.packet_pack(seq, 0, 0, MAX_BUFFER, chunk)
            client_socket.sendto(pkt, addr)
            buffer[seq] = (pkt, len(chunk))
            print(f"Sent packet seq={seq}")
            seq += len(chunk)
            offset += len(chunk)

        # wait for ACKs
        try:
            pkt_data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
            srv_seq, srv_ack, flags, rwnd_new, _ = common.packet_unpack(pkt_data)

            if flags & common.ACK:
                # Duplicate ACK
                if srv_ack == send_base:
                    dup_acks += 1
                    print(f"Duplicate ACK for seq={srv_ack} ({dup_acks}x)")
                    if dup_acks == 3 and send_base in buffer:
                        # Fast retransmit: retransmit send_base packet
                        print(f"Fast retransmit triggered for seq={send_base}")
                        client_socket.sendto(buffer[send_base][0], addr)
                        ssthresh = max(cwnd // 2, CHUNK_SIZE)
                        cwnd = ssthresh
                        print(f"cwnd reduced to {cwnd}")
                elif srv_ack > send_base:
                    # New ACK: slide window
                    acked_seqs = [s for s in buffer if s + buffer[s][1] <= srv_ack]
                    for s in acked_seqs:
                        del buffer[s]
                    send_base = srv_ack
                    dup_acks = 0  # reset duplicate ACKs

                    # AIMD congestion control
                    if cwnd < ssthresh:
                        cwnd += CHUNK_SIZE / cwnd # slow start (exponential)
                    else:
                        cwnd += 1  # linear
                    print(f"Received ACK for seq={srv_ack}, cwnd now {cwnd}")
            rwnd = rwnd_new  # update receiver window

        except socket.timeout:
            # retransmit oldest unacked packet
            if buffer:
                oldest_seq = min(buffer.keys())
                client_socket.sendto(buffer[oldest_seq][0], addr)
                print(f"Timeout: retransmitting seq={oldest_seq}")
                ssthresh = max(cwnd // 2, CHUNK_SIZE)
                cwnd = CHUNK_SIZE
                print(f"Timeout → cwnd reset to {cwnd}, ssthresh={ssthresh}")
                dup_acks = 0

    return seq

def send_fin(addr, seq):
    fin_pkt = common.packet_pack(seq, 0, common.FIN, MAX_BUFFER)
    client_socket.sendto(fin_pkt, addr)
    print(f"Sent FIN seq={seq}")

    data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
    srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)

    if flags & common.ACK:
        print("Received ACK for FIN")
        return True

    else:
        print("FIN ACK never received → closing anyway")
        return False

def close_connection(addr, client_seq):
    try:
        data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
    except socket.timeout:
        print("No server FIN → closing")
        return

    seq, ack, flags, rwnd, payload = common.packet_unpack(data)

    if flags & common.FIN:
        print("Received server FIN")

        ack_pkt = common.packet_pack(client_seq, seq + 1, common.ACK, MAX_BUFFER)
        client_socket.sendto(ack_pkt, addr)
        print("Sent ACK for server FIN")

        # TIME-WAIT
        print(f"Entering TIME-WAIT for {TIME_WAIT} seconds...")
        time.sleep(TIME_WAIT)

        print("Connection closed (client)")



if __name__ == "__main__":
    addr, next_seq = connect()

    # put test data here (each component will be sent as seperate message)
    test_data = [
        b"Hello server!",
        b"This is a second message."
    ]

    for data in test_data:
        next_seq = send_data(addr, next_seq, data)

    send_fin(addr, next_seq)
    close_connection(addr, next_seq)