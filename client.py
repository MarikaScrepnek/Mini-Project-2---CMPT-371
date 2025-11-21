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
client_socket.settimeout(5) # set socket to timeout after 5 seconds of waiting

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

        return addr, seq, srv_seq + 1
    
    # if didn't receive SYN-ACK abort
    else:
        raise RuntimeError("Did not receive SYN-ACK from server")

def send_data(addr, next_seq, ack, data):
    # can modify this to see behavioral changes for congestion control
    init_cwnd = CHUNK_SIZE # 1 MSS
    init_ssthresh = 10000 # can start large, will be adjusted on loss

    seq = next_seq # sequence number of next byte to send
    send_base = seq # sequence number of the oldest unacknowledged byte
    buffer = {} # keeps track of packets that have been sent but not acknowledged (sender window) - key is sequence number
    dup_acks = 0  # counts duplicate acks
    data_len = len(data)
    offset = 0 # current position in data payload
    rwnd = MAX_BUFFER  # initialize rwnd to max, will update with server ACKs

    cwnd = init_cwnd # initial cwnd
    ssthresh = init_ssthresh # inital ssthresh

    # while there's still data to send or unackowledged packets
    while send_base < next_seq + data_len or buffer:
        # while there's still data to send and theres room for more unacked packets - limited by either cwnd or rwnd (whichever is more restricting)
        while offset < data_len and sum(length for (_, length) in buffer.values()) < min(cwnd, rwnd):
            chunk = data[offset:offset+CHUNK_SIZE] # grab next chunk of data to send
            pkt = common.packet_pack(seq, ack, 0, MAX_BUFFER, chunk) # create a packet with that chunk *****
            client_socket.sendto(pkt, addr) # send packet to server
            buffer[seq] = (pkt, len(chunk)) # add packet to unackowledged packet buffer
            print(f"Sent packet seq={seq}")
            # update variables
            seq += len(chunk)
            offset += len(chunk)

        # wait for ACKs
        try:
            pkt_data, _ = client_socket.recvfrom(MAX_INPUT_SIZE) # receive message from server
            srv_seq, srv_ack, flags, rwnd_new, _ = common.packet_unpack(pkt_data) # unpack the header
            rwnd = rwnd_new  # update receiver window

            # if the message is an ACK
            if flags & common.ACK:
                # Duplicate ACK
                if srv_ack == send_base: # have everything up to send_base, and still missing the next byte (didn't receive send_base)
                    # increment duplicate ack count
                    dup_acks += 1
                    print(f"Duplicate ACK for seq={srv_ack} ({dup_acks}x)")
                    # if the duplicate ack count is 3 and we still have send_base in the unacked buffer to send
                    if dup_acks == 3 and send_base in buffer:
                        print(f"Fast retransmit triggered for seq={send_base}")
                        client_socket.sendto(buffer[send_base][0], addr) # resend the packet

                        # congestion control update (loss detected)
                        ssthresh = max(cwnd // 2, CHUNK_SIZE) # set ssthresh to half of cwnd at loss (has to be at least the size of one packet)
                        cwnd = init_cwnd
                        print(f"cwnd reduced to {cwnd}")
                # new ACK
                elif srv_ack > send_base:
                    # slide sender window forward (remove ack packets from buffer, and push send_base forward)
                    acked_seqs = [s for s in buffer if s + buffer[s][1] <= srv_ack]
                    for s in acked_seqs:
                        del buffer[s]
                    send_base = srv_ack
                    ack = send_base

                    dup_acks = 0  # reset duplicate ACKs

                    # slow start (exponential)
                    if cwnd < ssthresh:
                        cwnd += CHUNK_SIZE
                    # congestion avoidance (linear)
                    else:
                        cwnd += CHUNK_SIZE * (CHUNK_SIZE / cwnd) # linear
                    print(f"Received ACK for seq={srv_ack}, cwnd now {cwnd}")

        # window timeout (another indication of loss)
        except socket.timeout:
            # if there's inflight unacked packets
            if buffer:
                # resend the lowest sequence number packet of unacked packets
                oldest_seq = min(buffer.keys())
                client_socket.sendto(buffer[oldest_seq][0], addr)
                print(f"Timeout: retransmitting seq={oldest_seq}")
                
                # loss, so reset cwnd and set ssthresh to half of cwnd at loss
                ssthresh = max(cwnd // 2, CHUNK_SIZE)
                cwnd = init_cwnd
                print(f"Timeout → cwnd reset to {cwnd}, ssthresh={ssthresh}")

                dup_acks = 0 # reset duplicate ack count
    return seq, ack # all data has been sent and acked

def close_connection(addr, seq, ack):
    # send a fin packet
    fin_pkt = common.packet_pack(seq, ack, common.FIN, MAX_BUFFER) #***
    client_socket.sendto(fin_pkt, addr)
    print(f"Sent FIN seq={seq}")
    seq += 1

    try:
        # receive data from server
        data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
        srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)
        ack = srv_seq + 1

        # if its an ACK we received an ACK for our fin
        if flags & common.ACK:
            print("Received ACK for FIN")

    except socket.timeout:
        print("FIN ACK not received, closing anyway")

        # enter timed wait
        print(f"Entering TIME-WAIT for {TIME_WAIT} seconds...")
        time.sleep(TIME_WAIT)

        # shut down
        print("Connection closed (client)")
        return

    try:
        data, _ = client_socket.recvfrom(MAX_INPUT_SIZE)
        srv_seq, srv_ack, flags, rwnd, _ = common.packet_unpack(data)
        ack = srv_seq + 1

        if flags & common.FIN:
            print("Received server FIN")

            # send ACK for server FIN
            ack_pkt = common.packet_pack(seq, ack, common.ACK, MAX_BUFFER)
            client_socket.sendto(ack_pkt, addr)
            print("Sent ACK for server FIN")
    
    except socket.timeout:
        print("FIN not received, closing anyway")

    # enter timed wait
    print(f"Entering TIME-WAIT for {TIME_WAIT} seconds...")
    time.sleep(TIME_WAIT)

    # shut down
    print("Connection closed (client)")

    return



if __name__ == "__main__":
    addr, next_seq, ack = connect()

    # put test data here (each component will be sent as seperate message)
    test_data = [
        b"Hello server!",
        b"This is a second message."
    ]

    # send each test data
    for data in test_data:
        next_seq, ack = send_data(addr, next_seq, ack, data)

    close_connection(addr, next_seq, ack)