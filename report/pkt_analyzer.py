from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
from scapy.layers.inet import TCP, IP
import matplotlib.pyplot as plt
import numpy as np

conf.verb = 0
pcapfile = 'TCP_PKTS.pcap'  # read file name
connection = 'connection.txt'
timedata = {}

packet_size = []
ackpkt = {}

'''
This is the skeleton code for the packet analyzer. You will need to complete the functions below. Note that 
you cannot modify the function signatures. You can add additional functions if you wish.
'''


def packet_info(pcap_file, save_file):
    '''
    :param pcap_file: path to pcap file
    :param save_file: path to save file of results
    :return: not specified
    '''
    # Open the pcap file
    packets = rdpcap(pcap_file)
    tcpConn = set()
    with open(save_file, 'w') as f:
        # Loop through all packets in the pcap file
        for packet in packets:
            if packet.haslayer('IP') and packet['IP'].version == 4:  # Check if it is an IP packet
                if 'TCP' in packet:
                    src_ip = packet['IP'].src
                    dst_ip = packet['IP'].dst
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    conn = (src_ip, src_port, dst_ip, dst_port)
                    # seq = packet['TCP'].seq
                    # ack = packet['TCP'].ack
                    if tcpConn.__contains__(conn):
                        continue
                    tcpConn.add(conn)
                    str = f'{conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]}'
                    f.write(str + '\n')


# iterate over each packet in the pcap file
def http_stream_analyzer(pcapfile, savefile, client_ip_prev, server_ip_prev, client_port_prev):
    """
    :param pcapfile: path to pcap file
    :param savefile: path to save file of analysis results
    :param client_ip_prev: ip address of client of HTTP stream waiting for analysis
    :param server_ip_prev: server ip address of HTTP stream waiting for analysis
    :param client_port_prev: port of client of HTTP stream waiting for analysis
    :return: not specified
    """
    packets = rdpcap(pcapfile)
    with open(savefile, 'w') as f:
        for pkt in packets:
            if pkt.haslayer('IP') and pkt.haslayer('TCP'):
                src_ip = pkt['IP'].src
                dst_ip = pkt['IP'].dst
                src_port = pkt['TCP'].sport
                dst_port = pkt['TCP'].dport
                if src_port == 80:
                    server_ip = src_ip
                    client_ip = dst_ip
                    client_port = dst_port
                elif dst_port == 80:
                    server_ip = dst_ip
                    client_ip = src_ip
                    client_port = src_port
                else:
                    continue
                if client_ip == client_ip_prev and server_ip == server_ip_prev and client_port == client_port_prev:
                    if pkt.haslayer(HTTPRequest):
                        version = pkt[HTTP].Http_Version.decode()
                        method = pkt[HTTPRequest].Method.decode()
                        path = pkt[HTTPRequest].Path.decode()
                        print(method + ' ' + path + ' ' + version, file=f)
                    elif pkt.haslayer(HTTPResponse):
                        version = pkt[HTTP].Http_Version.decode()
                        status_code = pkt[HTTPResponse].Status_Code.decode()
                        reason_phrase = pkt[HTTPResponse].Reason_Phrase.decode()
                        print(version + ' ' + status_code + ' ' + reason_phrase, file=f)
                    else:
                        print('..NO HEADER..', file=f)


def tcp_stream_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    """
    :param file: path to pcap file
    :param savefile: path to save file of analysis results
    :param client_ip_prev: ip address of client of TCP stream waiting for analysis
    :param server_ip_prev: ip address of server of TCP stream waiting for analysis
    :param client_port_prev: port of client of TCP stream waiting for analysis
    :param server_port_prev: port of server of TCP stream waiting for analysis
    :return: not specified
    """
    packets = rdpcap(file)
    packet_num = 0
    direction = ''
    server_seq = 0
    client_seq = 0
    rel_seq = 0
    rel_ack = 0
    with open(savefile, 'w') as f:
        # Server : 14.117.43.13:443 <-> Client : 11.28.187.144:1433
        print(f'Server : {server_ip_prev}:{server_port_prev} <-> Client : {client_ip_prev}:{client_port_prev}', file=f)

        for packet in packets:
            if 'TCP' in packet:
                src_ip = packet.payload.src
                dst_ip = packet.payload.dst
                src_port = packet.payload.sport
                dst_port = packet.payload.dport

                # src_ip = packet['IP'].src
                # dst_ip = packet['IP'].dst
                # src_port = packet['TCP'].sport
                # dst_port = packet['TCP'].dport
                isPkt = 0
                if src_ip == client_ip_prev and dst_ip == server_ip_prev and src_port == client_port_prev and dst_port == server_port_prev:
                    # client to server
                    isPkt = 1
                    direction = 'Client -> Server'
                    packet_num += 1
                    seq = packet['TCP'].seq
                    ack = packet['TCP'].ack
                    if client_seq == 0:  # first packet
                        client_seq = seq
                    rel_seq = seq - client_seq
                    rel_ack = ack - server_seq
                    if server_seq == 0:
                        rel_ack = 0
                elif src_ip == server_ip_prev and dst_ip == client_ip_prev and src_port == server_port_prev and dst_port == client_port_prev:
                    # server to client
                    isPkt = 1
                    direction = 'Server -> Client'
                    packet_num += 1
                    seq = packet['TCP'].seq
                    ack = packet['TCP'].ack
                    if server_seq == 0:
                        server_seq = seq
                    rel_seq = seq - server_seq
                    rel_ack = ack - client_seq

                if isPkt == 1:
                    flags = ''
                    field = packet['TCP'].flags
                    if field & 0x01:
                        flags += 'F'  # FIN
                    if field & 0x02:
                        flags += 'S'  # SYN
                    if field & 0x04:
                        flags += 'R'  # RST
                    if field & 0x08:
                        flags += 'P'  # PSH
                    if field & 0x10:
                        flags += 'A'  # ACK
                    if field & 0x20:
                        flags += 'U'  # URG
                    if field & 0x40:
                        flags += 'E'  # ECE
                    if field & 0x80:
                        flags += 'C'  # CWR

                    print(
                        f'{direction} Num: {packet_num}, SEQ: {rel_seq}, ACK: {rel_ack} {flags}', file=f)


def my_tcp_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    packets = rdpcap(file)
    packet_num = 0
    direction = ''
    server_seq = 0
    client_seq = 0
    rel_seq = 0
    rel_ack = 0

    basetime = 0
    flag = True
    last_ack = 0

    with open(savefile, 'w') as f:
        # Server : 14.117.43.13:443 <-> Client : 11.28.187.144:1433
        print(f'Server : {server_ip_prev}:{server_port_prev} <-> Client : {client_ip_prev}:{client_port_prev}', file=f)

        for packet in packets:
            # if packet.haslayer(IP) and 'TCP' in packet:
            if 'TCP' in packet:
                src_ip = packet.payload.src
                dst_ip = packet.payload.dst
                src_port = packet.payload.sport
                dst_port = packet.payload.dport
                isPkt = 0

                time = packet.time

                if src_ip == client_ip_prev and dst_ip == server_ip_prev and src_port == client_port_prev and dst_port == server_port_prev:
                    # client to server
                    isPkt = 1
                    direction = 'Client -> Server'
                    seq = packet['TCP'].seq
                    ack = packet['TCP'].ack

                    # Task 2
                    if flag:
                        if last_ack == 0:
                            last_ack = ack

                        else:
                            size = ack - last_ack
                            packet_size.append(size)
                            flag = False # avoid calculating the same ack
                            last_ack = ack

                elif src_ip == server_ip_prev and dst_ip == client_ip_prev and src_port == server_port_prev and dst_port == client_port_prev:
                    # server to client
                    isPkt = 1
                    direction = 'Server -> Client'
                    if basetime == 0:
                        basetime = time

                    timedata[float(time - basetime)] = len(packet['TCP'])

                    flag = True

                if isPkt == 1:
                    flags = ''
                    field = packet['TCP'].flags
                    if field & 0x01:
                        flags += 'F'  # FIN
                    if field & 0x02:
                        flags += 'S'  # SYN
                    if field & 0x04:
                        flags += 'R'  # RST
                    if field & 0x08:
                        flags += 'P'  # PSH
                    if field & 0x10:
                        flags += 'A'  # ACK
                    if field & 0x20:
                        flags += 'U'  # URG
                    if field & 0x40:
                        flags += 'E'  # ECE
                    if field & 0x80:
                        flags += 'C'  # CWR
                    print(
                        f'{direction} Num: {packet_num}, SEQ: {rel_seq}, ACK: {rel_ack} {flags} ',
                        file=f)


def draw(time_interval):  # Define the time interval to group packets within
    # Initialize lists to store the grouped packet sizes and timestamps
    grouped_packet_sizes = []
    grouped_timestamps = []

    # Loop through the dictionary and group packets within the time interval
    curr_packet_size = 0
    curr_timestamp = None
    for timestamp, packet_size in timedata.items():
        # Check if this is the first packet in the group
        if curr_timestamp is None:
            curr_timestamp = timestamp
            curr_packet_size = packet_size
        # Check if this packet is within the time interval of the current group
        elif timestamp - curr_timestamp <= time_interval:
            curr_packet_size += packet_size
        # This packet is outside the time interval of the current group, so start a new group
        else:
            grouped_packet_sizes.append(curr_packet_size)
            grouped_timestamps.append(curr_timestamp)
            curr_timestamp = timestamp
            curr_packet_size = packet_size
    # Add the last group to the list
    grouped_packet_sizes.append(curr_packet_size)
    grouped_timestamps.append(curr_timestamp)

    # Plot the new graph
    fig, ax = plt.subplots()
    # ax.plot(grouped_timestamps[0:len(grouped_timestamps) // 4], grouped_packet_sizes[0:len(grouped_packet_sizes) // 4])
    ax.plot(grouped_timestamps, grouped_packet_sizes)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Packet Size (Bytes)')
    ax.set_title(f'Packet Sizes Grouped within {time_interval} Seconds')
    x_ticks = np.arange(0, max(grouped_timestamps)+ 0.1, 0.2)
    ax.set_xticks(x_ticks)
    plt.show()


def drawAck(ack_size):  # Define the number of acks to group packets within
    cnt = 0
    group_size = []
    cur_size = 0
    for size in packet_size:
        if cnt < ack_size:
            cnt += 1
            cur_size += size
        else:
            group_size.append(cur_size)
            cur_size = size
            cnt = 0
    group_size.append(cur_size)

    fig, ax = plt.subplots()
    # ax.plot(group_size[0:len(group_size) // 3])
    ax.plot(group_size)
    ax.set_xlabel('ACK')
    ax.set_ylabel('Packet Size (Bytes)')
    ax.set_title(f'Packet Sizes Grouped within {ack_size} ACKs')
    # x_ticks = np.arange(0, len(group_size) + 1, 5)
    # ax.set_xticks(x_ticks)

    plt.show()



if __name__ == '__main__':
    # my_tcp_analyzer('biliPacket.pcap', 'biliout.txt', '2001:da8:201d:1109::351', '240e:f7:c010:304:38::10', 64331, 443)
    # 240e:f7:c010:304:38::10:443 -> 2001:da8:201d:1109::351:64331
    # my_tcp_analyzer('sws.pcap', 'Alice.txt', '10.32.60.95', '137.132.84.203', 56241, 443)
    # draw(0.1)

    # my_tcp_analyzer('sws2.pcap', 'Alice.txt', '10.32.60.95', '137.132.84.203', 57942, 443) #0.08
    # draw(0.1)
    # my_tcp_analyzer('wget1.pcap', 'Alice.txt', '10.24.176.129', '198.143.164.252', 50838, 443) #0.2
    my_tcp_analyzer('wget2.pcap', 'Alice.txt', '2001:da8:201d:1109::3bc1', '2402:f000:1:400::2', 51032, 443)  # 0.08
    draw(0.1)
    # drawAck(50)
