import socket
import struct
import time
import subprocess
from dotenv import load_dotenv
import os

load_dotenv()
PORT_TO_OPEN = int(os.getenv('PORT_TO_OPEN', 8000))
TIMEOUT = int(os.getenv('TIMEOUT', 30))
DURATION_TO_KEEP_OPEN = int(os.getenv('DURATION_TO_KEEP_OPEN', 60))
PORT_SEQUENCE = [int(port) for port in os.getenv('PORT_SEQUENCE', '117,3939,7331').split(',')]

import logging
logging.basicConfig(filename='knock.log', level=logging.INFO)

def tcp_get_destination_port(packet):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0:20])
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    ihl = ip_header[0] & 0xF
    """
    ihl shows len of ip header in 32 bit words
    """
    ip_header_len = ihl * 4


    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |       |C|E|U|A|P|R|S|F|                               |
   | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
   |       |       |R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           [Options]                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               :
   :                             Data                              :
   :                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    if len(packet) < ip_header_len + 20:
        return None

    tcp_header = struct.unpack('!HHLLBBHHH', packet[ip_header_len:ip_header_len+20])
    destination_port = tcp_header[1]

    return destination_port



def main():
    ip_dict = {}
    """
    ip_dict:
    key: ip address
    value: {pos: sequence position, last_knock_time: last knock time, last_time_port_opened: when port was opened to this addr,
            is_open: flag to see is port open}
    """
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        data, addr_interface = raw_socket.recvfrom(65565)
        current_time = time.time()
        dest_port = tcp_get_destination_port(data)
        addr = addr_interface[0]

        """
        delete iptables rule if timeout exceed
        """
        if addr in ip_dict and ip_dict[addr]['is_open'] and current_time - ip_dict[addr]['last_time_port_opened'] > DURATION_TO_KEEP_OPEN:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', str(addr), '-p', 'tcp', '--dport', str(PORT_TO_OPEN), '-j', 'ACCEPT'])
            ip_dict[addr]['is_open'] = False

        """
        reset current sequence if current destination port doesnt match with needed sequence
        """
        #print(dest_port)
        if addr not in ip_dict:
            ip_dict[addr] = {'pos': 0, 'last_knock_time': current_time, 'last_time_port_opened': current_time, 'is_open': False}
        elif dest_port is None or dest_port not in PORT_SEQUENCE:
            print(f"dest_port:{dest_port}, {addr}, {ip_dict[addr]['pos']}")
            ip_dict[addr]['pos'] = 0
            continue
        print(dest_port)
        print(f"{addr}, {ip_dict[addr]['pos']}")
        if current_time - ip_dict[addr]['last_knock_time'] > TIMEOUT:
            ip_dict[addr]['pos'] = 0
        logging.info(f"Knock on {dest_port} from {addr}")


        """
        update values if destination port is matched
        """
        if PORT_SEQUENCE[ip_dict[addr]['pos']] == dest_port:
            ip_dict[addr]['pos'] += 1
            ip_dict[addr]['last_knock_time'] = current_time

        """
        add accept rule to iptables if sequences completed
        """
        if len(PORT_SEQUENCE) == ip_dict[addr]['pos']:
            print('Success')
            subprocess.run(['iptables', '-I', 'INPUT', '-s', str(addr), '-p', 'tcp', '--dport', str(PORT_TO_OPEN), '-j', 'ACCEPT'])
            ip_dict[addr]['pos'] = 0
            ip_dict[addr]['last_time_port_open'] = current_time
            ip_dict[addr]['is_open'] = True

if __name__ == "__main__":
    main()