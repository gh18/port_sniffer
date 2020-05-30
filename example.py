import argparse
import socket
from multiprocessing.dummy import Pool

tcp_opened_ports = []
udp_opened_ports = []

MIN_PORT = 0
MAX_PORT = 65535
ADDRESS = "127.0.0.1"


def main():
    args = parse_args()
    start_position = int(args["start"]) if int(args["start"]) >= MIN_PORT else MIN_PORT
    end_position = int(args["end"]) if int(args["end"]) <= MAX_PORT else MAX_PORT
    pool = Pool(500)
    if args["type"].lower() == "all":
        pool.map(scan_ports, range(start_position, end_position + 1))
    elif args["type"].lower() == "udp":
        pool.map(scan_udp_port, range(start_position, end_position + 1))
    elif args["type"].lower() == "tcp":
        pool.map(scan_tcp_port, range(start_position, end_position + 1))
    pool.close()
    pool.join()
    if args["type"].lower() == "all" or args["type"].lower() == "udp":
        print("UDP opened ports: " + str(udp_opened_ports))
    if args["type"].lower() == "all" or args["type"].lower() == "tcp":
        print("TCP opened ports: " + str(tcp_opened_ports))


def scan_tcp_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((ADDRESS, port))
            tcp_opened_ports.append(port)
            sock.close()
        except socket.error:
            # TCP port is closed
            pass
    tcp_opened_ports.sort()


def scan_udp_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            sock.sendto(b'Hi, port!', (ADDRESS, port))
            sock.recvfrom(1024)
        except socket.error as e:
            # UDP port is opened
            if str(e) == 'timed out':
                udp_opened_ports.append(port)
    udp_opened_ports.sort()


def scan_ports(port):
    scan_tcp_port(port)
    scan_udp_port(port)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-address", help="set IP-address which you want to scan", default=ADDRESS)
    parser.add_argument("-start", help="set the first port for scanner", default=MIN_PORT)
    parser.add_argument("-end", help="set the last port for scanner", default=MAX_PORT)
    parser.add_argument("-type", help="set the type of port for scanner", default="all")
    return vars(parser.parse_args())


if __name__ == "__main__":
    print(ADDRESS)
    main()
