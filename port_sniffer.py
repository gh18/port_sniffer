from multiprocessing.dummy import Pool
import argparse
import socket
import sys
from datetime import datetime


"""
Корнеев Михаил, КН-203 (ИЕНиМ-280208)
"""

# default configuration
IP_ADDRESS = '127.0.0.1'
FIRST_PORT = 0
LAST_PORT = 65535


def parse_arguments():
    """Sets valid arguments to be applied"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', help='IP-ADDRESS to scan opened ports', default=IP_ADDRESS)
    parser.add_argument('--first', help='FIRST port to start scanning', default=FIRST_PORT)
    parser.add_argument('--last', help='LAST port to scan', default=LAST_PORT)
    parser.add_argument('--type', help='TYPE of port to scan', default='all')
    # print(vars(parser.parse_args()))
    return vars(parser.parse_args())


tcp_ports = list()


def scan_tcp(port_):
    """Scans TCP ports"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((IP_ADDRESS, port_))
            tcp_ports.append(port_)
            sock.close()
        except socket.error:                    # TCP port is closed
            pass
    tcp_ports.sort()


udp_ports = list()


def scan_udp(port_):
    """Scans UDP ports"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            sock.sendto(b'message', (IP_ADDRESS, port_))
            sock.recvfrom(1024)
        except socket.error as ex:              # UDP port is open
            if str(ex) == 'timed out':
                udp_ports.append(port_)
    udp_ports.sort()


def scan_ports(port_):
    """Scans all ports within set boundaries (all by default)"""
    scan_tcp(port_)
    scan_udp(port_)


def run_sniffer():
    """Runs the script"""
    args = parse_arguments()
    pool = Pool(1000)
    if int(args['first']) >= FIRST_PORT:
        starting_port = int(args['first'])
    else:
        starting_port = FIRST_PORT
    if int(args['last']) <= LAST_PORT:
        final_port = int(args['last'])
    else:
        final_port = LAST_PORT
    switcher = {
        'all': scan_ports,
        'tcp': scan_tcp,
        'udp': scan_udp
    }
    func = switcher.get(args['type'].lower(), 'Invalid query')
    pool.map(func, range(starting_port, final_port + 1))
    pool.close()
    pool.join()
    print_out_ports(args['type'])


def print_out_ports(type: str):
    """Prints out opened ports to console"""
    if type.lower() == 'all' or type.lower() == 'tcp':
        print('TCP ports opened: ' + str(tcp_ports))
    if type.lower() == 'all' or type.lower() == 'udp':
        print('UDP ports opened: ' + str(udp_ports))


if __name__ == '__main__':
    address = parse_arguments()['ip']
    print('-' * 45)
    print(f'Please wait, scanning {address} ports...')
    print('-' * 45)
    start = datetime.utcnow()
    try:
        run_sniffer()
    except KeyboardInterrupt as ex:
        print('Error: ' + str(ex.__module__))
    end = datetime.utcnow()
    time = end - start
    print(f'Scan completed in: {time}')

# TODO: domain name translation to IP_Address
# TODO: determine what protocols are working on the specific port
