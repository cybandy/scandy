#!/usr/bin/python

''''
Scandy is a network scanning tool
version 2.0
Features
- Added banner for all open ports
- Stopped printing closed ports and added the banner to the portscan at runtime
- special for html, ftp
- Added vulnerability checker with vulners python wrapper
Copyright (c) 2023
'''

# import libraries
try:
    import argparse
    import socket
    import telnetlib
    import sys
    import os
    import subprocess
    import threading
    from datetime import datetime
    from queue import Queue
    from termcolor import colored
    import ftplib
    import requests
    import vulners
    from manuf import manuf
    from scapy.layers.l2 import getmacbyip
    from scapy.layers.inet import IP
    from scapy.arch import get_if_addr
    from scapy.config import conf
except ImportError:
    print(f"run the command pip install -r requirements.txt to install required libraries")


def host_stat(ip):
    if subprocess.call(f"ping -c 1 {ip}", stdout=False, stderr=False) == 0 or \
            subprocess.call(f"ping -n 1 {ip}", stdout=False) == 0:
        return True
    return False


class ScandyBasic:

    def __init__(self):
        self.queue = Queue()
        self.port = 0
        self.target = ''
        self.ports_list = list()
        self.active_ip = dict()
        self.banner = b''
        self.openports = list()
        self.closeports = list()
        self.scan_results = {
            'state': '',
            'service': '',
            'banner': ''
        }

        os.system('color')
        self.starting()

        return

    def starting(self):
        # ====== pretty banner added =====
        with open("banner.txt") as f:
            file = f.read()
            print(f"\n {file}")

        print(f"{'-' * 60}\n Starting ScAndy at local:{datetime.now().strftime('%d/%m/%Y, %H:%M:%S')} \n{'-' * 60}\n")
        return

    def port_range_conversion(self, strings):
        ports = list()
        # convert port to range of integers
        if strings[0] <= 0 or strings[1] > 65535:
            print("Port range must be between 1 to 65535")
            sys.exit()

        elif strings[1] > strings[0]:
            ports = list(range(strings[0], strings[1] + 1))
            if not self.port == 0:
                ports.append(self.port)
                ports = list(set(ports))
                ports.sort()
            # ports.append(self.port)

            for p in ports:
                self.queue.put(p)
            return

        else:
            print("Enter a valid port range")
            sys.exit()

    def targetInfo(self):
        mac = getmacbyip(self.target)
        p = manuf.MacParser(update=False)
        manufacturer = p.get_all(mac)
        return f"MAC Address: {colored(mac, 'blue')}, manufacturer: {colored(manufacturer.manuf_long, 'blue')}" if manufacturer.manuf_long else f"MAC Address: {colored(mac, 'blue')}, manufacturer: Unknown"


class ScandyCore(ScandyBasic):

    def __init__(self):
        super().__init__()

        # the code below parse the input parameters and validate the code first
        parser = argparse.ArgumentParser(
            prog='ScAndy',
            description="Network scanner of a target/ip",
        )
        parser.add_argument('-H', '--Host', nargs='+', metavar='Host target', required=True, help='host to be scanned.'
                                                                                                  'Example -H 127.0.0.1 or --Host localhost')

        parser.add_argument('-p', '--port', type=int, metavar='port', help='port of the scan target. Example -p 80 or'
                                                                           ' --port 80')

        parser.add_argument('-pr', '--PortRange', type=int, nargs=2, help='Scan Port range. Example -pr 1 100')
        parser.add_argument('-t', '--Threads', metavar='Number of Threads', type=int,
                            default=50, help='-t 30 or --Threads 40')

        parser.add_argument('-v', '--verbose', action='store', nargs='?', dest='verbose', default='no',
                            help='Verbose')
        args = parser.parse_args()
        self.host = args.Host
        self.target = [ip for ip in IP(src=get_if_addr(conf.iface), dst=args.Host)]

        # Input validators below
        self.verbose = args.verbose

        # checks if no port or port range was supplied then it scans first 100 ports
        if args.port is None and (args.PortRange is None):
            args.PortRange = [1, 100]
            print(f"Scanning port {args.PortRange[0]} to {args.PortRange[-1]}")

        if args.port is not None:
            # check out of standard port range
            if (args.port <= 0) or (args.port > 65535):
                print("Port must be between 1 and 65535")
                sys.exit()
            self.port = args.port
            if args.PortRange is None:
                self.queue.put(args.port)
        if args.PortRange is not None:
            self.port_range_conversion(args.PortRange)
        if args.Threads > self.queue.qsize():
            self.threads = self.queue.qsize()
        else:
            self.threads = args.Threads

        return

    def IpAddressValidator(self, group):
        # results = Queue()
        each_ip = {'status': '', 'hostname': ''}
        for ip in group:
            ip = ip.dst
            # print(f'{ip}\n')
            if host_stat(ip):
                each_ip['status'] = 'alive'
            else:
                each_ip['status'] = "down"
                continue

            # try:
            #     ip = socket.gethostbyname(ip)
            #     # each_ip['status'] = 'alive'
            # except socket.gaierror:
            #     pass

            try:
                h = socket.gethostbyaddr(ip)
                each_ip['hostname'] = h[0]
                ip = h[-1]
            except socket.herror:
                pass
                # if host_stat(ip):
                #     each_ip['status'] = 'alive'
                # else:
                #     each_ip['status'] = "down"
            # self.active_ip.put_nowait({ip: each_ip})
            self.active_ip[ip] = each_ip

        return

    def NetworkScanner(self):
        self.IpAddressValidator()
        active_ip = []
        # active_ip = [(i, v) for i, v in ips if v['status'] == 'alive']
        for i in range(ips.qsize):
            pass
        return


import concurrent.futures
from itertools import islice


def batched(iterable, n):
    "Batch data into tuples of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while (batch := tuple(islice(it, n))):
        yield batch


if __name__ == '__main__':
    socket.setdefaulttimeout(3)
    f = ScandyCore()

    if f.threads <= len(f.target):
        batch_len = len(f.target) // f.threads
    else:
        batch_len = f.threads
    print(f"{'*' * 120}\n Scanning IP network or IP range: {f.host}\n {'-' * 120}")

    executor = concurrent.futures.ThreadPoolExecutor(f.threads)
    futures = [executor.submit(f.IpAddressValidator, batch)
               for batch in batched(f.target, batch_len)]
    concurrent.futures.wait(futures)
    print(f'Reachable targets \n{f.active_ip}')
    # print(f"{'-' * 120}\n Finished Scanning IP network or IP range\n {'-' * 120}")

    # thread_list = []
    # scan_thread =[]
    # for t in range(f.threads):
    #     thread = threading.Thread(target=f.IpAddressValidator)
    #     thread_list.append(thread)
    #     # sc_thread = threading.Thread(target=f.NetworkScanner())
    #     # scan_thread.append(sc_thread)
    #
    # # for active ip addresses
    # for thread in thread_list:
    #     thread.start()
    #
    # for thread in thread_list:
    #     thread.join()

    # for net scan
    # for thread in scan_thread:
    #     thread.start()
    # for thread in scan_thread:
    #     thread.join()
