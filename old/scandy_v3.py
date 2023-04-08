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
except ImportError:
    print(f"run the command pip install -r requirements.txt to install required libraries")


# host_stat = lambda ip: True if subprocess.call(f"ping -c 1 {ip}", stdout=False) == 0 \
#                                 or subprocess.call(f"ping -n 1 {ip}", stdout=False) == 0 else False


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
        parser.add_argument('-H', '--Host', metavar='Host target', required=True, help='host to be scanned.'
                                                                                       'Example -H 127.0.0.1 or --Host localhost')

        parser.add_argument('-p', '--port', type=int, metavar='port', help='port of the scan target. Example -p 80 or'
                                                                           ' --port 80')

        parser.add_argument('-pr', '--PortRange', type=int, nargs=2, help='Scan Port range. Example -pr 1 100')
        parser.add_argument('-t', '--Threads', metavar='Number of Threads', type=int,
                            default=50, help='-t 30 or --Threads 40')

        parser.add_argument('-v', '--verbose', action='store', nargs='?', dest='verbose', default='no',
                            help='Verbose')
        args = parser.parse_args()
        # parsing, validating and printing target information below
        try:
            self.target = socket.gethostbyname(args.Host)
        except socket.gaierror:
            print(f"Hostname {args.Host} could not be resolved")
            sys.exit()

        try:
            self.hostname = socket.gethostbyaddr(self.target)
            print(f"Hostname - {self.hostname[0]}")
        except socket.herror:
            if not host_stat(self.target):
                print(f"Target({args.Host}) seems to be down")
                sys.exit()
            else:
                pass
        # mac address
        print(self.targetInfo())

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

        print(f"{'Port':<20} {'State':<20} {'Service':<20} {'Banner':<20}")

    def portscan(self):

        while not self.queue.empty():
            port = self.queue.get()

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # socket.setdefaulttimeout(10)
                    service = self.portservice(port)
                    s.settimeout(2)
                    if s.connect_ex((self.target, port)):
                        if self.verbose != 'no':
                            print(f"{port}{'/tcp':<20} {colored('close', 'red'):<20}")
                        self.closeports.append(port)
                    else:
                        banner = self.port_banner(s, port)
                        self.openports.append(port)
                        print(
                            f"{port}{'/tcp':<20} {colored('open', 'green'):<20} {service:<20} {banner}")
            except TimeoutError:
                pass
            self.queue.task_done()
        return

    @staticmethod
    def portservice(port):
        if port > 0 or port < 1024:
            try:
                return socket.getservbyport(port, "tcp")
            except:
                return "Unknown"

    def port_banner(self, s, port):
        banner = ""
        teln_banner_grabber = range(1, 80)
        if port in teln_banner_grabber:
            banner = self.port_banner2(port)
        else:
            try:
                s.send(b'Banner_query\r\n')
                try:
                    banner = s.recv(100)
                except ConnectionResetError:
                    pass
            except:
                pass
        if 'html' in str(banner).lower() or 'http' in str(banner).lower():
            banner = self.html_port(port)
        if 'ftp' in str(banner).lower():
            banner = self.ftp_port(port)

        return banner if isinstance(banner, str) else banner.decode('utf-8')

    def port_banner2(self, port):
        banner = ""
        try:
            with telnetlib.Telnet(self.target, port, timeout=10) as tn:
                banner = tn.read_until(b"zaiesedtgwseqeserweqawqrwrdrf", timeout=1)
        except:
            pass
        return banner

    def html_port(self, port):
        uploads = {'points': 3, 'total': 10}
        req = requests.get(f"http://{self.target}:{port}/", params=uploads)
        return req.headers['Server'].encode("utf-8")

    def ftp_port(self, port):
        ftp = ftplib.FTP()
        ftp.connect(self.target, port)
        banner = ftp.getwelcome()
        try:
            login = ftp.login()
            if 'successful' in login:
                banner = banner + colored('    Vulnerable to anonymous login', 'red')
            ftp.quit()
        except:
            pass

        return banner.encode("utf-8")


if __name__ == '__main__':
    f = ScandyCore()
    thread_list = []

    for t in range(f.threads):
        thread = threading.Thread(target=f.portscan)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()
