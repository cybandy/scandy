#!/bin/env python


# import libraries
import argparse
import concurrent.futures
import ftplib
import socket
import subprocess
import sys
import telnetlib
from collections import deque
from itertools import islice
import requests
import scapy.all as scapy
from manuf import manuf
from termcolor import colored


class ScandyBasic:
    def __init__(self):
        self.scan_ports = None
        self.inactive_ips = None
        self.active_ips = None
        self.target = None
        self.args = None
        self.argument_processor()
        self.realtime = False

    def scandy_program_banner(self):
        with open('./banner.txt') as file:
            banner = file.read()
            print(banner)

        return ''

    def argument_processor(self):

        parser = argparse.ArgumentParser(
            prog="Scandy",
            description=f"{self.scandy_program_banner()}\n"
                        f"Network scanning tool. Note that you have to be on the same network",
        )

        parser.add_argument('-t', '--target', nargs='+', metavar='Target ip', required=True,
                            help="Network ip address (range) to scan"
                                 "Example: scandy -H 192.168.0.10 or"
                                 "scandy -H 192.168.0.10 192.168.0. 20"
                            )

        parser.add_argument('-p', '--port', nargs='*', metavar='Port number(s)', type=int, default=0,
                            help='Scanning port of your target. Example -p 80, --port 21 22 80 443 3306'
                            )

        parser.add_argument('-pr', '--portrange', type=int, nargs=2,
                            help='Specify the range or port numbers you want to scan'
                                 'Example: scandy -pr 1 1000. This means you are scanning from port 1 to 1000'
                            )
        parser.add_argument('-th', '--threads', type=int, default=50,
                            help='The number of threads scandy should use.'
                                 'Example: -t 20. Default is 50')

        parser.add_argument('-v', '--verbose', nargs='?', dest='Verbose', default='no',
                            help='Verbose'
                            )
        # parser.print_help()

        self.args = parser.parse_args()
        self.target = self.args.target

        if self.args.Verbose == 'no':
            self.args.Verbose = False
        elif self.args.Verbose == None:
            self.args.Verbose = True
        else:
            parser.print_help()
            sys.exit()

    def target_ip_processor(self):
        target_ip = self.args.target
        all_ip_addresses = []
        local_ip = scapy.get_if_addr(scapy.conf.iface)
        for ip in target_ip:

            if '/' in ip:
                for i in scapy.IP(src=local_ip, dst=ip):
                    all_ip_addresses.append(i.dst)

            else:
                all_ip_addresses.append(scapy.IP(src=local_ip, dst=ip).dst)

        return all_ip_addresses

    def ip_validator(self, ips):
        """
        This function validate the list of ip address and return a tuple of active ip address list, inactive ip
        addresses.
        active ip means it can be reached by your host machine, inactive ips vice versa

        :param ips: List or iterable ip addresses
        :return: ([active ips], [inactive ips]
        """
        self.active_ips = deque()
        self.inactive_ips = []
        hostname = [f"{'':<15}"]
        for ip in ips:

            try:
                print(ip)
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                # print(f"Hostname {ip} could not be resolved")
                pass

            try:
                hostname = socket.gethostbyaddr(ip)
                # print(f"Hostname - {hostname[0]}")
            except socket.herror:
                if not host_stat(ip):
                    # print(f"Target({ip}) seems to be down")
                    continue
                else:
                    pass

            mac = scapy.getmacbyip(ip).upper()
            print(f"{ip}{'':<7}\t{hostname[0]}{'':<7}\t{mac}{'':<7}\t{mac_manufactuer(mac)}")
            self.active_ips.append((ip, mac))

            # try:
            #     ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
            #                            scapy.ARP(pdst=ip), timeout=3, verbose=False
            #                            )
            # except Exception as e:
            #     print(e)
            #     continue
            # if len(ans) > 0:
            #     act_ip = ans[-1]
            #     mac = act_ip.answer.payload.hwsrc.upper()
            #     print(f"{ip}\t{mac}\t{self.mac_manufactuer(mac)}")
            #     self.active_ips.append((act_ip.answer.payload.psrc, mac))

        return self.active_ips

    def port_port_range_validator(self):
        self.scan_ports = []
        if self.args.port != 0:

            self.args.port.sort()
            [valid_port_number(i) for i in self.args.port]

            if self.args.portrange is not None:
                self.args.portrange.sort()
                [valid_port_number(i) for i in self.args.portrange]
                a, z = self.args.portrange[0], self.args.portrange[-1]
                self.scan_ports = chain(list(range(a, z + 1)), self.args.port)

            else:
                return self.args.port

        else:

            if self.args.portrange is not None:
                self.args.portrange.sort()
                [valid_port_number(i) for i in self.args.portrange]
                a, z = self.args.portrange[0], self.args.portrange[-1]
                self.scan_ports = list(range(a, z + 1))

            else:
                print("No port specified: Defaulting to port scan range 1 to 1000...")
                self.scan_ports = list(range(1, 1001))
        return self.scan_ports

        # return (chain(self.args.port, self.args.portrange))

    @staticmethod
    def port_banner2(ip, port):
        banner = ""
        try:
            with telnetlib.Telnet(ip, port, timeout=10) as tn:
                banner = tn.read_until(b"zaiesedtgwseqeserweqawqrwrdrf", timeout=1)
        except:
            pass
        return banner

    def port_banner(self, s, ip, port):
        banner = ""
        teln_banner_grabber = range(1, 80)
        if port in teln_banner_grabber:
            banner = self.port_banner2(ip, port)
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
            banner = html_port(ip, port)
        if 'ftp' in str(banner).lower():
            banner = ftp_port(ip, port)

        if isinstance(banner, str):
            return banner
        else:
            try:
                return banner.decode('utf-8')
            except:
                return str(banner)

    def speed(self, func, iterable_obj, ports=None):
        '''

        :param ports: 
        :param func: The function you are executing
        :param iterable_obj: the iterable object eg list that you want to pass to the function
        :return: results of the function
        '''

        if ports != None:
            self.realtime = True if len(iterable_obj) <= 3 else False
            iterable_obj = [(i, j) for i, j in ip_port_pair(iterable_obj, ports)]

        if self.args.threads <= len(iterable_obj):
            batch_len = len(iterable_obj) // self.args.threads
        else:
            batch_len = len(iterable_obj)

        self.realtime = self.realtime and (batch_len > 200) and (self.args.threads < 101)

        # executor = concurrent.futures.ThreadPoolExecutor(self.args.threads)

        with concurrent.futures.ThreadPoolExecutor(self.args.threads) as executor:
            futures = [
                executor.submit(func, batch)
                for batch in batched(iterable_obj, batch_len)
            ]

            concurrent.futures.wait(futures)

        if ports != None:
            return [i.result() for i in futures]

        return from_iterable([i.result() for i in futures])

    def table_print(self, data):
        if self.realtime:
            return
        res = dict()
        for r in data:
            ip, d = list(r.items())[0]
            if ip not in res.keys():
                res[ip] = list()
            res[ip].append(d)

        for k in res.keys():
            line = sorted([i for i in from_iterable(res[k])], key=lambda x: x['port'])
            print(f"{'-' * 120}\nScanned results for {k}\n {'-' * 120}")
            print("{:<10} {:<10} {:<10} {:<10}".format('Ports', 'States', 'Service', 'Banner'))
            for d in line:
                print("{:<10} {:<10} {:<10}".format(d['port'], d['status'], d['service'], d['banner']))


def html_port(ip, port):
    uploads = {'points': 3, 'total': 10}
    req = requests.get(f"http://{ip}:{port}/", params=uploads)
    return req.headers['Server'].encode("utf-8")


def ftp_port(ip, port):
    ftp = ftplib.FTP()
    ftp.connect(ip, port)
    banner = ftp.getwelcome()
    try:
        login = ftp.login()
        if 'successful' in login:
            banner = banner + colored('    Vulnerable to anonymous login', 'red')
        ftp.quit()
    except:
        pass

    return banner.encode("utf-8")


def batched(iterable, n):
    "Batch data into tuples of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch


def ip_port_pair(x, y):
    for i in x:
        for j in y:
            yield i, j


def from_iterable(iterables):
    # chain.from_iterable(['ABC', 'DEF']) --> A B C D E F
    for it in iterables:
        for element in it:
            yield element


def portservice(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except:
        return "Unknown"


def chain(*iterables):
    # chain('ABC', 'DEF') --> A B C D E F
    for it in iterables:
        for element in it:
            yield element


def valid_port_number(x):
    if 0 < x < 65536:
        return True
    else:
        print(
            f'port {x} is invalid port number. Port should be within 1 to 65536')
        sys.exit()


def host_stat(ip):
    """
    This ping the ip if it is alive
    :param ip:
    :return:
    """
    if subprocess.run(['ping', '-c', '1', ip], capture_output=True).returncode == 0 or \
            subprocess.run(['ping', '-n', '1', ip], capture_output=True).returncode == 0:
        return True
    return False


def mac_manufactuer(mac):
    p = manuf.MacParser(update=False)
    manufacturer = p.get_manuf_long(mac)
    return "Unknown" if manufacturer is None else manufacturer
