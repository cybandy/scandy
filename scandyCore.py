import argparse
import sys
import telnetlib
import socket
import scapy.all as scapy
from scapy.all import IP, TCP, ICMP, srp1, Ether, sr, sr1
import manuf
from helpers.nice_functions import from_iterable
import requests
import ftplib

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ScandyCore:
    def __init__(self) -> None:
        self.args = None
        self._argument_processor()
        self._ipValidator()
        # self._portValidator(self.args.port, "port")
        # self._portValidator(self.args.portrange, "port range")
        self.port = self._portValidator(
            zip([self.args.port, self.args.portrange], ["port", "port range"]))
        self.target = self.ip_processor()

        self.activeips = self._active_devices_ip()
        self.port_scanner()

    def _argument_processor(self):
        """
        Process all cli arguments
        python scandy -t 192.168.227.3 192.168.227.4 -p 21 22 80, --portrange 1024 1
        """
        parser = argparse.ArgumentParser(
            prog="Scandy",
            description="Network Scanner"
        )
        parser.add_argument("-t", "--target", nargs="*", required=True,
                            help="The target IP to scan")

        parser.add_argument("-p", "--port", nargs="*", type=int, default=None,
                            help="The port to be scanned")
        parser.add_argument("-pr", "--portrange", nargs=2, type=int, default=[],
                            help="The port range to be scanned")

        self.args = parser.parse_args()

        if self.args.portrange:
            self.args.portrange.sort()
        if self.args.port:
            self.args.port.sort()

        return

    def port_scanner(self):
        active_ip = self.activeips.keys()
        
        for ip in active_ip:
            pkt = IP(dst=ip)/TCP(flags="S", dport=self.port)
            ans, unans = sr(pkt, timeout=60, verbose=False)

            pkts_open_ports = ans.filter(
                lambda s, r: TCP in r and r[TCP].flags == "SA")
            if not pkts_open_ports:
                print(f"{ip} has no open ports")
                continue
            print(
                f"-------------------------------\n Port Scanning - {ip}\n--------------------------------\n")
            for s, r in pkts_open_ports:
                add_info = ""
                service = self.port_service(s.dport)
                banner = self._port_banner(ip, s.dport)

                # html banner
                if "html" in banner.lower() or ("http" in banner.lower()):
                    banner = self.http_banner(ip, s.dport)
                
                # ftp banner
                if "ftp" in banner.casefold():
                    banner, add_info = self.ftp_banner_additional_info(ip, s.dport)

                print(f"[+] TCP/{s.dport}   opened    {service}    {banner} {add_info}")


    def port_service(self,port):
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"
              

    def _port_banner(self, ip, port):
        banner = b""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            try:
                s.send(b"Banner_query\r\n")
                try:
                    banner = s.recv(100)
                except ConnectionResetError:
                    pass
            except:
                pass
        
        try:
            banner = banner.decode("utf-8")
        except:
            banner = str(banner)

        return banner

    def http_banner(self, ip, port):
        uploads = {"points": 3, "total": 10}
        req = requests.get(f"http://{ip}:{port}/", params=uploads)
        return req.headers["Server"]
    
    def ftp_banner_additional_info(self, ip,port):
        ftp = ftplib.FTP()
        ftp.connect(ip, port)
        banner = ftp.getwelcome()
        try:
            login = ftp.login()
            if "successful" in login:
                add_info= "Vulnerable to anonymous login"
            ftp.quit()
        except:
            pass
        return banner, add_info

    def telnet_port_banner(self, ip, port):
        banner = b""
        try:
            with telnetlib.Telnet(ip, port, timeout=2) as tn:
                banner = tn.read_until(b"asdksfjwelfjgwgwklfw", timeout=1)

        except:
            pass

        return banner.decode("utf-8")

    def _portValidator(self, data):
        p = []
        for port, name in data:
            if port:
                p_bool = [0 < i < 65536 for i in port]
                if not all(p_bool):
                    sys.exit(
                        f"Check the entered {name}: {port}. Valid port number should be between 1 and 65536")
                if name == "port range":
                    port = list(range(port[0], port[1]+1))
                p.append(port)

        if not p:
            return list(range(1, 1025))

        return list(
            set(
                [i for i in from_iterable(p)]
            )
        )

    def ip_processor(self):
        for ip in self.args.target:
            if "/" not in ip:
                yield ip
                continue
            for i in IP(dst=ip):
                yield i.dst

    def _ipValidator(self):
        for ip in self.args.target:
            if len(ip.split(".")) != 4:
                sys.exit(
                    f"Please enter a correct IPv4 address. {ip} not correct")
        return

    def _active_devices_ip(self):
        ips = list(self.target)
        active_ip = dict()
        for ip in ips:
            pkt = Ether()/IP(dst=ip)/ICMP()
            res = srp1(pkt, timeout=3, verbose=False)
            if res:
                os = self.os_fingerprinting(res.payload.ttl)
                mac_addr = res.src
                manufacturer = self.manufacturer(mac_addr)
                print(f"[+] {ip} : {mac_addr}: {manufacturer}: {os}")
                active_ip[ip] = {
                    "os": os, "mac": mac_addr, "manuf": manufacturer
                }
                continue
        if not active_ip:
            sys.exit(
                f"Sorry! None of the devices/IP(s) {self.args.target} could be reached.")
        return active_ip

    @staticmethod
    def os_fingerprinting(ttl_val):
        if ttl_val <= 64:
            return "Linux/Unix"
        elif ttl_val == 128:
            return "Windows"
        elif ttl_val == 254:
            return "Solaris"
        else:
            return "Unknown"

    @staticmethod
    def manufacturer(mac_addr):
        p = manuf.MacParser(update=False)
        if not mac_addr:
            return None
        m = p.get_manuf_long(mac_addr)
        return "Unknown" if m is None else m


    def vuln_search(self, text):
        pass        