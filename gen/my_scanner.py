#!/usr/bin/python
from scapy.all import *

ip_range = '192.168.1.1/24'

from scapy.all import *


def scan_port(ip, port):
    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        return True
    else:
        return False


import nmap


def scan_vulns(ip, port):
    nm = nmap.PortScanner()
    nm.scan(ip, str(port))
    if 'tcp' in nm[ip]['proto'] and nm[ip]['tcp'][port]['state'] == 'open':
        output = nm[ip]['tcp'][port]['script']
        return output
    else:
        return None


def main(ip_range):
    for ip in IP(ip_range):
        for port in range(1, 1025):
            if scan_port(str(ip), port):
                print(f"{ip}:{port} - Open")
                output = scan_vulns(str(ip), port)
                if output:
                    print(output)


if __name__ == 'main':
    main()
