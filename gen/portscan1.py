#!/usr/bin/python

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)

# "192.168.114.1"
host = input("[+] Enter the host IP: ") #"10.0.2.4"

# port = 80
port = input("[+] Enter the port")
range_port = range(1, 1000)


def portscanner(h, p):
    if sock.connect_ex((h, p)):
        print(f"Port {p} is close")

    else:
        print(f"Port {p} is open")


def manyportscan(h, range_p):
    # it scans range of ports
    for p in range_p:
        portscanner(h, p)


portscanner(host, port)
# manyportscan(host, range_port)
