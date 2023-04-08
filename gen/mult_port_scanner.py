#!/usr/bin/python

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)

# "192.168.114.1"
host = input("[+] Enter the host IP: ")  # "10.0.2.4"


def portscanner(h, p):
    if sock.connect_ex((h, p)):
        print(f"Port {p} is close")

    else:
        print(f"Port {p} is open")


for p in range(1, 100):
    portscanner(host, p);
