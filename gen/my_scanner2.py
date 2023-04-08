#!/usr/bin/python
'''
This programs scans for open port of a target
'''

# ====== import libraries ==========
import sys
import argparse
import socket
from datetime import datetime


def starting():
    # ====== pretty banner added =====
    with open("../banner.txt") as f:
        file = f.read()
        print(f"\n {file}")

    print(f"{'-'*60}\n Starting ScAndy at {datetime.now()} {'-'*60}\n")

def print_headers():
    return

def port_range_conversion(strings):
    # convert port to range of integers
    return list(range(strings[0], strings[1] + 1))


def input_parameters():
    # this function parse the input parameters and validate the code first
    parser = argparse.ArgumentParser(
        prog='ScAndy',
        description="Network scanner of a target/ip",
    )
    parser.add_argument('-H', '--Host', metavar='Host target', required=True, help='host to be scanned')

    parser.add_argument('-p', '--port', type=int, default=80, metavar='port', help='port of the scan target')

    parser.add_argument('-pr', '--PortRange', type=int, nargs=2, help='Scan Port range.')


    args = parser.parse_args()
    target = socket.gethostbyname(args.Host) # translate hostname like google.com to IPv4
    port = args.port
    port_range = port_range_conversion(args.PortRange)






if __name__ == '__main__':
    starting()
    input_parameters()