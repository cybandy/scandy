#!/bin/python

import time
from datetime import datetime

from ScandyBasic import *
from vuln import scan_vulns


class Scandy(ScandyBasic):
    def __init__(self):
        super().__init__()
        self.target = self.args.target

    def portscan(self, ip_ports):
        """
        This function scan for open port of an ip
        :param ip_ports: a tuple of ip and port example. ip_ports=(ip,port)
        :return: return dictionary of key = ip, value = [dict(status,service,port,banner)]
        """
        res = dict()
        message = ''
        status = ''
        banner = ''
        for ip, port in ip_ports:
            if ip not in res.keys():
                res[ip] = list()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((ip, port)):
                    if self.args.Verbose:
                        # service = portservice(port)
                        if self.realtime:
                            # message = f"{port}/tcp\t     {colored('close', 'red')}\n"
                            message = f"[-] {port}/tcp{'':<10} {colored('close', 'red')}{'':<10} {'':<10} {'':<10}"
                            print(message)
                        status = colored('close', 'red')
                        res[ip].append({
                            'status': status,
                            'port': port
                        })
                        continue
                else:
                    service = port_service(port)
                    banner = self.port_banner(s, ip, port)
                    status = colored('open', 'green')
                    # message = f"{port}\t     {colored('open', 'green')}\t     {service} {banner}"
                    message = f"[+] {port} {'':<10}{colored(status, 'green')}{'':<10}{service}{'':<10}{banner} {'':<10}"
                    if self.realtime:
                        print(message)
                    # print(message)
                    res[ip].append({
                        'status': status,
                        'service': service,
                        'port': port,
                        'banner': banner
                    })
            message, status, banner = '', '', ''
        return res


def main():
    f = Scandy()
    p = f.port_port_range_validator()
    f.scan_ports = list(set([i for i in p]))
    f.scan_ports.sort()

    print(f"Starting ScAndy at local:{datetime.now().strftime('%d/%m/%Y, %H:%M:%S')}"
          f"\n\n"
          f"Scanning for connected devices on the network"
          f" {f.args.target}")

    # scan for devices on the network
    all_ips = f.target_ip_processor()
    # =======================================================================
    start_time = time.time()
    # k = f.ip_validator(all_ips)
    k = f.speed(f.ip_validator, all_ips)
    end_time = time.time()
    print(f"Duration {end_time - start_time} seconds")
    # ==========================================================================
    active_ips = set()
    table = ColorTable()
    table.field_names = ["IP Address", "Hostname", "Mac Address", "Manufacturer"]
    for i in k:
        active_ips.add(i[0])
        if i in table.rows:
            continue
        table.add_row(i)
    active_ips = list(active_ips)

    print(table.get_string(sortby="IP Address"))
    # print(f"{colored(len(active_ips), 'green')} devices were discovered")

    active_ips.sort()
    if len(active_ips) == 0:
        print(colored(f"{all_ips} cannot be reached", 'red'))
        sys.exit()
    start_time = time.time()
    res = f.speed(f.portscan, active_ips, f.scan_ports)
    end_time = time.time()
    print(f"Time taken to scan  {end_time - start_time} seconds")
    # ==========================================================================
    v = f.table_print(res)
    # scan_vulns(v)


if __name__ == '__main__':
    main()
