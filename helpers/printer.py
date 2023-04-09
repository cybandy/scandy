# from helpers.nice_functions import from_iterable
import pickle
from prettytable.colortable import ColorTable
from termcolor import colored

def from_iterable(iterables):
    # chain.from_iterable(['ABC', 'DEF']) --> A B C D E F
    for it in iterables:
        for element in it:
            yield element

def sort_data(data,keys):
    res = {k:[] for k in keys}
    for d in data:
        for k,v in d.items():
            res[k].append(v)
    for k in keys:
        res[k] = list(from_iterable(res[k]))
    return res
    


def table_print(data, keys):
    res = sort_data(data,keys)

    for ip, data in res.items():
        table = ColorTable()
        table.field_names = ['Port', 'State', 'Service', 'Banner', "Addition info"]
        if not data:
            print(colored(f"\n[-] Device - {ip} has no open ports\n", "red"))
            continue
        table.add_rows(data)
        print(colored(f"\n[+] Scanned results for IP - {ip}", "blue"))
        table.vrules = 1
        table.hrules=1
        print(table.get_string(sortby="Port"))





if __name__=='__main__':
    with open('data', "rb") as f:
        data = pickle.load(f)
    with open('key', "rb") as f:
        key = pickle.load(f)

    table_print(data,keys=key)