""" from itertools import islice
import time
import concurrent.futures


def batched(iterable, n):
    "Batch data into tuples of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch

def task(n):
    for i in n:
        time.sleep(1)
    return


def speed(func, jobs, num_workers):
    len_batch = len(jobs) // num_workers
    with concurrent.futures.ThreadPoolExecutor(num_workers) as executor:
        futures = [
            executor.submit(func, batch)
            for batch in batched(jobs, len_batch)
            
        ]


if __name__=='__main__':
    num_task = list(range(10))
    # print(list(batched(num_task, 2)))
    start_time = time.time()

    speed(task, num_task, 10)
    
    end_time = time.time()
    print(f"It took {end_time-start_time} second(s) to complete")
     """



from scapy.all import *
from pprint import pprint

def ip_pair(x, y):
    for i in x:
        for j in y:
            yield i,j


# ip_range = IP(dst="192.168.227.1/28")
# ip_range = [i.dst for i in ip_range]

# port_range = list(range(1,10))

# unique_ips = {i for i,j in ip_pair(ip_range, port_range)}

# pprint(unique_ips)





