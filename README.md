# Scandy_

Scandy is a network vulnerability scanner built with python

## Features

- Scan network for connected devices.
     - command scandy -t 192.168.95.1/24
- Scan for open ports
- Search for existing CVE for open ports using [Vulners API](https://vulners.com)

## Installation
Install the required packages to use

    pip install -r requirements.txt

## Usage
I have a tutorial of how I developed this scanner on [Youtube @cybandy](https://youtube.com/playlist?list=PLE9wWR6sJKjEyCgneyZPK_2qk9rggPv1J) you can check it out.

|   Commands    	   |     Description         	      |
|:-----------------:|:------------------------------:|
| -t or --target 	  |    Target network ip      	    |
|  -p or --port  	  |    port(s) to scan       	     |
| -th or --thread 	 | Number of thread. Default 50 	 |
| -v or --verbose 	 |  Print all closed ports    	   |

The command below will check if the IP can be reached and then scan default ports 1-1024
```sh
sudo python -t 192.168.227.3
```

The command below will check if the IP can be reached and then scan default port 22, 80, 221
```sh
sudo python -t 192.168.227.3 -p 80 22 221
```

The command below will check for all the device on the network 192.168.227.1/28 can be reached and then scan default port 22, 80, 221 and ports in the range of 2000 - 5000
```sh
sudo python -t 192.168.227.1/28 -p 80 22 221 -pr 2000 5000
```