# Scandy 

  
Scandy is a network vulnerability scanner built with python.
This works best on linux(kali) but to use it on windows check the branch [old_version](https://github.com/andyboat75/scandy/tree/old_version "old_version")
I have a tutorial of how I developed this scanner on [![@cybandy](https://img.shields.io/badge/cybandy-%23EE4831.svg?&style=for-the-badge&logo=youtube&logoColor=white "@cybandy")](https://youtube.com/playlist?list=PLE9wWR6sJKjEyCgneyZPK_2qk9rggPv1J "@cybandy") you can check it out.  
  
## Features  
  

 - Scan network for connected(active) devices. 
 - Retrieve information such as Mac address, OS, Host name,
 - Scan for open ports, port services, port banner and additional vulnerabilities.
 - Search for existing CVE for open ports using [Vulners API](https://vulners.com)  

## Installation

Create a python environment
`python -m venv venv`

Activate the environment
`source ./venv/bin/activate`

Install the required packages to use 
`pip install -r requirements.txt`

#### Caution
Because scapy interact directly with the raw socket of your system it requires sudo priveledges. You can directly call sudo as I have shown below or follow the explanation [here](http://https://github.com/Forescout/project-memoria-detector/issues/6 "here") to tweak it as you want it.
## Usage

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