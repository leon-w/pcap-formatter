# pcap-formatter

A simple tool to extract basic information from `pcap` files.


## Build (Linux)

Requires a `C++17` compatible compiler.
The following dependencies need to be installed:

* [libpcap](https://www.tcpdump.org/) (`sudo apt-get install libpcap-dev`)
* [pcapplusplus](https://pcapplusplus.github.io/)

Use `make all` to compile.

## Usage

```
Usage: ./pcap-formatter [options] input

Positional arguments:
input       	input pcap file(s)

Optional arguments:
-h --help   	show this help message and exit
-o --output 	output file, if not provided STDOUT is used
-b          	binary output
```

## Output format

One line per packet. Timestamp in microsecods (us), source ip, destination ip, protocol, source port, destination port.

Example (3 packets):

```
1453381200038679 96.14.133.52 1.96.145.140 6 53965 80
1453381200038679 210.29.57.250 15.19.73.154 6 80 63545
1453381200038680 207.169.184.4 1.96.167.103 6 24227 443
```

### binary (`-b`)

Same as above. 21 bytes per packet. All numbers are big endian.
