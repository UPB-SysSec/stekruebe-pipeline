# Stekruebe Ticket Redirection Large Scale Scanning
This artifact contains a slimmed-down version of the large-scale scanning setup for detecting session ticket confusion attacks in the wild.
It has been modified to work with a local dummy server setup to demonstrate the functionality.

## Usage
The artifact consists of a series of (Python) scripts and Docker containers.
### Requirements
- Python 3.12+
- Docker
- Docker Compose
- pip
- golang 1.19+
For Ubuntu 25.04, you can install the required dependencies with:
```bash
apt install python3-dev python3-full docker.io cmake libjudy-dev libgmp-dev libpcap-dev flex byacc libjson-c-dev gengetopt libunistring-dev golang
systemctl start docker.service
sudo curl -L "https://github.com/docker/compose/releases/download/v2.35.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## How to set up
1. Build required dependencies (our custom forks of `zmap`, `zgrab2`, and `zdns`)
```
sudo ./build_dependencies.sh
```
`sudo` is required to give `zmap` access to the network interface.
Check if the build was successful by running the binaries.
```bash
./zdns/zdns --help
./zmap/src/zmap --help
./zmapv6/src/zmap --help
./zgrab2_tls13/cmd/zgrab2/zgrab2 --help
```

Also check that the dummy server and corresponding DNS resolution are working:
```bash
./setup.sh #for running
dig @127.0.0.1 -p 8053 a.com
```
which should yield two `172.x.0.x` addresses.

## How to run
1. Set up the local dummy servers and DNS
```bash
./setup.sh
```
2. Run the all-in-one script
```bash
./0_all_in_one.sh
```
## Troubleshooting
### ZMap does not have permission to access the network interface
If you get something like
```
May 08 17:06:29.447 [FATAL] recv: could not open device wlan0: wlan0: You don't have permission to perform this capture on that device (socket: Operation not permitted)
```
from `zmap`, you need to give `zmap` the required permissions (manually) to access the network interface. You can do this by running:
```
sudo setcap cap_net_raw=eip zmapv6/src/zmap                                                                                               
sudo setcap cap_net_raw=eip zmap/src/zmap
```
### Something "connection refused", but only with `zgrab2`
Make sure that your host `/etc/hosts` does not contain any entries for `{a,b,c,d}.com`, as this may interfere with the DNS setup.
We had to learn this the hard way.

### "Connection Refused" when "Generating clusters"
The `sleep` for spawning Neo4J may not be sufficient (also considering pulling the image for the first time). Try to increase the sleep delay, and execute `neo4j/run_prefix_neo4j.sh` manually once.
