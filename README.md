# Stekruebe Ticket Redirection Large Scale Scanning
This artifact contains a slimmed-down version of the large-scale scanning setup for detecting session ticket confusion attacks in the wild.
It has been modified to work with a local dummy server setup to demonstrate the functionality.
The original setup was heavily customized for our own infrastructure, so functionality was removed to make it easier to run on a local machine (e.g. running `zmap` against Docker containers doesn't work well).
All changes are marked with comments `# AE Version` in the code.

Note that this repository relies on a custom fork of `zgrab2` and `zcrypto` to support the required functionality, which are built using the `build_dependencies.sh` script.

## Usage
The artifact itself consists of a series of (Python) scripts and Docker containers.
Instructions here are based on a clean Ubuntu 25.04 installation, but should work on other distributions as well.
### Requirements
- Python 3.12+
- Docker
- Docker Compose
- pip
- golang 1.19+
You can install these dependencies using the following commands:
```bash
apt install python3-dev python3-full docker.io cmake libjudy-dev libgmp-dev libpcap-dev flex byacc libjson-c-dev gengetopt libunistring-dev golang
systemctl start docker.service
sudo curl -L "https://github.com/docker/compose/releases/download/v2.35.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```
Also make sure that you have cloned the submodules, either by using the `--recurse-submodules` flag when cloning or by running:
```bash
git submodule init
git submodule update
```

## How to set up
1. Build required dependencies (our custom fork of `zgrab2` and appropiate versions of `zmap` and `zdns`)
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
sudo ./setup.sh
dig @127.0.0.1 -p 8053 a.com
```
which should yield two `172.x.0.x` addresses.

## How to run
1. Set up the local dummy servers and DNS
```bash
sudo ./setup.sh
```
2. Run the all-in-one script
```bash
sudo ./0_all_in_one.sh
```
3. Examine the `analysisdump` folder for the results of the scans.
The folder contains a list of all potentially successful resumptions across hosts, grouped by AS.
        Within, each path `./<target IP>/<source IP>/` contains a separate scan result.
I.e. the folder `./172.19.0.5/172.19.0.3/` contains the different resulting HTML documents when resuming at **.5** with a ticket from **.3**:
`0_initial.html` is the original page at **.3**, without a ticket. `1_resumed.html` contains the page received by **.5** after resumption.
`2_*_supposed_origin.html` contains the closest HTML match, for `1_resumed.html`, based on different metrics.
`_meta.md` summarizes these findings, including which domain we believe to have encountered.
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
The `sleep` for spawning Neo4J may not be sufficient to actually start. Try to increase the sleep delay.
