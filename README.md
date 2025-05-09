# Stekruebe Ticket Redirection Large Scale Scanning

## How to set up
1. Build required dependencies (our custom forks of `zmap`, `zgrab2`, and `zdns`)
```
sudo ./build_dependencies.sh
```
`sudo` is required to give `zmap` access to the network interface.

## How to run
1. Set up the local dummy servers
```
cd ae-dummy-servers
docker-compose up -d
```
2. Setup DNS server for ZDNS
```
./generate_dummy_hosts.sh
./run_local_dns.sh
```
Check if DNS resolution works:
```
dig @127.0.0.1 -p 5353 a.com 
```
Should yield a `172.x.0.x` address.

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