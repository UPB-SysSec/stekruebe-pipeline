import sys
import ipaddress

if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <blocklist>")
    sys.exit(1)

blocklist_fn = sys.argv[1]

def read_blocklist(fn):
    with open(fn) as f:
        for ln in f:
            yield ipaddress.ip_network(ln.strip())

blocked = list(read_blocklist(blocklist_fn))

def is_blocked(ip: str):
    addr = ipaddress.ip_address(ip)
    for net in blocked:
        if addr in net:
            return True
    return False

try:
    while ip := input().strip():
        if not is_blocked(ip):
            print(ip)
except EOFError:
    pass
