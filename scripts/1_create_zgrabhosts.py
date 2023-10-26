import json
import csv
import sys
from itertools import chain

if not len(sys.argv) == 4:
    print(f"Usage: python3 {sys.argv[0]} <zdns output file> <zmap output file> <file for zgrab2>")
    sys.exit(1)

resolved_fn, open_ips_fn, open_ips_csv_fn = sys.argv[1:]

ips_to_domains = {}
with open(resolved_fn) as f_resolved:
    for line in f_resolved:
        item = json.loads(line)
        domanin = item.get("name")
        for ip in chain(
            item.get("data", {}).get("ipv4_addresses", []),
            item.get("data", {}).get("ipv6_addresses", []),
        ):
            if ip not in ips_to_domains:
                ips_to_domains[ip] = []
            ips_to_domains[ip].append(domanin)

with open(open_ips_fn) as f_port, open(open_ips_csv_fn, "w", newline="") as f_out:
    writer = csv.writer(f_out)
    for ln in f_port:
        ip = ln.strip()
        if ip in ips_to_domains:
            # print(ip, " ".join(ips_to_domains[ip]), sep=",")
            for domain in ips_to_domains[ip]:
                writer.writerow([ip, domain])
        else:
            print("[!] No domain for", ip)
