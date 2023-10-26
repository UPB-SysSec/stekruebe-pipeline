import json
import sys

N = 5
EXPECTED_IP_DOMAIN_PAIRS = 1346875
# interested in
fields = ["ip", "domain", ("data", "tls", "result", "handshake_log", "session_ticket")]

tickets = {}
handled = set()

if not len(sys.argv) == 3:
    print(f"Usage: python3 {sys.argv[0]} <zgrab output> <outfile>")
    sys.exit(1)

zgrab_fn, out_fn = sys.argv[1:]

with open(zgrab_fn) as f_in, open(out_fn, "w") as f_out:
    for ln in f_in:
        item = json.loads(ln)
        ip = item["ip"]
        domain = item["domain"]
        try:
            ticket = item["data"]["tls"]["result"]["handshake_log"]["session_ticket"]
        except KeyError:
            ticket = None
        key = (ip, domain)
        if key not in tickets:
            assert key not in handled
            tickets[key] = []
        tickets[key].append(ticket)
        if len(tickets[key]) >= N:
            json.dump({"ip": ip, "domain": domain, "tickets": tickets[key]}, f_out)
            f_out.write("\n")
            del tickets[key]
            handled.add(key)
            if len(handled) % 10_000 == 0:
                print(
                    f"Handled: {len(handled):7d} ({100*len(handled)/EXPECTED_IP_DOMAIN_PAIRS:6.2f}%) | Currently open: {len(tickets):7d}"
                )
assert not tickets, tickets
