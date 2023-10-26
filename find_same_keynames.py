import json
import base64

global_prefixes = {}


def get_prefixes(tickets: list[bytes]) -> list[bytes]:
    for ticket in tickets:
        yield ticket[:16]
        # yield ticket[:4]


with open("out/7_merged_zgrab.json") as f:
    for ln in f:
        item = json.loads(ln)
        ip = item["ip"]
        domain = item["domain"]
        tickets = item["tickets"]
        # filter tickets
        while None in tickets:
            tickets.remove(None)
        tickets = list(filter(lambda x: "value" in x, tickets))
        if len(tickets) < 3:
            continue
        tickets = map(lambda x: x["value"], tickets)
        tickets = map(base64.b64decode, tickets)
        host_prefixes = set(get_prefixes(tickets))

        for prefix in host_prefixes:
            if prefix not in global_prefixes:
                global_prefixes[prefix] = dict()
            if domain not in global_prefixes[prefix]:
                global_prefixes[prefix][domain] = set()
            global_prefixes[prefix][domain].add(ip)

for prefix, domains in sorted(global_prefixes.items(), key=lambda x: len(x[1]), reverse=True):
    if len(domains) > 1:
        print(f"{prefix.hex()} -> [{len(domains)}] {domains}")
