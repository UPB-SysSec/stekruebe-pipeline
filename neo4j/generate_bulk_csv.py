from dataclasses import dataclass
import csv
import base64
import json
from tqdm import tqdm

# for a useful progress bar
NUM_LINES = 1909754

nodes = set()
edges = set()


@dataclass(frozen=True)
class Node:
    uid: int
    content: str
    label: str

    def __hash__(self):
        return hash((self.label, self.content))

    def __init__(self, content, label):
        self.content = content
        self.label = label
        self.uid = hash(self)

    def row(self):
        return (self.uid, self.content, self.label)


class PrefixNode(Node):
    def __init__(self, prefix):
        length = len(prefix)
        assert length % 2 == 0
        label = f"PREFIX;PREFIX{length//2}"
        super().__init__(content=prefix, label=label)


class DomainNode(Node):
    def __init__(self, domain):
        super().__init__(content=domain, label="DOMAIN")


class IPNode(Node):
    def __init__(self, ip):
        is_ipv6 = ":" in ip
        label = "IP;" + ("IPV6" if is_ipv6 else "IPV4")
        super().__init__(content=ip, label=label)


@dataclass
class Edge:
    uid: int
    src: hash(Node)
    dst: hash(Node)
    label: str

    def __init__(self, src, dst, label):
        self.src = hash(src)
        self.dst = hash(dst)
        self.uid = hash((src, dst))
        self.label = label

    def __hash__(self):
        return hash((self.uid, self.label))

    def row(self):
        return (self.src, self.dst, self.label)


"""
p = PrefixNode("abab")
d = DomainNode("google.com")
i4 = IPNode("127.0.0.1")
i6 = IPNode(":::1")
print(p, d, i4, i6)

e = Edge(p, i4)
print(e)
"""

with open("import/domains_header.csv", "w") as f:
    f.write(":ID,domain,:LABEL\n")
with open("import/ips_header.csv", "w") as f:
    f.write(":ID,ip,:LABEL\n")
with open("import/prefixes_header.csv", "w") as f:
    f.write(":ID,prefix,:LABEL\n")
with open("import/relationships_header.csv", "w") as f:
    f.write(":START_ID,:END_ID,:TYPE\n")

with open("../out/7_merged_zgrab.json") as f, open("import/domains.csv", "w") as fd, open(
    "import/ips.csv", "w"
) as fi, open("import/prefixes.csv", "w") as fp, open("import/relationships.csv", "w") as fr:
    # ugh, lets make this somewhat portable
    wd = csv.writer(fd)
    wi = csv.writer(fi)
    wp = csv.writer(fp)
    wr = csv.writer(fr)

    # for a useful progress bar
    # use line number for unique hashes
    for i, ln in enumerate(tqdm(f, total=NUM_LINES)):
        item = json.loads(ln)

        ip = IPNode(item["ip"])
        domain = DomainNode(item["domain"])

        domain_to_ip_edge = Edge(domain, ip, "USES")

        tickets = item["tickets"]
        # filter tickets
        while None in tickets:
            tickets.remove(None)

        tickets = list(filter(lambda x: "value" in x, tickets))
        if len(tickets) > 0:
            tickets = map(lambda x: x["value"], tickets)
            tickets = map(base64.b64decode, tickets)
            tickets = tuple(tickets)

            prefixes = set([t[:4] for t in tickets] + [t[:16] for t in tickets])

            if domain not in nodes:
                wd.writerow(domain.row())
                nodes.add(domain)
            if ip not in nodes:
                wi.writerow(ip.row())
                nodes.add(ip)
            if domain_to_ip_edge not in edges:
                wr.writerow(domain_to_ip_edge.row())
                edges.add(domain_to_ip_edge)

            for p in prefixes:
                prefix = PrefixNode(p.hex())
                if prefix not in nodes:
                    wp.writerow(prefix.row())
                    nodes.add(prefix)
                domain_to_prefix_edge = Edge(domain, prefix, "ISSUES")
                if domain_to_prefix_edge not in edges:
                    wr.writerow(domain_to_prefix_edge.row())
                    edges.add(domain_to_prefix_edge)
                ip_to_prefix_edge = Edge(ip, prefix, "ISSUES")
                if ip_to_prefix_edge not in edges:
                    wr.writerow(ip_to_prefix_edge.row())
                    edges.add(ip_to_prefix_edge)
