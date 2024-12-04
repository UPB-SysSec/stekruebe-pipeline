from dataclasses import dataclass
import csv
import base64
import json
from tqdm import tqdm
import sys

# for a useful progress bar
NUM_LINES = 2128158

nodes = set()
edges = set()


@dataclass()
class Node:
    _FILENAME = ""
    _HEADER_FILENAME = ""
    _WRITER = csv.writer(sys.stdout)
    uid: int
    content: str
    labels: str

    def __hash__(self):
        return hash((self.content, self.labels))

    def __init__(self, content, label):
        self.content = content
        self.labels = label
        self.uid = hash(self)

    def row(self):
        return (self.uid, self.content, self.labels)

    def header():
        return ":ID,content,:LABEL"

    def write_to_csv(self):
        self._WRITER.writerow(self.row())


class PrefixNode(Node):
    _FILENAME = "import/prefixes.csv"
    _HEADER_FILENAME = "import/prefixes_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))

    def __init__(self, prefix, version, scan):
        self.prefix_length = len(prefix) // 2  # hex, but we want bytes length
        self.version = version
        self.scan = scan

        super().__init__(content=prefix, label="PREFIX")

    def __hash__(self):
        return hash((self.content, self.prefix_length, self.version, self.scan, self.labels))

    def header():
        return ":ID,prefix,length:int,version,scan,:LABEL"

    def row(self):
        return (
            self.uid,
            self.content,
            self.prefix_length,
            self.version,
            self.scan,
            self.labels,
        )


class DomainNode(Node):
    _FILENAME = "import/domains.csv"
    _HEADER_FILENAME = "import/domains_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))

    def __init__(self, domain):
        super().__init__(content=domain, label="DOMAIN")

    def header():
        return ":ID,domain,:LABEL"


class IPNode(Node):
    _FILENAME = "import/ips.csv"
    _HEADER_FILENAME = "import/ips_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))

    def __init__(self, ip):
        is_ipv6 = ":" in ip
        label = "IP;" + ("IPV6" if is_ipv6 else "IPV4")
        super().__init__(content=ip, label=label)

    def header():
        return ":ID,ip,:LABEL"


@dataclass
class Edge:
    _FILENAME = "import/relationships.csv"
    _HEADER_FILENAME = "import/relationships_header.csv"
    _WRITER = csv.writer(open(_FILENAME, "w"))
    uid: int
    src: hash(Node)
    dst: hash(Node)
    label: str

    def __init__(self, src, dst, label):
        self.src = hash(src)
        self.dst = hash(dst)
        self.label = label
        self.uid = hash(self)

    def __hash__(self):
        return hash(self.row())

    def row(self):
        return (self.src, self.dst, self.label)

    def header():
        return ":START_ID,:END_ID,:TYPE"

    def write_to_csv(self):
        self._WRITER.writerow(self.row())


# for a useful progress bar
print("[1] Generating nodes and edges")
with open("../out/7_merged_zgrab_all.json") as f:
    f.seek(0, 2)
    file_length = f.tell()
    f.seek(0)
    progress = tqdm(total=file_length, unit="B", unit_scale=True)
    while ln := f.readline():
        progress.update(len(ln))
        item = json.loads(ln)

        ip_node = IPNode(item["ip"])
        domain_node = DomainNode(item["domain"])
        nodes.add(ip_node)
        nodes.add(domain_node)

        # domain --:USES--> ip
        edges.add(Edge(domain_node, ip_node, "USES"))

        for connection in item["results"]:
            for probe_name, result in connection.items():
                if "_error" in result:
                    # _error does not appear when we have a successful connection
                    continue
                # not a fan, might as well use "tickets" for 1.2 as well :D
                tickets = result.get("tickets", []) + ([result["ticket"]] if "ticket" in result else [])

                for ticket in tickets:
                    # ticket is a base64 encoded ticket, we are only interested in the first 4 and 16 bytes
                    ticket = base64.b64decode(ticket)
                    prefix4 = PrefixNode(ticket[:4].hex(), result["version"], scan=probe_name)
                    prefix16 = PrefixNode(ticket[:16].hex(), result["version"], scan=probe_name)

                    nodes.add(prefix4)
                    nodes.add(prefix16)

                    # ip --:ISSUES--> prefix, domain --:ISSUES--> prefix
                    edges.add(Edge(ip_node, prefix4, "ISSUES"))
                    edges.add(Edge(domain_node, prefix4, "ISSUES"))
                    # ip --:ISSUES--> prefix, domain --:ISSUES--> prefix
                    edges.add(Edge(ip_node, prefix16, "ISSUES"))
                    edges.add(Edge(domain_node, prefix16, "ISSUES"))


print("[2] Writing headers to csv")
for object in [DomainNode, IPNode, PrefixNode, Edge]:
    with open(object._HEADER_FILENAME, "w") as f:
        f.write(object.header())

print("[3] Writing edges to csv")
for e in tqdm(edges):
    e.write_to_csv()
print("[4] Writing nodes to csv")
for n in tqdm(nodes):
    n.write_to_csv()
