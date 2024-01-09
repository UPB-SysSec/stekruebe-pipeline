from typing import Any
import plotly.graph_objects as go
from dataclasses import dataclass, field
import csv
import os.path as op
import functools
import json
import types
import inspect

OUTDIR = functools.partial(op.join, "out_python")
TRANCO = "tranco_7X8NX.csv"
OUTDIR = functools.partial(op.join, "out")
# TRANCO = "tranco_LYK84.csv"


class COLORS:
    black = "rgba(0, 0, 0, 1)"
    red = "rgba(255, 0, 0, 1)"
    green = "rgba(0, 255, 0, 1)"
    blue = "rgba(0, 0, 255, 1)"
    cyan = "rgba(0, 255, 255, 1)"
    gray = "rgba(128, 128, 128, 1)"


ZDNS_COLORS = {
    "NOERROR": COLORS.black,
    "NXDOMAIN": COLORS.red,
    "SERVFAIL": COLORS.red,
    "ERROR": COLORS.red,
    "ITERATIVE_TIMEOUT": COLORS.red,
    "REFUSED": COLORS.red,
    "FORMERR": COLORS.red,
    "TIMEOUT": COLORS.red,
    "AUTHFAIL": COLORS.red,
    "NOTAUTH": COLORS.red,
    "NOTIMP": COLORS.red,
}


class IP_COLORS:
    v4 = COLORS.blue
    v4_6 = COLORS.cyan
    v6 = COLORS.green


@dataclass
class Node:
    name: str
    color: str
    expected_value: int
    is_err: bool = False
    actual_value_in: int = 0
    actual_value_out: int = 0

    x: float = None
    y: float = None

    def __hash__(self) -> int:
        return id(self)


@dataclass
class Edge:
    value: int
    color: str = None


@dataclass
class Domain:
    phase_associations: dict["Phase Class", Node] = field(default_factory=dict)
    ip4s: set[str] = field(default_factory=set)
    ip6s: set[str] = field(default_factory=set)


PHASES = []


def phase(cls):
    PHASES.append(cls)
    return cls


_DATA = {}
try:
    with open(OUTDIR("stats.csv"), newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            a, b, c = row
            if a not in _DATA:
                _DATA[a] = {}
            assert b not in _DATA[a]
            _DATA[a][b] = json.loads(c)
except FileNotFoundError:
    _DATA = dict(
        ReadTranco=dict(output_size=1_000_000),
        ZDNS=dict(status_counts={}, only_v4=0, both_v4_and_v6=0, only_v6=0, no_ips=0),
    )
    with open(OUTDIR("0_resolved.json")) as f:
        for ln in f:
            item = json.loads(ln)
            status = item["status"]
            if status not in _DATA["ZDNS"]["status_counts"]:
                _DATA["ZDNS"]["status_counts"][status] = 0
            _DATA["ZDNS"]["status_counts"][status] += 1


@phase
class tranco:
    T1M = Node("T1M", COLORS.black, _DATA["ReadTranco"]["output_size"])


@phase
class zdns:
    NOERROR: Node = None


for status, count in _DATA["ZDNS"]["status_counts"].items():
    if status == "NOERROR":
        color = COLORS.black
    else:
        color = COLORS.red
    setattr(zdns, status, Node(status, color, count, status != "NOERROR"))


@phase
class resolved:
    v4 = Node("v4 only", IP_COLORS.v4, _DATA["ZDNS"]["only_v4"])
    v4_6 = Node("v4+v6", IP_COLORS.v4_6, _DATA["ZDNS"]["both_v4_and_v6"])
    v6 = Node("v6 only", IP_COLORS.v6, _DATA["ZDNS"]["only_v6"])
    no_ip = Node("No IP", COLORS.red, _DATA["ZDNS"]["no_ips"], True)


@phase
class blocklist:
    v4 = Node("v4 only", IP_COLORS.v4, None)
    v4_6 = Node("v4+v6", IP_COLORS.v4_6, None)
    v6 = Node("v6 only", IP_COLORS.v6, None)
    blocklist = Node("IP Blocklist", COLORS.red, None, True)


@phase
class zmap:
    v4 = Node("v4 open", IP_COLORS.v4, None)
    v4_6 = Node("v4+v6 open", IP_COLORS.v4_6, None)
    v6 = Node("v6 open", IP_COLORS.v6, None)
    closed = Node("Closed", COLORS.black, None, True)


@phase
class zgrab:
    ticket = Node("tickets", COLORS.green, None)
    no_ticket = Node("no ticket", COLORS.black, None)
    multiple_errors = Node("multiple_errors", COLORS.red, None, True)


_zgrab_statii = set()
with open(OUTDIR("7_merged_zgrab.json")) as f:
    for ln in f:
        item = json.loads(ln)
        status = set(map(lambda x: x.get("status"), item["results"]))
        for s in status:
            _zgrab_statii.add(s)
for status in _zgrab_statii:
    if status == "success":
        continue
    setattr(zgrab, status, Node(status, COLORS.red, None, True))


# create edges by iterating over all domains

domains: dict[str, Domain] = {}

print("Loading domains")
with open(TRANCO) as f:
    reader = csv.reader(f)
    for row in reader:
        _, domain_name = row
        domain = domains[domain_name] = Domain()
        domain.phase_associations[tranco] = tranco.T1M

print("Loading IP Addresses")
with open(OUTDIR("0_resolved.json")) as f:
    for ln in f:
        item = json.loads(ln)
        domain_name = item["name"]
        domain = domains[domain_name]
        domain.ip4s = set(item.get("data", {}).get("ipv4_addresses", []))
        domain.ip6s = set(item.get("data", {}).get("ipv6_addresses", []))
        domain.phase_associations[zdns] = getattr(zdns, item["status"])
        if domain.ip4s and domain.ip6s:
            domain.phase_associations[resolved] = resolved.v4_6
        elif domain.ip4s:
            domain.phase_associations[resolved] = resolved.v4
        elif domain.ip6s:
            domain.phase_associations[resolved] = resolved.v6
        else:
            domain.phase_associations[resolved] = resolved.no_ip

print("Loading blocked")
with open(OUTDIR("2_resolved_filtered_v4.ips")) as f4, open(OUTDIR("2_resolved_filtered_v6.ips")) as f6:
    ip4s = set(map(lambda x: x.strip(), f4))
    ip6s = set(map(lambda x: x.strip(), f6))

    for domain in domains.values():
        overlap4 = domain.ip4s & ip4s
        overlap6 = domain.ip6s & ip6s
        if overlap4 and overlap6:
            domain.phase_associations[blocklist] = blocklist.v4_6
        elif overlap4:
            domain.phase_associations[blocklist] = blocklist.v4
        elif overlap6:
            domain.phase_associations[blocklist] = blocklist.v6
        else:
            domain.phase_associations[blocklist] = blocklist.blocklist

print("Loading zmap results")
with open(OUTDIR("3_https_hosts_v4.ips")) as f4, open(OUTDIR("3_https_hosts_v6.ips")) as f6:
    ip4s = set(map(lambda x: x.strip(), f4))
    ip6s = set(map(lambda x: x.strip(), f6))

    for domain in domains.values():
        overlap4 = domain.ip4s & ip4s
        overlap6 = domain.ip6s & ip6s
        if overlap4 and overlap6:
            domain.phase_associations[zmap] = zmap.v4_6
        elif overlap4:
            domain.phase_associations[zmap] = zmap.v4
        elif overlap6:
            domain.phase_associations[zmap] = zmap.v6
        else:
            domain.phase_associations[zmap] = zmap.closed

print("Loading zgrab")
with open(OUTDIR("7_merged_zgrab.json")) as f:
    for ln in f:
        item = json.loads(ln)
        domain_name = item["domain"]
        domain = domains[domain_name]

        tickets = sum(map(lambda x: 1 if x.get("ticket") else 0, item["results"]))
        status = set(map(lambda x: x.get("status"), item["results"]))

        if len(status) > 1:
            if "success" in status:
                status = "success"
            else:
                status = "multiple_errors"
        else:
            status = status.pop()

        if status == "success":
            if tickets:
                domain.phase_associations[zgrab] = zgrab.ticket
            else:
                domain.phase_associations[zgrab] = zgrab.no_ticket
        else:
            domain.phase_associations[zgrab] = getattr(zgrab, status)

print("Loading Nodes")
nodes = []
for i, p in enumerate(PHASES):
    setattr(p, "_err_node", Node(f"_err{i}", "rgba(0,0,0,0)", 0, True))
    phase_nodes = inspect.getmembers(p, lambda x: isinstance(x, Node))
    nodes.extend(map(lambda x: x[1], phase_nodes))

print("Creating Edges")
edges: dict[tuple[Node, Node], Edge] = {}

for domain in domains.values():
    has_error = False
    for phasel, phaser in list(zip(PHASES, PHASES[1:])):
        if has_error:
            domain.phase_associations[phaser] = phaser._err_node
        node_r = domain.phase_associations[phaser]
        if node_r.is_err:
            # entering error state - forward into generic error states afterwards
            has_error = True

for domain in domains.values():
    for phasel, phaser in zip(PHASES, PHASES[1:]):
        node_l = domain.phase_associations[phasel]
        node_r = domain.phase_associations[phaser]
        if (node_l, node_r) not in edges:
            edges[(node_l, node_r)] = Edge(0)

        edge = edges[(node_l, node_r)]
        node_l.actual_value_out += 1
        node_r.actual_value_in += 1
        edge.value += 1

# for phasel, phaser in zip(PHASES, PHASES[1:]):
#     lerr = phasel._err_node
#     rerr = phaser._err_node
#     edges[(lerr, rerr)] = Edge(lerr.actual_value_in)
#     lerr.actual_value_out += lerr.actual_value_in
#     rerr.actual_value_in += lerr.actual_value_in

for (a, b), edge in edges.items():
    edge.color = a.color.replace(", 1)", ", 0.5)")

print("Rendering")
fig = go.Figure(
    data=[
        go.Sankey(
            # arrangement="fixed",
            # snap, perpendicular, freeform, fixed
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=[node.name for node in nodes],
                color=[node.color for node in nodes],
                x=[node.x for node in nodes],
                y=[node.y for node in nodes],
            ),
            link=dict(
                source=[nodes.index(edge[0]) for edge in edges],
                target=[nodes.index(edge[1]) for edge in edges],
                value=[value.value for value in edges.values()],
                color=[edge.color for edge in edges.values()],
            ),
        )
    ]
)

# fig.update_layout(title_text="Basic Sankey Diagram", font_size=10)
# fig.show()
fig.write_html("graph/stats.html")
