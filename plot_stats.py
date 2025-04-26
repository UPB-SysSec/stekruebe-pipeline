import glob
from typing import Any
import plotly.graph_objects as go
from dataclasses import dataclass, field
import csv
import os.path as op
import functools
import json
import types
import inspect

OUTDIR = functools.partial(op.join, "out_submission")
TRANCO = "../tranco_V9V2N.csv"

_ERROR_NODES = False
_FIX_X = True
_EDGE_SOURCE_COLOR = False
_ZMAP_TO_SANS_LOOP = False


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
    unblocked_4s: set[str] = field(default_factory=set)
    unblocked_6s: set[str] = field(default_factory=set)
    open_4s: set[str] = field(default_factory=set)
    open_6s: set[str] = field(default_factory=set)
    zgrab_status12: list[str] = field(default_factory=list)
    zgrab_status13: list[str] = field(default_factory=list)


PHASES = []


def phase(cls):
    PHASES.append(cls)
    return cls


_DATA = {}
try:
    with open(OUTDIR("missing.csv"), newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            stage, key, value = row
            if key == "output_size":
                continue
            value = float(value)

            _DATA[stage] = _DATA.get(stage, 0) + value
            # if a not in _DATA:
            #     _DATA[a] = {}
            # assert b not in _DATA[a]
            # _DATA[a][b] = float(c)
except FileNotFoundError:
    _DATA = dict(
        ReadTranco=dict(output_size=1_000_000),
        ZDNS=dict(status_counts={}, only_v4=0, both_v4_and_v6=0, only_v6=0, no_ips=0),
    )
for resolved_file in glob.glob(OUTDIR("0_resolved*.json")):
    with open(resolved_file) as f:
        for ln in f:
            item = json.loads(ln)
            status = item["status"]
            if status not in _DATA["ZDNS"]["status_counts"]:
                _DATA["ZDNS"]["status_counts"][status] = 0
            _DATA["ZDNS"]["status_counts"][status] += 1
print(_DATA)


@phase
class inputs:
    TRANCO_T1M = Node("T1M", COLORS.black, _DATA["ReadTranco"]["output_size"])
    SANS = Node("SANS", COLORS.black, None)


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


_SUMMARIZE_ZGRAB_ERRORS = False


@phase
class zgrab:
    ticket_12 = Node("Tickets 1.2", COLORS.blue, None)

    ticket_12_13 = Node("Tickets 1.2 and 1.3", COLORS.cyan, None)

    ticket_13 = Node("Tickets 1.3", COLORS.green, None)

    no_ticket = Node("no tickets", COLORS.black, None)

    multiple_errors = Node("multiple_errors", COLORS.red, None, True)

    error = Node("error", COLORS.red, None, True)
    # error states are added dynamically if _SUMMARIZE_ZGRAB_ERRORS is False


# create edges by iterating over all domains
# TRANCO is only the beginning, from second run onward they come from the resolved files

domains: dict[str, Domain] = {}

print("Loading domains")
with open(TRANCO) as f:
    reader = csv.reader(f)
    for row in reader:
        _, domain_name = row
        domain = domains[domain_name] = Domain()
        domain.phase_associations[inputs] = inputs.TRANCO_T1M
for resolved_file in glob.glob(OUTDIR("0_resolved*.json")):
    with open(resolved_file) as f:
        if ".r00" in f.name:
            continue
        for ln in f:
            item = json.loads(ln)
            domain_name = item.get("name")
            if not domain_name:
                continue
            domain = domains[domain_name] = Domain()
            domain.phase_associations[inputs] = inputs.SANS


def _handle_resolved():
    print("Loading IP Addresses")
    for resolved_file in glob.glob(OUTDIR("0_resolved*.json")):
        with open(resolved_file) as f:
            for ln in f:
                item = json.loads(ln)
                domain_name = item.get("name")
                if not domain_name:
                    print("No domain item in", f.name)
                    continue
                domain = domains[domain_name]
                data = item.get("data") or {}  # assigns dict() even when data exists but null
                domain.ip4s.update(data.get("ipv4_addresses", []))
                domain.ip6s.update(data.get("ipv6_addresses", []))
                domain.phase_associations[zdns] = getattr(zdns, item["status"])
    for domain in domains.values():
        if domain.ip4s and domain.ip6s:
            domain.phase_associations[resolved] = resolved.v4_6
        elif domain.ip4s:
            domain.phase_associations[resolved] = resolved.v4
        elif domain.ip6s:
            domain.phase_associations[resolved] = resolved.v6
        else:
            domain.phase_associations[resolved] = resolved.no_ip


_handle_resolved()


def _handle_after_blocklist() -> types.NoneType:
    print("Loading blocked")
    non_blocked_ip4s = set()
    non_blocked_ip6s = set()
    for resolved_filtered_file_v4 in glob.glob(OUTDIR("2_resolved_filtered_v4*.ips")):
        with open(resolved_filtered_file_v4) as f4:
            non_blocked_ip4s.update(map(lambda x: x.strip(), f4))
    for resolved_filtered_file_v6 in glob.glob(OUTDIR("2_resolved_filtered_v6*.ips")):
        with open(resolved_filtered_file_v6) as f6:
            non_blocked_ip6s.update(map(lambda x: x.strip(), f6))

    for domain in domains.values():
        remaining4 = domain.ip4s & non_blocked_ip4s
        remaining6 = domain.ip6s & non_blocked_ip6s
        domain.unblocked_4s = remaining4
        domain.unblocked_6s = remaining6
        if remaining4 and remaining6:
            domain.phase_associations[blocklist] = blocklist.v4_6
        elif remaining4:
            domain.phase_associations[blocklist] = blocklist.v4
        elif remaining6:
            domain.phase_associations[blocklist] = blocklist.v6
        else:
            domain.phase_associations[blocklist] = blocklist.blocklist
    # non_blocked_ip4s.clear()
    # non_blocked_ip6s.clear()


_handle_after_blocklist()


def _handle_zmap():
    print("Loading zmap results")
    zmap_ip4s = set()
    zmap_ip6s = set()
    for zmap_file_v4 in glob.glob(OUTDIR("3_https_hosts_v4*.ips")):
        with open(zmap_file_v4) as f4:
            zmap_ip4s.update(map(lambda x: x.strip(), f4))
    for zmap_file_v6 in glob.glob(OUTDIR("3_https_hosts_v6*.ips")):
        with open(zmap_file_v6) as f6:
            zmap_ip6s.update(map(lambda x: x.strip(), f6))

    for _domain_name, domain in domains.items():
        open4 = domain.ip4s & zmap_ip4s
        open6 = domain.ip6s & zmap_ip6s
        domain.open_4s = open4
        domain.open_6s = open6
        if open4 and open6:
            domain.phase_associations[zmap] = zmap.v4_6
        elif open4:
            domain.phase_associations[zmap] = zmap.v4
        elif open6:
            domain.phase_associations[zmap] = zmap.v6
        else:
            domain.phase_associations[zmap] = zmap.closed
    # zmap_ip4s.clear()
    # zmap_ip6s.clear()


_handle_zmap()


def _handle_zgrab():
    print("Loading zgrab")
    for zgrab_file in glob.glob(OUTDIR("7_merged_zgrab.r*.json")):
        # for zgrab_file in glob.glob(OUTDIR("7_merged_zgrab_all.json")):
        print(f"-{zgrab_file}")
        with open(zgrab_file) as f:
            for ln in f:
                item = json.loads(ln)
                domain_name = item["domain"]
                domain = domains[domain_name]

                def get_status(item, ticket_key):
                    status = item["status"]
                    if ticket_key in item:
                        assert status == "success"
                        return "ticket"
                    elif status == "success" and (ticket_key not in item or not item[ticket_key]):
                        return "no_ticket"
                    elif status == "success":
                        return "weirdsuccess"
                    else:
                        return item["status"]

                for result in item["results"]:
                    domain.zgrab_status12.append(get_status(result["https-tls1_0-1_2"], "ticket"))
                    domain.zgrab_status13.append(get_status(result["https-tls1_3"], "tickets"))
                assert domain.zgrab_status12
                assert domain.zgrab_status13

    print("-postprocessing zgrab")
    for _domain_name, domain in domains.items():
        # tickets = sum(map(lambda x: 1 if x.get("ticket") else 0, item["results"]))

        # STATUSes per version: ticket, no_ticket, error
        errors = set()

        def flatten_statii(statii):
            if not statii:
                return "did not run"
            if "ticket" in statii:
                return "ticket"
            elif "no_ticket" in statii:
                return "no_ticket"
            else:
                errors.update(statii)
                return "error"

        status_12 = flatten_statii(domain.zgrab_status12)
        status_13 = flatten_statii(domain.zgrab_status13)

        if status_12 == "ticket" and status_13 == "ticket":
            classification = zgrab.ticket_12_13
        elif status_12 == "ticket":
            classification = zgrab.ticket_12
        elif status_13 == "ticket":
            classification = zgrab.ticket_13
        elif status_12 == "no_ticket" or status_13 == "no_ticket":
            classification = zgrab.no_ticket
        elif status_12 == "did not run" and status_13 == "did not run":
            classification = "did_not_run_12_13"
        elif status_12 == "did not run":
            classification = "did_not_run_12"
        elif status_13 == "did not run":
            classification = "did_not_run_13"
        else:
            if _SUMMARIZE_ZGRAB_ERRORS:
                classification = zgrab.error
            else:
                # classification = "+".join(sorted(errors))
                if len(errors) > 1:
                    classification = zgrab.multiple_errors
                else:
                    if not errors:
                        print("No error, no ticket, no no_ticket")
                        print(domain.zgrab_status12, domain.zgrab_status13)
                        print(status_12, status_13)
                        print(status_12 == "ticket", status_13 == "ticket")
                        print(status_12 == "ticket" and status_13 == "ticket")
                        print("ticket" in domain.zgrab_status12, "ticket" in domain.zgrab_status13)
                        print("no_ticket" in domain.zgrab_status12, "no_ticket" in domain.zgrab_status13)
                        errors.add("no_error")
                    classification = errors.pop()

        if isinstance(classification, str):
            if not hasattr(zgrab, classification):
                print("Adding", classification)
                setattr(zgrab, classification, Node(classification, COLORS.red, None, True))
            domain.phase_associations[zgrab] = getattr(zgrab, classification)
        else:
            domain.phase_associations[zgrab] = classification


_handle_zgrab()

print("Loading Nodes")
nodes = []
for pi, p in enumerate(PHASES):
    if _ERROR_NODES:
        setattr(p, "_err_node", Node(f"_err{pi}", "rgba(0,0,0,0)", 0, True))
    phase_nodes = inspect.getmembers(p, lambda x: isinstance(x, Node))
    nodes.extend(map(lambda x: x[1], phase_nodes))
    if _FIX_X:
        # print()
        # print(i, p)
        for ni, (_, node) in enumerate(phase_nodes):
            node.x = pi / (len(PHASES) - 1)
            if node.y is None:
                if node.is_err:
                    node.y = 0.8
                else:
                    node.y = 0.1
            # print(i, p, node.name, node.x)

print("Creating Edges")
edges: dict[tuple[Node, Node], Edge] = {}

# patch error flows
for domain in domains.values():
    has_error = False
    for phaser in PHASES:
        if has_error:
            if _ERROR_NODES:
                domain.phase_associations[phaser] = phaser._err_node
            elif phaser in domain.phase_associations:
                assert domain.phase_associations[phaser].is_err, (domain, phaser)
                del domain.phase_associations[phaser]
        else:
            node_r = domain.phase_associations.get(phaser)
            if node_r and node_r.is_err:
                # entering error state - forward into generic error states afterwards
                has_error = True

# create edges
for domain in domains.values():
    for phasel, phaser in zip(PHASES, PHASES[1:]):
        node_l = domain.phase_associations[phasel]
        if phaser not in domain.phase_associations:
            assert node_l.is_err, node_l
            break
        node_r = domain.phase_associations[phaser]
        if (node_l, node_r) not in edges:
            edges[(node_l, node_r)] = Edge(0)

        edge = edges[(node_l, node_r)]
        node_l.actual_value_out += 1
        node_r.actual_value_in += 1
        edge.value += 1
if _ZMAP_TO_SANS_LOOP:
    for domain in domains.values():
        if domain.phase_associations[inputs] is inputs.SANS:
            # insert edge from zmap to sans
            if zmap not in domain.phase_associations:
                continue
            if domain.phase_associations[zmap] is zmap.closed:
                continue
            node_l = domain.phase_associations[zmap]
            node_r = domain.phase_associations[inputs]
            if (node_l, node_r) not in edges:
                edges[(node_l, node_r)] = Edge(0)
            edge = edges[(node_l, node_r)]
            node_l.actual_value_out += 1
            node_r.actual_value_in += 1
            edge.value += 1

# set edge colors
for (a, b), edge in edges.items():
    if _EDGE_SOURCE_COLOR:
        color = a.color
    else:
        color = b.color
    edge.color = color.replace(", 1)", ", 0.5)")

print("Rendering")
fig = go.Figure(
    data=[
        go.Sankey(
            arrangement="snap",
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

fig.update_traces(texttemplate="%{value:.10f}")

# fig.update_layout(title_text="Basic Sankey Diagram", font_size=10)
# fig.show()
fig.write_html("graph_res/stats.html")
with open("raw_data.txt", "w") as f:
    f.write(str(nodes))
