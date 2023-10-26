import json
import base64
import pickle
import os.path as op
from dataclasses import dataclass, field
import os

TOTAL_LINES = 1909754


class NodeType:
    DOMAIN = 0
    IP = 1
    PREFIX_4 = 2
    PREFIX_16 = 3


ALL_NODES: dict[str, "Node"] = {}


@dataclass(frozen=True)
class Node:
    id: str
    typ: int
    connections: set["str"] = field(default_factory=set)

    def add_connection(self, target: "Node"):
        assert isinstance(target, Node)
        self.connections.add(target.id)
        target.connections.add(self.id)

    def get_neighbors(self, typ: NodeType = None):
        for id in self.connections:
            neighbor = ALL_NODES[id]
            if typ is None or neighbor.typ == typ:
                yield neighbor

    def get_reachable_nodes(
        self,
        target_typ: NodeType = None,
        only_via: list[NodeType] = None,
        *,
        first_include_self=True,
        seen_stack=None,
        maxhops=None,
    ):
        if maxhops is not None and maxhops < 0:
            return
        if seen_stack is None:
            seen_stack = set()
        seen_stack.add(self.id)
        if self.typ is None or self.typ == target_typ:
            if first_include_self:
                yield self
        if maxhops is not None and maxhops == 0:
            return
        for neighbor in self.get_neighbors():
            if neighbor.id in seen_stack:
                continue
            if only_via is not None and neighbor.typ not in only_via:
                continue
            yield from neighbor.get_reachable_nodes(
                target_typ, seen_stack=seen_stack, maxhops=maxhops - 1 if maxhops is not None else None
            )

    def has_other_reachable(self, target_typ: NodeType = None, *, maxhops=None):
        for _ in self.get_reachable_nodes(target_typ, seen_stack=set([self]), maxhops=maxhops):
            return True
        return False

    def __hash__(self) -> int:
        return hash(self.id)


def get_prefixes(tickets: list[bytes], length) -> list[bytes]:
    for ticket in tickets:
        yield ticket[:length]


def parse_nodes():
    def get_node(id: str, typ: NodeType):
        if id not in ALL_NODES:
            ALL_NODES[id] = Node(id, typ)
        else:
            assert ALL_NODES[id].typ == typ
        return ALL_NODES[id]

    with open("out/7_merged_zgrab.json") as f:
        lineno = 0
        for ln in f:
            lineno += 1
            item = json.loads(ln)
            ip = item["ip"]
            domain = item["domain"]
            tickets = item["tickets"]

            # filter tickets
            while None in tickets:
                tickets.remove(None)
            tickets = list(filter(lambda x: "value" in x, tickets))
            if len(tickets) > 0:
                tickets = map(lambda x: x["value"], tickets)
                tickets = map(base64.b64decode, tickets)
                tickets = tuple(tickets)
                host_prefixes_4 = set(get_prefixes(tickets, 4))
                host_prefixes_16 = set(get_prefixes(tickets, 16))

                domain_node = get_node(domain, NodeType.DOMAIN)
                ip_node = get_node(ip, NodeType.IP)
                prefix4_nodes = [get_node(prefix.hex(), NodeType.PREFIX_4) for prefix in host_prefixes_4]
                prefix16_nodes = [get_node(prefix.hex(), NodeType.PREFIX_16) for prefix in host_prefixes_16]

                host_nodes = [ip_node] + prefix4_nodes + prefix16_nodes
                for n in host_nodes:
                    domain_node.add_connection(n)

            if lineno % 25000 == 0:
                print(
                    f"{lineno:7d}/{TOTAL_LINES:7d} lines ({100*lineno/TOTAL_LINES:5.2f}%) | {len(ALL_NODES):7d} nodes (factor {len(ALL_NODES)/lineno:5.3f})"
                )


def load_nodes():
    global ALL_NODES
    if not op.exists("graph/.nodes.pickle"):
        parse_nodes()
        with open("graph/.nodes.pickle", "wb") as f:
            pickle.dump(ALL_NODES, f)
        print(f"Parsed {len(ALL_NODES)} nodes")
    else:
        print("Loading nodes from pickle")
        with open("graph/.nodes.pickle", "rb") as f:
            ALL_NODES = pickle.load(f)
        print(f"loaded {len(ALL_NODES)} nodes")


def dump_json(nodes_to_dump, fname="graph/data.json", *, print_progress=False):
    if print_progress:
        print("Preparing JSON")
    json_nodes = []
    json_links = []
    for i, node in enumerate(nodes_to_dump):
        if print_progress and i % 25000 == 0:
            print(f"{i:7d}/{len(nodes_to_dump):7d} ({100*i/len(nodes_to_dump):5.2f}%)")
        json_nodes.append({"id": node.id, "group": node.typ})
        if node.typ == NodeType.DOMAIN:
            for neighbor in node.get_neighbors():
                json_links.append({"source": node.id, "target": neighbor.id})
    if print_progress:
        print("Writing JSON")
    os.makedirs(op.dirname(fname), exist_ok=True)
    with open(fname, "w") as f:
        json.dump(
            {
                "nodes": json_nodes,
                "links": json_links,
            },
            f,
        )
    if print_progress:
        print("Done dumping JSON")


def dump_dot(nodes_to_dump, fname="graph/graph.dot"):
    COLORS = {
        NodeType.DOMAIN: "red",
        NodeType.IP: "blue",
        NodeType.PREFIX_4: "green",
        NodeType.PREFIX_16: "yellow",
    }
    os.makedirs(op.dirname(fname), exist_ok=True)
    with open(fname, "w") as f:
        f.write("graph G{\n")
        for n in nodes_to_dump:
            f.write(f'"{n.id}" [color="{COLORS[n.typ]}"];\n')
        for n in nodes_to_dump:
            if n.typ != NodeType.DOMAIN:
                continue
            for c in n.get_neighbors():
                f.write(f'"{n.id}" -- "{c.id}";\n')
        f.write("}\n")


def main_single_graph():
    load_nodes()

    print("Filtering domain nodes")

    domain_nodes_to_dump = set()
    domain_nodes_handled = set()

    for i, node in enumerate(ALL_NODES.values()):
        if i % 10000 == 0:
            print(f"{i:7d}/{len(ALL_NODES):7d} ({100*i/len(ALL_NODES):5.2f}%)")
        if node.typ != NodeType.DOMAIN:
            continue
        if node in domain_nodes_handled:
            continue
        domain_nodes_handled.add(node)
        my_ips = set(node.get_neighbors(NodeType.IP))
        for neighbor in node.get_reachable_nodes(NodeType.DOMAIN, maxhops=2, first_include_self=False):
            their_ips = set(neighbor.get_neighbors(NodeType.IP))
            if len(my_ips.symmetric_difference(their_ips)) > 0:
                # have at least one IP that is not shared
                domain_nodes_to_dump.add(node)
                domain_nodes_handled.add(neighbor)
                domain_nodes_to_dump.add(neighbor)
                break

    print(f"Filtered domain nodes {len(domain_nodes_handled)} -> {len(domain_nodes_to_dump)}")

    print("Collecting all required neighbor nodes")

    nodes_to_dump = set()
    for i, node in enumerate(domain_nodes_to_dump):
        if i % 25000 == 0:
            print(f"{i:7d}/{len(domain_nodes_to_dump):7d} ({100*i/len(domain_nodes_to_dump):5.2f}%)")
        nodes_to_dump.add(node)
        for neighbor in node.get_neighbors():
            nodes_to_dump.add(neighbor)

    print(f"Dumping {len(nodes_to_dump)} nodes (reduced from {len(ALL_NODES)})")

    dump_json(nodes_to_dump, print_progress=True)
    dump_dot(nodes_to_dump)
    print("Done")


def main_clusters():
    load_nodes()

    print("Clustering domain nodes")

    clusters: list[set[Node]] = list()
    domain_nodes_handled = set()

    for i, node in enumerate(ALL_NODES.values()):
        if i % 25000 == 0:
            print(f"{i:7d}/{len(ALL_NODES):7d} ({100*i/len(ALL_NODES):5.2f}%) | {len(clusters):7d} clusters")
        if node.typ != NodeType.DOMAIN:
            continue
        if node in domain_nodes_handled:
            continue
        domain_nodes_handled.add(node)

        add_cluster = False
        cluster = {node}

        my_ips = set(node.get_neighbors(NodeType.IP))
        reachable_domain_generator = node.get_reachable_nodes(
            NodeType.DOMAIN,
            only_via=[
                NodeType.DOMAIN,
                NodeType.PREFIX_16,
                NodeType.PREFIX_4,
            ],
            maxhops=2,
            first_include_self=False,
        )
        for neighbor in reachable_domain_generator:
            domain_nodes_handled.add(neighbor)
            cluster.add(neighbor)
            their_ips = set(neighbor.get_neighbors(NodeType.IP))
            if len(my_ips.symmetric_difference(their_ips)) > 0:
                # have at least one IP that is not shared
                add_cluster = True
                break
        if add_cluster:
            for neighbor in reachable_domain_generator:
                domain_nodes_handled.add(neighbor)
                cluster.add(neighbor)
            clusters.append(cluster)

    print(f"Clustered {len(domain_nodes_handled)} domain nodes -> {len(clusters)} clusters")

    clusters.sort(key=lambda x: len(x), reverse=True)

    for i, cluster in enumerate(clusters):
        nodes_to_dump = set()
        for node in cluster:
            nodes_to_dump.add(node)
            for neighbor in node.get_neighbors():
                nodes_to_dump.add(neighbor)

        print(f"Cluster {i}/{len(clusters)}: {len(cluster)} domain nodes / {len(nodes_to_dump)} total nodes")

        dump_json(nodes_to_dump, fname=f"graph/clusters/json/{i}.json")
        dump_dot(nodes_to_dump, fname=f"graph/clusters/dot/{i}.dot")
    print("Done")


if __name__ == "__main__":
    main_clusters()
