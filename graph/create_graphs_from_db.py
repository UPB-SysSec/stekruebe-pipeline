from tqdm import tqdm
import sys
from abc import ABC, abstractmethod
import os
import json
from neo4j import GraphDatabase, RoutingControl, Result

OUTPUT_DIRECTORY = "./out/"


"""
Needlessly OOP - will leave it here, just in case
"""

class GraphSerializer(ABC):
    # TODO: graph is a neo4j graph object
    def __init__(self, graph):
        self.graph = graph

    @abstractmethod
    def write():
        pass


class JSONGraphSerializer(GraphSerializer):
    def __init__(self, graph, path_to_file="graph.json"):
        super().__init__(graph)
        self.nodes = []
        self.edges = []
        self.path_to_file = path_to_file

    def _get_id_key(self, node):
        if "DOMAIN" in node.labels:
            return "domain"
        if "IP" in node.labels:
            return "ip"
        if "PREFIX" in node.labels:
            return "prefix"

    def _get_group(self, node):
        if "DOMAIN" in node.labels:
            return 0
        if "IPV4" in node.labels:
            return 1
        if "IPV6" in node.labels:
            return 4
        if "PREFIX4" in node.labels:
            return 2
        if "PREFIX16" in node.labels:
            return 3

    def _write_node(self, node):
        self.nodes.append(
            {
                "id": node._properties.get(self._get_id_key(node)),
                "group": self._get_group(node),
            }
        )

    def _write_edge(self, edge):
        source, target = edge.nodes
        self.edges.append(
            {
                "source": source._properties.get(self._get_id_key(source)),
                "target": target._properties.get(self._get_id_key(target)),
            }
        )

    def write(self):
        for n in self.graph.nodes:
            self._write_node(n)
        for e in self.graph.relationships:
            self._write_edge(e)
        os.makedirs(os.path.dirname(self.path_to_file), exist_ok=True)
        with open(self.path_to_file, "w") as file:
            json.dump({"nodes": self.nodes, "links": self.edges}, file)

class DotGraphSerializer(GraphSerializer):
    def __init__(self, graph, path_to_file="graph.dot"):
        super().__init__(graph)
        self.nodes = []
        self.edges = []
        self.path_to_file = path_to_file

    def _get_id_key(self, node):
        if "DOMAIN" in node.labels:
            return "domain"
        if "IP" in node.labels:
            return "ip"
        if "PREFIX" in node.labels:
            return "prefix"

    def _get_color(self, node):
        if "DOMAIN" in node.labels:
            return "red"
        if "IPV4" in node.labels:
            return "blue"
        if "IPV6" in node.labels:
            return "lightblue"
        if "PREFIX4" in node.labels:
            return "green"
        if "PREFIX16" in node.labels:
            return "yellow"

    def _write_node(self, node, file):
        color = self._get_color(node)
        node_id = node._properties.get(self._get_id_key(node)),
        file.write(f'"{node_id}" [color="{color}"];\n')

    def _write_edge(self, edge, file):
        source, target = edge.nodes
        source_id = source._properties.get(self._get_id_key(source)),
        target_id = target._properties.get(self._get_id_key(target)),
        file.write('"{source_id}" -- "{target_id}";\n')

    def write(self):
        os.makedirs(os.path.dirname(self.path_to_file), exist_ok=True)
        with open(self.path_to_file, "w") as file:
            file.write("graph G{\n")
            for n in self.graph.nodes:
                self._write_node(n, file)
            for e in self.graph.relationships:
                self._write_edge(e, file)
            file.write("}\n")


def _return_cluster(driver, cluster_id):
    result = driver.execute_query(
        "MATCH (n {clusterID: $cluster_id}) -[e]- () RETURN n,e",
        cluster_id=cluster_id,
        routing_=RoutingControl.READ,
        # EXPERIMENTAL
        result_transformer_=Result.graph,
    )
    return result


NEO4J_URI = os.environ.get("NEO4J_URI", "neo4j://localhost:7687/")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "neo4j")

print(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# get all clusterIDs for relevant clusters
# TODO: batch this for cluster 0. Until then: fuck it
all_ids = driver.execute_query(
        "MATCH (x:DOMAIN) WITH x.clusterID AS id, COUNT(x) AS count WHERE count>1 AND count<100000 RETURN id",
        routing_=RoutingControl.READ,
)

for r in tqdm(all_ids.records):
    i = r["id"]

    cluster_graph = _return_cluster(driver, i)
    json_path = os.path.join(OUTPUT_DIRECTORY, "json", f"{i}.json")
    j = JSONGraphSerializer(cluster_graph, json_path)
    j.write()
    dot_path = os.path.join(OUTPUT_DIRECTORY, "dot", f"{i}.dot")
    d = DotGraphSerializer(cluster_graph, dot_path)
    d.write()

driver.close()
