from neo4j import GraphDatabase, Driver
from enum import Enum
import time
from dataclasses import dataclass

with open("neo4j/credentials") as f:
    user, password = f.read().strip().split(":")


@dataclass(frozen=True)
class Connectable:
    ip: str
    port: int

    def __str__(self):
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"<Connectable {self.ip!r}:{self.port!r}>"


def scan(domain_from: str, addr_from: Connectable, *targed_addrs: Connectable):
    print(f"Scanning {domain_from!r} from {addr_from!r} to {len(targed_addrs)} targets")
    # dummy interface for scan.py


class IPType(Enum):
    V4 = "IPV4"
    V6 = "IPV6"


class Domain:
    def __init__(self, domain):
        self.domain = domain

    def _evaluate_from(self, driver: Driver, source_ip: IPType):
        # TODO randomize order of targets (to hit more distinct IPs)
        # TODO dry v4 and v6
        with driver.session() as session:
            _targets = session.run(
                """
                    MATCH (d1:DOMAIN {domain: $domain})--(ip1:IP {ip: $ip})--(p:PREFIX)--(ip2:IPV4)--(d2:DOMAIN)
                    WHERE ip1<>ip2 AND d1<>d2 AND NOT (d1)-->(ip2)
                    RETURN DISTINCT ip2
                    LIMIT 10
                    UNION
                    MATCH (d1:DOMAIN {domain: $domain})--(ip1:IP {ip: $ip})--(p:PREFIX)--(ip2:IPV6)--(d2:DOMAIN)
                    WHERE ip1<>ip2 AND d1<>d2 AND NOT (d1)-->(ip2)
                    RETURN DISTINCT ip2
                    LIMIT 10
                    """,
                domain=self.domain,
                ip=source_ip,
            )
            local_targets = []
            for target_ips in _targets:
                target_ips = target_ips[0]
                local_targets.append(Connectable(target_ips, 443))

        scan(self.domain, source_ip, *local_targets)

    def _evaluate(self, driver: Driver, tfrom: IPType):
        if not isinstance(tfrom, IPType):
            raise TypeError("tfrom must be IPType")

        with driver.session() as session:
            # get source IPs
            ips = session.run(
                f"""
                MATCH (d:DOMAIN {{domain: $domain}})--(ip:{tfrom.value})
                RETURN DISTINCT ip.ip
                """,
                domain=self.domain,
            )

            for source_ip in ips:
                self._evaluate_from(driver, source_ip[0])

    def evaluate(self, driver: Driver):
        for tfrom in IPType:
            self._evaluate(driver, tfrom)


def get_domains(driver: Driver, cluster: int = None):
    with driver.session() as session:
        if cluster is None:
            query = session.run("MATCH (n: DOMAIN) RETURN n.domain AS domain")
        else:
            assert isinstance(cluster, int)
            query = session.run("MATCH (n: DOMAIN {clusterID: $cluster}) RETURN n.domain AS domain", cluster=cluster)
        for record in query:
            yield Domain(record.get("domain"))


def main():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=(user, password))

    # getting all domains takes a bit, but still reasonable | about 47 seconds for 620,076 domains

    CLUSTER = None
    # CLUSTER = 4283  # Test Cluster (8409 domains)
    DOMAINS = set(get_domains(driver, CLUSTER))
    print(f"Fetched {len(DOMAINS)} domains")

    for domain in DOMAINS:
        domain.evaluate(driver)


if __name__ == "__main__":
    main()
