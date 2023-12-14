from neo4j import GraphDatabase, Driver
from enum import Enum
import time
from dataclasses import dataclass
import datetime
from multiprocessing.pool import ThreadPool
from threading import Thread

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


class _Stats:
    def __init__(self) -> None:
        self.domains = 0
        self.targets = 0
        self.expected_domains = 0
        self.start_time = 0

    def start(self, expected_domains: int):
        self.start_time = time.time()
        self.expected_domains = expected_domains

    def done_domain(self):
        self.domains += 1

    def done_targets(self, n):
        self.targets += n

    def __str__(self) -> str:
        elapsed = time.time() - self.start_time
        if self.domains == 0:
            ETA = None
            DURATION = None
        else:
            ETA = (self.expected_domains - self.domains) / (self.domains / elapsed)
            DURATION = datetime.timedelta(seconds=elapsed + ETA)
            ETA = datetime.timedelta(seconds=ETA)
        return (
            f"Total: {self.domains} domains, {self.targets} targets in {elapsed:.2f} seconds | "
            f"{self.domains/elapsed:.2f} domains/s {100.0*self.domains/self.expected_domains:5.2f}% | "
            f"ETA: {ETA} / Total: {DURATION} | "
            f"{self.targets/elapsed:.2f} targets/s"
        )


STATS = _Stats()


def _stats_printer():
    while STATS.start_time == 0:
        time.sleep(2)
    while True:
        print(STATS)
        time.sleep(2)


Thread(target=_stats_printer, daemon=True, name="Stats Printer").start()


def scan(domain_from: str, addr_from: Connectable, *targed_addrs: Connectable):
    # dummy interface for scan.py
    # print(f"Scanning {domain_from!r} from {addr_from!r} to {len(targed_addrs)} targets")
    STATS.done_targets(len(targed_addrs))


class IPType(Enum):
    V4 = "IPV4"
    V6 = "IPV6"


# TODO dry v4 and v6
_BASE_QUERY = """
CALL {{
    MATCH (d1:DOMAIN {{domain: $domain}})--(ip1:IP {{ip: $ip}})--(p:PREFIX)--(ip2:{ip_target_type})--(d2:DOMAIN)
    WHERE ip1<>ip2 AND d1<>d2 AND NOT (d1)-->(ip2)
    RETURN DISTINCT ip2
}}
RETURN *
ORDER BY rand()
LIMIT 10
"""


class Domain:
    def __init__(self, domain):
        self.domain = domain

    def _evaluate_from(self, driver: Driver, source_ip: str):
        with driver.session() as session:
            _targets = session.run(
                _BASE_QUERY.format(ip_target_type=IPType.V4.value)
                + " UNION "
                + _BASE_QUERY.format(ip_target_type=IPType.V6.value),
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

        STATS.done_domain()


def get_domains(driver: Driver, cluster: int = None):
    with driver.session() as session:
        if cluster is None:
            query = session.run("MATCH (n: DOMAIN) RETURN n.domain AS domain")
        else:
            assert isinstance(cluster, int)
            query = session.run("MATCH (n: DOMAIN {clusterID: $cluster}) RETURN n.domain AS domain", cluster=cluster)
        for record in query:
            yield Domain(record.get("domain"))


def main(parallelize):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=(user, password))

    # getting all domains takes a bit, but still reasonable | about 47 seconds for 620,076 domains

    CLUSTER = None
    # CLUSTER = 4283  # Test Cluster (8409 domains)
    DOMAINS = set(get_domains(driver, CLUSTER))
    print(f"Fetched {len(DOMAINS)} domains")

    STATS.start(len(DOMAINS))

    if parallelize:
        with ThreadPool() as pool:
            pool.map(lambda d: d.evaluate(driver), DOMAINS)
    else:
        for domain in DOMAINS:
            domain.evaluate(driver)


if __name__ == "__main__":
    main(True)
