import abc
import json
import subprocess
import sys
import tempfile
from typing import Any
from neo4j import GraphDatabase, Driver, Session, Result
from enum import Enum
import time
from dataclasses import dataclass
import datetime
from multiprocessing.pool import ThreadPool
from pymongo import MongoClient
from threading import Thread
import inspect

with open("neo4j/credentials") as f:
    neo4j_user, neo4j_password = f.read().strip().split(":")
with open("mongo/credentials") as f:
    mongo_user, mongo_password = f.read().strip().split(":")


@dataclass(frozen=True)
class Connectable:
    ip: str
    port: int

    def __str__(self):
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"<Connectable {self.ip!r}:{self.port!r}>"


@dataclass
class _DBStats:
    executed_queries: int = 0
    done_queries: int = 0
    db_hits: int = 0
    time_ready: int = 0
    time_consumed: int = 0


class _Stats:
    def __init__(self) -> None:
        self.domains = 0
        self.targets = 0
        self.expected_domains = 0
        self.start_time = 0
        self.db = {}
        self.executed_queries = 0
        self.done_queries = 0

    def start(self, expected_domains: int):
        self.start_time = time.time()
        self.expected_domains = expected_domains

    def done_domain(self):
        self.domains += 1

    def done_targets(self, n):
        self.targets += n

    def performed_query(self, result: Result = None):
        callsite = inspect.stack()[2]
        callsite_str = f"{callsite.function}({callsite.lineno})"
        if callsite_str not in self.db:
            self.db[callsite_str] = _DBStats()
        dbstats: _DBStats = self.db[callsite_str]
        if result is not None:
            original_close = result._on_closed
            # 0 is this function, 1 is _Profile{Session/Driver}, 2 is the actual caller

            def _result_closed():
                # summary = result.consume()
                summary = result._obtain_summary()
                dbstats.done_queries += 1
                self.done_queries += 1
                hits = summary.profile["dbHits"]
                for child in summary.profile["children"]:
                    hits += child["dbHits"]
                dbstats.db_hits += hits
                dbstats.time_ready += summary.result_available_after
                dbstats.time_consumed += summary.result_consumed_after
                return original_close()

            result._on_closed = _result_closed
        dbstats.executed_queries += 1
        self.executed_queries += 1

    def __str__(self) -> str:
        elapsed = time.time() - self.start_time
        if self.domains == 0:
            ETA = None
            DURATION = None
        else:
            ETA = (self.expected_domains - self.domains) / (self.domains / elapsed)
            DURATION = datetime.timedelta(seconds=elapsed + ETA)
            ETA = datetime.timedelta(seconds=ETA)
        ret = (
            f"Total: {self.domains} domains, {self.targets} targets in {elapsed:.2f} seconds | "
            f"{self.domains/elapsed:.2f} domains/s {100.0*self.domains/self.expected_domains:5.2f}% | "
            f"ETA: {ETA} / Total: {DURATION} | "
            f"{self.targets/elapsed:.2f} targets/s"
        )
        if self.executed_queries > 0:
            ret += "\n"
            if self.done_queries == 0:
                ret += f"{self.done_queries} queries executed"
            else:
                # we have stats for results
                ret += f"{self.done_queries} queries executed ({self.executed_queries - self.done_queries} open)\n"
                ret_stats = []
                for callsite, stats in self.db.items():
                    ret_stats.append(
                        f"  {callsite}\n"
                        f"    {stats.executed_queries} executed ({stats.executed_queries - stats.done_queries} open)\n"
                        f"    {stats.db_hits/(stats.done_queries or 1):.1f} avg DB hits/query\n"
                        f"    {stats.time_ready/(stats.done_queries or 1):.1f}ms avg results ready | {stats.time_consumed/(stats.done_queries or 1):.1f}ms avg results consume"
                    )
                ret += "\n".join(ret_stats)

        return ret


STATS = _Stats()


def _stats_printer():
    while STATS.start_time == 0:
        time.sleep(2)
    while True:
        print(STATS)
        time.sleep(2)


Thread(target=_stats_printer, daemon=True, name="Stats Printer").start()


class _ProfileSession:
    def __init__(self, stats: _Stats, inner: Session, profile: bool) -> None:
        self._stats = stats
        self._session = inner
        self._profile = profile

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    def __enter__(self):
        res = self._session.__enter__()
        assert res is self._session
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._session.__exit__(exc_type, exc_value, traceback)

    def run(self, query: str, *args, **kwargs):
        if self._profile:
            query_res = self._session.run("PROFILE " + query, *args, **kwargs)
            self._stats.performed_query(query_res)
        else:
            query_res = self._session.run(query, *args, **kwargs)
            self._stats.performed_query()

        return query_res


class _ProfileDriver:
    def __init__(self, stats: _Stats, inner: Driver, profile: bool) -> None:
        self._stats = stats
        self._driver = inner
        self._profile = profile

    def __getattr__(self, name: str) -> Any:
        return getattr(self._driver, name)

    def session(self):
        return _ProfileSession(self._stats, self._driver.session(), self._profile)


class ScanVersion(Enum):
    TLS1_2 = "12"
    TLS1_3 = "13"


class Scanner(abc.ABC):
    @abc.abstractmethod
    def scan(self, domain_from: str, addr_from: Connectable, *targed_addrs: Connectable, version=ScanVersion.TLS1_2):
        pass


class DummyScanner(Scanner):
    def scan(self, domain_from: str, addr_from: Connectable, *targed_addrs: Connectable, version=ScanVersion.TLS1_2):
        print(f"Scanning {domain_from} from {addr_from} to {len(targed_addrs)} targets on version {version.value}")
        STATS.done_targets(len(targed_addrs))


class Zgrab2Scanner(Scanner):
    _INITIAL_TICKET_1_2_CONFIG = [
        "./zgrab2",
        "tls",
        "--min-version=0x0301",
        "--max-version=0x0303",
        "--force-session-ticket",
        "--port=443",
        "--use-session-cache=2",
    ]
    _INITIAL_TICKET_1_3_CONFIG = [
        "./zgrab2",
        "http",
        "--use-https",
        "--max-redirects=1",
        "--redirects-succeed",
        # tls options
        "--min-version=0x0304",
        "--max-version=0x0304",
        "--port=443",
        "--use-session-cache=2",
    ]

    _REDIRECT_TICKET_1_2_CONFIG = [
        "./zgrab2",
        "http",
        "--use-https",
        "--max-redirects=1",
        "--redirects-succeed",
        # tls options
        "--min-version=0x0303",  # TODO TLS: match with initial ticket dynamically
        "--max-version=0x0303",  # TODO TLS: match with initial ticket dynamically
        "--port=443",
        "--use-session-cache=1",
    ]
    _REDIRECT_TICKET_1_3_CONFIG = [
        "./zgrab2",
        "http",
        "--use-https",
        "--max-redirects=1",
        "--redirects-succeed"
        # tls options
        "--min-version=0x0304",
        "--max-version=0x0304",
        "--port=443",
        "--use-session-cache=1",
    ]

    def __init__(
        self, mongo_driver, db_name="steckruebe", collection_name=f"ticket_redirection_{str(datetime.datetime.now())}"
    ) -> None:
        self.mongo_driver = mongo_driver
        self.mongo_db = mongo_driver[db_name]
        self.mongo_collection = self.mongo_db[collection_name]

    def scan(self, domain_from: str, addr_from: Connectable, *target_addrs: Connectable, version):
        if version == ScanVersion.TLS1_2:
            res = self._scan_by_config(
                domain_from,
                addr_from,
                *target_addrs,
                initial_config=self._INITIAL_TICKET_1_2_CONFIG,
                redirect_config=self._REDIRECT_TICKET_1_2_CONFIG,
            )
            # potentially version specific pre-database processing here
        elif version == ScanVersion.TLS1_3:
            res = self._scan_by_config(
                domain_from,
                addr_from,
                *target_addrs,
                initial_config=self._INITIAL_TICKET_1_3_CONFIG,
                redirect_config=self._REDIRECT_TICKET_1_3_CONFIG,
            )
        else:
            raise ValueError("Unknown version")
        insert = self.mongo_collection.insert_one(res)
        STATS.done_targets(len(target_addrs))

    def _scan_by_config(
        self,
        domain_from: str,
        addr_from: Connectable,
        *target_addrs: Connectable,
        initial_config: list,
        redirect_config: list,
    ):
        # get ticket for domain_from
        input_string = f"{addr_from.ip},{domain_from},\n".encode()
        with tempfile.TemporaryDirectory() as cache_dir:
            initial = subprocess.run(
                initial_config + ["--session-cache-dir", cache_dir],
                input=input_string,
                capture_output=True,
            )
            result = dict()
            result["initial"] = json.loads(initial.stdout)
            result["zgrab_initial_exitcode"] = initial.returncode

            # TODO TLS: check whether initial gave a ticket

            input_string = "".join([f"{target_addr.ip},{domain_from}\n" for target_addr in target_addrs]).encode()
            redirect = subprocess.run(
                redirect_config + ["--session-cache-dir", cache_dir],
                input=input_string,
                capture_output=True,
            )
            result["zgrab_redirect_exitcode"] = redirect.returncode
            redirect_results = [json.loads(res) for res in redirect.stdout.splitlines()]
            # TODO SH: filter objects
            # HTTP: body_sha, body_title, status_code, location_header
            # del certs
            # TODO SH: persist status line from stderr?
            result["redirect"] = redirect_results
            # newline separated json objects
            return result


class IPType(Enum):
    V4 = "IPV4"
    V6 = "IPV6"


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

    def _evaluate_from(self, driver: Driver, scanner: Scanner, source_ip: str):
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
                target_ips = target_ips[0].get("ip")  # get the ip from the Neo4j result
                local_targets.append(Connectable(target_ips, 443))

        scanner.scan(
            self.domain, Connectable(source_ip, 443), *local_targets, version=ScanVersion.TLS1_2
        )  # TODO SNH: select correct version

    def _evaluate(self, driver: Driver, scanner: Scanner, tfrom: IPType):
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
                self._evaluate_from(driver, scanner, source_ip[0])

    def evaluate(self, driver: Driver, scanner: Scanner):
        for tfrom in IPType:
            self._evaluate(driver, scanner, tfrom)

        STATS.done_domain()


def get_domains(driver: Driver, cluster: int = None, limit: int = None):
    with driver.session() as session:
        if cluster is None:
            query = "MATCH (n: DOMAIN) RETURN n.domain AS domain"
        else:
            assert isinstance(cluster, int)
            query = "MATCH (n: DOMAIN {clusterID: $cluster}) RETURN n.domain AS domain"
        if limit is not None:
            query += f" LIMIT $limit"
        query = session.run(query, cluster=cluster, limit=limit)
        for record in query:
            yield Domain(record.get("domain"))


def print_dummy_query():
    print(
        "PROFILE\n"
        + _BASE_QUERY.format(ip_target_type="IP")
        .replace("$domain", '"r3---sn-5uaeznes.googlevideo.com"')
        .replace("$ip", '"172.217.128.200"')
    )


def main(parallelize, create_indexes=True, profile=True):
    # print_dummy_query()

    neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=(neo4j_user, neo4j_password))
    if profile:
        neo4j_driver = _ProfileDriver(STATS, neo4j_driver, profile)

    # getting all domains takes a bit, but still reasonable | about 47 seconds for 620,076 domains

    if create_indexes:
        # prepare indexes
        neo4j_driver.execute_query("CREATE INDEX ip_lookup IF NOT EXISTS FOR (x:IP) ON (x.ip)")
        neo4j_driver.execute_query("CREATE INDEX domain_lookup IF NOT EXISTS FOR (x:DOMAIN) ON (x.domain)")

    mongo_url = f"mongodb://{mongo_user}:{mongo_password}@snhebrok-eval.cs.upb.de:27018/?authSource=admin&readPreference=primary&appname=MongoDB+Compass&directConnection=true&ssl=true"
    print(f"Connecting to {mongo_url=}")
    mongo_driver = MongoClient(mongo_url)
    mongo_driver.server_info()
    print("Connected to MongoDB")
    scanner = Zgrab2Scanner(mongo_driver=mongo_driver)

    # CLUSTER = None
    # LIMIT = None
    CLUSTER = 4283  # Test Cluster (8409 domains)
    LIMIT = 10000  # Test Limit
    DOMAINS = set(get_domains(neo4j_driver, CLUSTER, LIMIT))
    print(f"Fetched {len(DOMAINS)} domains")

    STATS.start(len(DOMAINS))

    if parallelize:
        num_threads = None
        if isinstance(parallelize, int):
            num_threads = parallelize
        with ThreadPool(processes=num_threads) as pool:
            pool.map(lambda d: d.evaluate(neo4j_driver, scanner), DOMAINS)
    else:
        for domain in DOMAINS:
            domain.evaluate(neo4j_driver, scanner)


if __name__ == "__main__":
    main(16, True, False)
