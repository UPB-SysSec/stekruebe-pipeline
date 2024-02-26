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
    TLS1_0 = "0x0301"
    TLS1_1 = "0x0302"
    TLS1_2 = "0x0303"
    TLS1_3 = "0x0304"

    @classmethod
    def from_name(cls, name: str):
        # TLSv1.3 -> TLS1_3
        return cls[name.replace("v", "").replace(".", "_")]


class Scanner(abc.ABC):
    @abc.abstractmethod
    def scan(self, domain_from: str, addr_from: Connectable, *targed_addrs: Connectable, version=ScanVersion.TLS1_2):
        pass


class DummyScanner(Scanner):
    def scan(self, domain_from: str, addr_from: Connectable, *targed_addrs: Connectable, version=...):
        print(f"Scanning {domain_from} from {addr_from} to {len(targed_addrs)} targets on version {version.value}")
        STATS.done_targets(len(targed_addrs))


class Zgrab2Scanner(Scanner):
    def build_command(
        probe="http",
        max_redirects=1,
        redirects_succeed=True,
        force_session_tickets=False,
        min_version=0x0303,
        max_version=0x0303,
        port=443,
        use_session_cache=1,
        session_cache_dir="cache",
    ):
        """
        This method implements generating a call to a small subset of zgrab2 probe functionality with a few (by no means exhaustive) sanity checks.
        Use it to construct a command that calls zgrab2 which can be passed into subprocess.run and similar.
        For documentation, see zgrab2 -h.
        """
        cmd = [
            "./zgrab2",
        ]

        if probe not in ["http", "tls"]:
            raise NotImplementedError()
        cmd.append(f"{probe}")

        if probe == "http":
            cmd.append("--use-https")
            if redirects_succeed:
                cmd.append("--redirects-succeed")
            if max_redirects:
                cmd.append(f"--max-redirects={max_redirects}")

        if force_session_tickets:
            cmd.append("--force-session-ticket")

        cmd.append(f"--min-version={min_version}")
        cmd.append(f"--max-version={max_version}")

        cmd.append(f"--port={port}")

        if use_session_cache:
            cmd.append(f"--use-session-cache={use_session_cache}")
        if use_session_cache and session_cache_dir is not None:
            cmd.append(f"--session-cache-dir={session_cache_dir}")

        return cmd

    def __init__(
        self, mongo_driver, db_name="steckruebe", collection_name=f"ticket_redirection_{str(datetime.datetime.now())}"
    ) -> None:
        self.mongo_driver = mongo_driver
        self.mongo_db = mongo_driver[db_name]
        self.mongo_collection = self.mongo_db[collection_name]

    def scan(self, domain_from: str, addr_from: Connectable, *target_addrs: Connectable, version):
        """
        This method implements the scanning of a domain and its targets.
        It calls into the implementation _scan and is mainly responsible for persisting the results.
        """
        res = self._scan(domain_from, addr_from, *target_addrs, version=version)
        insert = self.mongo_collection.insert_one(res)
        STATS.done_targets(len(target_addrs))

    def _scan(
        self,
        domain_from: str,
        addr_from: Connectable,
        *target_addrs: Connectable,
        version: ScanVersion,
    ):
        """
        This method implements the actual scanning of a domain and its targets.
        """
        # get ticket for domain_from
        input_string = f"{addr_from.ip},{domain_from},\n".encode()
        with tempfile.TemporaryDirectory() as cache_dir:
            if version == ScanVersion.TLS1_2:
                initial_config = Zgrab2Scanner.build_command(
                    probe="tls",
                    force_session_tickets=True,
                    min_version=0x0301,
                    max_version=0x0303,
                    port=443,
                    use_session_cache=2,
                    session_cache_dir=cache_dir,
                )
            elif version == ScanVersion.TLS1_3:
                initial_config = Zgrab2Scanner.build_command(
                    probe="http",
                    max_redirects=1,
                    redirects_succeed=True,
                    min_version=0x0304,
                    max_version=0x0304,
                    port=443,
                    use_session_cache=2,
                    session_cache_dir=cache_dir,
                )
            else:
                # FIXME: technically this is implemented, but not tested
                raise NotImplementedError()

            initial = subprocess.run(
                initial_config,
                input=input_string,
                capture_output=True,
            )

            result = dict()
            result["initial"] = json.loads(initial.stdout)
            result["zgrab_initial_exitcode"] = initial.returncode

            # stop if no ticket was found, even though we expected one
            try:
                if result["initial"]["data"]["tls"]["result"]["handshake_log"]["session_ticket"] is not None:
                    initial_version_key = hex(
                        result["initial"]["data"]["tls"]["result"]["handshake_log"]["server_hello"]["version"]["value"]
                    )
            except KeyError:
                print("failed before redirecting, no ticket found")
                result["redirect"] = None
                return result

            if version == ScanVersion.TLS1_2:
                redirect_config = Zgrab2Scanner.build_command(
                    # FIXME: previously version up to 1.2 for resumption or exactly the previous version?
                    probe="http",
                    max_redirects=1,
                    redirects_succeed=True,
                    min_version=initial_version_key,
                    max_version=0x0303,
                    port=443,
                    use_session_cache=1,
                    session_cache_dir=cache_dir,
                )
            elif version == ScanVersion.TLS1_3:
                redirect_config = Zgrab2Scanner.build_command(
                    probe="http",
                    max_redirects=1,
                    redirects_succeed=True,
                    min_version=0x0304,
                    max_version=0x0304,
                    port=443,
                    use_session_cache=1,
                    session_cache_dir=cache_dir,
                )
            else:
                # FIXME: technically this is implemented, but not tested
                raise NotImplementedError()

            input_string = "".join([f"{target_addr.ip},{domain_from}\n" for target_addr in target_addrs]).encode()
            redirect = subprocess.run(
                redirect_config,
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
    RETURN DISTINCT [p.version, ip2.ip] as item
}}
RETURN *
ORDER BY rand()
LIMIT 10
"""


class Domain:
    def __init__(self, domain):
        self.domain = domain

    def _evaluate_from_ip(self, driver: Driver, scanner: Scanner, source_ip: str):
        with driver.session() as session:
            _targets = session.run(
                _BASE_QUERY.format(ip_target_type=IPType.V4.value)
                + " UNION "
                + _BASE_QUERY.format(ip_target_type=IPType.V6.value),
                domain=self.domain,
                ip=source_ip,
            )
            targets_by_version = {}
            for target in _targets:
                target_version, target_ip = target[0]
                if target_version not in targets_by_version:
                    targets_by_version[target_version] = []
                targets_by_version[target_version].append(Connectable(target_ip, 443))

        for version, local_targets in targets_by_version.items():
            scanner.scan(
                self.domain, Connectable(source_ip, 443), *local_targets, version=ScanVersion.from_name(version)
            )

    def _evaluate_in_iptype(self, driver: Driver, scanner: Scanner, tfrom: IPType):
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
                self._evaluate_from_ip(driver, scanner, source_ip[0])

    def evaluate(self, driver: Driver, scanner: Scanner):
        for tfrom in IPType:
            self._evaluate_in_iptype(driver, scanner, tfrom)

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


def main(parallelize, create_indexes=True, profile=False):
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
    scanner = DummyScanner()

    CLUSTER = None
    LIMIT = None
    CLUSTER = 374  # Test Cluster (2094 domains)
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
    # main(16, True, False)
    main(False, True, False)
