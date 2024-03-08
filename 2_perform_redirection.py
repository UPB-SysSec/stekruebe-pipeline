import abc
import subprocess
import sys
import tempfile
from typing import Any
from neo4j import GraphDatabase, Driver, Session, Result
from enum import Enum
import time
from dataclasses import dataclass, field
import datetime
from multiprocessing.pool import ThreadPool
from pymongo import MongoClient
from threading import Thread
import inspect
import traceback
from utils import JsonFilter
from itertools import product
from utils.credentials import mongodb_creds, neo4j_creds
from utils import json_serialization as json
from utils.result import Connectable, Zgrab2ResumptionResult, ScanVersion, Zgrab2ResumptionResultStatus
from utils.misc import extract_title


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
        time.sleep(1)
    while True:
        print(STATS)
        time.sleep(60)


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


class Scanner(abc.ABC):
    @abc.abstractmethod
    def scan(self, domain_from: str, addr_from: Connectable, target_addrs: list[Connectable], version):
        pass


class DummyScanner(Scanner):

    def scan(self, domain_from: str, addr_from: Connectable, target_addrs: list[Connectable], version):
        print(f"Scanning {domain_from} from {addr_from} to {len(target_addrs)} targets on version {version.name}")
        STATS.done_targets(len(target_addrs))


class ZgrabHelper:
    @staticmethod
    def get_tls_handshake_log(result: dict):
        data = result.get("data")
        if "http" in data:
            return data["http"]["result"]["response"]["request"]["tls_log"]["handshake_log"]
        try:
            return data["tls"]["result"]["handshake_log"]
        except KeyError:
            return None

    @staticmethod
    def has_ticket(result: dict):
        try:
            handshake_log = ZgrabHelper.get_tls_handshake_log(result)
            if ZgrabHelper.get_version_name(result) == "TLSv1.3":
                post_handshake = handshake_log["post_handshake"]
                tickets = post_handshake["session_tickets"]
                return bool(tickets)
            else:
                return bool(handshake_log["session_ticket"])
        except KeyError:
            return False

    @staticmethod
    def get_version(result: dict):
        try:
            server_hello = ZgrabHelper.get_tls_handshake_log(result)["server_hello"]
            version = server_hello["version"]
            if "supported_versions" in server_hello:
                version = server_hello["supported_versions"]["selected_version"]
            return version
        except KeyError:
            return None

    @staticmethod
    def get_version_name(result: dict):
        try:
            return ZgrabHelper.get_version(result)["name"]
        except (KeyError, TypeError):
            return None

    @staticmethod
    def get_version_key(result: dict):
        try:
            return hex(ZgrabHelper.get_version(result)["value"])
        except (KeyError, TypeError):
            return None


ZGRAB2_FILTER = JsonFilter(
    "data.http.result.*",
    "!data.http.result.response.status_code",
    "!data.http.result.response.status_line",
    "!data.http.result.response.headers",
    "!data.http.result.response.body_sha256",
    "!data.http.result.response.content_length",
    "!data.http.result.response.content_title",
    "!data.http.result.response.request.tls_log",
    "*.handshake_log.server_certificates.*.parsed",
)


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

        cmd.append("--user-agent=Mozilla/5.0 zgrab/fork-tls1.3")
        cmd.append("--senders=1")  # throttle ourselves a bit. We are running multithreaded anyways.

        return cmd

    def __init__(
        self,
        mongo_driver: MongoClient,
        db_name="steckruebe",
        collection_name=f"ticket_redirection_{str(datetime.datetime.now())}",
    ) -> None:
        self.mongo_driver = mongo_driver
        self.mongo_db = mongo_driver[db_name]
        self.mongo_collection = self.mongo_db[collection_name]
        self.mongo_collection.create_index("domain_from")
        self.mongo_collection.create_index("addr_from")
        self.mongo_collection.create_index("version")
        self.mongo_collection.create_index("status")

    def scan(self, domain_from: str, addr_from: Connectable, target_addrs: list[Connectable], version):
        """
        This method implements the scanning of a domain and its targets.
        It calls into the implementation _scan and is mainly responsible for persisting the results.
        """
        res = Zgrab2ResumptionResult(
            domain_from=domain_from,
            addr_from=addr_from,
            target_addrs=target_addrs,
            version=version,
            status=Zgrab2ResumptionResultStatus.PENDING,
        )
        try:
            _res = self._scan(domain_from, addr_from, target_addrs, version, res)
            assert _res is res
            res = res.to_dict()
        except Exception as e:
            res = {"error": str(e), "traceback": traceback.format_exc()}
        assert isinstance(res, dict)
        insert = self.mongo_collection.insert_one(res)
        STATS.done_targets(len(target_addrs))

    def filter_result(self, result: dict):
        try:
            body = result["data"]["http"]["result"]["response"]["body"]
            # extract title from html body
            result["data"]["http"]["result"]["response"]["content_title"] = title = extract_title(body)
        except KeyError:
            pass
        return ZGRAB2_FILTER(result)

    def _parse_status_line(self, process):
        try:
            return json.loads(process.stderr.decode().strip().split("\n")[-1])
        except:
            return {"error": "failed to parse", "raw": repr(process.stderr), "traceback": traceback.format_exc()}

    def _scan(
        self,
        domain_from: str,
        addr_from: Connectable,
        target_addrs: Connectable,
        version: ScanVersion,
        res: Zgrab2ResumptionResult,
    ):
        """
        This method implements the actual scanning of a domain and its targets.
        """
        # get ticket for domain_from
        input_string = f"{addr_from.ip},{domain_from},\n".encode()
        with tempfile.TemporaryDirectory() as cache_dir:
            min_version = 0x0301 if version != ScanVersion.TLS1_3 else 0x0304
            max_version = 0x0303 if version != ScanVersion.TLS1_3 else 0x0304
            initial_config = Zgrab2Scanner.build_command(
                probe="http",
                max_redirects=0,
                redirects_succeed=True,
                force_session_tickets=version != ScanVersion.TLS1_3,
                min_version=min_version,
                max_version=max_version,
                port=443,
                use_session_cache=2,
                session_cache_dir=cache_dir,
            )

            initial = subprocess.run(
                initial_config,
                input=input_string,
                capture_output=True,
            )
            res.initial_exitcode = initial.returncode
            res.initial_status_line = self._parse_status_line(initial)
            res.status = Zgrab2ResumptionResultStatus.INITIAL_RAN

            res.initial = self.filter_result(json.loads(initial.stdout))
            res.status = Zgrab2ResumptionResultStatus.INITIAL_PARSED

            initial_version_key = ZgrabHelper.get_version_key(res.initial)
            if initial_version_key is None:
                # print("failed before redirecting, no version key found")
                res.status = Zgrab2ResumptionResultStatus.INITIAL_NO_VERSION
                return res
            if not ZgrabHelper.has_ticket(res.initial):
                # print("failed before redirecting, no ticket found")
                res.status = Zgrab2ResumptionResultStatus.INITIAL_NO_TICKET
                return res

            min_version = initial_version_key
            redirect_config = Zgrab2Scanner.build_command(
                probe="http",
                max_redirects=0,
                redirects_succeed=True,
                min_version=min_version,
                max_version=max_version,
                port=443,
                use_session_cache=1,
                session_cache_dir=cache_dir,
            )

            input_string = "".join([f"{target_addr.ip},{domain_from}\n" for target_addr in target_addrs]).encode()
            redirect = subprocess.run(
                redirect_config,
                input=input_string,
                capture_output=True,
            )
            res.redirect_exitcode = redirect.returncode
            res.redirect_status_line = self._parse_status_line(redirect)
            res.status = Zgrab2ResumptionResultStatus.RESUMPTION_RAN
            redirect_results = [self.filter_result(json.loads(res)) for res in redirect.stdout.splitlines()]
            res.status = Zgrab2ResumptionResultStatus.RESUMPTION_PARSED
            # HTTP: body_sha, body_title, status_code, location_header
            # del certs
            res.redirect = redirect_results
            # newline separated json objects
            res.status = Zgrab2ResumptionResultStatus.SUCCESS
            return res


class IPType(Enum):
    V4 = "IPV4"
    V6 = "IPV6"


_BASE_QUERY = """
CALL {{
    MATCH (d1:DOMAIN {{domain: $domain}})--(ip1:IP {{ip: $ip}})--(p:PREFIX)--(ip2:{ip_target_type}), (d1)--(p)
    WHERE ip1<>ip2 AND NOT (d1)-->(ip2) AND p.version{v13_equality_operator}"TLSv1.3"
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
            _QUERY = []
            for iptype, is_TLS_13 in product(IPType, [False, True]):
                _QUERY.append(
                    _BASE_QUERY.format(ip_target_type=iptype.value, v13_equality_operator="=" if is_TLS_13 else "<>")
                )
            _QUERY = " UNION ".join(_QUERY)
            _targets = session.run(
                _QUERY,
                domain=self.domain,
                ip=source_ip,
            )
            targets_13 = []
            targets_pre13 = []
            for target in _targets:
                target_version, target_ip = target[0]
                if target_version == "TLSv1.3":
                    targets_13.append(Connectable(target_ip, 443))
                else:
                    targets_pre13.append(Connectable(target_ip, 443))

        if targets_13:
            scanner.scan(self.domain, Connectable(source_ip, 443), targets_13, ScanVersion.TLS1_3)
        if targets_pre13:
            scanner.scan(self.domain, Connectable(source_ip, 443), targets_pre13, ScanVersion.PRE_1_3)

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

    neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=neo4j_creds.as_tuple())
    if profile:
        neo4j_driver = _ProfileDriver(STATS, neo4j_driver, profile)

    # getting all domains takes a bit, but still reasonable | about 47 seconds for 620,076 domains

    if create_indexes:
        # prepare indexes
        neo4j_driver.execute_query("CREATE INDEX ip_lookup IF NOT EXISTS FOR (x:IP) ON (x.ip)")
        neo4j_driver.execute_query("CREATE INDEX domain_lookup IF NOT EXISTS FOR (x:DOMAIN) ON (x.domain)")
        neo4j_driver.execute_query("CREATE INDEX prefix_version_lookup IF NOT EXISTS FOR (x:PREFIX) ON (x.version)")

    # mongo_url = f"mongodb://{mongo_user}:{mongo_password}@snhebrok-eval.cs.upb.de:27018/?authSource=admin&readPreference=primary&appname=MongoDB+Compass&directConnection=true&ssl=true"
    mongo_url = f"mongodb://{mongodb_creds.as_str()}@127.0.0.1:27017/?authSource=admin&readPreference=primary&directConnection=true&ssl=true"
    print(f"Connecting to {mongo_url=}")
    mongo_driver = MongoClient(mongo_url, tlsAllowInvalidCertificates=True)
    mongo_driver.server_info()
    print("Connected to MongoDB")
    scanner = Zgrab2Scanner(mongo_driver=mongo_driver)
    # scanner = DummyScanner()  # Test

    CLUSTER = None
    LIMIT = None
    # MATCH (n:DOMAIN) RETURN n.clusterID, count(n.clusterID) as c ORDER BY c DESC
    # CLUSTER = 393  # Test Cluster (2094 domains)
    # LIMIT = 1000  # Test Limit

    if (
        CLUSTER is not None
        or LIMIT is not None
        or isinstance(scanner, DummyScanner)
        or profile
        or not parallelize
        or not create_indexes
    ):
        print(f"TEST mode is active: {CLUSTER=}, {LIMIT=}, {scanner=}, {profile=}, {parallelize=}, {create_indexes=}")
    else:
        print("Production Mode | gl;hf")

    DOMAINS = set(get_domains(neo4j_driver, CLUSTER, LIMIT))
    print(f"Fetched {len(DOMAINS)} domains ({CLUSTER=}, {LIMIT=})")
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


def test(domain: str):
    neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=neo4j_creds.as_tuple())
    scanner = DummyScanner()  # Test
    Domain(domain).evaluate(neo4j_driver, scanner)


def test_with_zgrab(domain: str):
    class FakeMongoDriver:
        def __getitem__(self, key):
            return self

        def insert_one(self, data):
            print(data)

    neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=neo4j_creds.as_tuple())
    scanner = Zgrab2Scanner(mongo_driver=FakeMongoDriver())
    Domain(domain).evaluate(neo4j_driver, scanner)


if __name__ == "__main__":
    # test("latam.com")
    # test_with_zgrab("latam.com")
    main(64, True, False)
    # main(False, True, False)
