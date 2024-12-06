import abc
import logging
import subprocess
import tempfile
from typing import Any
from neo4j import GraphDatabase, Driver, Session, Result
from enum import Enum
import time
from dataclasses import dataclass, field
import datetime
import multiprocessing
from multiprocessing import Pool as ProcessPool
from multiprocessing.pool import ThreadPool
from pymongo.collection import Collection
from threading import Thread
import inspect
import traceback
from utils import JsonFilter
from utils.botp import BagOfTreePaths, BagOfXPaths
from utils import json_serialization as json
from utils.result import Connectable, Zgrab2ResumptionResult, ScanVersion, Zgrab2ResumptionResultStatus
from utils.misc import extract_title
from utils.db import connect_mongo, connect_neo4j


@dataclass
class _DBStats:
    executed_queries: int = 0
    done_queries: int = 0
    db_hits: int = 0
    time_ready: int = 0
    time_consumed: int = 0


# Global Scan Context
class ScanContext:
    neo4j: GraphDatabase = None
    mongo_result_collection: Collection = None
    scanner: "Scanner" = None

    @staticmethod
    def initialize(
        mongo_collection_name=None, *, create_indexes=True, verify_connectivity=True, dummy_scanner=False, profile=False
    ):
        if not mongo_collection_name:
            mongo_collection_name = f"ticket_redirection_{datetime.datetime.now():%Y-%m-%d_%H:%M}"

        ScanContext.neo4j = connect_neo4j(verify_connectivity=verify_connectivity)
        if profile:
            ScanContext.neo4j = _ProfileDriver(STATS, ScanContext.neo4j, profile)

        mongodb = connect_mongo(verify_connectivity=verify_connectivity)
        database = mongodb["steckruebe"]
        if mongo_collection_name == "test" and "test" in database.list_collection_names():
            database["test"].drop()
        ScanContext.mongo_result_collection = database[mongo_collection_name]

        if dummy_scanner:
            ScanContext.scanner = DummyScanner()
        else:
            ScanContext.scanner = Zgrab2Scanner()

        if create_indexes:
            # prepare indexes
            ScanContext.neo4j.execute_query("CREATE INDEX ip_lookup IF NOT EXISTS FOR (x:IP) ON (x.ip)")
            ScanContext.neo4j.execute_query("CREATE INDEX domain_lookup IF NOT EXISTS FOR (x:DOMAIN) ON (x.domain)")
            ScanContext.neo4j.execute_query(
                "CREATE INDEX prefix_version_lookup IF NOT EXISTS FOR (x:PREFIX) ON (x.version)"
            )

            ScanContext.mongo_result_collection.create_index("domain_from")
            ScanContext.mongo_result_collection.create_index("addr_from.ip")
            ScanContext.mongo_result_collection.create_index("version")
            ScanContext.mongo_result_collection.create_index("status")
            # prepare indexes for 3_evaluate; now it is basically free, later it costs some time
            ScanContext.mongo_result_collection.create_index("_analyzed")
            ScanContext.mongo_result_collection.create_index([("status", 1), ("_analyzed", 1)])


class _Stats:
    def __init__(self) -> None:
        self.domains = multiprocessing.Value("Q", 0)
        self.targets = multiprocessing.Value("Q", 0)
        self.expected_domains = 0
        self.start_time = 0
        self.db = {}
        self.executed_queries = 0
        self.done_queries = 0

    def start(self, expected_domains: int):
        self.start_time = time.time()
        self.expected_domains = expected_domains

    def done_domain(self):
        with self.domains.get_lock():
            self.domains.value += 1

    def done_targets(self, n):
        with self.targets.get_lock():
            self.targets.value += n

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
        if self.domains.value == 0:
            ETA = None
            DURATION = None
            PERCENT = 0
        else:
            ETA = (self.expected_domains - self.domains.value) / (self.domains.value / elapsed)
            DURATION = datetime.timedelta(seconds=elapsed + ETA)
            ETA = datetime.timedelta(seconds=ETA)
            if self.expected_domains == 0:
                PERCENT = 0
            else:
                PERCENT = self.domains.value / self.expected_domains
        ret = (
            f"Total: {self.domains.value}/{self.expected_domains} domains, {self.targets.value} targets in {elapsed:.2f} seconds | "
            f"{self.domains.value/elapsed:.2f} domains/s {PERCENT:6.2%} | "
            f"ETA: {ETA} / Total: {DURATION} | "
            f"{self.targets.value/elapsed:.2f} targets/s"
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
STATS_INTERVAL = 60


def _stats_printer():
    while STATS.start_time == 0:
        time.sleep(1)
    while True:
        print(STATS)
        time.sleep(STATS_INTERVAL)


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
    "!data.http.result.response.body",
    "!data.http.result.response.body_len",
    "!data.http.result.response.body_botp",
    "!data.http.result.response.body_boxp",
    "!data.http.result.response.status_code",
    "!data.http.result.response.status_line",
    "!data.http.result.response.headers",
    "!data.http.result.response.body_sha256",
    "!data.http.result.response.content_length",
    "!data.http.result.response.content_title",
    "!data.http.result.response.request.tls_log",
    "*.handshake_log.server_certificates.chain.parsed",
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
            "zgrab2_tls13",
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
            cmd.append("--max-size=1024")
            cmd.append("--user-agent=Mozilla/5.0 zgrab/fork-tls1.3")

        if force_session_tickets:
            cmd.append("--force-session-ticket")

        cmd.append(f"--min-version={min_version}")
        cmd.append(f"--max-version={max_version}")

        cmd.append(f"--port={port}")

        if use_session_cache:
            cmd.append(f"--use-session-cache={use_session_cache}")
        if use_session_cache and session_cache_dir is not None:
            cmd.append(f"--session-cache-dir={session_cache_dir}")

        cmd.append("--senders=1")  # throttle ourselves a bit. We are running multithreaded anyways.

        return cmd

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
            raise e
            res = {"error": str(e), "traceback": traceback.format_exc()}
        assert isinstance(res, dict)
        try:
            ScanContext.mongo_result_collection.insert_one(res)
        except Exception as e:
            print(
                f"Failed to insert result for {domain_from=} {addr_from=} {target_addrs=} {version=} into MongoDB: {e}"
            )
        STATS.done_targets(len(target_addrs))

    def filter_result(self, result: dict):
        try:
            body = result["data"]["http"]["result"]["response"]["body"]
            # extract title from html body
            title = extract_title(body)
            if title and len(title) > 1000:
                domain = result["domain"]
                ip = result["ip"]
                print(f"WARN: long title encountered ({domain}@{ip}) length: {len(title)}, truncating to 2.000")
                title = title[:2_000]
            result["data"]["http"]["result"]["response"]["content_title"] = title
            # if we keep the body for debugging, we truncate it a bit
            result["data"]["http"]["result"]["response"]["body_len"] = len(body)
            result["data"]["http"]["result"]["response"]["body"] = body[:10_000]
            result["data"]["http"]["result"]["response"]["body_botp"] = BagOfTreePaths(body).paths
            result["data"]["http"]["result"]["response"]["body_boxp"] = BagOfXPaths(body).paths
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
            for redirect_result in redirect_results:
                del redirect_result["domain"]  # this is the domain_from and just confusing
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


# TODO: maybe replace rand() with something reproducible
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

    def _evaluate_from_ip(
        self,
        source_ip: str,
        versions_to_evaluate=(ScanVersion.TLS1_3, ScanVersion.PRE_1_3),
    ):
        if set(versions_to_evaluate) > {ScanVersion.TLS1_3, ScanVersion.PRE_1_3}:
            raise ValueError("versions_to_evaluate must be a subset of {TLS1_3, PRE_1_3}")

        with ScanContext.neo4j.session() as session:
            _QUERY = []
            for iptype in IPType:
                for version in versions_to_evaluate:
                    _QUERY.append(
                        _BASE_QUERY.format(
                            ip_target_type=iptype.value,
                            v13_equality_operator="=" if version == ScanVersion.TLS1_3 else "<>",
                        )
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

        # Always scann all domain,ip pairs, even if we do not have a target
        # This enables us to gather all bodies
        # if targets_13:
        if ScanVersion.TLS1_3 in versions_to_evaluate:
            ScanContext.scanner.scan(self.domain, Connectable(source_ip, 443), targets_13, ScanVersion.TLS1_3)
        # if targets_pre13:
        if ScanVersion.PRE_1_3 in versions_to_evaluate:
            ScanContext.scanner.scan(self.domain, Connectable(source_ip, 443), targets_pre13, ScanVersion.PRE_1_3)

    def _evaluate_in_iptype(self, tfrom: IPType):
        if not isinstance(tfrom, IPType):
            raise TypeError("tfrom must be IPType")

        with ScanContext.neo4j.session() as session:
            # get source IPs
            ips = session.run(
                f"""
                MATCH (d:DOMAIN {{domain: $domain}})--(ip:{tfrom.value})
                RETURN DISTINCT ip.ip
                """,
                domain=self.domain,
            )

            for source_ip in ips:
                self._evaluate_from_ip(source_ip[0])

    def evaluate(self):
        for tfrom in IPType:
            self._evaluate_in_iptype(tfrom)
        STATS.done_domain()


def get_domains(cluster: int = None, limit: int = None):
    with ScanContext.neo4j.session() as session:
        if cluster is None:
            query = "MATCH (n: DOMAIN) RETURN n.domain AS domain"
        else:
            assert isinstance(cluster, int)
            query = "MATCH (n: DOMAIN {clusterID: $cluster}) RETURN n.domain AS domain"
        if limit is not None:
            query += f" LIMIT $limit"
        query = session.run(query, cluster=cluster, limit=limit)
        for record in query:
            yield record.get("domain")


def print_dummy_query():
    print(
        "PROFILE\n"
        + _BASE_QUERY.format(ip_target_type="IP")
        .replace("$domain", '"r3---sn-5uaeznes.googlevideo.com"')
        .replace("$ip", '"172.217.128.200"')
    )


def evaluate_domain(domain: str):
    assert isinstance(domain, str)
    return Domain(domain).evaluate()


def main(
    parallelize,
    *,
    create_indexes=True,
    profile=False,
    dummy_scanner=False,
    explicit_collection=None,
    CLUSTER=None,
    LIMIT=None,
):

    ScanContext.initialize(
        mongo_collection_name=explicit_collection,
        create_indexes=create_indexes,
        profile=profile,
        dummy_scanner=dummy_scanner,
    )

    # print_dummy_query()

    # getting all domains takes a bit, but still reasonable | about 47 seconds for 620,076 domains

    if (
        CLUSTER is not None
        or LIMIT is not None
        or isinstance(ScanContext.scanner, DummyScanner)
        or profile
        or not parallelize
        or not create_indexes
        or explicit_collection
    ):
        global STATS_INTERVAL
        STATS_INTERVAL = 10
        print(
            f"TEST mode is active: {CLUSTER=}, {LIMIT=}, {ScanContext.scanner=}, {profile=}, {parallelize=}, {create_indexes=}, {explicit_collection=}"
        )
    else:
        print("Production Mode | gl;hf")

    DOMAINS = set(get_domains(CLUSTER, LIMIT))
    print(f"Fetched {len(DOMAINS)} domains ({CLUSTER=}, {LIMIT=})")
    STATS.start(len(DOMAINS))

    if parallelize or parallelize is None:
        num_threads = None
        if isinstance(parallelize, (int, type(None))):
            num_threads = parallelize
        with ProcessPool(processes=num_threads) as pool:
            pool.map(evaluate_domain, DOMAINS)
    else:
        for domain in DOMAINS:
            evaluate_domain(domain)

    print("DONE")
    print(STATS)


# region TEST Stuff


def evaluate_missing_pairs(missing_domain_ip_pairs: dict[tuple[str, str], ScanVersion], parallelize, collection_name):
    raise NotImplementedError("broken since creating scancontext")

    def _evaluate_missing_domain(entry):
        (domain, ip), versions_to_evaluate = entry
        Domain(domain)._evaluate_from_ip(scanner, ip, versions_to_evaluate)
        STATS.done_domain()

    STATS.start(len(missing_domain_ip_pairs))
    if parallelize:
        num_threads = None
        if isinstance(parallelize, int):
            num_threads = parallelize
        with ThreadPool(processes=num_threads) as pool:
            pool.imap(_evaluate_missing_domain, missing_domain_ip_pairs.items())
    else:
        for entry in missing_domain_ip_pairs.items():
            _evaluate_missing_domain(entry)


def main_missing():
    with open("91.log") as f:
        missing = {}
        # skip header
        for ln in f:
            if ln.startswith("Missing in both versions:"):
                break
        for version_miss, next_start_ln in [
            ((ScanVersion.TLS1_3, ScanVersion.PRE_1_3), "Missing only 1.3:"),
            ((ScanVersion.TLS1_3,), "Missing only 1.2:"),
            ((ScanVersion.PRE_1_3,), None),
        ]:
            print(version_miss, len(missing))
            for ln in f:
                ln = ln.strip()
                if ln.startswith("("):
                    domain, ip = ln.strip("()").split(", ")
                    domain = domain.strip("'")
                    ip = ip.strip("'")
                    if "adoptapet.com" not in domain:
                        continue
                    missing[(domain, ip)] = version_miss
                else:
                    assert ln.startswith("Missing")
                    if next_start_ln == ln.strip():
                        break
                    raise ValueError(ln)
        # evaluate_missing_pairs(missing, 64, "ticket_redirection_2024-06-12 19:41:10.680922")
        evaluate_missing_pairs(missing, False, "test")


def test(domain: str):
    ScanContext.scanner = DummyScanner()
    Domain(domain).evaluate()


def test_with_zgrab(domain: str):
    class FakeMongoDriver:
        def __getitem__(self, key):
            return self

        def insert_one(self, data):
            print(data)

    ScanContext.neo4j = connect_neo4j()
    ScanContext.scanner = Zgrab2Scanner(mongo_driver=FakeMongoDriver())
    Domain(domain).evaluate()


# endregion TEST Stuff

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s | %(process)d %(processName)s - %(name)s.%(funcName)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("neo4j").setLevel(logging.CRITICAL)
    # from utils import debug
    # debug.MemoryMonitor(key_type="traceback", limit=10, trace_depth=10).start()
    # main(64*3, explicit_collection="test")
    main(64 * 3)  # PROD
